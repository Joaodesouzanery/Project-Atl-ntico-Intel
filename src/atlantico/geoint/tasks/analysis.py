"""
Tasks Celery de análise GEOINT.

- geoint_analyze_deforestation: severity + NDVI + trend
- geoint_cluster_fires:         DBSCAN em focos recentes
- geoint_detect_water_anomalies: Z-score em observações pendentes
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from atlantico.geoint.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


# ─── Desmatamento ──────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="geoint.analyze_deforestation",
    queue="geoint_analysis",
)
def geoint_analyze_deforestation(self, event_ids: list[str] | None = None) -> dict:
    """
    Processa eventos de desmatamento pendentes.
    1. Busca DeforestationEvents com analysis_status='pending'
    2. Classifica severity via DeforestationProcessor
    3. Tenta computar NDVI (se imagery disponível)
    4. Marca como processed e dispara alertas para eventos acima do limiar
    """
    try:
        return asyncio.run(_async_analyze_deforestation(event_ids))
    except Exception as exc:
        logger.error("geoint_analyze_deforestation falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_analyze_deforestation(event_ids: list[str] | None) -> dict:
    from atlantico.config.settings import get_settings
    from atlantico.geoint.processing.deforestation_processor import DeforestationProcessor
    from atlantico.geoint.repositories.deforestation_repo import DeforestationRepository
    from atlantico.geoint.repositories.imagery_repo import ImageryRepository
    from atlantico.storage.database import AsyncSessionLocal
    from atlantico.storage.encrypted_field import EncryptionContext

    settings = get_settings()
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(settings.master_key_bytes)

    processor = DeforestationProcessor()
    processed = 0
    alerts_queued = 0

    async with AsyncSessionLocal() as session:
        defor_repo = DeforestationRepository(session)
        imagery_repo = ImageryRepository(session)

        events = await defor_repo.list_unprocessed(limit=200)

        for event in events:
            try:
                # Reclassifica severity (pode ter mudado com novos dados)
                new_severity = processor.classify_severity(float(event.area_ha))

                # Tenta correlacionar com imagens Sentinel-2 disponíveis
                if event.geom is not None:
                    geom_str = str(event.geom)
                    if "SRID=" in geom_str:
                        geom_str = geom_str.split(";", 1)[1]
                    imagery_list = await imagery_repo.list_for_area(
                        polygon_wkt=geom_str,
                        since=event.acquired_at - timedelta(days=30) if event.acquired_at else datetime.now(tz=timezone.utc) - timedelta(days=30),
                        max_cloud_cover=20.0,
                    )
                    # NDVI computation requires local imagery files — returns None
                    # if imagery files not downloaded locally (Sprint 5+)
                    ndvi_before, ndvi_after = processor.compute_ndvi_change(
                        geometry_wkt=geom_str,
                        before_imagery_path=None,
                        after_imagery_path=None,
                    )
                    if ndvi_before is not None or ndvi_after is not None:
                        await defor_repo.update_ndvi(event.id, ndvi_before, ndvi_after)
                else:
                    ndvi_before = ndvi_after = None

                await defor_repo.mark_processed(event.id, "processed")
                processed += 1

                # Dispara alerta se acima do limiar
                if float(event.area_ha) >= settings.geoint_deforestation_alert_ha:
                    geoint_generate_alerts.delay(
                        event_type="deforestation",
                        event_ids=[str(event.id)],
                    )
                    alerts_queued += 1

            except Exception as exc:
                logger.warning("Falha ao processar evento %s: %s", event.id, exc)
                continue

        await session.commit()

    return {"processed": processed, "alerts_queued": alerts_queued}


# ─── Incêndio — Clustering DBSCAN ─────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    name="geoint.cluster_fires",
    queue="geoint_analysis",
)
def geoint_cluster_fires(self, since_iso: str | None = None) -> dict:
    """
    Executa DBSCAN em focos de incêndio recentes.
    Persiste FireClusters, atualiza FireHotspot.cluster_id, verifica infraestrutura.
    """
    try:
        return asyncio.run(_async_cluster_fires(since_iso))
    except Exception as exc:
        logger.error("geoint_cluster_fires falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_cluster_fires(since_iso: str | None) -> dict:
    from atlantico.config.settings import get_settings
    from atlantico.geoint.processing.fire_processor import FireProcessor
    from atlantico.geoint.repositories.fire_repo import FireRepository
    from atlantico.geoint.repositories.infrastructure_repo import InfrastructureRepository
    from atlantico.storage.database import AsyncSessionLocal
    from atlantico.storage.encrypted_field import EncryptionContext

    settings = get_settings()
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(settings.master_key_bytes)

    if since_iso:
        since = datetime.fromisoformat(since_iso).replace(tzinfo=timezone.utc)
    else:
        since = datetime.now(tz=timezone.utc) - timedelta(hours=24)

    processor = FireProcessor()
    clusters_created = 0
    hotspots_clustered = 0

    async with AsyncSessionLocal() as session:
        fire_repo = FireRepository(session)
        infra_repo = InfrastructureRepository(session)

        hotspots = await fire_repo.list_hotspots_unprocessed(since=since, limit=5000)

        if not hotspots:
            return {"clusters_created": 0, "hotspots_clustered": 0}

        clusters = processor.cluster_hotspots(
            hotspots=hotspots,
            eps_km=settings.geoint_fire_cluster_eps_km,
            min_samples=settings.geoint_fire_cluster_min_samples,
        )

        for cluster in clusters:
            # Verifica proximidade a infraestrutura crítica
            centroid_str = str(cluster.centroid_geom)
            if "SRID=" in centroid_str:
                centroid_str = centroid_str.split(";", 1)[1]

            nearby_assets = await infra_repo.find_within_buffer(
                geometry_wkt=centroid_str,
                buffer_km=settings.geoint_infra_buffer_km,
            )

            if nearby_assets:
                cluster.near_infrastructure = True
                cluster.infra_asset_ids = [str(a.id) for a in nearby_assets]

            # Persiste o cluster
            saved_cluster = await fire_repo.store_cluster(cluster)
            clusters_created += 1

            # Associa hotspots ao cluster
            # Identifica quais hotspots pertencem a este cluster
            # (baseado na distância dentro de eps_km do centroide)
            cluster_hotspot_ids = await _find_hotspots_for_cluster(
                fire_repo=fire_repo,
                cluster=saved_cluster,
                hotspots=hotspots,
                eps_km=settings.geoint_fire_cluster_eps_km,
            )

            if cluster_hotspot_ids:
                await fire_repo.assign_cluster(cluster_hotspot_ids, saved_cluster.id)
                hotspots_clustered += len(cluster_hotspot_ids)

            # Dispara alerta se cluster acima do limiar
            if cluster.hotspot_count >= settings.geoint_fire_alert_cluster_size:
                geoint_generate_alerts.delay(
                    event_type="fire_cluster",
                    event_ids=[str(saved_cluster.id)],
                )

        await session.commit()

    return {"clusters_created": clusters_created, "hotspots_clustered": hotspots_clustered}


async def _find_hotspots_for_cluster(
    fire_repo,
    cluster,
    hotspots,
    eps_km: float,
) -> list[uuid.UUID]:
    """Encontra hotspots que pertencem ao cluster por proximidade ao centroide."""
    centroid_str = str(cluster.centroid_geom)
    if "SRID=" in centroid_str:
        centroid_str = centroid_str.split(";", 1)[1]

    import re
    match = re.search(r"POINT\s*\(\s*([-\d.]+)\s+([-\d.]+)\s*\)", centroid_str)
    if not match:
        return []

    clon = float(match.group(1))
    clat = float(match.group(2))

    nearby = await fire_repo.list_hotspots_near_point(
        lon=clon,
        lat=clat,
        radius_km=eps_km,
    )
    return [h.id for h in nearby if h.cluster_id is None]


# ─── Recursos Hídricos — Anomalia Z-score ─────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="geoint.detect_water_anomalies",
    queue="geoint_analysis",
)
def geoint_detect_water_anomalies(self) -> dict:
    """
    Detecta anomalias Z-score em observações hídricas pendentes.
    Dispara alertas para observações com anomalia.
    """
    try:
        return asyncio.run(_async_detect_water_anomalies())
    except Exception as exc:
        logger.error("geoint_detect_water_anomalies falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_detect_water_anomalies() -> dict:
    from atlantico.config.settings import get_settings
    from atlantico.geoint.processing.water_processor import WaterProcessor
    from atlantico.geoint.repositories.water_repo import WaterRepository
    from atlantico.storage.database import AsyncSessionLocal
    from atlantico.storage.encrypted_field import EncryptionContext

    settings = get_settings()
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(settings.master_key_bytes)

    since = datetime.now(tz=timezone.utc) - timedelta(hours=6)
    processor = WaterProcessor()
    analyzed = 0
    anomalies_found = 0

    async with AsyncSessionLocal() as session:
        water_repo = WaterRepository(session)
        observations = await water_repo.list_unanalyzed(since=since, limit=1000)

        for obs in observations:
            try:
                mean, stddev = await water_repo.get_historical_stats(
                    station_code=obs.station_code,
                    measurement_type=obs.measurement_type,
                    lookback_days=365,
                )

                result = processor.analyze_observation(
                    obs=obs,
                    historical_mean=mean,
                    historical_stddev=stddev,
                    stddev_threshold=settings.geoint_water_anomaly_stddev,
                )

                await water_repo.save_anomaly_analysis(
                    observation_id=obs.id,
                    historical_mean=result["historical_mean"],
                    historical_stddev=result["historical_stddev"],
                    z_score=result["z_score"],
                    anomaly_type=result["anomaly_type"],
                    anomaly_severity=result["anomaly_severity"],
                )

                analyzed += 1
                if result["has_anomaly"]:
                    anomalies_found += 1
                    geoint_generate_alerts.delay(
                        event_type="water_anomaly",
                        event_ids=[str(obs.id)],
                    )

            except Exception as exc:
                logger.warning("Falha ao analisar observação %s: %s", obs.id, exc)
                continue

        await session.commit()

    return {"analyzed": analyzed, "anomalies_found": anomalies_found}


# Import circular resolvido no final
from atlantico.geoint.tasks.alert_tasks import geoint_generate_alerts  # noqa: E402
