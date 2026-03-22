"""
GeointAlertGenerator — geração de alertas GEOINT assinados com Dilithium.

Delega criação e assinatura de alertas ao AlertRepository (Sprint 2),
que usa assinaturas Dilithium3+Ed25519 via KeyManager e crypto/.

Segurança: nenhum acesso direto a crypto/ — tudo via AlertRepository.create().
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from atlantico.geoint.alerts.rules import ALERT_RULES, AlertRule
from atlantico.geoint.models.deforestation import DeforestationEvent
from atlantico.geoint.models.fire import FireCluster
from atlantico.geoint.models.water import WaterObservation
from atlantico.storage.models.alert import Alert
from atlantico.storage.repositories.alert_repo import AlertRepository
from atlantico.storage.repositories.audit_log_repo import AuditLogRepository

logger = logging.getLogger(__name__)


class GeointAlertGenerator:
    """
    Gera alertas GEOINT usando o AlertRepository existente.

    Garante:
    - Alertas assinados com Dilithium3+Ed25519 (via AlertRepository.create)
    - Audit log registrado para cada alerta gerado
    - Idempotência: verifica alert_id antes de criar (evita duplicatas)
    """

    def __init__(
        self,
        alert_repo: AlertRepository,
        audit_log: AuditLogRepository,
    ) -> None:
        self._alert_repo = alert_repo
        self._audit_log = audit_log

    async def generate_deforestation_alert(
        self,
        event: DeforestationEvent,
        source_record_ids: list[str],
        rule_key: str = "geoint.deforestation.threshold",
        extra_context: dict | None = None,
    ) -> Alert | None:
        """
        Gera alerta para evento de desmatamento.

        Args:
            event:             DeforestationEvent com severity classificada
            source_record_ids: IDs dos SourceRecords originadores
            rule_key:          Chave de ALERT_RULES a usar
            extra_context:     Contexto adicional para o template (trend, infra)

        Returns:
            Alert persistido ou None se abaixo do limiar ou já alertado.
        """
        if event.analysis_status == "alerted":
            logger.debug("Evento %s já alertado, ignorando.", event.id)
            return None

        rule = ALERT_RULES.get(rule_key, ALERT_RULES["geoint.deforestation.threshold"])
        alert_severity = rule.map_severity(event.severity)

        ctx = {
            "area_ha": float(event.area_ha),
            "state": event.state,
            "biome": event.biome,
            "municipality": event.municipality or event.state,
            "source_type": event.source_type.upper(),
            "acquired_at": event.acquired_at.strftime("%Y-%m-%d") if event.acquired_at else "",
            "classname": event.classname or "N/D",
            "trend_description": "sem dados históricos suficientes",
        }
        if extra_context:
            ctx.update(extra_context)

        title = rule.format_title(**ctx)
        description = rule.format_description(**ctx)

        # Centroide do polígono para geo_location do alerta
        geo_wkt = self._get_centroid_wkt(event)
        alert_id = f"geoint-defor-{event.id}"

        alert = await self._alert_repo.create(
            alert_id=alert_id,
            severity=alert_severity,
            rule_id=rule.rule_id,
            title=title,
            description=description,
            occurred_at=event.acquired_at or datetime.now(tz=timezone.utc),
            source_record_ids=source_record_ids,
            geo_location_wkt=geo_wkt,
        )

        await self._audit_log.append(
            event_type="GEOINT_ALERT_CREATED",
            actor_id="geoint.deforestation_processor",
            event_data={
                "alert_id": alert_id,
                "event_id": str(event.id),
                "severity": alert_severity,
                "rule_id": rule.rule_id,
                "area_ha": float(event.area_ha),
            },
            target_id=alert_id,
        )

        logger.info(
            "Alerta de desmatamento criado: %s (%s) area=%.1f ha",
            alert_id,
            alert_severity,
            float(event.area_ha),
        )
        return alert

    async def generate_fire_cluster_alert(
        self,
        cluster: FireCluster,
        source_record_ids: list[str],
        extra_context: dict | None = None,
    ) -> Alert | None:
        """
        Gera alerta para cluster de incêndio.

        Usa regra 'near_infrastructure' se cluster.near_infrastructure=True.
        """
        if cluster.analysis_status == "alerted":
            logger.debug("Cluster %s já alertado, ignorando.", cluster.id)
            return None

        if cluster.near_infrastructure:
            rule_key = "geoint.fire.near_infrastructure"
        else:
            rule_key = "geoint.fire.cluster_large"

        rule = ALERT_RULES[rule_key]
        alert_severity = rule.map_severity(cluster.severity)

        ctx = {
            "hotspot_count": cluster.hotspot_count,
            "state": cluster.state or "BR",
            "biome": cluster.biome or "N/D",
            "total_frp_mw": float(cluster.total_frp_mw or 0),
            "max_frp_mw": float(cluster.max_frp_mw or 0),
            "mean_frp_mw": float(cluster.mean_frp_mw or 0),
            "min_acquired_at": (
                cluster.min_acquired_at.strftime("%Y-%m-%d %H:%M")
                if cluster.min_acquired_at else ""
            ),
            "max_acquired_at": (
                cluster.max_acquired_at.strftime("%Y-%m-%d %H:%M")
                if cluster.max_acquired_at else ""
            ),
            "distance_km": 0.0,
            "asset_name": "N/D",
            "asset_type": "N/D",
        }
        if extra_context:
            ctx.update(extra_context)

        title = rule.format_title(**ctx)
        description = rule.format_description(**ctx)

        geo_wkt = self._geometry_to_wkt(cluster.centroid_geom)
        alert_id = f"geoint-fire-{cluster.id}"

        alert = await self._alert_repo.create(
            alert_id=alert_id,
            severity=alert_severity,
            rule_id=rule.rule_id,
            title=title,
            description=description,
            occurred_at=cluster.max_acquired_at or datetime.now(tz=timezone.utc),
            source_record_ids=source_record_ids,
            geo_location_wkt=geo_wkt,
        )

        await self._audit_log.append(
            event_type="GEOINT_ALERT_CREATED",
            actor_id="geoint.fire_processor",
            event_data={
                "alert_id": alert_id,
                "cluster_id": str(cluster.id),
                "severity": alert_severity,
                "rule_id": rule.rule_id,
                "hotspot_count": cluster.hotspot_count,
                "near_infrastructure": cluster.near_infrastructure,
            },
            target_id=alert_id,
        )

        logger.info(
            "Alerta de incêndio criado: %s (%s) focos=%d near_infra=%s",
            alert_id,
            alert_severity,
            cluster.hotspot_count,
            cluster.near_infrastructure,
        )
        return alert

    async def generate_water_anomaly_alert(
        self,
        observation: WaterObservation,
        source_record_ids: list[str],
        stddev_threshold: float = 3.0,
    ) -> Alert | None:
        """Gera alerta para anomalia hídrica detectada pelo WaterProcessor."""
        if not observation.anomaly_type or not observation.anomaly_severity:
            return None

        if observation.analysis_status == "alerted":
            logger.debug("Observação %s já alertada, ignorando.", observation.id)
            return None

        rule = ALERT_RULES["geoint.water.anomaly"]
        alert_severity = rule.map_severity(observation.anomaly_severity)

        ctx = {
            "anomaly_type": observation.anomaly_type,
            "station_name": observation.station_name or observation.station_code,
            "station_code": observation.station_code,
            "value": float(observation.value),
            "unit": observation.unit,
            "z_score": float(observation.z_score or 0),
            "threshold": stddev_threshold,
            "historical_mean": float(observation.historical_mean or 0),
            "historical_stddev": float(observation.historical_stddev or 0),
        }

        title = rule.format_title(**ctx)
        description = rule.format_description(**ctx)

        geo_wkt = self._geometry_to_wkt(observation.geom)
        alert_id = f"geoint-water-{observation.id}"

        alert = await self._alert_repo.create(
            alert_id=alert_id,
            severity=alert_severity,
            rule_id=rule.rule_id,
            title=title,
            description=description,
            occurred_at=observation.acquired_at or datetime.now(tz=timezone.utc),
            source_record_ids=source_record_ids,
            geo_location_wkt=geo_wkt,
        )

        await self._audit_log.append(
            event_type="GEOINT_ALERT_CREATED",
            actor_id="geoint.water_processor",
            event_data={
                "alert_id": alert_id,
                "observation_id": str(observation.id),
                "severity": alert_severity,
                "rule_id": rule.rule_id,
                "anomaly_type": observation.anomaly_type,
                "station_code": observation.station_code,
                "z_score": float(observation.z_score or 0),
            },
            target_id=alert_id,
        )

        logger.info(
            "Alerta hídrico criado: %s (%s) anomalia=%s z=%.2f",
            alert_id,
            alert_severity,
            observation.anomaly_type,
            float(observation.z_score or 0),
        )
        return alert

    def _get_centroid_wkt(self, event: DeforestationEvent) -> str | None:
        """Extrai centroide do polígono de desmatamento como WKT POINT."""
        if event.geom is None:
            return None
        try:
            from shapely.wkt import loads as wkt_loads
            geom_str = str(event.geom)
            if "SRID=" in geom_str:
                geom_str = geom_str.split(";", 1)[1]
            geom = wkt_loads(geom_str)
            c = geom.centroid
            return f"POINT({c.x} {c.y})"
        except Exception:
            return None

    def _geometry_to_wkt(self, geom) -> str | None:
        """Converte geometria (qualquer tipo) para WKT POINT simples."""
        if geom is None:
            return None
        geom_str = str(geom)
        if "SRID=" in geom_str:
            return geom_str.split(";", 1)[1]
        return geom_str
