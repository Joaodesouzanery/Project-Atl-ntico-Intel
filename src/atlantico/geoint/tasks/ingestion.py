"""
Tasks Celery de ingestão GEOINT.

Cada task ingere uma fonte específica:
- geoint_ingest_prodes   — INPE PRODES (anual)
- geoint_ingest_deter    — INPE DETER (near-real-time)
- geoint_ingest_bdqueimadas — INPE BDQueimadas (focos de calor)
- geoint_ingest_sentinel2   — ESA Sentinel-2 (metadados)
- geoint_ingest_hidroweb    — ANA HidroWeb (hidrologia)

Pattern: asyncio.run(_async_impl(...)) em task síncrona Celery.
Idempotência: ON CONFLICT DO NOTHING em todos os repositórios.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from atlantico.geoint.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_since(since_iso: str | None, default_days: int) -> datetime:
    """Retorna datetime de início de ingestão."""
    if since_iso:
        return datetime.fromisoformat(since_iso).replace(tzinfo=timezone.utc)
    return datetime.now(tz=timezone.utc) - timedelta(days=default_days)


def _get_bbox() -> tuple[float, float, float, float]:
    """Retorna bbox padrão do Brasil das configurações."""
    from atlantico.config.settings import get_settings
    return get_settings().geoint_default_bbox_tuple


# ─── PRODES ────────────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=300,
    name="geoint.ingest_prodes",
    queue="geoint_ingestion",
)
def geoint_ingest_prodes(self, since_iso: str | None = None) -> dict:
    """Ingere polígonos PRODES desde since_iso (padrão: último ano)."""
    try:
        return asyncio.run(_async_ingest_prodes(since_iso))
    except Exception as exc:
        logger.error("geoint_ingest_prodes falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_ingest_prodes(since_iso: str | None) -> dict:
    since = _get_since(since_iso, default_days=366)
    bbox = _get_bbox()

    from atlantico.geoint.connectors.inpe_prodes import INPEProdesConnector
    async with INPEProdesConnector() as connector:
        observations = await connector.fetch(since=since, bbox=bbox)

    ingested = await _persist_deforestation_observations(observations)
    return {
        "source": "inpe.prodes.v2",
        "ingested": ingested,
        "skipped_duplicates": len(observations) - ingested,
        "since": since.isoformat(),
    }


# ─── DETER ─────────────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=120,
    name="geoint.ingest_deter",
    queue="geoint_ingestion",
)
def geoint_ingest_deter(self, since_iso: str | None = None) -> dict:
    """Ingere detecções DETER desde since_iso (padrão: últimas 24h)."""
    try:
        return asyncio.run(_async_ingest_deter(since_iso))
    except Exception as exc:
        logger.error("geoint_ingest_deter falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_ingest_deter(since_iso: str | None) -> dict:
    since = _get_since(since_iso, default_days=1)
    bbox = _get_bbox()

    from atlantico.geoint.connectors.inpe_deter import INPEDeterConnector
    async with INPEDeterConnector() as connector:
        observations = await connector.fetch(since=since, bbox=bbox)

    ingested = await _persist_deforestation_observations(observations)
    return {
        "source": "inpe.deter.v1",
        "ingested": ingested,
        "skipped_duplicates": len(observations) - ingested,
        "since": since.isoformat(),
    }


# ─── BDQueimadas ───────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    name="geoint.ingest_bdqueimadas",
    queue="geoint_ingestion",
)
def geoint_ingest_bdqueimadas(self, since_iso: str | None = None) -> dict:
    """Ingere focos de calor BDQueimadas desde since_iso (padrão: últimas 6h)."""
    try:
        return asyncio.run(_async_ingest_bdqueimadas(since_iso))
    except Exception as exc:
        logger.error("geoint_ingest_bdqueimadas falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_ingest_bdqueimadas(since_iso: str | None) -> dict:
    since = _get_since(since_iso, default_days=0)
    if not since_iso:
        since = datetime.now(tz=timezone.utc) - timedelta(hours=6)
    bbox = _get_bbox()

    from atlantico.geoint.connectors.inpe_bdqueimadas import INPEBDQueimadasConnector
    async with INPEBDQueimadasConnector() as connector:
        observations = await connector.fetch(since=since, bbox=bbox)

    ingested = await _persist_fire_observations(observations)
    return {
        "source": "inpe.bdqueimadas.v1",
        "ingested": ingested,
        "skipped_duplicates": len(observations) - ingested,
        "since": since.isoformat(),
    }


# ─── ESA Sentinel-2 ────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=120,
    name="geoint.ingest_sentinel2",
    queue="geoint_ingestion",
)
def geoint_ingest_sentinel2(self, since_iso: str | None = None) -> dict:
    """Ingere metadados Sentinel-2 desde since_iso (padrão: últimas 24h)."""
    try:
        return asyncio.run(_async_ingest_sentinel2(since_iso))
    except Exception as exc:
        logger.error("geoint_ingest_sentinel2 falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_ingest_sentinel2(since_iso: str | None) -> dict:
    since = _get_since(since_iso, default_days=1)
    bbox = _get_bbox()

    from atlantico.geoint.connectors.esa_sentinel2 import ESASentinel2Connector
    async with ESASentinel2Connector() as connector:
        observations = await connector.fetch(since=since, bbox=bbox)

    ingested = await _persist_imagery_observations(observations)
    return {
        "source": "esa.sentinel2.v1",
        "ingested": ingested,
        "skipped_duplicates": len(observations) - ingested,
        "since": since.isoformat(),
    }


# ─── ANA HidroWeb ──────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=120,
    name="geoint.ingest_hidroweb",
    queue="geoint_ingestion",
)
def geoint_ingest_hidroweb(self, since_iso: str | None = None) -> dict:
    """Ingere leituras HidroWeb desde since_iso (padrão: últimas 24h)."""
    try:
        return asyncio.run(_async_ingest_hidroweb(since_iso))
    except Exception as exc:
        logger.error("geoint_ingest_hidroweb falhou: %s", exc)
        raise self.retry(exc=exc)


async def _async_ingest_hidroweb(since_iso: str | None) -> dict:
    since = _get_since(since_iso, default_days=1)
    bbox = _get_bbox()

    from atlantico.geoint.connectors.ana_hidroweb import ANAHidroWebConnector
    async with ANAHidroWebConnector() as connector:
        observations = await connector.fetch(since=since, bbox=bbox)

    ingested = await _persist_water_observations(observations)
    return {
        "source": "ana.hidroweb.v1",
        "ingested": ingested,
        "skipped_duplicates": len(observations) - ingested,
        "since": since.isoformat(),
    }


# ─── Helpers de Persistência ───────────────────────────────────────────────────


async def _build_db_session():
    """Cria sessão async para as tasks de ingestão."""
    from atlantico.config.settings import get_settings
    from atlantico.storage.database import AsyncSessionLocal
    from atlantico.storage.encrypted_field import EncryptionContext

    settings = get_settings()
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(settings.master_key_bytes)

    return AsyncSessionLocal()


async def _persist_deforestation_observations(observations) -> int:
    """Persiste observações de desmatamento via pipeline completo."""
    from atlantico.config.settings import get_settings
    from atlantico.crypto.key_manager import KeyManager
    from atlantico.geoint.repositories.deforestation_repo import DeforestationRepository
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository

    settings = get_settings()
    ingested = 0

    async with await _build_db_session() as session:
        km = KeyManager(master_key=settings.master_key_bytes)
        _ensure_keys(km)

        source_repo = SourceRecordRepository(session=session, key_manager=km)
        defor_repo = DeforestationRepository(session=session)

        for obs in observations:
            try:
                # 1. Persiste payload bruto com envelope PQC
                record = await source_repo.store(
                    record_id=obs.external_id,
                    source_id=obs.source_id,
                    data_classification=obs.data_classification,
                    payload=obs.payload,
                    acquired_at=obs.acquired_at,
                    geo_bounds_wkt=obs.geo_bounds_wkt,
                )
                # 2. Persiste evento tipado
                event = await defor_repo.store(obs=obs, source_record_id=record.id)
                if event is not None:
                    ingested += 1
            except Exception as exc:
                logger.warning("Falha ao persistir observação %s: %s", obs.external_id, exc)
                continue

        await session.commit()

    return ingested


async def _persist_fire_observations(observations) -> int:
    """Persiste focos de calor via pipeline completo."""
    from atlantico.config.settings import get_settings
    from atlantico.crypto.key_manager import KeyManager
    from atlantico.geoint.repositories.fire_repo import FireRepository
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository

    settings = get_settings()
    ingested = 0

    async with await _build_db_session() as session:
        km = KeyManager(master_key=settings.master_key_bytes)
        _ensure_keys(km)

        source_repo = SourceRecordRepository(session=session, key_manager=km)
        fire_repo = FireRepository(session=session)

        for obs in observations:
            try:
                record = await source_repo.store(
                    record_id=obs.external_id,
                    source_id=obs.source_id,
                    data_classification=obs.data_classification,
                    payload=obs.payload,
                    acquired_at=obs.acquired_at,
                    geo_bounds_wkt=obs.geo_bounds_wkt,
                )
                hotspot = await fire_repo.store_hotspot(obs=obs, source_record_id=record.id)
                if hotspot is not None:
                    ingested += 1
            except Exception as exc:
                logger.warning("Falha ao persistir foco %s: %s", obs.external_id, exc)
                continue

        await session.commit()

    return ingested


async def _persist_water_observations(observations) -> int:
    """Persiste leituras hídricas via pipeline completo."""
    from atlantico.config.settings import get_settings
    from atlantico.crypto.key_manager import KeyManager
    from atlantico.geoint.repositories.water_repo import WaterRepository
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository

    settings = get_settings()
    ingested = 0

    async with await _build_db_session() as session:
        km = KeyManager(master_key=settings.master_key_bytes)
        _ensure_keys(km)

        source_repo = SourceRecordRepository(session=session, key_manager=km)
        water_repo = WaterRepository(session=session)

        for obs in observations:
            try:
                record = await source_repo.store(
                    record_id=obs.external_id,
                    source_id=obs.source_id,
                    data_classification=obs.data_classification,
                    payload=obs.payload,
                    acquired_at=obs.acquired_at,
                    geo_bounds_wkt=obs.geo_bounds_wkt,
                )
                water_obs = await water_repo.store(obs=obs, source_record_id=record.id)
                if water_obs is not None:
                    ingested += 1
            except Exception as exc:
                logger.warning("Falha ao persistir leitura %s: %s", obs.external_id, exc)
                continue

        await session.commit()

    return ingested


async def _persist_imagery_observations(observations) -> int:
    """Persiste metadados de imagens via pipeline completo."""
    from atlantico.config.settings import get_settings
    from atlantico.crypto.key_manager import KeyManager
    from atlantico.geoint.repositories.imagery_repo import ImageryRepository
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository

    settings = get_settings()
    ingested = 0

    async with await _build_db_session() as session:
        km = KeyManager(master_key=settings.master_key_bytes)
        _ensure_keys(km)

        source_repo = SourceRecordRepository(session=session, key_manager=km)
        imagery_repo = ImageryRepository(session=session)

        for obs in observations:
            try:
                record = await source_repo.store(
                    record_id=obs.external_id,
                    source_id=obs.source_id,
                    data_classification=obs.data_classification,
                    payload=obs.payload,
                    acquired_at=obs.acquired_at,
                    geo_bounds_wkt=obs.geo_bounds_wkt,
                )
                imagery = await imagery_repo.store(obs=obs, source_record_id=record.id)
                if imagery is not None:
                    ingested += 1
            except Exception as exc:
                logger.warning("Falha ao persistir imagem %s: %s", obs.external_id, exc)
                continue

        await session.commit()

    return ingested


def _ensure_keys(km) -> None:
    """Garante que o KeyManager tem chaves KEM e de assinatura ativas."""
    from atlantico.crypto.exceptions import KeyNotFoundError
    try:
        km.get_active_kem_public_key()
    except (KeyNotFoundError, Exception):
        km.generate_kem_keypair()

    try:
        km.get_active_signing_public_key()
    except (KeyNotFoundError, Exception):
        km.generate_signing_keypair()
