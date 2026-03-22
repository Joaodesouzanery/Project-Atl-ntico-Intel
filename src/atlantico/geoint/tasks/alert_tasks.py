"""
Task Celery de geração de alertas GEOINT.

geoint_generate_alerts: gera alertas Dilithium-assinados para eventos GEOINT.
Idempotente: verifica alert_id antes de criar para evitar duplicatas.
"""

from __future__ import annotations

import asyncio
import logging

from atlantico.geoint.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    name="geoint.generate_alerts",
    queue="geoint_analysis",
)
def geoint_generate_alerts(
    self,
    event_type: str,
    event_ids: list[str],
) -> dict:
    """
    Gera alertas GEOINT via AlertRepository (Dilithium-assinados).

    Args:
        event_type: "deforestation" | "fire_cluster" | "water_anomaly"
        event_ids:  UUIDs dos eventos para os quais gerar alertas

    Returns:
        Dict com alerts_created, already_exists, errors
    """
    try:
        return asyncio.run(_async_generate_alerts(event_type, event_ids))
    except Exception as exc:
        logger.error("geoint_generate_alerts falhou (type=%s): %s", event_type, exc)
        raise self.retry(exc=exc)


async def _async_generate_alerts(
    event_type: str,
    event_ids: list[str],
) -> dict:
    from atlantico.config.settings import get_settings
    from atlantico.crypto.key_manager import KeyManager
    from atlantico.geoint.alerts.generator import GeointAlertGenerator
    from atlantico.storage.database import AsyncSessionLocal
    from atlantico.storage.encrypted_field import EncryptionContext
    from atlantico.storage.repositories.alert_repo import AlertRepository
    from atlantico.storage.repositories.audit_log_repo import AuditLogRepository

    settings = get_settings()
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(settings.master_key_bytes)

    alerts_created = 0
    already_exists = 0
    errors = 0

    async with AsyncSessionLocal() as session:
        km = KeyManager(master_key=settings.master_key_bytes)
        _ensure_keys(km)

        alert_repo = AlertRepository(session=session, key_manager=km)
        audit_log = AuditLogRepository(session=session, key_manager=km)
        generator = GeointAlertGenerator(alert_repo=alert_repo, audit_log=audit_log)

        for event_id_str in event_ids:
            try:
                alert = await _generate_single_alert(
                    generator=generator,
                    session=session,
                    event_type=event_type,
                    event_id_str=event_id_str,
                )
                if alert is None:
                    already_exists += 1
                else:
                    alerts_created += 1
            except Exception as exc:
                logger.warning(
                    "Falha ao gerar alerta para %s %s: %s",
                    event_type,
                    event_id_str,
                    exc,
                )
                errors += 1

        await session.commit()

    return {
        "event_type": event_type,
        "alerts_created": alerts_created,
        "already_exists": already_exists,
        "errors": errors,
    }


async def _generate_single_alert(generator, session, event_type: str, event_id_str: str):
    """Gera alerta para um evento individual."""
    import uuid

    event_uuid = uuid.UUID(event_id_str)

    if event_type == "deforestation":
        from sqlalchemy import select
        from atlantico.geoint.models.deforestation import DeforestationEvent

        result = await session.execute(
            select(DeforestationEvent).where(DeforestationEvent.id == event_uuid)
        )
        event = result.scalar_one_or_none()
        if event is None:
            logger.warning("DeforestationEvent %s não encontrado", event_id_str)
            return None

        return await generator.generate_deforestation_alert(
            event=event,
            source_record_ids=[str(event.source_record_id)],
        )

    elif event_type == "fire_cluster":
        from sqlalchemy import select
        from atlantico.geoint.models.fire import FireCluster

        result = await session.execute(
            select(FireCluster).where(FireCluster.id == event_uuid)
        )
        cluster = result.scalar_one_or_none()
        if cluster is None:
            logger.warning("FireCluster %s não encontrado", event_id_str)
            return None

        return await generator.generate_fire_cluster_alert(
            cluster=cluster,
            source_record_ids=[],  # Hotspots são relacionados via cluster_id
        )

    elif event_type == "water_anomaly":
        from sqlalchemy import select
        from atlantico.geoint.models.water import WaterObservation

        result = await session.execute(
            select(WaterObservation).where(WaterObservation.id == event_uuid)
        )
        obs = result.scalar_one_or_none()
        if obs is None:
            logger.warning("WaterObservation %s não encontrada", event_id_str)
            return None

        return await generator.generate_water_anomaly_alert(
            observation=obs,
            source_record_ids=[str(obs.source_record_id)],
        )

    else:
        logger.error("event_type desconhecido: %s", event_type)
        return None


def _ensure_keys(km) -> None:
    """Garante chaves ativas no KeyManager."""
    from atlantico.crypto.exceptions import KeyNotFoundError
    try:
        km.get_active_kem_public_key()
    except (KeyNotFoundError, Exception):
        km.generate_kem_keypair()
    try:
        km.get_active_signing_public_key()
    except (KeyNotFoundError, Exception):
        km.generate_signing_keypair()
