"""
Tarefas Celery de geração de alertas FININT.

Dispara alertas Dilithium-assinados para anomalias detectadas.
"""

from __future__ import annotations

import asyncio
import logging

from atlantico.finint.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="finint.generate_alerts", bind=True, max_retries=3)
def generate_alerts(self) -> dict:
    """Gera alertas para anomalias FININT pendentes."""
    return asyncio.run(_generate_alerts_async())


async def _generate_alerts_async() -> dict:
    from atlantico.storage.database import get_async_session
    from atlantico.storage.repositories.alert_repo import AlertRepository
    from atlantico.storage.repositories.audit_log_repo import AuditLogRepository
    from atlantico.finint.repositories.market_indicator_repo import MarketIndicatorRepository
    from atlantico.finint.alerts.generator import FinintAlertGenerator

    alerts_generated = 0

    async with get_async_session() as session:
        alert_repo = AlertRepository(session)
        audit_log = AuditLogRepository(session)
        indicator_repo = MarketIndicatorRepository(session)
        generator = FinintAlertGenerator(alert_repo=alert_repo, audit_log=audit_log)

        # Busca indicadores com anomalia detectada
        from sqlalchemy import select
        from atlantico.finint.models.market_indicator import MarketIndicator
        stmt = (
            select(MarketIndicator)
            .where(MarketIndicator.analysis_status == "anomaly")
            .limit(100)
        )
        result = await session.execute(stmt)
        anomalous = list(result.scalars().all())

        for indicator in anomalous:
            try:
                alert = await generator.generate_market_anomaly_alert(
                    series_code=indicator.series_code,
                    series_name=indicator.series_name,
                    source_id=indicator.source_id,
                    reference_date=indicator.reference_date,
                    value=float(indicator.value),
                    unit=indicator.unit or "",
                    z_score=float(indicator.z_score or 0),
                    anomaly_type=indicator.anomaly_type or "spike_up",
                    anomaly_severity=indicator.anomaly_severity or "MEDIUM",
                    source_record_ids=[str(indicator.source_record_id)],
                )
                if alert:
                    await indicator_repo.mark_analyzed(
                        indicator.id,
                        z_score=float(indicator.z_score or 0),
                        anomaly_type=indicator.anomaly_type,
                        anomaly_severity=indicator.anomaly_severity,
                        status="alerted",
                    )
                    alerts_generated += 1
            except Exception as exc:
                logger.warning("Falha ao gerar alerta para indicador %s: %s", indicator.id, exc)

        await session.commit()

    logger.info("finint.generate_alerts: %d alertas gerados.", alerts_generated)
    return {"alerts_generated": alerts_generated}
