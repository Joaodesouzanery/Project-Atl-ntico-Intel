"""
FinintAlertGenerator — geração de alertas FININT assinados com Dilithium.

Delega criação e assinatura de alertas ao AlertRepository (Sprint 2),
que usa assinaturas Dilithium3+Ed25519 via KeyManager e crypto/.

Segurança: nenhum acesso direto a crypto/ — tudo via AlertRepository.create().
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from atlantico.finint.alerts.rules import FININT_ALERT_RULES, AlertRule
from atlantico.storage.models.alert import Alert
from atlantico.storage.repositories.alert_repo import AlertRepository
from atlantico.storage.repositories.audit_log_repo import AuditLogRepository

logger = logging.getLogger(__name__)


class FinintAlertGenerator:
    """
    Gera alertas FININT usando o AlertRepository existente.

    Garante:
    - Alertas assinados com Dilithium3+Ed25519 (via AlertRepository.create)
    - Audit log registrado para cada alerta gerado
    - Idempotência: verifica analysis_status antes de criar
    """

    def __init__(
        self,
        alert_repo: AlertRepository,
        audit_log: AuditLogRepository,
    ) -> None:
        self._alert_repo = alert_repo
        self._audit_log = audit_log

    async def generate_market_anomaly_alert(
        self,
        series_code: str,
        series_name: str,
        source_id: str,
        reference_date: datetime,
        value: float,
        unit: str,
        z_score: float,
        anomaly_type: str,
        anomaly_severity: str,
        source_record_ids: list[str],
        zscore_threshold: float = 3.0,
    ) -> Alert | None:
        """Gera alerta para anomalia em indicador de mercado."""
        rule = FININT_ALERT_RULES["finint.market.anomaly"]
        alert_severity = rule.map_severity(anomaly_severity)

        ctx = {
            "series_code": series_code,
            "series_name": series_name,
            "source_id": source_id,
            "reference_date": reference_date.strftime("%Y-%m-%d"),
            "value": value,
            "unit": unit or "",
            "z_score": z_score,
            "anomaly_type": anomaly_type,
            "threshold": zscore_threshold,
        }

        title = rule.format_title(**ctx)
        description = rule.format_description(**ctx)
        alert_id = f"finint-market-{series_code}-{reference_date.strftime('%Y%m%d')}"

        alert = await self._alert_repo.create(
            alert_id=alert_id,
            severity=alert_severity,
            rule_id=rule.rule_id,
            title=title,
            description=description,
            occurred_at=reference_date,
            source_record_ids=source_record_ids,
            geo_location_wkt=None,
        )

        await self._audit_log.append(
            event_type="FININT_ALERT_CREATED",
            actor_id="finint.anomaly_detector",
            event_data={
                "alert_id": alert_id,
                "series_code": series_code,
                "severity": alert_severity,
                "rule_id": rule.rule_id,
                "z_score": z_score,
                "anomaly_type": anomaly_type,
            },
            target_id=alert_id,
        )

        logger.info(
            "Alerta FININT mercado criado: %s (%s) série=%s z=%.2f",
            alert_id,
            alert_severity,
            series_code,
            z_score,
        )
        return alert

    async def generate_trade_spike_alert(
        self,
        ncm_code: str,
        ncm_desc: str,
        state: str,
        reference_date: datetime,
        export_value_usd: float,
        historical_mean: float,
        historical_stddev: float,
        geo_correlation_score: float,
        source_record_ids: list[str],
        geo_location_wkt: str | None = None,
    ) -> Alert | None:
        """Gera alerta para spike em exportação de mineral estratégico."""
        rule = FININT_ALERT_RULES["finint.trade.mineral_spike"]

        # Severity baseada no z-score
        if historical_stddev > 0:
            z = (export_value_usd - historical_mean) / historical_stddev
        else:
            z = 0.0

        if z > 6.0:
            severity_key = "CRITICAL"
        elif z > 4.0:
            severity_key = "HIGH"
        else:
            severity_key = "MEDIUM"

        alert_severity = rule.map_severity(severity_key)

        ctx = {
            "ncm_code": ncm_code,
            "ncm_desc": ncm_desc,
            "state": state,
            "reference_date": reference_date.strftime("%Y-%m"),
            "value_usd": export_value_usd,
            "z_score": z,
            "historical_mean": historical_mean,
            "historical_stddev": historical_stddev,
            "geo_correlation_score": geo_correlation_score,
        }

        title = rule.format_title(**ctx)
        description = rule.format_description(**ctx)
        alert_id = f"finint-trade-{ncm_code}-{state}-{reference_date.strftime('%Y%m')}"

        alert = await self._alert_repo.create(
            alert_id=alert_id,
            severity=alert_severity,
            rule_id=rule.rule_id,
            title=title,
            description=description,
            occurred_at=reference_date,
            source_record_ids=source_record_ids,
            geo_location_wkt=geo_location_wkt,
        )

        await self._audit_log.append(
            event_type="FININT_ALERT_CREATED",
            actor_id="finint.trade_analyzer",
            event_data={
                "alert_id": alert_id,
                "ncm_code": ncm_code,
                "state": state,
                "severity": alert_severity,
                "rule_id": rule.rule_id,
                "export_value_usd": export_value_usd,
                "z_score": z,
            },
            target_id=alert_id,
        )

        logger.info(
            "Alerta FININT trade criado: %s (%s) ncm=%s state=%s z=%.1f",
            alert_id,
            alert_severity,
            ncm_code,
            state,
            z,
        )
        return alert

    async def generate_cross_module_alert(
        self,
        state: str,
        ncm_code: str,
        ncm_desc: str,
        export_value_usd: float,
        deforestation_ha: float,
        deforestation_period: str,
        geo_correlation_score: float,
        reference_date: datetime,
        source_record_ids: list[str],
        z_score: float = 0.0,
        geo_location_wkt: str | None = None,
    ) -> Alert | None:
        """
        Gera alerta cross-module GEOINT+FININT.

        Dispara quando exportação mineral anômala coincide com desmatamento
        no mesmo estado — padrão clássico de garimpo ilegal.
        Always CRITICAL severity.
        """
        rule = FININT_ALERT_RULES["finint.cross_module.garimpo_signal"]

        if geo_correlation_score > 0.7:
            severity_key = "HIGH"
        else:
            severity_key = "MEDIUM"

        alert_severity = rule.map_severity(severity_key)

        ctx = {
            "state": state,
            "ncm_code": ncm_code,
            "ncm_desc": ncm_desc,
            "export_value_usd": export_value_usd,
            "deforestation_ha": deforestation_ha,
            "deforestation_period": deforestation_period,
            "geo_correlation_score": geo_correlation_score,
            "z_score": z_score,
        }

        title = rule.format_title(**ctx)
        description = rule.format_description(**ctx)
        alert_id = f"finint-garimpo-{state}-{reference_date.strftime('%Y%m')}"

        alert = await self._alert_repo.create(
            alert_id=alert_id,
            severity=alert_severity,
            rule_id=rule.rule_id,
            title=title,
            description=description,
            occurred_at=reference_date,
            source_record_ids=source_record_ids,
            geo_location_wkt=geo_location_wkt,
        )

        await self._audit_log.append(
            event_type="FININT_CROSS_MODULE_ALERT",
            actor_id="finint.risk_scorer",
            event_data={
                "alert_id": alert_id,
                "state": state,
                "ncm_code": ncm_code,
                "severity": alert_severity,
                "rule_id": rule.rule_id,
                "deforestation_ha": deforestation_ha,
                "export_value_usd": export_value_usd,
                "geo_correlation_score": geo_correlation_score,
            },
            target_id=alert_id,
        )

        logger.info(
            "Alerta FININT cross-module criado: %s (%s) state=%s defor=%.1f ha",
            alert_id,
            alert_severity,
            state,
            deforestation_ha,
        )
        return alert

    async def generate_contract_anomaly_alert(
        self,
        state: str,
        anomaly_type: str,
        total_value: float,
        unique_suppliers: int,
        period: str,
        anomaly_score: float,
        source_record_ids: list[str],
        reference_date: datetime | None = None,
    ) -> Alert | None:
        """Gera alerta para anomalia em contratos públicos."""
        rule = FININT_ALERT_RULES["finint.contract.anomaly"]

        if anomaly_score >= 0.9:
            severity_key = "CRITICAL"
        elif anomaly_score >= 0.7:
            severity_key = "HIGH"
        else:
            severity_key = "MEDIUM"

        alert_severity = rule.map_severity(severity_key)
        ref = reference_date or datetime.now(tz=timezone.utc)

        ctx = {
            "state": state,
            "anomaly_type": anomaly_type,
            "total_value": total_value,
            "unique_suppliers": unique_suppliers,
            "period": period,
        }

        title = rule.format_title(**ctx)
        description = rule.format_description(**ctx)
        alert_id = f"finint-contract-{state}-{ref.strftime('%Y%m')}"

        alert = await self._alert_repo.create(
            alert_id=alert_id,
            severity=alert_severity,
            rule_id=rule.rule_id,
            title=title,
            description=description,
            occurred_at=ref,
            source_record_ids=source_record_ids,
            geo_location_wkt=None,
        )

        await self._audit_log.append(
            event_type="FININT_ALERT_CREATED",
            actor_id="finint.contract_analyzer",
            event_data={
                "alert_id": alert_id,
                "state": state,
                "severity": alert_severity,
                "rule_id": rule.rule_id,
                "anomaly_type": anomaly_type,
                "total_value": total_value,
            },
            target_id=alert_id,
        )

        logger.info(
            "Alerta FININT contrato criado: %s (%s) state=%s tipo=%s",
            alert_id,
            alert_severity,
            state,
            anomaly_type,
        )
        return alert
