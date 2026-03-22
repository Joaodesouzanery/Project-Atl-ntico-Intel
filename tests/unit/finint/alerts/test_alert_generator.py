"""
Testes unitários para FinintAlertGenerator.

Testa generate_market_anomaly_alert(), generate_trade_spike_alert(),
generate_cross_module_alert() e generate_contract_anomaly_alert().
Usa mocks para AlertRepository e AuditLogRepository.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from atlantico.finint.alerts.generator import FinintAlertGenerator


@pytest.fixture
def alert_repo():
    repo = MagicMock()
    repo.create = AsyncMock(return_value=MagicMock())
    return repo


@pytest.fixture
def audit_log():
    log = MagicMock()
    log.append = AsyncMock(return_value=None)
    return log


@pytest.fixture
def generator(alert_repo, audit_log) -> FinintAlertGenerator:
    return FinintAlertGenerator(alert_repo=alert_repo, audit_log=audit_log)


_REF_DATE = datetime(2024, 6, 15, tzinfo=timezone.utc)


# ─── generate_market_anomaly_alert ────────────────────────────────────────────


class TestGenerateMarketAnomalyAlert:
    @pytest.mark.asyncio
    async def test_chama_alert_repo_create(self, generator, alert_repo):
        await generator.generate_market_anomaly_alert(
            series_code="13522",
            series_name="Exportações ouro",
            source_id="bcb.sgs.v1",
            reference_date=_REF_DATE,
            value=5000.0,
            unit="US$ milhões",
            z_score=4.5,
            anomaly_type="spike_up",
            anomaly_severity="HIGH",
            source_record_ids=["rec-001"],
        )
        alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_chama_audit_log_append(self, generator, audit_log):
        await generator.generate_market_anomaly_alert(
            series_code="13522",
            series_name="Exportações ouro",
            source_id="bcb.sgs.v1",
            reference_date=_REF_DATE,
            value=5000.0,
            unit="US$ milhões",
            z_score=4.5,
            anomaly_type="spike_up",
            anomaly_severity="HIGH",
            source_record_ids=["rec-001"],
        )
        audit_log.append.assert_called_once()

    @pytest.mark.asyncio
    async def test_alert_id_formato_correto(self, generator, alert_repo):
        await generator.generate_market_anomaly_alert(
            series_code="13522",
            series_name="Exportações ouro",
            source_id="bcb.sgs.v1",
            reference_date=_REF_DATE,
            value=5000.0,
            unit="US$ milhões",
            z_score=4.5,
            anomaly_type="spike_up",
            anomaly_severity="HIGH",
            source_record_ids=["rec-001"],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["alert_id"] == "finint-market-13522-20240615"

    @pytest.mark.asyncio
    async def test_rule_id_correto(self, generator, alert_repo):
        await generator.generate_market_anomaly_alert(
            series_code="1",
            series_name="Selic",
            source_id="bcb.sgs.v1",
            reference_date=_REF_DATE,
            value=10.5,
            unit="%",
            z_score=3.5,
            anomaly_type="spike_up",
            anomaly_severity="MEDIUM",
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["rule_id"] == "finint.market.anomaly.v1"

    @pytest.mark.asyncio
    async def test_retorna_alerta(self, generator):
        result = await generator.generate_market_anomaly_alert(
            series_code="1",
            series_name="Selic",
            source_id="bcb.sgs.v1",
            reference_date=_REF_DATE,
            value=10.5,
            unit="%",
            z_score=3.5,
            anomaly_type="spike_up",
            anomaly_severity="MEDIUM",
            source_record_ids=[],
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_severity_passada_corretamente(self, generator, alert_repo):
        await generator.generate_market_anomaly_alert(
            series_code="1",
            series_name="Selic",
            source_id="bcb.sgs.v1",
            reference_date=_REF_DATE,
            value=10.5,
            unit="%",
            z_score=5.0,
            anomaly_type="spike_up",
            anomaly_severity="CRITICAL",
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["severity"] == "CRITICAL"


# ─── generate_trade_spike_alert ───────────────────────────────────────────────


class TestGenerateTradeSpikeAlert:
    @pytest.mark.asyncio
    async def test_chama_alert_repo_create(self, generator, alert_repo):
        await generator.generate_trade_spike_alert(
            ncm_code="7108",
            ncm_desc="Ouro",
            state="PA",
            reference_date=_REF_DATE,
            export_value_usd=5_000_000.0,
            historical_mean=500_000.0,
            historical_stddev=100_000.0,
            geo_correlation_score=0.8,
            source_record_ids=["rec-002"],
        )
        alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_alert_id_formato_correto(self, generator, alert_repo):
        await generator.generate_trade_spike_alert(
            ncm_code="7108",
            ncm_desc="Ouro",
            state="AM",
            reference_date=_REF_DATE,
            export_value_usd=5_000_000.0,
            historical_mean=500_000.0,
            historical_stddev=100_000.0,
            geo_correlation_score=0.8,
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["alert_id"] == "finint-trade-7108-AM-202406"

    @pytest.mark.asyncio
    async def test_rule_id_correto(self, generator, alert_repo):
        await generator.generate_trade_spike_alert(
            ncm_code="7108",
            ncm_desc="Ouro",
            state="PA",
            reference_date=_REF_DATE,
            export_value_usd=5_000_000.0,
            historical_mean=500_000.0,
            historical_stddev=100_000.0,
            geo_correlation_score=0.5,
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["rule_id"] == "finint.trade.mineral_spike.v1"

    @pytest.mark.asyncio
    async def test_z_alto_resulta_severity_critical(self, generator, alert_repo):
        # z = (5_000_000 - 500_000) / 100_000 = 45σ → CRITICAL (map HIGH→CRITICAL)
        await generator.generate_trade_spike_alert(
            ncm_code="7108",
            ncm_desc="Ouro",
            state="PA",
            reference_date=_REF_DATE,
            export_value_usd=5_000_000.0,
            historical_mean=500_000.0,
            historical_stddev=100_000.0,
            geo_correlation_score=0.0,
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_chama_audit_log(self, generator, audit_log):
        await generator.generate_trade_spike_alert(
            ncm_code="7108",
            ncm_desc="Ouro",
            state="PA",
            reference_date=_REF_DATE,
            export_value_usd=5_000_000.0,
            historical_mean=500_000.0,
            historical_stddev=100_000.0,
            geo_correlation_score=0.5,
            source_record_ids=[],
        )
        audit_log.append.assert_called_once()
        call_kwargs = audit_log.append.call_args.kwargs
        assert call_kwargs["event_type"] == "FININT_ALERT_CREATED"


# ─── generate_cross_module_alert ──────────────────────────────────────────────


class TestGenerateCrossModuleAlert:
    @pytest.mark.asyncio
    async def test_chama_alert_repo_create(self, generator, alert_repo):
        await generator.generate_cross_module_alert(
            state="PA",
            ncm_code="7108",
            ncm_desc="Ouro",
            export_value_usd=10_000_000.0,
            deforestation_ha=800.0,
            deforestation_period="2024-Q1",
            geo_correlation_score=0.9,
            reference_date=_REF_DATE,
            source_record_ids=["rec-geo", "rec-trade"],
        )
        alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_alert_id_formato_correto(self, generator, alert_repo):
        await generator.generate_cross_module_alert(
            state="AM",
            ncm_code="7108",
            ncm_desc="Ouro",
            export_value_usd=10_000_000.0,
            deforestation_ha=800.0,
            deforestation_period="2024-Q1",
            geo_correlation_score=0.9,
            reference_date=_REF_DATE,
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["alert_id"] == "finint-garimpo-AM-202406"

    @pytest.mark.asyncio
    async def test_rule_id_garimpo(self, generator, alert_repo):
        await generator.generate_cross_module_alert(
            state="PA",
            ncm_code="7108",
            ncm_desc="Ouro",
            export_value_usd=10_000_000.0,
            deforestation_ha=500.0,
            deforestation_period="2024-Q1",
            geo_correlation_score=0.8,
            reference_date=_REF_DATE,
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["rule_id"] == "finint.cross_module.garimpo_signal.v1"

    @pytest.mark.asyncio
    async def test_geo_alto_resulta_critical(self, generator, alert_repo):
        # geo_correlation_score > 0.7 → HIGH key → mapeado para CRITICAL
        await generator.generate_cross_module_alert(
            state="PA",
            ncm_code="7108",
            ncm_desc="Ouro",
            export_value_usd=10_000_000.0,
            deforestation_ha=1000.0,
            deforestation_period="2024-Q1",
            geo_correlation_score=0.9,
            reference_date=_REF_DATE,
            source_record_ids=[],
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_audit_log_evento_cross_module(self, generator, audit_log):
        await generator.generate_cross_module_alert(
            state="PA",
            ncm_code="7108",
            ncm_desc="Ouro",
            export_value_usd=5_000_000.0,
            deforestation_ha=300.0,
            deforestation_period="2024-Q2",
            geo_correlation_score=0.7,
            reference_date=_REF_DATE,
            source_record_ids=[],
        )
        audit_log.append.assert_called_once()
        call_kwargs = audit_log.append.call_args.kwargs
        assert call_kwargs["event_type"] == "FININT_CROSS_MODULE_ALERT"

    @pytest.mark.asyncio
    async def test_source_record_ids_passados(self, generator, alert_repo):
        ids = ["src-001", "src-002", "geo-003"]
        await generator.generate_cross_module_alert(
            state="MT",
            ncm_code="7108",
            ncm_desc="Ouro",
            export_value_usd=5_000_000.0,
            deforestation_ha=600.0,
            deforestation_period="2024-Q3",
            geo_correlation_score=0.8,
            reference_date=_REF_DATE,
            source_record_ids=ids,
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["source_record_ids"] == ids


# ─── generate_contract_anomaly_alert ──────────────────────────────────────────


class TestGenerateContractAnomalyAlert:
    @pytest.mark.asyncio
    async def test_chama_alert_repo_create(self, generator, alert_repo):
        await generator.generate_contract_anomaly_alert(
            state="PA",
            anomaly_type="supplier_concentration",
            total_value=2_000_000.0,
            unique_suppliers=1,
            period="2024-Q2",
            anomaly_score=0.85,
            source_record_ids=["rec-con"],
            reference_date=_REF_DATE,
        )
        alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_rule_id_correto(self, generator, alert_repo):
        await generator.generate_contract_anomaly_alert(
            state="AM",
            anomaly_type="volume_spike",
            total_value=5_000_000.0,
            unique_suppliers=3,
            period="2024-Q1",
            anomaly_score=0.9,
            source_record_ids=[],
            reference_date=_REF_DATE,
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["rule_id"] == "finint.contract.anomaly.v1"

    @pytest.mark.asyncio
    async def test_score_acima_0_9_severity_critical(self, generator, alert_repo):
        await generator.generate_contract_anomaly_alert(
            state="PA",
            anomaly_type="volume_spike",
            total_value=10_000_000.0,
            unique_suppliers=1,
            period="2024-Q1",
            anomaly_score=0.95,
            source_record_ids=[],
            reference_date=_REF_DATE,
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_score_0_7_a_0_9_severity_high(self, generator, alert_repo):
        await generator.generate_contract_anomaly_alert(
            state="PA",
            anomaly_type="supplier_concentration",
            total_value=1_000_000.0,
            unique_suppliers=2,
            period="2024-Q1",
            anomaly_score=0.75,
            source_record_ids=[],
            reference_date=_REF_DATE,
        )
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_chama_audit_log(self, generator, audit_log):
        await generator.generate_contract_anomaly_alert(
            state="MT",
            anomaly_type="supplier_concentration",
            total_value=500_000.0,
            unique_suppliers=1,
            period="2024-Q1",
            anomaly_score=0.8,
            source_record_ids=[],
        )
        audit_log.append.assert_called_once()

    @pytest.mark.asyncio
    async def test_sem_reference_date_usa_utc_now(self, generator, alert_repo):
        # Não deve lançar exceção mesmo sem reference_date
        await generator.generate_contract_anomaly_alert(
            state="RR",
            anomaly_type="volume_spike",
            total_value=1_000_000.0,
            unique_suppliers=2,
            period="2024-Q4",
            anomaly_score=0.6,
            source_record_ids=[],
        )
        alert_repo.create.assert_called_once()
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["occurred_at"] is not None
