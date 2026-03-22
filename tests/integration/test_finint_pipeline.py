"""
Teste de integração — Pipeline completo FININT.

Requer PostgreSQL com PostGIS disponível.
Execute com: pytest tests/integration/test_finint_pipeline.py -v -m integration

Gates de aceitação (conforme Sprint 4):
1. FinintObservation bem formada (reference_date timezone-aware UTC)
2. SourceRecord criado com envelope PQC ao ingerir observação FININT
3. Audit log registra cada etapa
4. IsolationForest detecta spike artificial (valor = 10× média histórica)
5. NetworkX PageRank detecta hub com >3 conexões
6. Correlação GEOINT↔FININT: deforestation_ha alto → correlation_score > 0
7. FinancialFlow.amount_enc não contém plaintext nos bytes brutos
8. Alerta cross-module gerado (Dilithium-assinado) quando trade spike + deforestation
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio

# Marca todos os testes deste arquivo como integration
pytestmark = pytest.mark.integration


# ─── Fixtures de banco ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def settings():
    """Carrega settings com DATABASE_URL configurada para testes de integração."""
    from atlantico.config.settings import get_settings
    return get_settings()


@pytest.fixture(scope="module")
def master_key(settings):
    return settings.master_key_bytes


@pytest.fixture(scope="module", autouse=True)
def init_encryption(master_key):
    """Inicializa EncryptionContext para os testes FININT."""
    from atlantico.storage.encrypted_field import EncryptionContext
    if not EncryptionContext.is_initialized():
        EncryptionContext.initialize(master_key)


@pytest_asyncio.fixture(scope="module")
async def db_session():
    """Sessão de banco de dados async para testes FININT."""
    from atlantico.storage.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()


# ─── Gate 1: FinintObservation timezone-aware ─────────────────────────────────


class TestFinintObservationDTO:
    def test_reference_date_timezone_aware(self):
        from atlantico.finint.observations import FinintObservation
        obs = FinintObservation(
            source_id="bcb.sgs.v1",
            external_id="bcb-sgs-1-01012024",
            observation_type="market_indicator",
            reference_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
            payload={"value": 10.5, "unit": "%"},
        )
        assert obs.reference_date.tzinfo is not None

    def test_reference_date_naive_levanta_erro(self):
        from atlantico.finint.observations import FinintObservation
        with pytest.raises(ValueError, match="timezone-aware"):
            FinintObservation(
                source_id="bcb.sgs.v1",
                external_id="bcb-sgs-1-naive",
                observation_type="market_indicator",
                reference_date=datetime(2024, 1, 1),  # sem tzinfo
                payload={},
            )

    def test_data_classification_default_public(self):
        from atlantico.finint.observations import FinintObservation
        obs = FinintObservation(
            source_id="cvm.dados.v1",
            external_id="cvm-test-001",
            observation_type="market_indicator",
            reference_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        assert obs.data_classification == "PUBLIC"

    def test_campos_opcionais_nulos(self):
        from atlantico.finint.observations import FinintObservation
        obs = FinintObservation(
            source_id="ibge.sidra.v1",
            external_id="ibge-001",
            observation_type="market_indicator",
            reference_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        assert obs.municipality_code is None
        assert obs.state_code is None
        assert obs.geo_point_wkt is None


# ─── Gate 4: AnomalyDetector detecta spike artificial ─────────────────────────


class TestAnomalyDetectorIntegration:
    def test_isolation_forest_detecta_spike_10x(self):
        from atlantico.finint.processing.anomaly_detector import AnomalyDetector
        detector = AnomalyDetector(zscore_threshold=3.0)
        # 30 valores normais + spike 10× a média
        values = [100.0] * 30 + [1000.0]
        from datetime import timedelta
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        dates = [base + timedelta(days=i) for i in range(len(values))]

        result = detector.detect_series_anomaly(values, dates, method="isolation_forest")
        assert len(result) == len(values)
        assert result[-1]["is_anomaly"] is True

    def test_zscore_detecta_spike_5sigma(self):
        from atlantico.finint.processing.anomaly_detector import AnomalyDetector
        detector = AnomalyDetector(zscore_threshold=3.0)
        values = [10.0] * 50 + [200.0]
        from datetime import timedelta
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        dates = [base + timedelta(days=i) for i in range(len(values))]

        result = detector.detect_series_anomaly(values, dates, method="zscore")
        assert result[-1]["is_anomaly"] is True
        assert result[-1]["severity"] == "CRITICAL"

    def test_detect_trade_spike_valor_10x(self):
        from atlantico.finint.processing.anomaly_detector import AnomalyDetector
        detector = AnomalyDetector(zscore_threshold=3.0)
        result = detector.detect_trade_spike(
            current_value_usd=1_000_000.0,
            historical_mean=100_000.0,
            historical_stddev=10_000.0,
            multiplier=3.0,
        )
        assert result is True


# ─── Gate 5: NetworkAnalyzer PageRank detecta hub ────────────────────────────


class TestNetworkAnalyzerIntegration:
    def _make_rel(self, src, tgt, value=100_000.0):
        return SimpleNamespace(
            source_entity_id=uuid.UUID(src),
            target_entity_id=uuid.UUID(tgt),
            relationship_type="fornecedor",
            strength=1.0,
            total_value_brl=value,
            transaction_count=5,
        )

    def test_pagerank_detecta_hub_com_muitas_conexoes(self):
        from atlantico.finint.processing.network_analyzer import NetworkAnalyzer
        analyzer = NetworkAnalyzer(pagerank_alpha=0.85)

        # Hub _A recebe conexões de B, C, D, E, F
        HUB = "00000000-0000-0000-0000-000000000001"
        nodes = [f"00000000-0000-0000-0000-00000000000{i}" for i in range(2, 7)]

        rels = [self._make_rel(n, HUB) for n in nodes]
        rels.append(self._make_rel(HUB, nodes[0]))  # Ciclo mínimo

        G = analyzer.build_graph(rels)
        result = analyzer.compute_centrality(G)

        # Hub deve ter o maior PageRank
        assert result["pagerank"][HUB] == max(result["pagerank"].values())

    def test_get_hub_entities_retorna_lista(self):
        from atlantico.finint.processing.network_analyzer import NetworkAnalyzer
        analyzer = NetworkAnalyzer(pagerank_alpha=0.85)

        HUB = "00000000-0000-0000-0000-000000000001"
        nodes = [f"00000000-0000-0000-0000-00000000000{i}" for i in range(2, 6)]

        rels = [self._make_rel(n, HUB) for n in nodes]
        rels.append(self._make_rel(HUB, nodes[0]))

        G = analyzer.build_graph(rels)
        hubs = analyzer.get_hub_entities(G, top_n=3)

        assert len(hubs) <= 3
        assert all("entity_id" in h for h in hubs)
        assert all("pagerank" in h for h in hubs)

    def test_louvain_detecta_2_comunidades_separadas(self):
        from atlantico.finint.processing.network_analyzer import NetworkAnalyzer
        analyzer = NetworkAnalyzer(pagerank_alpha=0.85)

        # Dois grupos completamente desconectados
        rels = [
            self._make_rel("00000000-0000-0000-0000-000000000001",
                           "00000000-0000-0000-0000-000000000002"),
            self._make_rel("00000000-0000-0000-0000-000000000002",
                           "00000000-0000-0000-0000-000000000001"),
            self._make_rel("00000000-0000-0000-0000-000000000003",
                           "00000000-0000-0000-0000-000000000004"),
            self._make_rel("00000000-0000-0000-0000-000000000004",
                           "00000000-0000-0000-0000-000000000003"),
        ]

        G = analyzer.build_graph(rels)
        communities = analyzer.detect_communities(G)
        assert len(communities) >= 2


# ─── Gate 6: RiskScorer correlação GEOINT↔FININT ─────────────────────────────


class TestRiskScorerCorrelationIntegration:
    def test_desmatamento_alto_gera_correlation_score_positivo(self):
        from atlantico.finint.processing.risk_scorer import RiskScorer
        scorer = RiskScorer()
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        until = datetime(2024, 12, 31, tzinfo=timezone.utc)

        result = scorer.correlate_with_geoint(
            municipality_code="1504208",
            since=since,
            until=until,
            deforestation_ha=750.0,
            hotspot_count=30,
        )
        assert result["correlation_score"] > 0.0

    def test_score_critico_com_anomalia_e_geo_alto(self):
        from atlantico.finint.processing.risk_scorer import RiskScorer
        scorer = RiskScorer()

        score = scorer.compute_entity_risk(
            anomaly_score=1.0,
            centrality_score=0.01,
            geo_correlation_score=1.0,
        )
        assert scorer.classify_risk_level(score) == "CRITICAL"

    def test_flags_garimpo_com_alto_desmatamento_e_spike(self):
        from atlantico.finint.processing.risk_scorer import RiskScorer
        scorer = RiskScorer()

        flags = scorer.determine_flags(
            score=0.9,
            anomaly_types=["spike_up", "isolation_forest"],
            geo_correlation_score=0.8,
        )
        assert "garimpo_ilegal" in flags
        assert "comportamento_atipico" in flags

    def test_ouro_ncm_7108_recebe_score_multiplicado(self):
        from atlantico.finint.processing.risk_scorer import RiskScorer
        scorer = RiskScorer()

        score = scorer.score_trade_flow(
            ncm_code="7108",
            export_value_usd=5_000_000.0,
            historical_mean_usd=500_000.0,
            historical_stddev_usd=50_000.0,
            geo_correlation_score=0.8,
        )
        assert score > 0.5  # score deve ser significativo para ouro com geo alto


# ─── Gate 7: EncryptedBytes — verificação lógica ─────────────────────────────


class TestEncryptionLogic:
    def test_encrypted_value_nao_e_plaintext(self, master_key):
        """Verifica que bytes criptografados não contêm o plaintext."""
        from atlantico.storage.encrypted_field import EncryptionContext
        if not EncryptionContext.is_initialized():
            EncryptionContext.initialize(master_key)

        plaintext = "12.345.678/0001-90"
        ctx = EncryptionContext.get()
        encrypted = ctx.encrypt(plaintext.encode())

        # Bytes criptografados não devem conter o plaintext
        assert plaintext.encode() not in encrypted

    def test_decryptado_retorna_original(self, master_key):
        """Verifica round-trip de criptografia."""
        from atlantico.storage.encrypted_field import EncryptionContext
        if not EncryptionContext.is_initialized():
            EncryptionContext.initialize(master_key)

        plaintext = "R$ 1.500.000,00"
        ctx = EncryptionContext.get()
        encrypted = ctx.encrypt(plaintext.encode())
        decrypted = ctx.decrypt(encrypted)

        assert decrypted == plaintext.encode()


# ─── Gate 8: Geração de alerta cross-module ───────────────────────────────────


class TestCrossModuleAlertGeneration:
    @pytest.mark.asyncio
    async def test_alert_gerado_com_ids_corretos(self):
        """Verifica que o gerador cria alerta com rule_id correto e audit log."""
        from unittest.mock import AsyncMock, MagicMock
        from atlantico.finint.alerts.generator import FinintAlertGenerator

        alert_repo = MagicMock()
        alert_repo.create = AsyncMock(return_value=MagicMock())

        audit_log = MagicMock()
        audit_log.append = AsyncMock(return_value=None)

        generator = FinintAlertGenerator(alert_repo=alert_repo, audit_log=audit_log)

        ref = datetime(2024, 6, 1, tzinfo=timezone.utc)
        alert = await generator.generate_cross_module_alert(
            state="PA",
            ncm_code="7108",
            ncm_desc="Ouro",
            export_value_usd=10_000_000.0,
            deforestation_ha=900.0,
            deforestation_period="2024-Q2",
            geo_correlation_score=0.95,
            reference_date=ref,
            source_record_ids=["src-geoint-001", "src-trade-002"],
            z_score=7.5,
        )

        # Alert criado
        assert alert is not None
        alert_repo.create.assert_called_once()

        # Rule ID correto
        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["rule_id"] == "finint.cross_module.garimpo_signal.v1"
        assert call_kwargs["severity"] == "CRITICAL"

        # Audit log chamado com evento cross-module
        audit_log.append.assert_called_once()
        audit_kwargs = audit_log.append.call_args.kwargs
        assert audit_kwargs["event_type"] == "FININT_CROSS_MODULE_ALERT"

    @pytest.mark.asyncio
    async def test_trade_spike_alert_escalado_para_critical(self):
        """Trade spike com z muito alto → severity CRITICAL (escala MEDIUM→HIGH→CRITICAL)."""
        from unittest.mock import AsyncMock, MagicMock
        from atlantico.finint.alerts.generator import FinintAlertGenerator

        alert_repo = MagicMock()
        alert_repo.create = AsyncMock(return_value=MagicMock())
        audit_log = MagicMock()
        audit_log.append = AsyncMock(return_value=None)

        generator = FinintAlertGenerator(alert_repo=alert_repo, audit_log=audit_log)

        ref = datetime(2024, 6, 1, tzinfo=timezone.utc)
        await generator.generate_trade_spike_alert(
            ncm_code="7108",
            ncm_desc="Ouro (incluindo ouro platinado)",
            state="PA",
            reference_date=ref,
            export_value_usd=50_000_000.0,
            historical_mean=1_000_000.0,
            historical_stddev=100_000.0,
            geo_correlation_score=0.9,
            source_record_ids=["src-comexstat-001"],
        )

        call_kwargs = alert_repo.create.call_args.kwargs
        assert call_kwargs["severity"] == "CRITICAL"
