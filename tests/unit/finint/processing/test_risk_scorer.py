"""
Testes unitários para RiskScorer.

Testa compute_entity_risk(), correlate_with_geoint(), score_trade_flow(),
classify_risk_level() e determine_flags().
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from atlantico.finint.processing.risk_scorer import RiskScorer


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer()


# ─── compute_entity_risk ──────────────────────────────────────────────────────


class TestComputeEntityRisk:
    def test_score_zero_se_tudo_zero(self, scorer):
        score = scorer.compute_entity_risk(
            anomaly_score=0.0,
            centrality_score=0.0,
            geo_correlation_score=0.0,
        )
        assert score == pytest.approx(0.0)

    def test_score_maximo_se_tudo_um(self, scorer):
        # centrality_score=1.0 → normalizado para 1.0 (1.0 * 100 = 100, clamp → 1.0)
        score = scorer.compute_entity_risk(
            anomaly_score=1.0,
            centrality_score=1.0,
            geo_correlation_score=1.0,
        )
        assert score == pytest.approx(1.0)

    def test_formula_pesos_corretos(self, scorer):
        # 0.4 * 0.8 + 0.3 * min(0.01*100, 1.0) + 0.3 * 0.5
        # = 0.32 + 0.3 * 1.0 + 0.15 = 0.77
        score = scorer.compute_entity_risk(
            anomaly_score=0.8,
            centrality_score=0.01,  # PageRank típico → normaliza * 100 = 1.0
            geo_correlation_score=0.5,
        )
        assert score == pytest.approx(0.77, rel=1e-3)

    def test_centrality_pequeno_normalizado(self, scorer):
        # centrality_score=0.005 → 0.005 * 100 = 0.5
        # score = 0.4 * 0.0 + 0.3 * 0.5 + 0.3 * 0.0 = 0.15
        score = scorer.compute_entity_risk(
            anomaly_score=0.0,
            centrality_score=0.005,
            geo_correlation_score=0.0,
        )
        assert score == pytest.approx(0.15, rel=1e-3)

    def test_score_clampado_em_um(self, scorer):
        # Mesmo com valores > 1 passados, score deve ficar em [0, 1]
        score = scorer.compute_entity_risk(
            anomaly_score=2.0,
            centrality_score=2.0,
            geo_correlation_score=2.0,
        )
        assert score <= 1.0

    def test_score_nao_negativo(self, scorer):
        score = scorer.compute_entity_risk(
            anomaly_score=-1.0,
            centrality_score=-1.0,
            geo_correlation_score=-1.0,
        )
        assert score >= 0.0

    def test_apenas_anomalia(self, scorer):
        # 0.4 * 1.0 = 0.4
        score = scorer.compute_entity_risk(
            anomaly_score=1.0,
            centrality_score=0.0,
            geo_correlation_score=0.0,
        )
        assert score == pytest.approx(0.4)

    def test_apenas_geo(self, scorer):
        # 0.3 * 1.0 = 0.3
        score = scorer.compute_entity_risk(
            anomaly_score=0.0,
            centrality_score=0.0,
            geo_correlation_score=1.0,
        )
        assert score == pytest.approx(0.3)


# ─── correlate_with_geoint ────────────────────────────────────────────────────


class TestCorrelateWithGeoint:
    _since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    _until = datetime(2024, 12, 31, tzinfo=timezone.utc)

    def test_sem_dados_score_zero(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=0.0, hotspot_count=0,
        )
        assert result["correlation_score"] == pytest.approx(0.0)

    def test_desmatamento_acima_500_score_alto(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=1000.0, hotspot_count=0,
        )
        # defor_score=1.0 * 0.7 = 0.7
        assert result["correlation_score"] == pytest.approx(0.7)

    def test_desmatamento_100_500_medio(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=200.0, hotspot_count=0,
        )
        # defor_score=0.6 * 0.7 = 0.42
        assert result["correlation_score"] == pytest.approx(0.42)

    def test_desmatamento_10_100_baixo(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=50.0, hotspot_count=0,
        )
        # defor_score=0.3 * 0.7 = 0.21
        assert result["correlation_score"] == pytest.approx(0.21)

    def test_focos_acima_20_bonus_fogo(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=0.0, hotspot_count=30,
        )
        # fire_score=0.5 * 0.3 = 0.15
        assert result["correlation_score"] == pytest.approx(0.15)

    def test_focos_5_20_bonus_fogo_medio(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=0.0, hotspot_count=10,
        )
        # fire_score=0.3 * 0.3 = 0.09
        assert result["correlation_score"] == pytest.approx(0.09)

    def test_combinacao_alta_desmatamento_e_fogo(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=600.0, hotspot_count=25,
        )
        # 1.0 * 0.7 + 0.5 * 0.3 = 0.85
        assert result["correlation_score"] == pytest.approx(0.85)

    def test_retorna_campos_corretos(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=100.0, hotspot_count=5,
        )
        assert "municipality_code" in result
        assert "deforestation_ha" in result
        assert "hotspot_count" in result
        assert "correlation_score" in result
        assert result["municipality_code"] == "1504208"

    def test_score_clampado_em_um(self, scorer):
        result = scorer.correlate_with_geoint(
            "1504208", self._since, self._until,
            deforestation_ha=10000.0, hotspot_count=1000,
        )
        assert result["correlation_score"] <= 1.0


# ─── score_trade_flow ─────────────────────────────────────────────────────────


class TestScoreTradeFlow:
    def test_ncm_ouro_multiplica_score(self, scorer):
        score_ouro = scorer.score_trade_flow(
            ncm_code="7108",
            export_value_usd=100000.0,
            historical_mean_usd=10000.0,
            historical_stddev_usd=1000.0,
            geo_correlation_score=0.0,
        )
        score_outro = scorer.score_trade_flow(
            ncm_code="2601",  # minério de ferro — não é high-risk
            export_value_usd=100000.0,
            historical_mean_usd=10000.0,
            historical_stddev_usd=1000.0,
            geo_correlation_score=0.0,
        )
        # NCM 7108 deve ter score maior (multiplicador 1.5)
        assert score_ouro > score_outro

    def test_ncm_pedra_preciosa_7101_alto_risco(self, scorer):
        score = scorer.score_trade_flow(
            ncm_code="7101",
            export_value_usd=50000.0,
            historical_mean_usd=1000.0,
            historical_stddev_usd=500.0,
            geo_correlation_score=0.0,
        )
        assert score > 0.0

    def test_sem_spike_score_baixo(self, scorer):
        # Valor igual à média → sem spike
        score = scorer.score_trade_flow(
            ncm_code="2601",
            export_value_usd=10000.0,
            historical_mean_usd=10000.0,
            historical_stddev_usd=1000.0,
            geo_correlation_score=0.0,
        )
        assert score == pytest.approx(0.0)

    def test_stddev_zero_sem_crash(self, scorer):
        score = scorer.score_trade_flow(
            ncm_code="7108",
            export_value_usd=1000000.0,
            historical_mean_usd=10000.0,
            historical_stddev_usd=0.0,
            geo_correlation_score=0.0,
        )
        # Com stddev=0, spike_score=0, mas geo_correlation pode somar
        assert 0.0 <= score <= 1.0

    def test_geo_correlation_amplifica_score(self, scorer):
        score_sem_geo = scorer.score_trade_flow(
            ncm_code="7108",
            export_value_usd=10000.0,
            historical_mean_usd=10000.0,
            historical_stddev_usd=1000.0,
            geo_correlation_score=0.0,
        )
        score_com_geo = scorer.score_trade_flow(
            ncm_code="7108",
            export_value_usd=10000.0,
            historical_mean_usd=10000.0,
            historical_stddev_usd=1000.0,
            geo_correlation_score=1.0,
        )
        assert score_com_geo > score_sem_geo

    def test_score_clampado(self, scorer):
        score = scorer.score_trade_flow(
            ncm_code="7108",
            export_value_usd=10_000_000.0,
            historical_mean_usd=10000.0,
            historical_stddev_usd=100.0,
            geo_correlation_score=1.0,
        )
        assert score <= 1.0


# ─── classify_risk_level ──────────────────────────────────────────────────────


class TestClassifyRiskLevel:
    def test_critical_acima_0_8(self, scorer):
        assert scorer.classify_risk_level(0.85) == "CRITICAL"
        assert scorer.classify_risk_level(1.0) == "CRITICAL"

    def test_high_0_6_a_0_8(self, scorer):
        assert scorer.classify_risk_level(0.6) == "HIGH"
        assert scorer.classify_risk_level(0.79) == "HIGH"

    def test_medium_0_4_a_0_6(self, scorer):
        assert scorer.classify_risk_level(0.4) == "MEDIUM"
        assert scorer.classify_risk_level(0.59) == "MEDIUM"

    def test_low_abaixo_0_4(self, scorer):
        assert scorer.classify_risk_level(0.0) == "LOW"
        assert scorer.classify_risk_level(0.39) == "LOW"

    def test_limite_exato_0_8(self, scorer):
        assert scorer.classify_risk_level(0.8) == "CRITICAL"

    def test_limite_exato_0_6(self, scorer):
        assert scorer.classify_risk_level(0.6) == "HIGH"


# ─── determine_flags ──────────────────────────────────────────────────────────


class TestDetermineFlags:
    def test_garimpo_ilegal_se_geo_alto(self, scorer):
        flags = scorer.determine_flags(
            score=0.5,
            anomaly_types=[],
            geo_correlation_score=0.6,
        )
        assert "garimpo_ilegal" in flags

    def test_sem_garimpo_se_geo_baixo(self, scorer):
        flags = scorer.determine_flags(
            score=0.5,
            anomaly_types=[],
            geo_correlation_score=0.3,
        )
        assert "garimpo_ilegal" not in flags

    def test_conta_laranja_se_concentracao(self, scorer):
        flags = scorer.determine_flags(
            score=0.5,
            anomaly_types=["supplier_concentration"],
            geo_correlation_score=0.0,
        )
        assert "conta_laranja" in flags

    def test_lavagem_dinheiro_se_spike_e_score_alto(self, scorer):
        flags = scorer.determine_flags(
            score=0.8,
            anomaly_types=["spike_up"],
            geo_correlation_score=0.0,
        )
        assert "lavagem_dinheiro" in flags

    def test_sem_lavagem_se_score_baixo(self, scorer):
        flags = scorer.determine_flags(
            score=0.5,
            anomaly_types=["spike_up"],
            geo_correlation_score=0.0,
        )
        assert "lavagem_dinheiro" not in flags

    def test_comportamento_atipico_isolation_forest(self, scorer):
        flags = scorer.determine_flags(
            score=0.5,
            anomaly_types=["isolation_forest"],
            geo_correlation_score=0.0,
        )
        assert "comportamento_atipico" in flags

    def test_multiplas_flags_ao_mesmo_tempo(self, scorer):
        flags = scorer.determine_flags(
            score=0.9,
            anomaly_types=["spike_up", "supplier_concentration", "isolation_forest"],
            geo_correlation_score=0.8,
        )
        assert "garimpo_ilegal" in flags
        assert "conta_laranja" in flags
        assert "lavagem_dinheiro" in flags
        assert "comportamento_atipico" in flags

    def test_sem_anomalias_sem_flags(self, scorer):
        flags = scorer.determine_flags(
            score=0.1,
            anomaly_types=[],
            geo_correlation_score=0.0,
        )
        assert flags == []
