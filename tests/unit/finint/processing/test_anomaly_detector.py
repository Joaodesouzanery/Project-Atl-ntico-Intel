"""
Testes unitários para AnomalyDetector.

Testa Z-score, Isolation Forest, anomalias em contratos e spikes comerciais.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from atlantico.finint.processing.anomaly_detector import AnomalyDetector


@pytest.fixture
def detector() -> AnomalyDetector:
    return AnomalyDetector(zscore_threshold=3.0)


def _make_dates(n: int) -> list[datetime]:
    """Cria lista de n datas mensais."""
    from datetime import timedelta
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return [base + timedelta(days=30 * i) for i in range(n)]


# ─── detect_series_anomaly (Z-score) ──────────────────────────────────────────


class TestDetectSeriesZscore:
    def test_menos_3_valores_retorna_lista_vazia(self, detector):
        result = detector.detect_series_anomaly([1.0, 2.0], _make_dates(2))
        assert result == []

    def test_serie_normal_sem_anomalias(self, detector):
        values = [10.0, 10.1, 9.9, 10.0, 10.2, 9.8] * 5
        dates = _make_dates(len(values))
        result = detector.detect_series_anomaly(values, dates, method="zscore")
        assert all(not r["is_anomaly"] for r in result)

    def test_spike_detectado(self, detector):
        # Valor 100× a média → anomalia
        values = [10.0] * 20 + [1000.0]
        dates = _make_dates(len(values))
        result = detector.detect_series_anomaly(values, dates, method="zscore")
        last = result[-1]
        assert last["is_anomaly"] is True
        assert last["anomaly_type"] == "spike_up"

    def test_spike_down_detectado(self, detector):
        values = [100.0] * 20 + [0.01]
        dates = _make_dates(len(values))
        result = detector.detect_series_anomaly(values, dates, method="zscore")
        last = result[-1]
        assert last["is_anomaly"] is True
        assert last["anomaly_type"] == "spike_down"

    def test_severidade_critical_acima_5_sigma(self, detector):
        # Media=10, stddev pequeno → valor muito alto = CRITICAL
        values = [10.0] * 50 + [200.0]
        dates = _make_dates(len(values))
        result = detector.detect_series_anomaly(values, dates, method="zscore")
        assert result[-1]["severity"] == "CRITICAL"

    def test_serie_constante_sem_anomalia(self, detector):
        values = [5.0] * 30
        dates = _make_dates(30)
        result = detector.detect_series_anomaly(values, dates, method="zscore")
        assert all(not r["is_anomaly"] for r in result)

    def test_retorna_z_score_para_cada_ponto(self, detector):
        values = [10.0, 10.0, 10.0, 10.0, 10.0]
        dates = _make_dates(5)
        result = detector.detect_series_anomaly(values, dates)
        assert len(result) == 5
        assert all("z_score" in r for r in result)


# ─── detect_series_anomaly (Isolation Forest) ─────────────────────────────────


class TestDetectSeriesIsolationForest:
    def test_isolation_forest_retorna_resultados(self, detector):
        values = [10.0] * 20 + [1000.0]
        dates = _make_dates(len(values))
        result = detector.detect_series_anomaly(values, dates, method="isolation_forest")
        assert len(result) == len(values)

    def test_isolation_forest_detecta_outlier(self, detector):
        values = [10.0] * 30 + [500.0]
        dates = _make_dates(len(values))
        result = detector.detect_series_anomaly(values, dates, method="isolation_forest")
        assert result[-1]["is_anomaly"] == True  # noqa: E712 — np.True_ != True

    def test_isolation_forest_tem_anomaly_type(self, detector):
        values = [10.0] * 30 + [500.0]
        dates = _make_dates(len(values))
        result = detector.detect_series_anomaly(values, dates, method="isolation_forest")
        assert result[-1]["anomaly_type"] == "isolation_forest"


# ─── detect_single_anomaly ────────────────────────────────────────────────────


class TestDetectSingleAnomaly:
    def test_dentro_do_threshold_retorna_none(self, detector):
        anomaly_type, severity, z = detector.detect_single_anomaly(
            value=10.0, historical_mean=10.0, historical_stddev=1.0, zscore_threshold=3.0
        )
        assert anomaly_type is None
        assert severity is None
        assert abs(z) < 3.0

    def test_spike_up_detectado(self, detector):
        anomaly_type, severity, z = detector.detect_single_anomaly(
            value=20.0, historical_mean=10.0, historical_stddev=2.0, zscore_threshold=3.0
        )
        assert anomaly_type == "spike_up"
        assert z == pytest.approx(5.0)

    def test_spike_down_detectado(self, detector):
        anomaly_type, _, z = detector.detect_single_anomaly(
            value=0.0, historical_mean=10.0, historical_stddev=2.0, zscore_threshold=3.0
        )
        assert anomaly_type == "spike_down"

    def test_stddev_zero_retorna_none(self, detector):
        anomaly_type, _, z = detector.detect_single_anomaly(
            value=100.0, historical_mean=10.0, historical_stddev=0.0
        )
        assert anomaly_type is None
        assert z == 0.0

    def test_severidade_medium(self, detector):
        # z = 3.5 → excess = 0.5 → MEDIUM
        _, severity, _ = detector.detect_single_anomaly(
            value=17.0, historical_mean=10.0, historical_stddev=2.0, zscore_threshold=3.0
        )
        assert severity == "MEDIUM"

    def test_severidade_critical(self, detector):
        # z = 5.0 → excess = 2.0 → CRITICAL
        _, severity, _ = detector.detect_single_anomaly(
            value=20.0, historical_mean=10.0, historical_stddev=2.0, zscore_threshold=3.0
        )
        assert severity == "CRITICAL"


# ─── detect_contract_anomaly ──────────────────────────────────────────────────


class TestDetectContractAnomaly:
    def test_sem_contratos_retorna_sem_anomalia(self, detector):
        result = detector.detect_contract_anomaly([], [])
        assert result["has_anomaly"] is False

    def test_concentracao_fornecedor_detectada(self, detector):
        # 1 fornecedor com 90% dos contratos
        values = [1000.0] * 9 + [100.0]
        suppliers = ["CNPJ-A"] * 9 + ["CNPJ-B"]
        result = detector.detect_contract_anomaly(
            values, suppliers, concentration_threshold=0.8
        )
        assert result["has_anomaly"] is True
        assert "supplier_concentration" in result["anomaly_types"]

    def test_volume_spike_detectado(self, detector):
        values = [100000.0]
        result = detector.detect_contract_anomaly(
            values, ["CNPJ-X"],
            historical_mean=1000.0,
            historical_stddev=100.0,
        )
        assert result["has_anomaly"] is True
        assert "volume_spike" in result["anomaly_types"]

    def test_sem_anomalia_normal(self, detector):
        values = [1000.0, 1200.0, 900.0]
        suppliers = ["CNPJ-A", "CNPJ-B", "CNPJ-C"]
        # total=3100 → histórico mean=3000, stddev=500 → z=0.2, abaixo de 3σ
        # concentração: cada fornecedor tem 1/3 ≈ 0.33 < 0.8 → sem concentração
        result = detector.detect_contract_anomaly(
            values, suppliers,
            historical_mean=3000.0, historical_stddev=500.0,
            concentration_threshold=0.8,
        )
        assert result["has_anomaly"] is False


# ─── detect_trade_spike ───────────────────────────────────────────────────────


class TestDetectTradeSpike:
    def test_valor_normal_retorna_false(self, detector):
        result = detector.detect_trade_spike(
            current_value_usd=10000.0,
            historical_mean=10000.0,
            historical_stddev=1000.0,
            multiplier=3.0,
        )
        assert result is False

    def test_spike_detectado(self, detector):
        # 10× a média com stddev pequeno → spike
        result = detector.detect_trade_spike(
            current_value_usd=100000.0,
            historical_mean=10000.0,
            historical_stddev=1000.0,
            multiplier=3.0,
        )
        assert result is True

    def test_stddev_zero_retorna_false(self, detector):
        result = detector.detect_trade_spike(
            current_value_usd=999999.0,
            historical_mean=100.0,
            historical_stddev=0.0,
        )
        assert result is False
