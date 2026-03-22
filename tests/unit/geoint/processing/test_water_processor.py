"""
Testes unitários para WaterProcessor.

Testa:
- detect_anomaly(): Z-score, tipos de anomalia, severidade
- detect_rapid_change(): numpy.gradient em série temporal
- analyze_observation(): análise completa
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from atlantico.geoint.processing.water_processor import WaterProcessor


@pytest.fixture
def processor() -> WaterProcessor:
    return WaterProcessor()


def _make_water_obs(
    value: float,
    measurement_type: str = "nivel",
    station_code: str = "17050001",
    minutes_offset: int = 0,
    historical_mean: float | None = None,
    historical_stddev: float | None = None,
    z_score: float | None = None,
    anomaly_type: str | None = None,
    anomaly_severity: str | None = None,
    analysis_status: str = "pending",
):
    """Cria stub de WaterObservation via SimpleNamespace (sem SQLAlchemy)."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        station_code=station_code,
        station_name=f"Estação {station_code}",
        measurement_type=measurement_type,
        value=value,
        unit="m" if measurement_type == "nivel" else "m³/s",
        acquired_at=datetime(2024, 8, 15, 12, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minutes_offset),
        historical_mean=historical_mean,
        historical_stddev=historical_stddev,
        z_score=z_score,
        anomaly_type=anomaly_type,
        anomaly_severity=anomaly_severity,
        analysis_status=analysis_status,
        geom="SRID=4326;POINT(-54.6 -25.4)",
    )


# ─── detect_anomaly ───────────────────────────────────────────────────────────


class TestDetectAnomaly:
    def test_dentro_do_threshold_retorna_none(self, processor):
        anomaly_type, anomaly_severity, z_score = processor.detect_anomaly(
            value=10.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=1.0,
            stddev_threshold=3.0,
        )
        assert anomaly_type is None
        assert anomaly_severity is None
        assert abs(z_score) < 3.0

    def test_stddev_zero_retorna_none(self, processor):
        anomaly_type, anomaly_severity, z_score = processor.detect_anomaly(
            value=100.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=0.0,
        )
        assert anomaly_type is None
        assert z_score == 0.0

    def test_stddev_negativo_retorna_none(self, processor):
        anomaly_type, anomaly_severity, z_score = processor.detect_anomaly(
            value=100.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=-1.0,
        )
        assert anomaly_type is None

    def test_nivel_acima_threshold_retorna_flood(self, processor):
        # z = (20 - 10) / 2 = 5.0 > 3.0 → flood
        anomaly_type, anomaly_severity, z_score = processor.detect_anomaly(
            value=20.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=2.0,
            stddev_threshold=3.0,
        )
        assert anomaly_type == "flood"
        assert anomaly_severity is not None
        assert z_score == pytest.approx(5.0)

    def test_nivel_abaixo_threshold_retorna_drought(self, processor):
        # z = (0 - 10) / 2 = -5.0 < -3.0 → drought
        anomaly_type, anomaly_severity, z_score = processor.detect_anomaly(
            value=0.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=2.0,
            stddev_threshold=3.0,
        )
        assert anomaly_type == "drought"
        assert z_score == pytest.approx(-5.0)

    def test_vazao_negativa_retorna_drought(self, processor):
        anomaly_type, _, _ = processor.detect_anomaly(
            value=100.0,
            measurement_type="vazao",
            historical_mean=5000.0,
            historical_stddev=100.0,
            stddev_threshold=3.0,
        )
        assert anomaly_type == "drought"

    def test_chuva_acima_retorna_extreme_precipitation(self, processor):
        anomaly_type, _, _ = processor.detect_anomaly(
            value=150.0,
            measurement_type="chuva",
            historical_mean=10.0,
            historical_stddev=5.0,
            stddev_threshold=3.0,
        )
        assert anomaly_type == "extreme_precipitation"

    def test_severidade_medium_entre_3_e_4_sigma(self, processor):
        # z = 3.5 → excess = 0.5 < 1.0 → MEDIUM
        _, anomaly_severity, _ = processor.detect_anomaly(
            value=17.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=2.0,  # z = 3.5
            stddev_threshold=3.0,
        )
        assert anomaly_severity == "MEDIUM"

    def test_severidade_high_entre_4_e_5_sigma(self, processor):
        # z = 4.5 → excess = 1.5 → HIGH
        _, anomaly_severity, _ = processor.detect_anomaly(
            value=19.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=2.0,  # z = 4.5
            stddev_threshold=3.0,
        )
        assert anomaly_severity == "HIGH"

    def test_severidade_critical_acima_5_sigma(self, processor):
        # z = 5.0 → excess = 2.0 → CRITICAL
        _, anomaly_severity, _ = processor.detect_anomaly(
            value=20.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=2.0,  # z = 5.0
            stddev_threshold=3.0,
        )
        assert anomaly_severity == "CRITICAL"

    def test_z_score_calculado_corretamente(self, processor):
        _, _, z_score = processor.detect_anomaly(
            value=13.0,
            measurement_type="nivel",
            historical_mean=10.0,
            historical_stddev=1.0,
        )
        assert z_score == pytest.approx(3.0)


# ─── detect_rapid_change ──────────────────────────────────────────────────────


class TestDetectRapidChange:
    def test_menos_3_observacoes_retorna_false(self, processor):
        obs_list = [
            _make_obs_with_value(5.0, 0),
            _make_obs_with_value(6.0, 60),
        ]
        result = processor.detect_rapid_change(obs_list)
        assert result is False

    def test_variacao_lenta_retorna_false(self, processor):
        obs_list = [
            _make_obs_with_value(10.0, 0),
            _make_obs_with_value(10.1, 60),
            _make_obs_with_value(10.2, 120),
            _make_obs_with_value(10.3, 180),
        ]
        result = processor.detect_rapid_change(obs_list, change_pct_threshold=50.0)
        assert result is False

    def test_variacao_rapida_retorna_true(self, processor):
        """Variação acima do threshold de 50% por hora."""
        # gradient([10, 20, 30], [0,1,2]) = [10, 10, 10]; mean=20; pct=50%+
        # Usar valores que garantam > 50%: [5, 20, 35] → grad=[15,15,15], mean=20 → 75%
        obs_list = [
            _make_obs_with_value(5.0, 0),
            _make_obs_with_value(20.0, 60),
            _make_obs_with_value(35.0, 120),
        ]
        result = processor.detect_rapid_change(obs_list, change_pct_threshold=50.0)
        assert result is True

    def test_valores_zero_retorna_false(self, processor):
        """Valores zero causariam divisão por zero — deve retornar False."""
        obs_list = [
            _make_obs_with_value(0.0, 0),
            _make_obs_with_value(0.0, 60),
            _make_obs_with_value(0.0, 120),
        ]
        result = processor.detect_rapid_change(obs_list)
        assert result is False


def _make_obs_with_value(value: float, minutes_offset: int) -> WaterObservation:
    return _make_water_obs(value=value, minutes_offset=minutes_offset)


# ─── analyze_observation ──────────────────────────────────────────────────────


class TestAnalyzeObservation:
    def test_sem_historico_retorna_sem_anomalia(self, processor):
        obs = _make_water_obs(value=10.0)
        result = processor.analyze_observation(
            obs=obs,
            historical_mean=None,
            historical_stddev=None,
        )
        assert result["has_anomaly"] is False
        assert result["z_score"] is None
        assert result["anomaly_type"] is None

    def test_com_historico_normal_sem_anomalia(self, processor):
        obs = _make_water_obs(value=10.0, measurement_type="nivel")
        result = processor.analyze_observation(
            obs=obs,
            historical_mean=10.0,
            historical_stddev=1.0,
            stddev_threshold=3.0,
        )
        assert result["has_anomaly"] is False
        assert result["z_score"] == pytest.approx(0.0)

    def test_com_anomalia_detectada(self, processor):
        # value = mean + 5 * stddev → z = 5 → anomalia CRITICAL
        obs = _make_water_obs(
            value=10.0 + 5 * 2.0,  # = 20.0
            measurement_type="nivel",
        )
        result = processor.analyze_observation(
            obs=obs,
            historical_mean=10.0,
            historical_stddev=2.0,
            stddev_threshold=3.0,
        )
        assert result["has_anomaly"] is True
        assert result["anomaly_type"] == "flood"
        assert result["anomaly_severity"] == "CRITICAL"
        assert result["z_score"] == pytest.approx(5.0)

    def test_resultado_contem_historico(self, processor):
        obs = _make_water_obs(value=10.0, measurement_type="nivel")
        result = processor.analyze_observation(
            obs=obs,
            historical_mean=9.5,
            historical_stddev=0.8,
        )
        assert result["historical_mean"] == pytest.approx(9.5)
        assert result["historical_stddev"] == pytest.approx(0.8)

    def test_z_score_extremo_injetado(self, processor):
        """Simula value = mean + 5*stddev para garantir detecção."""
        mean = 100.0
        stddev = 10.0
        value = mean + 5 * stddev  # z = 5.0

        obs = _make_water_obs(value=value, measurement_type="nivel")
        result = processor.analyze_observation(
            obs=obs,
            historical_mean=mean,
            historical_stddev=stddev,
            stddev_threshold=3.0,
        )
        assert result["has_anomaly"] is True
        assert result["anomaly_severity"] == "CRITICAL"
