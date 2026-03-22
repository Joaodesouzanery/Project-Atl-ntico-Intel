"""
Testes unitários para FireProcessor.

Testa:
- DBSCAN clustering com métrica haversine
- Classificação de severidade de clusters
- Extração de lat/lon de geometrias WKT
- Estatísticas FRP (numpy)
- Detecção de crescimento temporal de FRP
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from atlantico.geoint.processing.fire_processor import FireProcessor


@pytest.fixture
def processor() -> FireProcessor:
    return FireProcessor()


def _make_hotspot(
    lat: float,
    lon: float,
    frp: float = 50.0,
    biome: str = "Amazônia",
    state: str = "PA",
    minutes_offset: int = 0,
):
    """Cria stub de FireHotspot via SimpleNamespace (sem SQLAlchemy)."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        geom=f"SRID=4326;POINT({lon} {lat})",
        frp=frp,
        biome=biome,
        state=state,
        acquired_at=datetime(2024, 8, 15, 14, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minutes_offset),
        cluster_id=None,
        brightness=320.0,
        confidence=85,
    )


# ─── classify_cluster_severity ────────────────────────────────────────────────


class TestClassifyClusterSeverity:
    def test_menos_5_hotspots_retorna_low(self, processor):
        assert processor.classify_cluster_severity(4, None) == "LOW"

    def test_5_hotspots_retorna_medium(self, processor):
        assert processor.classify_cluster_severity(5, None) == "MEDIUM"

    def test_14_hotspots_retorna_medium(self, processor):
        assert processor.classify_cluster_severity(14, None) == "MEDIUM"

    def test_15_hotspots_retorna_high(self, processor):
        assert processor.classify_cluster_severity(15, None) == "HIGH"

    def test_49_hotspots_retorna_high(self, processor):
        assert processor.classify_cluster_severity(49, None) == "HIGH"

    def test_50_hotspots_retorna_critical(self, processor):
        assert processor.classify_cluster_severity(50, None) == "CRITICAL"

    def test_frp_acima_1000mw_retorna_critical(self, processor):
        assert processor.classify_cluster_severity(3, 1000.0) == "CRITICAL"

    def test_frp_999mw_nao_critica_por_frp(self, processor):
        # 3 hotspots < 5 (LOW), FRP < 1000 MW → LOW
        assert processor.classify_cluster_severity(3, 999.9) == "LOW"

    @pytest.mark.parametrize(
        "count,frp,expected",
        [
            (1, None, "LOW"),
            (4, None, "LOW"),
            (5, None, "MEDIUM"),
            (15, None, "HIGH"),
            (50, None, "CRITICAL"),
            (3, 1000.0, "CRITICAL"),
            (3, 500.0, "LOW"),
        ],
    )
    def test_parametrizado(self, processor, count, frp, expected):
        assert processor.classify_cluster_severity(count, frp) == expected


# ─── _get_lat / _get_lon ──────────────────────────────────────────────────────


class TestGetLatLon:
    def test_extrai_lat_de_point_wkt(self, processor):
        h = _make_hotspot(lat=-3.5, lon=-52.0)
        assert processor._get_lat(h) == pytest.approx(-3.5)

    def test_extrai_lon_de_point_wkt(self, processor):
        h = _make_hotspot(lat=-3.5, lon=-52.0)
        assert processor._get_lon(h) == pytest.approx(-52.0)

    def test_geom_none_retorna_zero(self, processor):
        h = _make_hotspot(lat=0, lon=0)
        h.geom = None
        assert processor._get_lat(h) == 0.0
        assert processor._get_lon(h) == 0.0

    def test_ponto_sem_srid(self, processor):
        h = _make_hotspot(lat=-5.0, lon=-60.0)
        h.geom = "POINT(-60.0 -5.0)"
        assert processor._get_lat(h) == pytest.approx(-5.0)
        assert processor._get_lon(h) == pytest.approx(-60.0)


# ─── _mode_value ─────────────────────────────────────────────────────────────


class TestModeValue:
    def test_lista_vazia_retorna_none(self, processor):
        assert processor._mode_value([]) is None

    def test_elemento_unico(self, processor):
        assert processor._mode_value(["Amazônia"]) == "Amazônia"

    def test_moda_correta(self, processor):
        values = ["Amazônia", "Cerrado", "Amazônia", "Amazônia"]
        assert processor._mode_value(values) == "Amazônia"

    def test_desempate_retorna_um_valor(self, processor):
        values = ["PA", "AM"]
        result = processor._mode_value(values)
        assert result in ("PA", "AM")


# ─── cluster_hotspots (DBSCAN) ────────────────────────────────────────────────


class TestClusterHotspots:
    def test_lista_vazia_retorna_lista_vazia(self, processor):
        result = processor.cluster_hotspots([], eps_km=5.0, min_samples=3)
        assert result == []

    def test_um_hotspot_abaixo_min_samples_retorna_vazio(self, processor):
        hotspots = [_make_hotspot(lat=-3.5, lon=-52.0)]
        result = processor.cluster_hotspots(hotspots, eps_km=5.0, min_samples=3)
        assert result == []

    def test_dois_grupos_bem_separados_retorna_dois_clusters(self, processor):
        """Dois grupos separados por > eps_km → 2 clusters distintos."""
        # Grupo 1: próximos ao ponto A
        group_a = [
            _make_hotspot(lat=-3.50, lon=-52.00),
            _make_hotspot(lat=-3.51, lon=-52.01),
            _make_hotspot(lat=-3.52, lon=-51.99),
        ]
        # Grupo 2: longe do grupo A (> 500 km)
        group_b = [
            _make_hotspot(lat=-15.00, lon=-47.00),
            _make_hotspot(lat=-15.01, lon=-47.01),
            _make_hotspot(lat=-15.02, lon=-46.99),
        ]
        hotspots = group_a + group_b

        result = processor.cluster_hotspots(hotspots, eps_km=10.0, min_samples=3)
        assert len(result) == 2

    def test_hotspots_proximos_retorna_um_cluster(self, processor):
        """Hotspots muito próximos entre si → 1 cluster."""
        hotspots = [
            _make_hotspot(lat=-3.50 + i * 0.001, lon=-52.00 + i * 0.001, frp=float(20 + i))
            for i in range(5)
        ]
        result = processor.cluster_hotspots(hotspots, eps_km=5.0, min_samples=3)
        assert len(result) == 1

    def test_cluster_tem_hotspot_count(self, processor):
        hotspots = [
            _make_hotspot(lat=-3.50 + i * 0.001, lon=-52.00 + i * 0.001)
            for i in range(5)
        ]
        result = processor.cluster_hotspots(hotspots, eps_km=5.0, min_samples=3)
        if result:
            assert result[0].hotspot_count == 5

    def test_cluster_tem_centroid_geom(self, processor):
        hotspots = [
            _make_hotspot(lat=-3.50 + i * 0.001, lon=-52.00 + i * 0.001)
            for i in range(5)
        ]
        result = processor.cluster_hotspots(hotspots, eps_km=5.0, min_samples=3)
        if result:
            assert result[0].centroid_geom is not None
            assert "POINT" in str(result[0].centroid_geom)

    def test_cluster_severity_classificada(self, processor):
        hotspots = [
            _make_hotspot(lat=-3.50 + i * 0.001, lon=-52.00 + i * 0.001)
            for i in range(5)
        ]
        result = processor.cluster_hotspots(hotspots, eps_km=5.0, min_samples=3)
        if result:
            assert result[0].severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_cluster_frp_stats_calculadas(self, processor):
        hotspots = [
            _make_hotspot(lat=-3.50 + i * 0.001, lon=-52.00 + i * 0.001, frp=float(100 + i))
            for i in range(5)
        ]
        result = processor.cluster_hotspots(hotspots, eps_km=5.0, min_samples=3)
        if result:
            cluster = result[0]
            assert cluster.total_frp_mw is not None
            assert cluster.max_frp_mw is not None
            assert cluster.mean_frp_mw is not None

    def test_cluster_run_id_propagado(self, processor):
        hotspots = [
            _make_hotspot(lat=-3.50 + i * 0.001, lon=-52.00 + i * 0.001)
            for i in range(5)
        ]
        run_id = "test-run-123"
        result = processor.cluster_hotspots(
            hotspots, eps_km=5.0, min_samples=3, cluster_run_id=run_id
        )
        if result:
            assert result[0].cluster_run_id == run_id


# ─── compute_frp_intensity ────────────────────────────────────────────────────


class TestComputeFrpIntensity:
    def test_sem_frp_retorna_unknown(self, processor):
        hotspots = [_make_hotspot(lat=-3.5, lon=-52.0, frp=None) for _ in range(3)]
        for h in hotspots:
            h.frp = None
        result = processor.compute_frp_intensity(hotspots)
        assert result["classification"] == "unknown"
        assert result["count_with_frp"] == 0

    def test_frp_baixo_retorna_low(self, processor):
        hotspots = [_make_hotspot(lat=-3.5 + i * 0.01, lon=-52.0, frp=5.0) for i in range(3)]
        result = processor.compute_frp_intensity(hotspots)
        assert result["classification"] == "low"

    def test_frp_moderado(self, processor):
        hotspots = [_make_hotspot(lat=-3.5 + i * 0.01, lon=-52.0, frp=50.0) for i in range(3)]
        result = processor.compute_frp_intensity(hotspots)
        assert result["classification"] == "moderate"

    def test_frp_alto(self, processor):
        hotspots = [_make_hotspot(lat=-3.5 + i * 0.01, lon=-52.0, frp=200.0) for i in range(3)]
        result = processor.compute_frp_intensity(hotspots)
        assert result["classification"] == "high"

    def test_frp_extremo(self, processor):
        hotspots = [_make_hotspot(lat=-3.5 + i * 0.01, lon=-52.0, frp=600.0) for i in range(3)]
        result = processor.compute_frp_intensity(hotspots)
        assert result["classification"] == "extreme"

    def test_estatisticas_corretas(self, processor):
        frp_values = [10.0, 20.0, 30.0]
        hotspots = [
            _make_hotspot(lat=-3.5 + i * 0.01, lon=-52.0, frp=v)
            for i, v in enumerate(frp_values)
        ]
        result = processor.compute_frp_intensity(hotspots)
        assert result["mean"] == pytest.approx(20.0)
        assert result["sum"] == pytest.approx(60.0)
        assert result["count_with_frp"] == 3


# ─── detect_frp_growth ────────────────────────────────────────────────────────


class TestDetectFrpGrowth:
    def test_menos_3_pontos_retorna_none(self, processor):
        hotspots = [_make_hotspot(lat=-3.5, lon=-52.0, frp=100.0)]
        result = processor.detect_frp_growth(hotspots)
        assert result is None

    def test_crescimento_positivo(self, processor):
        hotspots = [
            _make_hotspot(lat=-3.5, lon=-52.0, frp=100.0, minutes_offset=0),
            _make_hotspot(lat=-3.5, lon=-52.0, frp=200.0, minutes_offset=60),
            _make_hotspot(lat=-3.5, lon=-52.0, frp=300.0, minutes_offset=120),
        ]
        result = processor.detect_frp_growth(hotspots)
        assert result is not None
        assert result > 0  # FRP crescendo

    def test_decrescimento(self, processor):
        hotspots = [
            _make_hotspot(lat=-3.5, lon=-52.0, frp=300.0, minutes_offset=0),
            _make_hotspot(lat=-3.5, lon=-52.0, frp=200.0, minutes_offset=60),
            _make_hotspot(lat=-3.5, lon=-52.0, frp=100.0, minutes_offset=120),
        ]
        result = processor.detect_frp_growth(hotspots)
        assert result is not None
        assert result < 0  # FRP decrescendo
