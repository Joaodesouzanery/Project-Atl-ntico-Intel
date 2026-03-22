"""
Testes unitários para DeforestationProcessor.

Testa:
- Classificação de severidade por área (ha)
- compute_ndvi_change() sem imagens locais → (None, None)
- compute_trend() com scipy.stats.linregress
"""

from __future__ import annotations

import pytest

from atlantico.geoint.processing.deforestation_processor import DeforestationProcessor


@pytest.fixture
def processor() -> DeforestationProcessor:
    return DeforestationProcessor()


# ─── classify_severity ────────────────────────────────────────────────────────


class TestClassifySeverity:
    def test_area_minima_retorna_low(self, processor):
        assert processor.classify_severity(0.0) == "LOW"

    def test_abaixo_limiar_medium_retorna_low(self, processor):
        assert processor.classify_severity(24.9) == "LOW"

    def test_exatamente_limiar_medium(self, processor):
        assert processor.classify_severity(25.0) == "MEDIUM"

    def test_entre_25_e_100_retorna_medium(self, processor):
        assert processor.classify_severity(50.0) == "MEDIUM"
        assert processor.classify_severity(99.9) == "MEDIUM"

    def test_exatamente_limiar_high(self, processor):
        assert processor.classify_severity(100.0) == "HIGH"

    def test_entre_100_e_500_retorna_high(self, processor):
        assert processor.classify_severity(200.0) == "HIGH"
        assert processor.classify_severity(499.9) == "HIGH"

    def test_exatamente_limiar_critical(self, processor):
        assert processor.classify_severity(500.0) == "CRITICAL"

    def test_acima_critical(self, processor):
        assert processor.classify_severity(1000.0) == "CRITICAL"
        assert processor.classify_severity(50000.0) == "CRITICAL"

    @pytest.mark.parametrize(
        "area_ha,expected",
        [
            (0.0, "LOW"),
            (10.0, "LOW"),
            (25.0, "MEDIUM"),
            (75.0, "MEDIUM"),
            (100.0, "HIGH"),
            (350.0, "HIGH"),
            (500.0, "CRITICAL"),
            (2000.0, "CRITICAL"),
        ],
    )
    def test_limites_parametrizados(self, processor, area_ha, expected):
        assert processor.classify_severity(area_ha) == expected


# ─── compute_ndvi_change ──────────────────────────────────────────────────────


class TestComputeNdviChange:
    def test_sem_imagens_retorna_none_none(self, processor):
        result = processor.compute_ndvi_change(
            geometry_wkt="POLYGON((-54 -3,-54 -3.1,-54.1 -3.1,-54.1 -3,-54 -3))",
            before_imagery_path=None,
            after_imagery_path=None,
        )
        assert result == (None, None)

    def test_imagem_inexistente_retorna_none(self, processor):
        """Path inválido → rasterio.open falha → retorna None."""
        result = processor.compute_ndvi_change(
            geometry_wkt="POLYGON((-54 -3,-54 -3.1,-54.1 -3.1,-54.1 -3,-54 -3))",
            before_imagery_path="/nonexistent/path/image.tif",
            after_imagery_path=None,
        )
        ndvi_before, ndvi_after = result
        assert ndvi_before is None
        assert ndvi_after is None

    def test_ambas_imagens_invalidas_retorna_none_none(self, processor):
        result = processor.compute_ndvi_change(
            geometry_wkt="POLYGON((-54 -3,-54 -3.1,-54.1 -3.1,-54.1 -3,-54 -3))",
            before_imagery_path="/nonexistent/before.tif",
            after_imagery_path="/nonexistent/after.tif",
        )
        assert result == (None, None)


# ─── compute_trend ────────────────────────────────────────────────────────────


class TestComputeTrend:
    def test_dados_insuficientes_menos_3_anos(self, processor):
        result = processor.compute_trend(
            biome="Amazônia",
            state="PA",
            yearly_area_ha={2022: 1000.0, 2023: 1100.0},  # só 2 anos
        )
        assert result["classification"] == "insufficient_data"
        assert result["slope"] is None

    def test_tendencia_crescente(self, processor):
        """Área aumentando linearmente → increasing."""
        yearly_area_ha = {
            2018: 1000.0,
            2019: 2000.0,
            2020: 3000.0,
            2021: 4000.0,
            2022: 5000.0,
        }
        result = processor.compute_trend(
            biome="Amazônia", state="AM", yearly_area_ha=yearly_area_ha
        )
        assert result["classification"] == "increasing"
        assert result["slope"] is not None
        assert result["slope"] > 0

    def test_tendencia_decrescente(self, processor):
        """Área diminuindo linearmente → decreasing."""
        yearly_area_ha = {
            2018: 5000.0,
            2019: 4000.0,
            2020: 3000.0,
            2021: 2000.0,
            2022: 1000.0,
        }
        result = processor.compute_trend(
            biome="Cerrado", state="MT", yearly_area_ha=yearly_area_ha
        )
        assert result["classification"] == "decreasing"
        assert result["slope"] < 0

    def test_tendencia_estavel(self, processor):
        """Área constante → stable (sem tendência significativa)."""
        yearly_area_ha = {
            2018: 1000.0,
            2019: 1005.0,
            2020: 995.0,
            2021: 1002.0,
            2022: 998.0,
        }
        result = processor.compute_trend(
            biome="Amazônia", state="PA", yearly_area_ha=yearly_area_ha
        )
        assert result["classification"] == "stable"

    def test_resultado_tem_campos_obrigatorios(self, processor):
        yearly_area_ha = {
            2018: 1000.0,
            2019: 2000.0,
            2020: 3000.0,
        }
        result = processor.compute_trend(
            biome="Amazônia", state="PA", yearly_area_ha=yearly_area_ha
        )
        assert "slope" in result
        assert "r_value" in result
        assert "p_value" in result
        assert "classification" in result
        assert "description" in result

    def test_descricao_contem_bioma_e_estado(self, processor):
        yearly_area_ha = {2018: 1000.0, 2019: 2000.0, 2020: 3000.0}
        result = processor.compute_trend(
            biome="Cerrado", state="GO", yearly_area_ha=yearly_area_ha
        )
        assert "Cerrado" in result["description"]
        assert "GO" in result["description"]

    def test_tres_anos_suficiente(self, processor):
        """3 anos é o mínimo para o cálculo."""
        yearly_area_ha = {2020: 500.0, 2021: 1000.0, 2022: 1500.0}
        result = processor.compute_trend(
            biome="Amazônia", state="RO", yearly_area_ha=yearly_area_ha
        )
        assert result["classification"] != "insufficient_data"
