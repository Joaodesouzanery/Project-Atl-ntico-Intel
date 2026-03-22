"""
DeforestationProcessor — análise de eventos de desmatamento.

Funcionalidades:
- Classificação de severidade por área
- Cálculo de NDVI (rasterio + numpy) quando imagens Sentinel-2 estão disponíveis
- Análise de tendência linear (scipy.stats.linregress) por bioma/estado
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime

import numpy as np

logger = logging.getLogger(__name__)


class DeforestationProcessor:
    """
    Algoritmos de análise para eventos de desmatamento.

    Stateless — não acessa banco de dados diretamente.
    Recebe objetos de domínio e retorna resultados calculados.
    """

    # Limiares de severidade em hectares
    SEVERITY_THRESHOLDS = {
        "CRITICAL": 500.0,
        "HIGH": 100.0,
        "MEDIUM": 25.0,
    }

    def classify_severity(self, area_ha: float) -> str:
        """
        Classifica severidade com base na área desmatada.

        Args:
            area_ha: Área em hectares

        Returns:
            "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        """
        if area_ha >= self.SEVERITY_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        if area_ha >= self.SEVERITY_THRESHOLDS["HIGH"]:
            return "HIGH"
        if area_ha >= self.SEVERITY_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        return "LOW"

    def compute_ndvi_change(
        self,
        geometry_wkt: str,
        before_imagery_path: str | None,
        after_imagery_path: str | None,
    ) -> tuple[float | None, float | None]:
        """
        Calcula variação de NDVI para a área de desmatamento.

        Usa rasterio para abrir bandas B4 (Red) e B8 (NIR) do Sentinel-2
        e recortar pelo polígono de desmatamento.

        NDVI = (NIR - Red) / (NIR + Red)

        Args:
            geometry_wkt: WKT do polígono de desmatamento
            before_imagery_path: Caminho para imagem Sentinel-2 anterior ao evento
            after_imagery_path: Caminho para imagem Sentinel-2 posterior ao evento

        Returns:
            Tupla (ndvi_before, ndvi_after). Valor None se imagem não disponível.

        Nota:
            Em Sprint 3, imagens não são baixadas localmente — método retorna
            (None, None) se caminhos não fornecidos. Download on-demand é Sprint 5+.
        """
        if before_imagery_path is None and after_imagery_path is None:
            return None, None

        ndvi_before = self._compute_ndvi_for_image(geometry_wkt, before_imagery_path)
        ndvi_after = self._compute_ndvi_for_image(geometry_wkt, after_imagery_path)
        return ndvi_before, ndvi_after

    def _compute_ndvi_for_image(
        self,
        geometry_wkt: str,
        imagery_path: str | None,
    ) -> float | None:
        """
        Calcula NDVI médio para um polígono em uma imagem raster.

        Usa rasterio para leitura e recorte (mask), numpy para NDVI.
        """
        if imagery_path is None:
            return None

        try:
            import rasterio
            from rasterio.mask import mask as rasterio_mask
            from shapely.wkt import loads as wkt_loads

            geom = wkt_loads(geometry_wkt)

            with rasterio.open(imagery_path) as ds:
                # Sentinel-2: B4=Red (banda 4), B8=NIR (banda 8)
                # Assumindo GeoTIFF com pelo menos 8 bandas
                red, _ = rasterio_mask(ds, [geom.__geo_interface__], crop=True, indexes=[4])
                nir, _ = rasterio_mask(ds, [geom.__geo_interface__], crop=True, indexes=[8])

                red = red.astype(np.float32)
                nir = nir.astype(np.float32)

                # Mascara nodata
                valid = (red > 0) & (nir > 0)
                if not np.any(valid):
                    return None

                denominator = nir[valid] + red[valid]
                nonzero = denominator != 0
                ndvi_values = np.full_like(red[valid], np.nan, dtype=np.float32)
                ndvi_values[nonzero] = (
                    (nir[valid][nonzero] - red[valid][nonzero]) / denominator[nonzero]
                )

                valid_ndvi = ndvi_values[~np.isnan(ndvi_values)]
                if len(valid_ndvi) == 0:
                    return None

                return float(np.mean(valid_ndvi))

        except ImportError:
            logger.warning(
                "rasterio não disponível para cálculo de NDVI. "
                "Instale: pip install rasterio"
            )
            return None
        except Exception as exc:
            logger.warning("Falha ao calcular NDVI para %s: %s", imagery_path, exc)
            return None

    def compute_trend(
        self,
        biome: str,
        state: str,
        yearly_area_ha: dict[int, float],
    ) -> dict:
        """
        Calcula tendência linear de desmatamento ao longo dos anos.

        Args:
            biome: Bioma analisado
            state: UF analisado
            yearly_area_ha: Dict {ano: area_ha_total} por ano

        Returns:
            Dict com slope, r_value, p_value, classification, description

        Classificação:
            slope > 0 e p_value < 0.05 → "increasing"
            slope < 0 e p_value < 0.05 → "decreasing"
            caso contrário             → "stable"
        """
        if len(yearly_area_ha) < 3:
            return {
                "slope": None,
                "r_value": None,
                "p_value": None,
                "classification": "insufficient_data",
                "description": f"Dados insuficientes para análise de tendência ({len(yearly_area_ha)} anos).",
            }

        try:
            from scipy import stats

            years = np.array(sorted(yearly_area_ha.keys()), dtype=float)
            areas = np.array([yearly_area_ha[y] for y in years.astype(int)], dtype=float)

            result = stats.linregress(years, areas)
            slope = float(result.slope)
            r_value = float(result.rvalue)
            p_value = float(result.pvalue)

            if p_value < 0.05:
                classification = "increasing" if slope > 0 else "decreasing"
            else:
                classification = "stable"

            direction_pt = {
                "increasing": "crescente",
                "decreasing": "decrescente",
                "stable": "estável",
            }[classification]

            description = (
                f"Tendência {direction_pt} de desmatamento em {biome}/{state}. "
                f"Variação: {slope:+.1f} ha/ano (R²={r_value**2:.2f}, p={p_value:.3f})."
            )

            return {
                "slope": slope,
                "r_value": r_value,
                "p_value": p_value,
                "classification": classification,
                "description": description,
            }

        except Exception as exc:
            logger.warning("Falha na análise de tendência: %s", exc)
            return {
                "slope": None,
                "r_value": None,
                "p_value": None,
                "classification": "error",
                "description": f"Erro na análise de tendência: {exc}",
            }
