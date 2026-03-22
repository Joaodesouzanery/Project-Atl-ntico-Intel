"""
Conector INPE PRODES — TerraBrasilis WFS 2.0.0.

PRODES (Programa de Cálculo do Desmatamento da Amazônia) mede anualmente
o desmatamento bruto na Amazônia Legal e outros biomas.

API: TerraBrasilis WFS 2.0.0 — acesso público, sem autenticação.
URL: https://terrabrasilis.dpi.inpe.br/geoserver/wfs
TypeNames: prodes-amz-nb:yearly_deforestation_biome (Amazônia)
           prodes-cerrado-nb:yearly_deforestation (Cerrado)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from shapely.geometry import shape

from atlantico.config.settings import get_settings
from atlantico.geoint.connectors.base import (
    ConnectorError,
    ConnectorParseError,
    GeointConnector,
    retry_with_backoff,
)
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)

# TypeNames por bioma
_PRODES_LAYERS = [
    "prodes-amz-nb:yearly_deforestation_biome",
    "prodes-cerrado-nb:yearly_deforestation",
]


class INPEProdesConnector(GeointConnector):
    """Conector INPE PRODES (dados anuais de desmatamento)."""

    SOURCE_ID = "inpe.prodes.v2"
    DEFAULT_CLASSIFICATION = "PUBLIC"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        bbox: tuple[float, float, float, float],
    ) -> list[GeointObservation]:
        """
        Busca polígonos de desmatamento PRODES desde `since.year`.

        PRODES é publicado anualmente — filtro por `year >= since.year`.
        """
        settings = get_settings()
        min_lon, min_lat, max_lon, max_lat = bbox
        observations: list[GeointObservation] = []

        for layer in _PRODES_LAYERS:
            params = {
                "service": "WFS",
                "version": "2.0.0",
                "request": "GetFeature",
                "typeNames": layer,
                "outputFormat": "application/json",
                "srsName": "EPSG:4326",
                "CQL_FILTER": (
                    f"year >= {since.year} AND "
                    f"BBOX(geom,{min_lat},{min_lon},{max_lat},{max_lon})"
                ),
                "count": "5000",
            }
            try:
                resp = await self.client.get(
                    settings.inpe_terrabrasilis_wfs_url,
                    params=params,
                )
                resp.raise_for_status()
            except Exception as exc:
                raise ConnectorError(
                    f"PRODES WFS falhou para layer={layer}: {exc}"
                ) from exc

            try:
                geojson = resp.json()
                features = geojson.get("features", [])
            except Exception as exc:
                raise ConnectorParseError(
                    f"PRODES WFS retornou JSON inválido para layer={layer}: {exc}"
                ) from exc

            for feat in features:
                obs = self._parse_feature(feat, layer)
                if obs is not None:
                    observations.append(obs)

        logger.info(
            "PRODES: %d observações desde %d (bbox=%s)",
            len(observations),
            since.year,
            bbox,
        )
        return observations

    def _parse_feature(
        self,
        feature: dict,
        layer: str,
    ) -> GeointObservation | None:
        props = feature.get("properties", {})
        geom_data = feature.get("geometry")

        if not geom_data or not props:
            return None

        try:
            geom = shape(geom_data)
            geometry_wkt = geom.wkt
            bounds = geom.bounds  # (min_lon, min_lat, max_lon, max_lat)
            bbox_wkt = self._make_bbox_polygon_wkt(*bounds)
        except Exception as exc:
            logger.warning("PRODES: falha ao parsear geometria: %s", exc)
            return None

        # Calcula área em ha (se não disponível, estimativa pela área WGS-84)
        area_km2 = float(props.get("area_km", 0) or 0)
        area_ha = area_km2 * 100.0

        # Determina external_id determinístico
        feat_id = (
            props.get("gid")
            or props.get("id")
            or props.get("uuid")
            or feature.get("id")
            or f"{layer}_{props.get('year')}_{geometry_wkt[:32]}"
        )
        external_id = f"prodes-{str(feat_id)}"

        # view_date como acquired_at (dia 1 do ano se apenas ano disponível)
        year = props.get("year") or props.get("ano")
        view_date_str = props.get("view_date") or f"{year}-01-01"
        try:
            acquired_at = datetime.strptime(
                str(view_date_str)[:10], "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)
        except Exception:
            acquired_at = datetime(int(year or 2024), 1, 1, tzinfo=timezone.utc)

        payload = {
            "year": props.get("year"),
            "area_km2": area_km2,
            "area_ha": area_ha,
            "state": props.get("uf") or props.get("state"),
            "municipality": props.get("county") or props.get("municipality"),
            "biome": props.get("biome") or props.get("bioma"),
            "classname": props.get("classname"),
            "sensor": props.get("sensor"),
            "pathrow": props.get("pathrow"),
            "view_date": str(view_date_str),
            "layer": layer,
        }

        return GeointObservation(
            source_id=self.SOURCE_ID,
            external_id=external_id,
            observation_type="deforestation",
            acquired_at=acquired_at,
            geometry_wkt=geometry_wkt,
            payload=payload,
            data_classification=self.DEFAULT_CLASSIFICATION,
            bbox_wkt=bbox_wkt,
        )

    async def health_check(self) -> bool:
        try:
            settings = get_settings()
            resp = await self.client.get(
                settings.inpe_terrabrasilis_wfs_url,
                params={"service": "WFS", "version": "2.0.0", "request": "GetCapabilities"},
                timeout=10.0,
            )
            return resp.status_code == 200
        except Exception:
            return False
