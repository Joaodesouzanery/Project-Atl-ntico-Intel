"""
Conector INPE DETER — TerraBrasilis WFS 2.0.0.

DETER (Detecção do Desmatamento em Tempo Real) fornece detecções
near-real-time de desmatamento e degradação florestal.

API: TerraBrasilis WFS 2.0.0 — acesso público, sem autenticação.
TypeNames: deter-amz:deter_amz (Amazônia)
           deter-cerrado:deter_cerrado (Cerrado)

Classificação: PUBLIC (dados publicados pelo INPE).
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

_DETER_LAYERS = [
    "deter-amz:deter_amz",
    "deter-cerrado:deter_cerrado",
]


class INPEDeterConnector(GeointConnector):
    """Conector INPE DETER (detecções near-real-time de desmatamento)."""

    SOURCE_ID = "inpe.deter.v1"
    DEFAULT_CLASSIFICATION = "PUBLIC"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        bbox: tuple[float, float, float, float],
    ) -> list[GeointObservation]:
        """Busca detecções DETER com view_date >= since."""
        settings = get_settings()
        min_lon, min_lat, max_lon, max_lat = bbox
        observations: list[GeointObservation] = []
        since_date = since.strftime("%Y-%m-%d")

        for layer in _DETER_LAYERS:
            params = {
                "service": "WFS",
                "version": "2.0.0",
                "request": "GetFeature",
                "typeNames": layer,
                "outputFormat": "application/json",
                "srsName": "EPSG:4326",
                "CQL_FILTER": (
                    f"view_date >= '{since_date}' AND "
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
                    f"DETER WFS falhou para layer={layer}: {exc}"
                ) from exc

            try:
                geojson = resp.json()
                features = geojson.get("features", [])
            except Exception as exc:
                raise ConnectorParseError(
                    f"DETER WFS retornou JSON inválido: {exc}"
                ) from exc

            for feat in features:
                obs = self._parse_feature(feat, layer)
                if obs is not None:
                    observations.append(obs)

        logger.info(
            "DETER: %d detecções desde %s (bbox=%s)",
            len(observations),
            since_date,
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
            bounds = geom.bounds
            bbox_wkt = self._make_bbox_polygon_wkt(*bounds)
        except Exception as exc:
            logger.warning("DETER: falha ao parsear geometria: %s", exc)
            return None

        area_km2 = float(props.get("area_km", 0) or 0)
        area_ha = area_km2 * 100.0

        feat_id = (
            props.get("gid")
            or feature.get("id")
            or f"{layer}_{props.get('view_date')}_{geometry_wkt[:32]}"
        )
        external_id = f"deter-{str(feat_id)}"

        view_date_str = str(props.get("view_date") or "")
        try:
            acquired_at = datetime.strptime(
                view_date_str[:10], "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)
        except Exception:
            acquired_at = datetime.now(tz=timezone.utc)

        payload = {
            "view_date": view_date_str,
            "classname": props.get("classname"),
            "quadrant": props.get("quadrant"),
            "path_row": props.get("path_row"),
            "uf": props.get("uf"),
            "county": props.get("county"),
            "area_km2": area_km2,
            "area_ha": area_ha,
            "sensor": props.get("sensor"),
            "satellite": props.get("satellite"),
            "biome": props.get("biome") or props.get("bioma"),
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
