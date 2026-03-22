"""
Conector ESA Sentinel-2 — Copernicus Data Space OData/STAC.

Busca metadados de produtos Sentinel-2 (L2A processados) disponíveis
para a área de interesse. Não baixa imagens — apenas registra metadados
para análise NDVI posterior.

API: Copernicus Data Space OData v1 + OAuth2 client credentials.
Autenticação: ATLANTICO_ESA_CLIENT_ID + ATLANTICO_ESA_CLIENT_SECRET
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from shapely.geometry import shape
from shapely.wkt import loads as wkt_loads

from atlantico.config.settings import get_settings
from atlantico.geoint.connectors.base import (
    ConnectorAuthError,
    ConnectorError,
    ConnectorParseError,
    GeointConnector,
    retry_with_backoff,
)
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)


class ESASentinel2Connector(GeointConnector):
    """Conector ESA Copernicus Sentinel-2 (metadados de produtos L2A)."""

    SOURCE_ID = "esa.sentinel2.v1"
    DEFAULT_CLASSIFICATION = "PUBLIC"

    def __init__(self) -> None:
        super().__init__()
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None

    async def _get_access_token(self) -> str:
        """Obtém ou renova token OAuth2 via client credentials."""
        import time

        settings = get_settings()

        # Verifica se token ainda é válido (com margem de 60s)
        if (
            self._access_token is not None
            and self._token_expires_at is not None
            and datetime.now(tz=timezone.utc).timestamp() < self._token_expires_at.timestamp() - 60
        ):
            return self._access_token

        if not settings.esa_client_id or not settings.esa_client_secret:
            raise ConnectorAuthError(
                "ESA Sentinel-2: ATLANTICO_ESA_CLIENT_ID e ATLANTICO_ESA_CLIENT_SECRET "
                "são obrigatórios. Configure as credenciais do Copernicus Data Space."
            )

        try:
            resp = await self.client.post(
                settings.copernicus_token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": settings.esa_client_id,
                    "client_secret": settings.esa_client_secret,
                },
            )
        except Exception as exc:
            raise ConnectorError(
                f"ESA Sentinel-2: falha ao obter token OAuth2: {exc}"
            ) from exc

        if resp.status_code == 401:
            raise ConnectorAuthError(
                "ESA Sentinel-2: credenciais inválidas (401). "
                "Verifique ATLANTICO_ESA_CLIENT_ID e ATLANTICO_ESA_CLIENT_SECRET."
            )
        if resp.status_code != 200:
            raise ConnectorError(
                f"ESA Sentinel-2: erro ao obter token HTTP {resp.status_code}"
            )

        token_data = resp.json()
        self._access_token = token_data["access_token"]
        expires_in = int(token_data.get("expires_in", 600))
        self._token_expires_at = datetime.fromtimestamp(
            datetime.now(tz=timezone.utc).timestamp() + expires_in,
            tz=timezone.utc,
        )
        return self._access_token

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        bbox: tuple[float, float, float, float],
    ) -> list[GeointObservation]:
        """
        Busca metadados Sentinel-2 L2A disponíveis desde `since` para `bbox`.

        Retorna SatelliteImagery observations (sem baixar pixels).
        """
        settings = get_settings()
        min_lon, min_lat, max_lon, max_lat = bbox

        token = await self._get_access_token()

        # OData filter: produto Sentinel-2 L2A, após since, intersecta bbox
        bbox_poly = (
            f"POLYGON(({min_lon} {min_lat},{max_lon} {min_lat},"
            f"{max_lon} {max_lat},{min_lon} {max_lat},{min_lon} {min_lat}))"
        )
        odata_filter = (
            f"Collection/Name eq 'SENTINEL-2' "
            f"and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' "
            f"and att/OData.CSC.StringAttribute/Value eq 'S2MSI2A') "
            f"and ContentDate/Start ge {since.strftime('%Y-%m-%dT%H:%M:%S.000Z')} "
            f"and OData.CSC.Intersects(area=geography'SRID=4326;{bbox_poly}')"
        )

        params: dict[str, Any] = {
            "$filter": odata_filter,
            "$orderby": "ContentDate/Start desc",
            "$top": 100,
            "$expand": "Attributes",
        }

        try:
            resp = await self.client.get(
                f"{settings.copernicus_catalog_url}/Products",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
        except ConnectorAuthError:
            raise
        except Exception as exc:
            raise ConnectorError(
                f"ESA Sentinel-2 OData falhou: {exc}"
            ) from exc

        try:
            data = resp.json()
            products = data.get("value", [])
        except Exception as exc:
            raise ConnectorParseError(
                f"ESA Sentinel-2: JSON inválido: {exc}"
            ) from exc

        observations = []
        for product in products:
            obs = self._parse_product(product)
            if obs is not None:
                observations.append(obs)

        logger.info(
            "ESA Sentinel-2: %d produtos desde %s (bbox=%s)",
            len(observations),
            since.isoformat(),
            bbox,
        )
        return observations

    def _parse_product(self, product: dict) -> GeointObservation | None:
        product_id = product.get("Id")
        product_name = product.get("Name", "")

        if not product_id:
            return None

        # Data de aquisição
        content_date = product.get("ContentDate", {})
        start_str = content_date.get("Start", "")
        try:
            acquired_at = datetime.fromisoformat(
                start_str.replace("Z", "+00:00")
            )
        except Exception:
            acquired_at = datetime.now(tz=timezone.utc)

        # Footprint (geometria do produto)
        footprint_str = product.get("Footprint") or product.get("GeoFootprint", {})
        try:
            if isinstance(footprint_str, str):
                geom = wkt_loads(footprint_str)
            elif isinstance(footprint_str, dict):
                geom = shape(footprint_str)
            else:
                return None
            geometry_wkt = geom.wkt
            bounds = geom.bounds
            bbox_wkt = self._make_bbox_polygon_wkt(*bounds)
        except Exception as exc:
            logger.warning("ESA Sentinel-2: falha ao parsear footprint: %s", exc)
            return None

        # Extrai atributos
        attrs = product.get("Attributes", [])
        attr_map = {}
        if isinstance(attrs, list):
            for a in attrs:
                attr_map[a.get("Name", "")] = a.get("Value")

        cloud_cover = attr_map.get("cloudCover") or product.get("CloudCover")
        tile_id = attr_map.get("tileId") or attr_map.get("tileid")
        relative_orbit = attr_map.get("relativeOrbitNumber")
        product_type = attr_map.get("productType", "S2MSI2A")

        # Detecta satélite pelo nome do produto
        if "S2A_" in product_name:
            satellite = "Sentinel-2A"
        elif "S2B_" in product_name:
            satellite = "Sentinel-2B"
        else:
            satellite = "Sentinel-2"

        payload = {
            "product_id": product_id,
            "product_name": product_name,
            "satellite": satellite,
            "product_type": product_type,
            "tile_id": tile_id,
            "relative_orbit": relative_orbit,
            "cloud_cover_pct": float(cloud_cover or 0),
            "size_bytes": product.get("ContentLength"),
            "online": product.get("Online", True),
            "content_date_start": start_str,
        }

        return GeointObservation(
            source_id=self.SOURCE_ID,
            external_id=f"sentinel2-{product_id}",
            observation_type="satellite_imagery",
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
                settings.copernicus_catalog_url,
                timeout=10.0,
            )
            return resp.status_code in (200, 404)
        except Exception:
            return False
