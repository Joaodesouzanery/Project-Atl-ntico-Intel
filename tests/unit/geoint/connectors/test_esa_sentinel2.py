"""
Testes unitários para ESASentinel2Connector.

Testa autenticação OAuth2 e parsing de produtos Sentinel-2 via OData.

Nota: _parse_product processa Footprint como WKT via shapely.wkt.loads()
      ou como GeoJSON dict. Usar WKT simples sem SRID prefix.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.geoint.connectors.esa_sentinel2 import ESASentinel2Connector
from atlantico.geoint.observations import GeointObservation


@pytest.fixture
def connector():
    c = ESASentinel2Connector.__new__(ESASentinel2Connector)
    c._client = AsyncMock()
    # Atributos de autenticação — correspondem ao __init__ do conector
    c._access_token = None
    c._token_expires_at = None
    return c


def _make_s2_product(
    product_id: str = "S2A_MSIL2A_20240815T133841_N0510_R053_T21MXU_20240815T201239",
    cloud_cover: float = 5.2,
    footprint: str | None = None,
) -> dict:
    """Cria produto Sentinel-2 com footprint WKT válido para shapely."""
    if footprint is None:
        # WKT simples sem SRID — shapely.wkt.loads() aceita este formato
        footprint = "POLYGON((-54.0 -3.0,-54.0 -3.5,-54.5 -3.5,-54.5 -3.0,-54.0 -3.0))"

    return {
        "Id": product_id,
        "Name": f"{product_id}.SAFE",
        "ContentDate": {"Start": "2024-08-15T13:38:41.000Z"},
        "ContentLength": 1024 * 1024 * 800,  # 800 MB
        "Attributes": [
            {"Name": "cloudCover", "Value": cloud_cover},
            {"Name": "tileId", "Value": "21MXU"},
            {"Name": "processorVersion", "Value": "05.09"},
            {"Name": "productType", "Value": "S2MSI2A"},
        ],
        "Footprint": footprint,
    }


def _make_mock_response(data, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def _mock_settings():
    s = MagicMock()
    s.copernicus_catalog_url = "https://catalogue.dataspace.copernicus.eu/odata/v1"
    s.copernicus_stac_url = "https://catalogue.dataspace.copernicus.eu/stac"
    s.copernicus_token_url = (
        "https://identity.dataspace.copernicus.eu/auth/realms/CDSE"
        "/protocol/openid-connect/token"
    )
    s.esa_client_id = "cdse-public"
    s.esa_client_secret = "test-secret"
    return s


# ─── Testes de _parse_product ─────────────────────────────────────────────────


class TestParseProduct:
    def test_observacao_valida(self, connector):
        prod = _make_s2_product()
        obs = connector._parse_product(prod)
        assert obs is not None
        assert obs.source_id == "esa.sentinel2.v1"
        assert obs.observation_type == "satellite_imagery"

    def test_external_id_usa_product_id(self, connector):
        pid = "S2A_MSIL2A_TEST_UNIQUE_ID"
        prod = _make_s2_product(product_id=pid)
        obs = connector._parse_product(prod)
        assert obs is not None
        assert pid in obs.external_id

    def test_acquired_at_timezone_aware(self, connector):
        prod = _make_s2_product()
        obs = connector._parse_product(prod)
        assert obs is not None
        assert obs.acquired_at.tzinfo is not None
        assert obs.acquired_at.year == 2024

    def test_footprint_wkt_parseado(self, connector):
        prod = _make_s2_product()
        obs = connector._parse_product(prod)
        assert obs is not None
        assert obs.geometry_wkt is not None
        assert "POLYGON" in obs.geometry_wkt.upper()

    def test_footprint_geojson_parseado(self, connector):
        """Footprint como GeoJSON dict também deve funcionar."""
        prod = _make_s2_product()
        prod["Footprint"] = {
            "type": "Polygon",
            "coordinates": [
                [
                    [-54.0, -3.0],
                    [-54.0, -3.5],
                    [-54.5, -3.5],
                    [-54.5, -3.0],
                    [-54.0, -3.0],
                ]
            ],
        }
        obs = connector._parse_product(prod)
        assert obs is not None
        assert "POLYGON" in obs.geometry_wkt.upper()

    def test_payload_cloud_cover(self, connector):
        prod = _make_s2_product(cloud_cover=12.5)
        obs = connector._parse_product(prod)
        assert obs is not None
        assert obs.payload.get("cloud_cover_pct") == pytest.approx(12.5)

    def test_produto_sem_id_retorna_none(self, connector):
        prod = _make_s2_product()
        del prod["Id"]
        obs = connector._parse_product(prod)
        assert obs is None

    def test_footprint_invalido_retorna_none(self, connector):
        prod = _make_s2_product()
        prod["Footprint"] = "NOT_VALID_WKT_!@#$"
        obs = connector._parse_product(prod)
        assert obs is None

    def test_classificacao_publica(self, connector):
        prod = _make_s2_product()
        obs = connector._parse_product(prod)
        assert obs is not None
        assert obs.data_classification == "PUBLIC"

    def test_sentinel2a_detectado_no_nome(self, connector):
        prod = _make_s2_product(product_id="S2A_MSIL2A_20240815T133841")
        obs = connector._parse_product(prod)
        assert obs is not None
        assert obs.payload.get("satellite") == "Sentinel-2A"

    def test_bbox_wkt_presente(self, connector):
        prod = _make_s2_product()
        obs = connector._parse_product(prod)
        assert obs is not None
        assert obs.bbox_wkt is not None
        assert "POLYGON" in obs.bbox_wkt.upper()


# ─── Testes de _get_access_token ──────────────────────────────────────────────


class TestAuthentication:
    @pytest.mark.asyncio
    async def test_get_token_faz_post_para_endpoint(self, connector):
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {
            "access_token": "test-token-abc",
            "expires_in": 3600,
        }
        connector.client.post = AsyncMock(return_value=token_resp)

        with patch(
            "atlantico.geoint.connectors.esa_sentinel2.get_settings",
            return_value=_mock_settings(),
        ):
            token = await connector._get_access_token()

        assert token == "test-token-abc"
        assert connector._access_token == "test-token-abc"

    @pytest.mark.asyncio
    async def test_token_cacheado_nao_refaz_request(self, connector):
        """Token válido em cache → segunda chamada não faz novo HTTP request."""
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {
            "access_token": "cached-token-xyz",
            "expires_in": 3600,
        }
        connector.client.post = AsyncMock(return_value=token_resp)

        with patch(
            "atlantico.geoint.connectors.esa_sentinel2.get_settings",
            return_value=_mock_settings(),
        ):
            token1 = await connector._get_access_token()
            token2 = await connector._get_access_token()

        assert token1 == token2
        # Apenas 1 POST deve ter sido feito
        assert connector.client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_sem_credenciais_lanca_auth_error(self, connector):
        from atlantico.geoint.connectors.base import ConnectorAuthError

        settings = _mock_settings()
        settings.esa_client_id = None
        settings.esa_client_secret = None

        with patch(
            "atlantico.geoint.connectors.esa_sentinel2.get_settings",
            return_value=settings,
        ):
            with pytest.raises(ConnectorAuthError):
                await connector._get_access_token()
