"""
Testes unitários para INPEProdesConnector.

Estratégia: mock do httpx.AsyncClient para simular respostas WFS.
Testa parsing de features GeoJSON e construção de GeointObservation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.geoint.connectors.inpe_prodes import INPEProdesConnector
from atlantico.geoint.observations import GeointObservation


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def connector():
    """Instância do conector sem cliente HTTP (para testes de parsing)."""
    c = INPEProdesConnector.__new__(INPEProdesConnector)
    c._client = AsyncMock()
    return c


def _make_wfs_feature(
    feat_id: str = "123",
    year: int = 2023,
    area_km: float = 5.0,
    biome: str = "Amazônia",
    state: str = "PA",
) -> dict:
    return {
        "type": "Feature",
        "id": feat_id,
        "geometry": {
            "type": "Polygon",
            "coordinates": [
                [
                    [-54.0, -3.0],
                    [-54.0, -3.1],
                    [-54.1, -3.1],
                    [-54.1, -3.0],
                    [-54.0, -3.0],
                ]
            ],
        },
        "properties": {
            "gid": feat_id,
            "year": year,
            "area_km": area_km,
            "biome": biome,
            "uf": state,
            "county": "Altamira",
            "classname": "DESMATAMENTO_CR",
            "sensor": "OLI",
            "view_date": f"{year}-07-15",
        },
    }


def _make_wfs_response(features: list[dict]) -> dict:
    return {"type": "FeatureCollection", "features": features}


# ─── Testes de _parse_feature ─────────────────────────────────────────────────


class TestParseFeature:
    def test_retorna_observacao_valida(self, connector):
        feat = _make_wfs_feature()
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")

        assert obs is not None
        assert isinstance(obs, GeointObservation)
        assert obs.source_id == "inpe.prodes.v2"
        assert obs.observation_type == "deforestation"
        assert obs.external_id.startswith("prodes-")

    def test_external_id_determinístico(self, connector):
        feat = _make_wfs_feature(feat_id="456")
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")

        assert obs.external_id == "prodes-456"

    def test_area_em_hectares(self, connector):
        feat = _make_wfs_feature(area_km=10.0)  # 10 km² = 1000 ha
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")

        assert obs.payload["area_ha"] == pytest.approx(1000.0)
        assert obs.payload["area_km2"] == pytest.approx(10.0)

    def test_acquired_at_timezone_aware(self, connector):
        feat = _make_wfs_feature(year=2022)
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")

        assert obs.acquired_at.tzinfo is not None
        assert obs.acquired_at.year == 2022

    def test_geometry_wkt_valida(self, connector):
        feat = _make_wfs_feature()
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")

        assert "POLYGON" in obs.geometry_wkt.upper()

    def test_bbox_wkt_presente(self, connector):
        feat = _make_wfs_feature()
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")

        assert obs.bbox_wkt is not None
        assert "POLYGON" in obs.bbox_wkt.upper()

    def test_payload_campos_obrigatorios(self, connector):
        feat = _make_wfs_feature(year=2023, biome="Cerrado", state="MT")
        obs = connector._parse_feature(feat, "prodes-cerrado-nb:yearly_deforestation")

        assert obs.payload["year"] == 2023
        assert obs.payload["biome"] == "Cerrado"
        assert obs.payload["state"] == "MT"
        assert obs.payload["layer"] == "prodes-cerrado-nb:yearly_deforestation"

    def test_feature_sem_geometria_retorna_none(self, connector):
        feat = {
            "type": "Feature",
            "id": "x",
            "geometry": None,
            "properties": {"year": 2023},
        }
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")
        assert obs is None

    def test_feature_sem_properties_retorna_none(self, connector):
        feat = {
            "type": "Feature",
            "id": "x",
            "geometry": {
                "type": "Polygon",
                "coordinates": [
                    [[-54.0, -3.0], [-54.0, -3.1], [-54.1, -3.1], [-54.0, -3.0]]
                ],
            },
            "properties": None,
        }
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")
        assert obs is None

    def test_classificacao_publica(self, connector):
        feat = _make_wfs_feature()
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")
        assert obs.data_classification == "PUBLIC"

    def test_view_date_sem_dia_usa_primeiro_dia_do_ano(self, connector):
        """Se view_date não está disponível, usa {year}-01-01."""
        feat = _make_wfs_feature(year=2021)
        # Remove view_date das properties
        feat["properties"].pop("view_date", None)
        feat["properties"]["year"] = 2021

        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")
        assert obs is not None
        assert obs.acquired_at.year == 2021

    def test_geometria_invalida_retorna_none(self, connector):
        feat = {
            "type": "Feature",
            "id": "y",
            "geometry": {"type": "InvalidType", "coordinates": []},
            "properties": {"year": 2023},
        }
        obs = connector._parse_feature(feat, "prodes-amz-nb:yearly_deforestation_biome")
        assert obs is None


# ─── Testes de fetch() ────────────────────────────────────────────────────────


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_retorna_observacoes(self, connector):
        features = [_make_wfs_feature("1"), _make_wfs_feature("2")]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _make_wfs_response(features)
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2023, 1, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch("atlantico.geoint.connectors.inpe_prodes.get_settings") as mock_settings:
            mock_settings.return_value.inpe_terrabrasilis_wfs_url = (
                "https://terrabrasilis.example/wfs"
            )
            observations = await connector.fetch(since=since, bbox=bbox)

        # Dois layers × 2 features = 4 observações
        assert len(observations) == 4
        for obs in observations:
            assert obs.source_id == "inpe.prodes.v2"
            assert obs.observation_type == "deforestation"

    @pytest.mark.asyncio
    async def test_fetch_feature_collection_vazia(self, connector):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"type": "FeatureCollection", "features": []}
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2023, 1, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch("atlantico.geoint.connectors.inpe_prodes.get_settings") as mock_settings:
            mock_settings.return_value.inpe_terrabrasilis_wfs_url = (
                "https://terrabrasilis.example/wfs"
            )
            observations = await connector.fetch(since=since, bbox=bbox)

        assert observations == []

    @pytest.mark.asyncio
    async def test_fetch_http_error_lanca_connector_error(self, connector):
        from atlantico.geoint.connectors.base import ConnectorError

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 503")
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2023, 1, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch("atlantico.geoint.connectors.inpe_prodes.get_settings") as mock_settings:
            mock_settings.return_value.inpe_terrabrasilis_wfs_url = (
                "https://terrabrasilis.example/wfs"
            )
            with pytest.raises(ConnectorError):
                await connector.fetch(since=since, bbox=bbox)

    @pytest.mark.asyncio
    async def test_fetch_source_id_correto(self, connector):
        features = [_make_wfs_feature("99")]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _make_wfs_response(features)
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch("atlantico.geoint.connectors.inpe_prodes.get_settings") as mock_settings:
            mock_settings.return_value.inpe_terrabrasilis_wfs_url = (
                "https://terrabrasilis.example/wfs"
            )
            observations = await connector.fetch(since=since, bbox=bbox)

        assert all(o.source_id == "inpe.prodes.v2" for o in observations)
