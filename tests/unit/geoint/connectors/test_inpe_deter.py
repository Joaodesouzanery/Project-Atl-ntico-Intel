"""
Testes unitários para INPEDeterConnector.

DETER fornece alertas near-real-time de desmatamento e degradação.
Testa parsing de features WFS e criação de GeointObservation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.geoint.connectors.inpe_deter import INPEDeterConnector
from atlantico.geoint.observations import GeointObservation


@pytest.fixture
def connector():
    c = INPEDeterConnector.__new__(INPEDeterConnector)
    c._client = AsyncMock()
    return c


def _make_deter_feature(
    feat_id: str = "deter-01",
    view_date: str = "2024-08-15",
    area_km2: float = 3.5,
    state: str = "AM",
) -> dict:
    return {
        "type": "Feature",
        "id": feat_id,
        "geometry": {
            "type": "Polygon",
            "coordinates": [
                [
                    [-60.0, -2.0],
                    [-60.0, -2.05],
                    [-60.05, -2.05],
                    [-60.05, -2.0],
                    [-60.0, -2.0],
                ]
            ],
        },
        "properties": {
            "gid": feat_id,
            "view_date": view_date,
            "area_km": area_km2,
            "classname": "DESMATAMENTO_CR",
            "uf": state,
            "county": "Manaus",
            "biome": "Amazônia",
            "sensor": "OLI",
        },
    }


def _make_wfs_response(features: list[dict]) -> dict:
    return {"type": "FeatureCollection", "features": features}


class TestParseFeature:
    def test_observacao_valida(self, connector):
        feat = _make_deter_feature()
        obs = connector._parse_feature(feat, "deter-amz:deter_amz")
        assert obs is not None
        assert obs.source_id == "inpe.deter.v1"
        assert obs.observation_type == "deforestation"

    def test_external_id_prefixo_deter(self, connector):
        feat = _make_deter_feature(feat_id="deter-xyz")
        obs = connector._parse_feature(feat, "deter-amz:deter_amz")
        assert obs.external_id.startswith("deter-")

    def test_acquired_at_timezone_aware(self, connector):
        feat = _make_deter_feature(view_date="2024-08-15")
        obs = connector._parse_feature(feat, "deter-amz:deter_amz")
        assert obs.acquired_at.tzinfo is not None
        assert obs.acquired_at.year == 2024

    def test_area_convertida_para_ha(self, connector):
        feat = _make_deter_feature(area_km2=2.5)
        obs = connector._parse_feature(feat, "deter-amz:deter_amz")
        assert obs.payload["area_ha"] == pytest.approx(250.0)

    def test_geometry_wkt_polygon(self, connector):
        feat = _make_deter_feature()
        obs = connector._parse_feature(feat, "deter-amz:deter_amz")
        assert "POLYGON" in obs.geometry_wkt.upper()

    def test_sem_geometria_retorna_none(self, connector):
        feat = _make_deter_feature()
        feat["geometry"] = None
        obs = connector._parse_feature(feat, "deter-amz:deter_amz")
        assert obs is None

    def test_sem_properties_retorna_none(self, connector):
        feat = _make_deter_feature()
        feat["properties"] = None
        obs = connector._parse_feature(feat, "deter-amz:deter_amz")
        assert obs is None


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_duas_layers(self, connector):
        """DETER usa 2 layers (Amazônia + Cerrado) — fetch multiplica."""
        features = [_make_deter_feature("d1"), _make_deter_feature("d2")]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _make_wfs_response(features)
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch("atlantico.geoint.connectors.inpe_deter.get_settings") as ms:
            ms.return_value.inpe_terrabrasilis_wfs_url = "https://terrabrasilis.example/wfs"
            observations = await connector.fetch(since=since, bbox=bbox)

        # 2 layers × 2 features = 4
        assert len(observations) == 4
        assert all(o.source_id == "inpe.deter.v1" for o in observations)

    @pytest.mark.asyncio
    async def test_fetch_vazio(self, connector):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _make_wfs_response([])
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch("atlantico.geoint.connectors.inpe_deter.get_settings") as ms:
            ms.return_value.inpe_terrabrasilis_wfs_url = "https://terrabrasilis.example/wfs"
            observations = await connector.fetch(since=since, bbox=bbox)

        assert observations == []
