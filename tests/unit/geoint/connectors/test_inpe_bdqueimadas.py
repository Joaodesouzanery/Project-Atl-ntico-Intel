"""
Testes unitários para INPEBDQueimadasConnector.

Testa parsing de focos de calor, validação de coordenadas e
tratamento de erros HTTP (401, 500).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.geoint.connectors.base import ConnectorAuthError, ConnectorError
from atlantico.geoint.connectors.inpe_bdqueimadas import INPEBDQueimadasConnector
from atlantico.geoint.observations import GeointObservation


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def connector():
    c = INPEBDQueimadasConnector.__new__(INPEBDQueimadasConnector)
    c._client = AsyncMock()
    return c


def _make_hotspot_record(
    rec_id: str = "foco-001",
    lat: float = -3.5,
    lon: float = -52.0,
    datahora: str = "2024-08-15 14:30",
) -> dict:
    return {
        "id": rec_id,
        "latitude": lat,
        "longitude": lon,
        "datahora": datahora,
        "municipio": "Altamira",
        "estado": "Pará",
        "bioma": "Amazônia",
        "satelite": "AQUA",
        "frp": 45.7,
        "brightness": 320.5,
        "confidence": 85,
        "risco_fogo": 0.8,
        "numero_dias_sem_chuva": 12,
    }


def _make_mock_response(data, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = data
    return resp


def _mock_settings():
    s = MagicMock()
    s.inpe_bdqueimadas_url = "https://queimadas.example/api"
    s.inpe_api_key = "test-key-123"
    return s


# ─── Testes de _parse_record ──────────────────────────────────────────────────


class TestParseRecord:
    def test_retorna_observacao_valida(self, connector):
        rec = _make_hotspot_record()
        obs = connector._parse_record(rec)

        assert obs is not None
        assert isinstance(obs, GeointObservation)
        assert obs.source_id == "inpe.bdqueimadas.v1"
        assert obs.observation_type == "fire_hotspot"

    def test_external_id_com_id_da_api(self, connector):
        rec = _make_hotspot_record(rec_id="abc-123")
        obs = connector._parse_record(rec)
        assert obs.external_id == "bdqueimadas-abc-123"

    def test_external_id_sem_id_usa_timestamp_lat_lon(self, connector):
        rec = _make_hotspot_record(lat=-4.5, lon=-51.2, datahora="2024-08-15 14:30")
        del rec["id"]
        obs = connector._parse_record(rec)
        assert obs.external_id.startswith("bdqueimadas-")
        assert "-4.5000" in obs.external_id or "202408" in obs.external_id

    def test_geometria_eh_point(self, connector):
        rec = _make_hotspot_record(lat=-3.5, lon=-52.0)
        obs = connector._parse_record(rec)
        assert obs.geometry_wkt == "POINT(-52.0 -3.5)"

    def test_bbox_wkt_presente(self, connector):
        rec = _make_hotspot_record(lat=-3.5, lon=-52.0)
        obs = connector._parse_record(rec)
        assert obs.bbox_wkt is not None
        assert "POLYGON" in obs.bbox_wkt.upper()

    def test_acquired_at_timezone_aware(self, connector):
        rec = _make_hotspot_record(datahora="2024-08-15 14:30")
        obs = connector._parse_record(rec)
        assert obs.acquired_at.tzinfo is not None
        assert obs.acquired_at.year == 2024

    def test_acquired_at_formato_iso(self, connector):
        rec = _make_hotspot_record(datahora="2024-08-15T14:30:00")
        obs = connector._parse_record(rec)
        assert obs.acquired_at.year == 2024
        assert obs.acquired_at.month == 8

    def test_lat_lon_zeros_retorna_none(self, connector):
        rec = _make_hotspot_record(lat=0, lon=0)
        obs = connector._parse_record(rec)
        assert obs is None

    def test_payload_campos_presentes(self, connector):
        rec = _make_hotspot_record(lat=-3.5, lon=-52.0)
        obs = connector._parse_record(rec)
        assert obs.payload["latitude"] == pytest.approx(-3.5)
        assert obs.payload["longitude"] == pytest.approx(-52.0)
        assert obs.payload["frp"] == pytest.approx(45.7)
        assert obs.payload["bioma"] == "Amazônia"

    def test_classificacao_publica(self, connector):
        obs = connector._parse_record(_make_hotspot_record())
        assert obs.data_classification == "PUBLIC"

    def test_campos_alternativos_latitude_longitude(self, connector):
        rec = {"lat": -5.0, "lon": -60.0, "datahora": "2024-01-01 08:00", "id": "x"}
        obs = connector._parse_record(rec)
        assert obs is not None
        assert obs.geometry_wkt == "POINT(-60.0 -5.0)"


# ─── Testes de fetch() ────────────────────────────────────────────────────────


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_lista_direta(self, connector):
        records = [_make_hotspot_record("1"), _make_hotspot_record("2")]
        connector.client.get = AsyncMock(
            return_value=_make_mock_response(records)
        )

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch(
            "atlantico.geoint.connectors.inpe_bdqueimadas.get_settings",
            return_value=_mock_settings(),
        ):
            observations = await connector.fetch(since=since, bbox=bbox)

        assert len(observations) == 2
        assert all(o.observation_type == "fire_hotspot" for o in observations)

    @pytest.mark.asyncio
    async def test_fetch_dict_com_features(self, connector):
        records = [_make_hotspot_record("3"), _make_hotspot_record("4")]
        connector.client.get = AsyncMock(
            return_value=_make_mock_response({"features": records})
        )

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch(
            "atlantico.geoint.connectors.inpe_bdqueimadas.get_settings",
            return_value=_mock_settings(),
        ):
            observations = await connector.fetch(since=since, bbox=bbox)

        assert len(observations) == 2

    @pytest.mark.asyncio
    async def test_fetch_dict_com_focos(self, connector):
        records = [_make_hotspot_record("5")]
        connector.client.get = AsyncMock(
            return_value=_make_mock_response({"focos": records})
        )

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch(
            "atlantico.geoint.connectors.inpe_bdqueimadas.get_settings",
            return_value=_mock_settings(),
        ):
            observations = await connector.fetch(since=since, bbox=bbox)

        assert len(observations) == 1

    @pytest.mark.asyncio
    async def test_fetch_http_401_lanca_auth_error(self, connector):
        connector.client.get = AsyncMock(
            return_value=_make_mock_response({}, status_code=401)
        )

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch(
            "atlantico.geoint.connectors.inpe_bdqueimadas.get_settings",
            return_value=_mock_settings(),
        ):
            with pytest.raises(ConnectorAuthError):
                await connector.fetch(since=since, bbox=bbox)

    @pytest.mark.asyncio
    async def test_fetch_http_500_lanca_connector_error(self, connector):
        connector.client.get = AsyncMock(
            return_value=_make_mock_response({}, status_code=500)
        )

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch(
            "atlantico.geoint.connectors.inpe_bdqueimadas.get_settings",
            return_value=_mock_settings(),
        ):
            with pytest.raises(ConnectorError):
                await connector.fetch(since=since, bbox=bbox)

    @pytest.mark.asyncio
    async def test_fetch_sem_api_key_nao_adiciona_header(self, connector):
        """Sem INPE_API_KEY configurada, não envia Authorization header."""
        records = [_make_hotspot_record()]
        connector.client.get = AsyncMock(
            return_value=_make_mock_response(records)
        )

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        settings = _mock_settings()
        settings.inpe_api_key = None

        with patch(
            "atlantico.geoint.connectors.inpe_bdqueimadas.get_settings",
            return_value=settings,
        ):
            observations = await connector.fetch(since=since, bbox=bbox)

        assert len(observations) == 1
        # Verifica que get foi chamado sem header Authorization
        call_kwargs = connector.client.get.call_args[1]
        assert "Authorization" not in call_kwargs.get("headers", {})

    @pytest.mark.asyncio
    async def test_fetch_excecao_rede_lanca_connector_error(self, connector):
        connector.client.get = AsyncMock(side_effect=Exception("Connection refused"))

        since = datetime(2024, 8, 1, tzinfo=timezone.utc)
        bbox = (-73.98, -33.75, -28.85, 5.27)

        with patch(
            "atlantico.geoint.connectors.inpe_bdqueimadas.get_settings",
            return_value=_mock_settings(),
        ):
            with pytest.raises(ConnectorError):
                await connector.fetch(since=since, bbox=bbox)
