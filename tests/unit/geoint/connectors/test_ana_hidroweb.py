"""
Testes unitários para ANAHidroWebConnector.

ANA HidroWeb fornece leituras de estações fluviométricas (nível, vazão, chuva).
Testa parsing de leituras de telemetria e criação de GeointObservation.

Nota: _parse_reading(reading, station_code, station_name, lat, lon)
      infere measurement_type a partir dos campos cota/vazao/chuva no dict.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.geoint.connectors.ana_hidroweb import ANAHidroWebConnector
from atlantico.geoint.observations import GeointObservation


@pytest.fixture
def connector():
    c = ANAHidroWebConnector.__new__(ANAHidroWebConnector)
    c._client = AsyncMock()
    return c


def _make_reading_nivel(
    cota: float = 350.0,
    data_str: str = "2024-08-15T06:00:00",
) -> dict:
    return {
        "data": data_str,
        "cota": cota,
        "vazao": None,
        "chuva": None,
        "nivelConsistencia": 1,
    }


def _make_reading_vazao(
    vazao: float = 1200.0,
    data_str: str = "2024-08-15T06:00:00",
) -> dict:
    return {
        "data": data_str,
        "cota": None,
        "vazao": vazao,
        "chuva": None,
        "nivelConsistencia": 2,
    }


def _make_reading_chuva(
    chuva: float = 15.0,
    data_str: str = "2024-08-15T06:00:00",
) -> dict:
    return {
        "data": data_str,
        "cota": None,
        "vazao": None,
        "chuva": chuva,
        "nivelConsistencia": 1,
    }


# ─── Testes de _parse_reading ─────────────────────────────────────────────────


class TestParseReading:
    def test_nivel_retorna_observacao_valida(self, connector):
        reading = _make_reading_nivel(cota=350.0)
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs is not None
        assert obs.source_id == "ana.hidroweb.v1"
        assert obs.observation_type == "water_gauge"
        assert obs.payload["measurement_type"] == "nivel"
        assert obs.payload["value"] == pytest.approx(350.0)

    def test_vazao_retorna_observacao_valida(self, connector):
        reading = _make_reading_vazao(vazao=2500.0)
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs is not None
        assert obs.payload["measurement_type"] == "vazao"
        assert obs.payload["value"] == pytest.approx(2500.0)

    def test_chuva_retorna_observacao_valida(self, connector):
        reading = _make_reading_chuva(chuva=15.5)
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs is not None
        assert obs.payload["measurement_type"] == "chuva"
        assert obs.payload["value"] == pytest.approx(15.5)

    def test_sem_valor_retorna_none(self, connector):
        reading = {
            "data": "2024-08-15T06:00:00",
            "cota": None,
            "vazao": None,
            "chuva": None,
        }
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs is None

    def test_sem_data_retorna_none(self, connector):
        reading = {"cota": 350.0}  # sem campo de data
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs is None

    def test_external_id_determinístico(self, connector):
        reading = _make_reading_nivel(data_str="2024-08-15T06:00:00")
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs.external_id.startswith("hidroweb-65290000-nivel-")

    def test_geometria_eh_point_com_lon_lat(self, connector):
        reading = _make_reading_nivel()
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs.geometry_wkt == "POINT(-54.591 -25.5574)"

    def test_bbox_wkt_presente(self, connector):
        reading = _make_reading_nivel()
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs.bbox_wkt is not None
        assert "POLYGON" in obs.bbox_wkt.upper()

    def test_acquired_at_timezone_aware(self, connector):
        reading = _make_reading_nivel(data_str="2024-08-15T06:00:00")
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs.acquired_at.tzinfo is not None
        assert obs.acquired_at.year == 2024

    def test_classificacao_publica(self, connector):
        reading = _make_reading_nivel()
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs.data_classification == "PUBLIC"

    def test_campo_alternativo_nivel(self, connector):
        """Suporte ao campo 'nivel' além de 'cota'."""
        reading = {
            "data": "2024-08-15T06:00:00",
            "nivel": 420.5,
        }
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs is not None
        assert obs.payload["measurement_type"] == "nivel"

    def test_prioridade_nivel_sobre_vazao(self, connector):
        """Quando ambos presentes, nivel tem prioridade."""
        reading = {
            "data": "2024-08-15T06:00:00",
            "cota": 350.0,
            "vazao": 1200.0,
        }
        obs = connector._parse_reading(
            reading=reading,
            station_code="65290000",
            station_name="Foz do Iguaçu",
            lat=-25.5574,
            lon=-54.5910,
        )
        assert obs.payload["measurement_type"] == "nivel"


class TestSourceIdConstant:
    def test_source_id_correto(self):
        assert ANAHidroWebConnector.SOURCE_ID == "ana.hidroweb.v1"

    def test_classificacao_padrao_publica(self):
        assert ANAHidroWebConnector.DEFAULT_CLASSIFICATION == "PUBLIC"
