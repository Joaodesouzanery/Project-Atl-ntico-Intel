"""
Testes unitários para BCBSgsConnector.

Testa parsing de registros JSON SGS, série vazia, datas timezone-aware.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.finint.connectors.bcb_sgs import BCBSgsConnector
from atlantico.finint.observations import FinintObservation


@pytest.fixture
def connector():
    c = BCBSgsConnector.__new__(BCBSgsConnector)
    c._client = AsyncMock()
    return c


def _make_sgs_record(date_str: str = "15/01/2024", value: str = "10.75") -> dict:
    return {"data": date_str, "valor": value}


class TestParseRecord:
    def test_observacao_valida(self, connector):
        record = _make_sgs_record()
        obs = connector._parse_record(record, 1, "Taxa Selic", "% a.a.")
        assert obs is not None
        assert isinstance(obs, FinintObservation)

    def test_source_id_correto(self, connector):
        record = _make_sgs_record()
        obs = connector._parse_record(record, 1, "Taxa Selic", "% a.a.")
        assert obs is not None
        assert obs.source_id == "bcb.sgs.v1"

    def test_observation_type_market_indicator(self, connector):
        record = _make_sgs_record()
        obs = connector._parse_record(record, 1, "Taxa Selic", "% a.a.")
        assert obs is not None
        assert obs.observation_type == "market_indicator"

    def test_reference_date_timezone_aware(self, connector):
        record = _make_sgs_record(date_str="15/01/2024")
        obs = connector._parse_record(record, 1, "Taxa Selic", "% a.a.")
        assert obs is not None
        assert obs.reference_date.tzinfo is not None
        assert obs.reference_date.year == 2024
        assert obs.reference_date.month == 1
        assert obs.reference_date.day == 15

    def test_value_no_payload(self, connector):
        record = _make_sgs_record(value="5.25")
        obs = connector._parse_record(record, 12, "IPCA", "% a.m.")
        assert obs is not None
        assert obs.payload["value"] == pytest.approx(5.25)

    def test_series_code_no_payload(self, connector):
        record = _make_sgs_record()
        obs = connector._parse_record(record, 13522, "Exportações Ouro", "US$ milhões")
        assert obs is not None
        assert obs.payload["series_code"] == 13522
        assert obs.payload["series_name"] == "Exportações Ouro"

    def test_valor_com_virgula_decimal(self, connector):
        record = {"data": "01/03/2024", "valor": "12,50"}
        obs = connector._parse_record(record, 1, "Selic", "% a.a.")
        assert obs is not None
        assert obs.payload["value"] == pytest.approx(12.50)

    def test_external_id_inclui_codigo_e_data(self, connector):
        record = _make_sgs_record(date_str="20/06/2024")
        obs = connector._parse_record(record, 1, "Selic", "% a.a.")
        assert obs is not None
        assert "bcb-sgs-1" in obs.external_id
        assert "20062024" in obs.external_id

    def test_data_vazia_retorna_none(self, connector):
        record = {"data": "", "valor": "5.0"}
        obs = connector._parse_record(record, 1, "Selic", "% a.a.")
        assert obs is None

    def test_valor_vazio_retorna_none(self, connector):
        record = {"data": "01/01/2024", "valor": ""}
        obs = connector._parse_record(record, 1, "Selic", "% a.a.")
        assert obs is None

    def test_valor_none_retorna_none(self, connector):
        record = {"data": "01/01/2024", "valor": None}
        obs = connector._parse_record(record, 1, "Selic", "% a.a.")
        assert obs is None

    def test_data_invalida_retorna_none(self, connector):
        record = {"data": "não-é-data", "valor": "5.0"}
        obs = connector._parse_record(record, 1, "Selic", "% a.a.")
        assert obs is None

    def test_classificacao_publica(self, connector):
        record = _make_sgs_record()
        obs = connector._parse_record(record, 1, "Selic", "% a.a.")
        assert obs is not None
        assert obs.data_classification == "PUBLIC"


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_retorna_observacoes(self, connector):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = [
            {"data": "15/01/2024", "valor": "10.75"},
            {"data": "16/01/2024", "valor": "10.80"},
        ]
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with patch("atlantico.finint.connectors.bcb_sgs.get_settings") as ms:
            ms.return_value.bcb_sgs_url = "https://api.bcb.gov.br/dados/serie/dados/serie"
            observations = await connector.fetch(since=since)

        # 6 séries × 2 registros cada = 12 observações
        assert len(observations) == 12
        for obs in observations:
            assert obs.source_id == "bcb.sgs.v1"

    @pytest.mark.asyncio
    async def test_fetch_serie_vazia_nao_gera_observacoes(self, connector):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = []
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with patch("atlantico.finint.connectors.bcb_sgs.get_settings") as ms:
            ms.return_value.bcb_sgs_url = "https://api.bcb.gov.br/dados/serie/dados/serie"
            observations = await connector.fetch(since=since)

        assert observations == []
