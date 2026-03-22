"""
Testes unitários para SiscomexComexStatConnector.

Testa parsing de exportações ComexStat, código NCM, valor USD.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.finint.connectors.siscomex_comex_stat import SiscomexComexStatConnector
from atlantico.finint.observations import FinintObservation


@pytest.fixture
def connector():
    c = SiscomexComexStatConnector.__new__(SiscomexComexStatConnector)
    c._client = AsyncMock()
    return c


def _make_trade_item(
    ncm: str = "7108",
    state: str = "PA",
    year: int = 2024,
    month: int = 6,
    value_usd: float = 5000000.0,
    weight_kg: float = 100.0,
) -> dict:
    return {
        "coNcm": ncm,
        "sgUf": state,
        "coAno": year,
        "coMes": month,
        "vlFob": value_usd,
        "kgLiquido": weight_kg,
        "coPais": "249",  # USA
        "noNcmPor": "Ouro (incluindo o ouro platinado)",
    }


class TestParseTradeItem:
    def test_observacao_valida(self, connector):
        item = _make_trade_item()
        obs = connector._parse_trade_item(item, "71")
        assert obs is not None
        assert isinstance(obs, FinintObservation)

    def test_source_id_correto(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(), "71")
        assert obs is not None
        assert obs.source_id == "mdic.comexstat.v1"

    def test_observation_type_trade_flow(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(), "71")
        assert obs is not None
        assert obs.observation_type == "trade_flow"

    def test_reference_date_timezone_aware(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(year=2024, month=6), "71")
        assert obs is not None
        assert obs.reference_date.tzinfo is not None
        assert obs.reference_date.year == 2024
        assert obs.reference_date.month == 6

    def test_ncm_code_no_payload(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(ncm="7108"), "71")
        assert obs is not None
        assert obs.payload["ncm_code"] == "7108"

    def test_export_value_usd_no_payload(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(value_usd=5_000_000.0), "71")
        assert obs is not None
        assert obs.payload["export_value_usd"] == pytest.approx(5_000_000.0)

    def test_net_weight_kg_no_payload(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(weight_kg=1500.0), "71")
        assert obs is not None
        assert obs.payload["net_weight_kg"] == pytest.approx(1500.0)

    def test_state_code_extraido(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(state="AM"), "71")
        assert obs is not None
        assert obs.state_code == "AM"

    def test_sh2_code_no_payload(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(), "71")
        assert obs is not None
        assert obs.payload["sh2_code"] == "71"

    def test_sem_ano_retorna_none(self, connector):
        item = _make_trade_item()
        del item["coAno"]
        obs = connector._parse_trade_item(item, "71")
        assert obs is None

    def test_sem_mes_retorna_none(self, connector):
        item = _make_trade_item()
        del item["coMes"]
        obs = connector._parse_trade_item(item, "71")
        assert obs is None

    def test_classificacao_publica(self, connector):
        obs = connector._parse_trade_item(_make_trade_item(), "71")
        assert obs is not None
        assert obs.data_classification == "PUBLIC"


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_retorna_observacoes(self, connector):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "data": [_make_trade_item("7108"), _make_trade_item("2616")]
        }
        connector.client.post = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with patch("atlantico.finint.connectors.siscomex_comex_stat.get_settings") as ms:
            ms.return_value.finint_strategic_ncm_list = ["7108", "2616", "8001"]
            observations = await connector.fetch(since=since)

        # 3 SH2 únicos (71, 26, 80) × 2 itens por response = 6
        assert len(observations) >= 2

    @pytest.mark.asyncio
    async def test_fetch_lista_vazia_retorna_lista_vazia(self, connector):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": []}
        connector.client.post = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with patch("atlantico.finint.connectors.siscomex_comex_stat.get_settings") as ms:
            ms.return_value.finint_strategic_ncm_list = ["7108"]
            observations = await connector.fetch(since=since)

        assert observations == []
