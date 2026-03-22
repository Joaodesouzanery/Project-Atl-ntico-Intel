"""
Testes unitários para IBGESidraConnector.

Testa parsing SIDRA, código município, valor agregado.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.finint.connectors.ibge_sidra import IBGESidraConnector
from atlantico.finint.observations import FinintObservation


@pytest.fixture
def connector():
    c = IBGESidraConnector.__new__(IBGESidraConnector)
    c._client = AsyncMock()
    return c


def _make_sidra_response(
    loc_id: str = "1504208",  # Altamira PA
    loc_nome: str = "Altamira",
    value: str = "28000.50",
    year: int = 2022,
) -> list:
    """Simula resposta da API SIDRA com 1 localidade."""
    return [
        {
            "resultados": [
                {
                    "series": [
                        {
                            "localidade": {"id": loc_id, "nome": loc_nome},
                            "serie": {str(year): value},
                        }
                    ]
                }
            ]
        }
    ]


class TestParseSidraResponse:
    def test_observacao_valida(self, connector):
        data = _make_sidra_response()
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert len(obs_list) == 1
        assert isinstance(obs_list[0], FinintObservation)

    def test_source_id_correto(self, connector):
        data = _make_sidra_response()
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert obs_list[0].source_id == "ibge.sidra.v1"

    def test_observation_type_market_indicator(self, connector):
        data = _make_sidra_response()
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert obs_list[0].observation_type == "market_indicator"

    def test_reference_date_timezone_aware(self, connector):
        data = _make_sidra_response(year=2022)
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert obs_list[0].reference_date.tzinfo is not None
        assert obs_list[0].reference_date.year == 2022

    def test_municipality_code_7_digitos(self, connector):
        data = _make_sidra_response(loc_id="1504208")
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert obs_list[0].municipality_code == "1504208"

    def test_value_float_no_payload(self, connector):
        data = _make_sidra_response(value="28000.50")
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert obs_list[0].payload["value"] == pytest.approx(28000.50)

    def test_table_name_no_payload(self, connector):
        data = _make_sidra_response()
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal per capita", 37, "R$", 2022)
        assert obs_list[0].payload["table_name"] == "PIB Municipal per capita"

    def test_year_no_payload(self, connector):
        data = _make_sidra_response(year=2021)
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2021)
        assert obs_list[0].payload["year"] == 2021

    def test_valor_x_ignorado(self, connector):
        """Valor 'X' significa dado sigiloso no IBGE — deve ser ignorado."""
        data = _make_sidra_response(value="X")
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert len(obs_list) == 0

    def test_valor_hifen_ignorado(self, connector):
        data = _make_sidra_response(value="-")
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert len(obs_list) == 0

    def test_classificacao_publica(self, connector):
        data = _make_sidra_response()
        obs_list = connector._parse_sidra_response(data, 5938, "PIB Municipal", 37, "R$", 2022)
        assert obs_list[0].data_classification == "PUBLIC"
