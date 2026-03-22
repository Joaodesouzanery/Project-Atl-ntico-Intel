"""
Testes unitários para CVMDadosAbertosConnector.

Testa parsing CSV, encoding UTF-8, campos obrigatórios.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.finint.connectors.cvm_dados_abertos import CVMDadosAbertosConnector
from atlantico.finint.observations import FinintObservation

# CSV mínimo válido (separador ;)
_CSV_HEADER = "DT_COMPTC;CNPJ_FUNDO;VL_PATRIM_LIQ;CAPTC_DIA;RESG_DIA;NR_COTST"
_CSV_ROW_1 = "2024-01-15;12.345.678/0001-90;1000000,00;50000,00;20000,00;100"
_CSV_ROW_2 = "2024-01-16;98.765.432/0001-10;2000000,00;0,00;100000,00;50"
_CSV_VALID = f"{_CSV_HEADER}\n{_CSV_ROW_1}\n{_CSV_ROW_2}"

# Linha sem CNPJ (inválida)
_CSV_MISSING_CNPJ = f"{_CSV_HEADER}\n2024-01-15;;1000000,00;50000,00;20000,00;100"


@pytest.fixture
def connector():
    c = CVMDadosAbertosConnector.__new__(CVMDadosAbertosConnector)
    c._client = AsyncMock()
    return c


class TestParseCsv:
    def test_parse_csv_retorna_observacoes(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        observations = connector._parse_csv(_CSV_VALID, since)
        assert len(observations) == 2

    def test_observacao_valida(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        observations = connector._parse_csv(_CSV_VALID, since)
        assert observations[0] is not None
        assert isinstance(observations[0], FinintObservation)

    def test_source_id_correto(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        obs_list = connector._parse_csv(_CSV_VALID, since)
        assert all(o.source_id == "cvm.dados.v1" for o in obs_list)

    def test_observation_type_market_indicator(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        obs_list = connector._parse_csv(_CSV_VALID, since)
        assert all(o.observation_type == "market_indicator" for o in obs_list)

    def test_reference_date_timezone_aware(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        obs_list = connector._parse_csv(_CSV_VALID, since)
        for obs in obs_list:
            assert obs.reference_date.tzinfo is not None

    def test_payload_contem_vl_patrim_liq(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        obs_list = connector._parse_csv(_CSV_VALID, since)
        assert obs_list[0].payload["vl_patrim_liq"] == pytest.approx(1000000.0)

    def test_payload_contem_captacao_dia(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        obs_list = connector._parse_csv(_CSV_VALID, since)
        assert obs_list[0].payload["captacao_dia"] == pytest.approx(50000.0)

    def test_payload_contem_nr_cotistas(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        obs_list = connector._parse_csv(_CSV_VALID, since)
        assert obs_list[0].payload["nr_cotistas"] == 100

    def test_linha_sem_cnpj_ignorada(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        observations = connector._parse_csv(_CSV_MISSING_CNPJ, since)
        assert len(observations) == 0

    def test_data_anterior_a_since_ignorada(self, connector):
        # Usar since posterior à data do CSV
        since = datetime(2024, 6, 1, tzinfo=timezone.utc)
        observations = connector._parse_csv(_CSV_VALID, since)
        assert len(observations) == 0

    def test_csv_vazio_retorna_lista_vazia(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        observations = connector._parse_csv(_CSV_HEADER, since)
        assert observations == []

    def test_classificacao_publica(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        obs_list = connector._parse_csv(_CSV_VALID, since)
        assert all(o.data_classification == "PUBLIC" for o in obs_list)
