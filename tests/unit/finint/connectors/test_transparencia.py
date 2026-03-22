"""
Testes unitários para TransparenciaContratosConnector.

Testa parsing de contratos, autenticação, campos obrigatórios.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlantico.finint.connectors.transparencia_contratos import TransparenciaContratosConnector
from atlantico.finint.connectors.base import ConnectorAuthError
from atlantico.finint.observations import FinintObservation


@pytest.fixture
def connector():
    c = TransparenciaContratosConnector.__new__(TransparenciaContratosConnector)
    c._client = AsyncMock()
    return c


def _make_contract(
    contract_id: str = "CT-2024-001",
    value: float = 500000.0,
    uf: str = "PA",
    date: str = "2024-06-15",
) -> dict:
    return {
        "id": contract_id,
        "dataAssinatura": date,
        "valorInicial": value,
        "objeto": "Serviços de consultoria ambiental",
        "modalidade": "PREGAO",
        "uf": uf,
        "fornecedor": {
            "cnpjCpf": "12.345.678/0001-90",
            "nome": "Empresa Teste LTDA",
        },
        "unidadeGestora": {
            "nome": "IBAMA PA",
        },
    }


def _mock_settings(has_key: bool = True):
    s = MagicMock()
    s.transparencia_api_key = "test-api-key" if has_key else ""
    s.transparencia_contratos_url = "https://api.portaldatransparencia.gov.br/api-de-dados/contratos"
    return s


class TestParseContract:
    def test_observacao_valida(self, connector):
        contract = _make_contract()
        obs = connector._parse_contract(contract)
        assert obs is not None
        assert isinstance(obs, FinintObservation)

    def test_source_id_correto(self, connector):
        obs = connector._parse_contract(_make_contract())
        assert obs is not None
        assert obs.source_id == "transparencia.contratos.v1"

    def test_observation_type_public_contract(self, connector):
        obs = connector._parse_contract(_make_contract())
        assert obs is not None
        assert obs.observation_type == "public_contract"

    def test_reference_date_timezone_aware(self, connector):
        obs = connector._parse_contract(_make_contract(date="2024-06-15"))
        assert obs is not None
        assert obs.reference_date.tzinfo is not None
        assert obs.reference_date.year == 2024

    def test_state_code_extraido(self, connector):
        obs = connector._parse_contract(_make_contract(uf="AM"))
        assert obs is not None
        assert obs.state_code == "AM"

    def test_payload_contem_campos_obrigatorios(self, connector):
        obs = connector._parse_contract(_make_contract(value=1000000.0))
        assert obs is not None
        assert obs.payload["contract_value"] == pytest.approx(1000000.0)
        assert obs.payload["contracting_entity"] == "IBAMA PA"

    def test_payload_contem_supplier_name(self, connector):
        obs = connector._parse_contract(_make_contract())
        assert obs is not None
        assert obs.payload["supplier_name"] == "Empresa Teste LTDA"

    def test_sem_id_retorna_none(self, connector):
        contract = _make_contract()
        del contract["id"]
        # sem nenhum campo de ID alternativo
        contract.pop("numero", None)
        contract.pop("numeroContratoEmpenho", None)
        obs = connector._parse_contract(contract)
        assert obs is None

    def test_sem_data_retorna_none(self, connector):
        contract = _make_contract()
        contract.pop("dataAssinatura", None)
        obs = connector._parse_contract(contract)
        assert obs is None

    def test_classificacao_publica(self, connector):
        obs = connector._parse_contract(_make_contract())
        assert obs is not None
        assert obs.data_classification == "PUBLIC"


class TestFetch:
    @pytest.mark.asyncio
    async def test_sem_api_key_lanca_auth_error(self, connector):
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with patch(
            "atlantico.finint.connectors.transparencia_contratos.get_settings",
            return_value=_mock_settings(has_key=False),
        ):
            with pytest.raises(ConnectorAuthError):
                await connector.fetch(since=since)

    @pytest.mark.asyncio
    async def test_fetch_retorna_observacoes(self, connector):
        contracts = [_make_contract("CT-001"), _make_contract("CT-002")]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = contracts
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with patch(
            "atlantico.finint.connectors.transparencia_contratos.get_settings",
            return_value=_mock_settings(),
        ):
            observations = await connector.fetch(since=since)

        assert len(observations) == 2
        for obs in observations:
            assert obs.source_id == "transparencia.contratos.v1"

    @pytest.mark.asyncio
    async def test_fetch_sem_contratos_retorna_lista_vazia(self, connector):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        connector.client.get = AsyncMock(return_value=mock_resp)

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with patch(
            "atlantico.finint.connectors.transparencia_contratos.get_settings",
            return_value=_mock_settings(),
        ):
            observations = await connector.fetch(since=since)

        assert observations == []
