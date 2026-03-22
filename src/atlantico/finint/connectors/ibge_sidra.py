"""
IBGESidraConnector — Dados municipais do IBGE via API SIDRA.

Ingere indicadores municipais (PIB per capita, produção agrícola/mineral)
para contextualizar anomalias financeiras por município.

API: https://servicodados.ibge.gov.br/api/v3/agregados
Autenticação: pública.

Tabelas SIDRA de interesse:
  5938 — PIB municipal (anual)
  839  — Produção agrícola municipal (PAM)
  1613 — Produção mineral (pesquisa mineral)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from atlantico.config.settings import get_settings
from atlantico.finint.connectors.base import (
    ConnectorError,
    FinintConnector,
    retry_with_backoff,
)
from atlantico.finint.observations import FinintObservation

logger = logging.getLogger(__name__)

# Tabela → (nome, variável SIDRA, unidade)
SIDRA_TABLES: dict[int, tuple[str, int, str]] = {
    5938: ("PIB Municipal per capita", 37, "R$ correntes"),
    839: ("Valor da produção agrícola municipal", 215, "R$ mil"),
}


class IBGESidraConnector(FinintConnector):
    """
    Conector para a API SIDRA do IBGE.

    Busca indicadores municipais para contextualizar dados FININT e GEOINT.
    Cada registro vira uma FinintObservation do tipo "market_indicator".
    """

    SOURCE_ID = "ibge.sidra.v1"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        state_codes: list[str] | None = None,
        municipality_codes: list[str] | None = None,
    ) -> list[FinintObservation]:
        """
        Busca indicadores SIDRA para os municípios/estados especificados.

        Ano de referência: `since.year` ao atual.
        """
        settings = get_settings()
        base_url = settings.ibge_sidra_url
        observations: list[FinintObservation] = []

        # Localidade: municípios brasileiros da Amazônia Legal
        # Se state_codes fornecido, filtra por estados; senão usa todos
        geo_level = "N6"   # municípios
        if state_codes:
            # Municípios do(s) estado(s) — formato SIDRA: IN N3 11,12,13
            geo_filter = f"N3/{','.join(state_codes)}"
        else:
            geo_filter = "N3/11,12,13,14,15,16,17,21,51"  # Estados Amazônia Legal

        since_year = since.year
        current_year = datetime.now(tz=timezone.utc).year

        for table_id, (table_name, variable_id, unit) in SIDRA_TABLES.items():
            for year in range(since_year, current_year + 1):
                url = (
                    f"{base_url}/{table_id}/periodos/{year}"
                    f"/variaveis/{variable_id}"
                    f"?localidades={geo_filter}&formato=json"
                )
                try:
                    resp = await self.client.get(url)
                    if resp.status_code == 404:
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc:
                    raise ConnectorError(f"IBGE SIDRA tabela {table_id} ano {year}: {exc}") from exc

                obs_list = self._parse_sidra_response(
                    data, table_id, table_name, variable_id, unit, year
                )
                observations.extend(obs_list)

        logger.info("IBGESidraConnector: %d observações coletadas.", len(observations))
        return observations

    def _parse_sidra_response(
        self,
        data: list,
        table_id: int,
        table_name: str,
        variable_id: int,
        unit: str,
        year: int,
    ) -> list[FinintObservation]:
        """Parseia resposta JSON da API SIDRA."""
        observations = []
        try:
            # Estrutura SIDRA: lista de resultados com series de localidades
            for result in data:
                if not isinstance(result, dict):
                    continue
                for series in result.get("resultados", []):
                    for loc_result in series.get("series", []):
                        loc = loc_result.get("localidade", {})
                        loc_id = str(loc.get("id", ""))
                        loc_nome = loc.get("nome", "")
                        # Valor do ano
                        serie_data = loc_result.get("serie", {})
                        value_str = serie_data.get(str(year), "-")
                        if value_str in ("-", "X", ""):
                            continue
                        try:
                            value = float(str(value_str).replace(",", ".").replace(" ", ""))
                        except ValueError:
                            continue

                        ref_date = datetime(year, 12, 31, tzinfo=timezone.utc)
                        external_id = f"ibge-sidra-{table_id}-{loc_id}-{year}"

                        obs = FinintObservation(
                            source_id=self.SOURCE_ID,
                            external_id=external_id,
                            observation_type="market_indicator",
                            reference_date=ref_date,
                            municipality_code=loc_id if len(loc_id) == 7 else None,
                            state_code=loc_id[:2] if len(loc_id) >= 2 else None,
                            payload={
                                "table_id": table_id,
                                "table_name": table_name,
                                "variable_id": variable_id,
                                "value": value,
                                "unit": unit,
                                "municipality_code": loc_id,
                                "municipality_name": loc_nome,
                                "year": year,
                            },
                            data_classification=self.DEFAULT_CLASSIFICATION,
                        )
                        observations.append(obs)
        except Exception as exc:
            logger.warning("Erro ao parsear resposta SIDRA: %s", exc)
        return observations

    async def health_check(self) -> bool:
        """Verifica acessibilidade da API SIDRA."""
        try:
            settings = get_settings()
            # Teste simples: consulta 1 período de 1 tabela
            url = f"{settings.ibge_sidra_url}/5938/periodos/2020/variaveis/37?localidades=N3/11&formato=json"
            resp = await self.client.get(url)
            return resp.status_code == 200
        except Exception:
            return False
