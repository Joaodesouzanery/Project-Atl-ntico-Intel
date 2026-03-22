"""
CVMDadosAbertosConnector — Dados abertos da CVM (Comissão de Valores Mobiliários).

Ingere informações de fundos de investimento e companhias abertas para
detectar anomalias de captação/resgate em fundos associados a mineração.

API: https://dados.cvm.gov.br/dados (arquivos CSV)
Autenticação: pública.
"""

from __future__ import annotations

import csv
import io
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

# Endpoints CVM dados abertos (arquivos CSV mensais)
_CVM_FUNDOS_URL = "https://dados.cvm.gov.br/dados/FI/DOC/INF_DIARIO/DADOS"


class CVMDadosAbertosConnector(FinintConnector):
    """
    Conector para dados abertos da CVM.

    Baixa informes diários de fundos de investimento (CSV).
    Cada linha = 1 FinintObservation do tipo "market_indicator".
    """

    SOURCE_ID = "cvm.dados.v1"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        state_codes: list[str] | None = None,
        municipality_codes: list[str] | None = None,
    ) -> list[FinintObservation]:
        """
        Busca informes diários de fundos da CVM.

        Baixa arquivos CSV mensais para os meses desde `since`.
        """
        observations: list[FinintObservation] = []
        year = since.year
        month = since.month
        now = datetime.now(tz=timezone.utc)

        while (year, month) <= (now.year, now.month):
            month_str = f"{year}{month:02d}"
            url = f"{_CVM_FUNDOS_URL}/inf_diario_fi_{month_str}.csv"

            try:
                resp = await self.client.get(url)
                if resp.status_code == 404:
                    # Arquivo ainda não disponível (mês atual)
                    logger.debug("CVM: arquivo %s não disponível ainda.", month_str)
                    break
                resp.raise_for_status()
                content = resp.text
            except Exception as exc:
                raise ConnectorError(f"CVM CSV {month_str}: {exc}") from exc

            parsed = self._parse_csv(content, since)
            observations.extend(parsed)
            logger.debug("CVM %s: %d registros", month_str, len(parsed))

            # Avança mês
            month += 1
            if month > 12:
                month = 1
                year += 1

        logger.info("CVMDadosAbertosConnector: %d observações coletadas.", len(observations))
        return observations

    def _parse_csv(self, content: str, since: datetime) -> list[FinintObservation]:
        """Parseia CSV de informes diários CVM."""
        observations = []
        try:
            reader = csv.DictReader(io.StringIO(content), delimiter=";")
            for row in reader:
                obs = self._parse_row(row, since)
                if obs is not None:
                    observations.append(obs)
        except Exception as exc:
            logger.warning("Erro ao parsear CSV CVM: %s", exc)
        return observations

    def _parse_row(self, row: dict, since: datetime) -> FinintObservation | None:
        """Converte linha CSV CVM em FinintObservation."""
        try:
            date_str = row.get("DT_COMPTC", "")
            cnpj = row.get("CNPJ_FUNDO", "")
            if not date_str or not cnpj:
                return None

            ref_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if ref_date < since:
                return None

            vl_patrim = row.get("VL_PATRIM_LIQ", "0").replace(",", ".").replace(" ", "")
            vl_captacao = row.get("CAPTC_DIA", "0").replace(",", ".").replace(" ", "")
            vl_resgate = row.get("RESG_DIA", "0").replace(",", ".").replace(" ", "")

            external_id = f"cvm-fi-{cnpj.replace('/', '').replace('.', '').replace('-', '')}-{date_str}"

            return FinintObservation(
                source_id=self.SOURCE_ID,
                external_id=external_id,
                observation_type="market_indicator",
                reference_date=ref_date,
                payload={
                    "cnpj_fundo": cnpj,
                    "vl_patrim_liq": float(vl_patrim or 0),
                    "captacao_dia": float(vl_captacao or 0),
                    "resgate_dia": float(vl_resgate or 0),
                    "nr_cotistas": int(row.get("NR_COTST", 0) or 0),
                },
                data_classification=self.DEFAULT_CLASSIFICATION,
            )
        except Exception as exc:
            logger.debug("Falha ao parsear linha CVM: %s — %s", row, exc)
            return None

    async def health_check(self) -> bool:
        """Verifica acessibilidade dos dados CVM."""
        try:
            resp = await self.client.get(_CVM_FUNDOS_URL, follow_redirects=True)
            return resp.status_code in (200, 301, 302)
        except Exception:
            return False
