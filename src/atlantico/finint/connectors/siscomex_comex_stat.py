"""
SiscomexComexStatConnector — Fluxos de comércio exterior via ComexStat MDIC.

Monitora exportações de minerais estratégicos (ouro NCM 7108, prata NCM 2616,
estanho NCM 8001) para detectar spikes associados a garimpo ilegal.

API: https://comexstat.mdic.gov.br/pt/home (dados públicos)
     Endpoint alternativo: https://api-comexstat.mdic.gov.br/

Autenticação: pública.
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

# NCMs de minerais estratégicos de interesse
STRATEGIC_SH2 = {
    "71": "Pérolas, pedras preciosas, metais preciosos (ouro, prata, platina)",
    "26": "Minérios, escórias e cinzas",
    "80": "Estanho e suas obras",
}

_COMEXSTAT_API = "https://api-comexstat.mdic.gov.br/general"


class SiscomexComexStatConnector(FinintConnector):
    """
    Conector para ComexStat MDIC (Siscomex).

    Monitora exportações de minerais estratégicos por UF e mês.
    Cada registro vira uma FinintObservation do tipo "trade_flow".
    """

    SOURCE_ID = "mdic.comexstat.v1"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        state_codes: list[str] | None = None,
        municipality_codes: list[str] | None = None,
    ) -> list[FinintObservation]:
        """
        Busca exportações de NCMs estratégicos desde `since`.

        Usa a API JSON do ComexStat para buscar dados mensais por SH2.
        """
        settings = get_settings()
        strategic_ncms = settings.finint_strategic_ncm_list

        observations: list[FinintObservation] = []
        since_year = since.year
        since_month = since.month
        now = datetime.now(tz=timezone.utc)

        # Filtrar por SH2 (primeiros 2 dígitos do NCM)
        sh2_codes = list({ncm[:2] for ncm in strategic_ncms if len(ncm) >= 2})

        for sh2 in sh2_codes:
            payload = {
                "flow": "export",
                "monthStart": f"{since_year}{since_month:02d}",
                "monthEnd": f"{now.year}{now.month:02d}",
                "sh2": sh2,
                "typeForm": 1,
                "typeOrder": 1,
            }
            if state_codes:
                payload["state"] = state_codes[0]  # API suporta 1 estado por query

            try:
                resp = await self.client.post(_COMEXSTAT_API, json=payload)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                raise ConnectorError(f"ComexStat SH2 {sh2}: {exc}") from exc

            items = data.get("data", data) if isinstance(data, dict) else data
            for item in (items if isinstance(items, list) else []):
                obs = self._parse_trade_item(item, sh2)
                if obs is not None:
                    observations.append(obs)

        logger.info("SiscomexComexStatConnector: %d fluxos coletados.", len(observations))
        return observations

    def _parse_trade_item(self, item: dict, sh2: str) -> FinintObservation | None:
        """Converte registro ComexStat em FinintObservation."""
        try:
            # Campos podem variar: year/month ou coAno/coMes
            year = item.get("coAno") or item.get("year") or item.get("co_ano")
            month = item.get("coMes") or item.get("month") or item.get("co_mes")
            if not year or not month:
                return None

            ref_date = datetime(int(year), int(month), 1, tzinfo=timezone.utc)

            ncm = str(item.get("coNcm") or item.get("ncm") or item.get("co_ncm") or sh2 + "00")
            ncm_desc = item.get("noNcmPor") or item.get("ncm_desc") or STRATEGIC_SH2.get(sh2, "")
            state = str(item.get("sgUf") or item.get("state") or item.get("sg_uf") or "")
            value_usd = float(
                item.get("vlFob") or item.get("value_usd") or item.get("vl_fob") or 0
            )
            weight_kg = float(
                item.get("kgLiquido") or item.get("net_weight") or item.get("kg_liquido") or 0
            )
            country = str(item.get("coPais") or item.get("country") or "")

            external_id = f"comexstat-{ncm}-{state}-{year}-{month:02d}"

            return FinintObservation(
                source_id=self.SOURCE_ID,
                external_id=external_id,
                observation_type="trade_flow",
                reference_date=ref_date,
                state_code=state[:2] if state else None,
                payload={
                    "ncm_code": ncm,
                    "ncm_desc": ncm_desc,
                    "sh2_code": sh2,
                    "export_value_usd": value_usd,
                    "net_weight_kg": weight_kg,
                    "state": state,
                    "country_code": country,
                    "year": int(year),
                    "month": int(month),
                },
                data_classification=self.DEFAULT_CLASSIFICATION,
            )
        except Exception as exc:
            logger.debug("Falha ao parsear ComexStat: %s — %s", item, exc)
            return None

    async def health_check(self) -> bool:
        """Verifica acessibilidade da API ComexStat."""
        try:
            resp = await self.client.get("https://comexstat.mdic.gov.br", follow_redirects=True)
            return resp.status_code in (200, 301, 302)
        except Exception:
            return False
