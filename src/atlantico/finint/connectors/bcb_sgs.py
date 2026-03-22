"""
BCBSgsConnector — Séries temporais do Banco Central via API SGS.

Ingere indicadores macroeconômicos (Selic, IPCA, exportações de ouro)
para análise de anomalias e correlação com GEOINT.

API pública: https://api.bcb.gov.br/dados/serie/dados/serie/{code}/dados
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

# Séries BCB monitoradas: code → (nome, unidade)
BCB_SERIES: dict[int, tuple[str, str]] = {
    1: ("Taxa Selic", "% a.a."),
    4: ("Taxa CDI", "% a.a."),
    12: ("IPCA", "% a.m."),
    13522: ("Exportações - Ouro (BC$)", "US$ milhões"),
    24363: ("Exportações - Minerais Metálicos", "US$ milhões"),
    3543: ("PIB Trimestral Acumulado", "R$ bilhões"),
}


class BCBSgsConnector(FinintConnector):
    """
    Conector para a API SGS do Banco Central do Brasil.

    Busca valores de séries temporais macroeconômicas.
    Cada valor vira uma FinintObservation do tipo "market_indicator".
    """

    SOURCE_ID = "bcb.sgs.v1"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        state_codes: list[str] | None = None,
        municipality_codes: list[str] | None = None,
    ) -> list[FinintObservation]:
        """Busca todas as séries BCB configuradas desde `since`."""
        settings = get_settings()
        base_url = settings.bcb_sgs_url
        since_str = since.strftime("%d/%m/%Y")
        until_str = datetime.now(tz=timezone.utc).strftime("%d/%m/%Y")

        observations: list[FinintObservation] = []

        for series_code, (series_name, unit) in BCB_SERIES.items():
            url = f"{base_url}/{series_code}/dados"
            params = {
                "formato": "json",
                "dataInicial": since_str,
                "dataFinal": until_str,
            }
            try:
                resp = await self.client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.warning(
                    "Erro ao buscar série BCB %d (%s): %s",
                    series_code,
                    series_name,
                    exc,
                )
                raise ConnectorError(f"BCB SGS série {series_code}: {exc}") from exc

            for record in data:
                obs = self._parse_record(record, series_code, series_name, unit)
                if obs is not None:
                    observations.append(obs)

        logger.info(
            "BCBSgsConnector: %d observações coletadas de %d séries.",
            len(observations),
            len(BCB_SERIES),
        )
        return observations

    def _parse_record(
        self,
        record: dict,
        series_code: int,
        series_name: str,
        unit: str,
    ) -> FinintObservation | None:
        """Converte registro JSON BCB SGS em FinintObservation."""
        try:
            date_str: str = record.get("data", "")
            value_str = record.get("valor", "")
            if not date_str or value_str in ("", None):
                return None

            # Formato BCB: DD/MM/YYYY
            ref_date = datetime.strptime(date_str, "%d/%m/%Y").replace(
                tzinfo=timezone.utc
            )
            value = float(str(value_str).replace(",", "."))
            external_id = f"bcb-sgs-{series_code}-{date_str.replace('/', '')}"

            return FinintObservation(
                source_id=self.SOURCE_ID,
                external_id=external_id,
                observation_type="market_indicator",
                reference_date=ref_date,
                payload={
                    "series_code": series_code,
                    "series_name": series_name,
                    "value": value,
                    "unit": unit,
                    "raw_date": date_str,
                },
                data_classification=self.DEFAULT_CLASSIFICATION,
            )
        except Exception as exc:
            logger.debug("Falha ao parsear registro BCB SGS: %s — %s", record, exc)
            return None

    async def health_check(self) -> bool:
        """Verifica acessibilidade da API BCB SGS."""
        try:
            settings = get_settings()
            url = f"{settings.bcb_sgs_url}/1/dados/ultimos/1"
            resp = await self.client.get(url, params={"formato": "json"})
            return resp.status_code == 200
        except Exception:
            return False
