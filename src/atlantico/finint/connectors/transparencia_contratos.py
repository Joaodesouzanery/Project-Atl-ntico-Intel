"""
TransparenciaContratosConnector — Contratos públicos via Portal da Transparência.

Ingere contratos federais por UF/município para detectar anomalias de volume
e concentração de fornecedores em municípios com alta atividade de garimpo.

API: https://api.portaldatransparencia.gov.br/api-de-dados/contratos
Autenticação: Bearer token via chave de API `transparencia_api_key`.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from atlantico.config.settings import get_settings
from atlantico.finint.connectors.base import (
    ConnectorAuthError,
    ConnectorError,
    FinintConnector,
    retry_with_backoff,
)
from atlantico.finint.observations import FinintObservation

logger = logging.getLogger(__name__)

# Número máximo de resultados por página
_PAGE_SIZE = 500


class TransparenciaContratosConnector(FinintConnector):
    """
    Conector para contratos públicos do Portal da Transparência.

    Cada contrato vira uma FinintObservation do tipo "public_contract".
    Campos sensíveis (CNPJ fornecedor, valor) ficam no payload para
    serem criptografados pelo repositório via EncryptedBytes.
    """

    SOURCE_ID = "transparencia.contratos.v1"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        state_codes: list[str] | None = None,
        municipality_codes: list[str] | None = None,
    ) -> list[FinintObservation]:
        """Busca contratos federais publicados desde `since`."""
        settings = get_settings()
        api_key = settings.transparencia_api_key
        if not api_key:
            raise ConnectorAuthError(
                "transparencia_api_key não configurada. "
                "Defina ATLANTICO_TRANSPARENCIA_API_KEY no ambiente."
            )

        base_url = settings.transparencia_contratos_url
        headers = {
            "chave-api-dados": api_key,
            "Accept": "application/json",
        }

        observations: list[FinintObservation] = []
        page = 1

        # Filtros: data de início a partir de `since`
        params: dict = {
            "dataInicio": since.strftime("%d/%m/%Y"),
            "pagina": page,
            "tamanhoPagina": _PAGE_SIZE,
        }
        if state_codes:
            params["uf"] = state_codes[0]  # API suporta uma UF por request

        while True:
            params["pagina"] = page
            try:
                resp = await self.client.get(base_url, params=params, headers=headers)
                if resp.status_code == 401:
                    raise ConnectorAuthError("Autenticação Portal Transparência falhou (401).")
                if resp.status_code == 403:
                    raise ConnectorAuthError("Acesso negado ao Portal Transparência (403).")
                resp.raise_for_status()
                data = resp.json()
            except ConnectorAuthError:
                raise
            except Exception as exc:
                raise ConnectorError(f"Transparência contratos página {page}: {exc}") from exc

            if not data:
                break

            for item in data:
                obs = self._parse_contract(item)
                if obs is not None:
                    observations.append(obs)

            if len(data) < _PAGE_SIZE:
                break
            page += 1

        logger.info(
            "TransparenciaContratosConnector: %d contratos coletados.",
            len(observations),
        )
        return observations

    def _parse_contract(self, item: dict) -> FinintObservation | None:
        """Converte contrato JSON do Portal Transparência em FinintObservation."""
        try:
            contract_id = str(
                item.get("id") or item.get("numero") or item.get("numeroContratoEmpenho", "")
            )
            if not contract_id:
                return None

            # Data de assinatura ou publicação
            date_raw = (
                item.get("dataAssinatura")
                or item.get("dataPublicacaoDou")
                or item.get("dataFimVigencia")
                or ""
            )
            if not date_raw:
                return None

            # Formato: YYYY-MM-DD ou DD/MM/YYYY
            ref_date = _parse_date_flexible(date_raw)
            if ref_date is None:
                return None

            external_id = f"transparencia-contrato-{contract_id}"
            value = item.get("valorInicial") or item.get("valor") or 0.0
            supplier_cnpj = (
                item.get("fornecedor", {}).get("cnpjCpf", "")
                if isinstance(item.get("fornecedor"), dict)
                else item.get("cnpjCpf", "")
            )
            supplier_name = (
                item.get("fornecedor", {}).get("nome", "")
                if isinstance(item.get("fornecedor"), dict)
                else item.get("nomeRazaoSocial", "")
            )
            contracting = (
                item.get("unidadeGestora", {}).get("nome", "")
                if isinstance(item.get("unidadeGestora"), dict)
                else item.get("orgaoSuperior", "")
            )
            uf = item.get("uf") or item.get("siglaUf") or ""

            return FinintObservation(
                source_id=self.SOURCE_ID,
                external_id=external_id,
                observation_type="public_contract",
                reference_date=ref_date,
                state_code=uf[:2] if uf else None,
                payload={
                    "contract_id": contract_id,
                    "contract_value": float(value),
                    "supplier_cnpj": supplier_cnpj,
                    "supplier_name": supplier_name,
                    "contracting_entity": contracting,
                    "contract_object": item.get("objeto", ""),
                    "modality": item.get("modalidade", ""),
                    "state": uf,
                },
                data_classification=self.DEFAULT_CLASSIFICATION,
            )
        except Exception as exc:
            logger.debug("Falha ao parsear contrato Transparência: %s — %s", item, exc)
            return None

    async def health_check(self) -> bool:
        """Verifica acessibilidade da API Portal da Transparência."""
        try:
            settings = get_settings()
            api_key = settings.transparencia_api_key
            if not api_key:
                return False
            headers = {"chave-api-dados": api_key, "Accept": "application/json"}
            params = {"pagina": 1, "tamanhoPagina": 1}
            resp = await self.client.get(
                settings.transparencia_contratos_url,
                params=params,
                headers=headers,
            )
            return resp.status_code in (200, 204)
        except Exception:
            return False


def _parse_date_flexible(date_str: str) -> datetime | None:
    """Tenta parsear data nos formatos YYYY-MM-DD ou DD/MM/YYYY."""
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(date_str[:10], fmt[:8]).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
