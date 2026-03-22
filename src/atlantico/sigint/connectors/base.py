"""
Interface base para conectores SIGINT.

Define o contrato que todos os conectores de inteligência de sinais devem
implementar e provê infraestrutura de resiliência (retry exponencial via tenacity).

Padrão idêntico ao geoint/connectors/base.py e finint/connectors/base.py.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar

import httpx
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from atlantico.sigint.observations import SigintObservation

logger = logging.getLogger(__name__)


# ─── Exceções ──────────────────────────────────────────────────────────────────


class ConnectorError(Exception):
    """Falha de rede ou API recuperável (após retries esgotados)."""


class ConnectorAuthError(ConnectorError):
    """Falha de autenticação não-recuperável na API externa."""


class ConnectorParseError(ConnectorError):
    """Resposta da API não pôde ser parseada para SigintObservation."""


class ConnectorRateLimitError(ConnectorError):
    """API externa retornou HTTP 429 — rate limit atingido."""


# ─── Decorator de retry ────────────────────────────────────────────────────────


def retry_with_backoff(func):
    """
    Decorator que aplica retry exponencial a métodos de conector SIGINT.

    Política:
    - Máximo 3 tentativas
    - Espera exponencial: 2s → 4s → 8s (máx 30s)
    - Retry apenas em ConnectorError e ConnectorRateLimitError
    - Não retenta ConnectorAuthError (credencial inválida)
    - Log de warning antes de cada tentativa de retry
    """
    return retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((ConnectorError, ConnectorRateLimitError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )(func)


# ─── Classe base ───────────────────────────────────────────────────────────────


class SigintConnector(ABC):
    """
    Interface base para todos os conectores SIGINT.

    Cada conector implementa fetch() para uma fonte específica,
    retornando observações normalizadas como lista de SigintObservation.

    Resiliência:
        Usar @retry_with_backoff em fetch() nas subclasses concretas.

    Segurança:
        Conectores NÃO tocam em crypto — apenas normalizam dados brutos.
        O pipeline de ingestão chama SourceRecordRepository.store() que
        aplica o envelope PQC a cada observação.

    Rate Limiting:
        APIs de threat intel têm limites rígidos. Cada conector deve
        respeitar os limites da respectiva API e usar headers de API key
        quando disponíveis via Settings.
    """

    SOURCE_ID: ClassVar[str]
    DEFAULT_CLASSIFICATION: ClassVar[str] = "PUBLIC"

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "SigintConnector":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            headers={"User-Agent": "ProjetoAtlantico-SIGINT/1.0"},
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError(
                f"{self.__class__.__name__} deve ser usado como context manager async. "
                "Use: async with connector as c: ..."
            )
        return self._client

    @abstractmethod
    async def fetch(
        self,
        since: datetime,
        limit: int = 100,
    ) -> list[SigintObservation]:
        """
        Busca observações da fonte externa publicadas/atualizadas desde `since`.

        Args:
            since:  Timestamp mínimo de referência (timezone-aware, UTC)
            limit:  Máximo de registros a retornar por chamada

        Returns:
            Lista de SigintObservation normalizadas (pode ser vazia).

        Raises:
            ConnectorError:          Falha de rede ou API (após retries)
            ConnectorAuthError:      Falha de autenticação (não-recuperável)
            ConnectorParseError:     Resposta não pôde ser parseada
            ConnectorRateLimitError: API retornou 429 (após retries)
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verifica se a API externa está acessível.

        Returns:
            True se acessível, False caso contrário.
            Nunca deve lançar exceção.
        """
        ...

    def _check_rate_limit(self, response: httpx.Response) -> None:
        """Lança ConnectorRateLimitError se HTTP 429."""
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "desconhecido")
            raise ConnectorRateLimitError(
                f"Rate limit atingido em {self.SOURCE_ID}. "
                f"Retry-After: {retry_after}s"
            )

    def _check_auth(self, response: httpx.Response) -> None:
        """Lança ConnectorAuthError se HTTP 401/403."""
        if response.status_code in (401, 403):
            raise ConnectorAuthError(
                f"Autenticação falhou em {self.SOURCE_ID}. "
                f"Verifique as credenciais da API. Status: {response.status_code}"
            )

    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Converte CVSS score numérico para severity canônica."""
        if cvss_score >= 9.0:
            return "CRITICAL"
        if cvss_score >= 7.0:
            return "HIGH"
        if cvss_score >= 4.0:
            return "MEDIUM"
        if cvss_score > 0.0:
            return "LOW"
        return "INFO"
