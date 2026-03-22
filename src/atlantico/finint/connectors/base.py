"""
Interface base para conectores FININT.

Define o contrato que todos os conectores financeiros devem implementar
e provê infraestrutura de resiliência (retry exponencial via tenacity).

Padrão idêntico ao geoint/connectors/base.py — mantém consistência de API.
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

from atlantico.finint.observations import FinintObservation

logger = logging.getLogger(__name__)


# ─── Exceções ──────────────────────────────────────────────────────────────────


class ConnectorError(Exception):
    """Falha de rede ou API recuperável (após retries esgotados)."""


class ConnectorAuthError(ConnectorError):
    """Falha de autenticação não-recuperável na API externa."""


class ConnectorParseError(ConnectorError):
    """Resposta da API não pôde ser parseada para FinintObservation."""


# ─── Decorator de retry ────────────────────────────────────────────────────────


def retry_with_backoff(func):
    """
    Decorator que aplica retry exponencial a métodos de conector FININT.

    Política:
    - Máximo 3 tentativas
    - Espera exponencial: 2s → 4s → 8s (máx 30s)
    - Apenas retries em ConnectorError (não em ConnectorAuthError)
    - Log de warning antes de cada tentativa de retry
    """
    return retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(ConnectorError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )(func)


# ─── Classe base ───────────────────────────────────────────────────────────────


class FinintConnector(ABC):
    """
    Interface base para todos os conectores FININT.

    Cada conector implementa fetch() para uma fonte específica,
    retornando observações normalizadas como lista de FinintObservation.

    Resiliência:
        Usar @retry_with_backoff em fetch() nas subclasses concretas.

    Segurança:
        Conectores NÃO tocam em crypto — apenas normalizam dados brutos.
        O pipeline de ingestão chama SourceRecordRepository.store() que
        aplica o envelope PQC a cada observação.
    """

    SOURCE_ID: ClassVar[str]
    DEFAULT_CLASSIFICATION: ClassVar[str] = "PUBLIC"

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "FinintConnector":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            headers={"User-Agent": "ProjetoAtlantico-FININT/1.0"},
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            msg = (
                f"{self.__class__.__name__} deve ser usado como context manager async. "
                "Use: async with connector as c: ..."
            )
            raise RuntimeError(msg)
        return self._client

    @abstractmethod
    async def fetch(
        self,
        since: datetime,
        state_codes: list[str] | None = None,
        municipality_codes: list[str] | None = None,
    ) -> list[FinintObservation]:
        """
        Busca observações da fonte externa desde `since`.

        Args:
            since:              Timestamp mínimo de referência (timezone-aware, UTC)
            state_codes:        Lista de UFs para filtrar (None = todos)
            municipality_codes: Lista de códigos IBGE de municípios (None = todos)

        Returns:
            Lista de FinintObservation normalizadas (pode ser vazia).

        Raises:
            ConnectorError: Falha de rede ou API (após retries esgotados)
            ConnectorAuthError: Falha de autenticação (não-recuperável)
            ConnectorParseError: Resposta não pôde ser parseada
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
