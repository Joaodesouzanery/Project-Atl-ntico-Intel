"""
Interface base para conectores Atlas.

Espelha o padrão de sigint/connectors/base.py mas é totalmente isolado:
NÃO importa de atlantico.sigint, .finint, .geoint, .crypto, .storage —
Atlas é vertical paralela (memory: project_atlas_pivot.md item 1).

Resiliência: tenacity (retry exponencial 2s→4s→8s, máx 3 tentativas).
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

from atlantico.atlas.observations import AtlasObservation

logger = logging.getLogger(__name__)


# ─── Exceções ──────────────────────────────────────────────────────────────────


class AtlasConnectorError(Exception):
    """Falha de rede ou API recuperável (após retries esgotados)."""


class AtlasConnectorAuthError(AtlasConnectorError):
    """Falha de autenticação não-recuperável."""


class AtlasConnectorParseError(AtlasConnectorError):
    """Resposta da API não pôde ser parseada para AtlasObservation."""


class AtlasConnectorRateLimitError(AtlasConnectorError):
    """API externa retornou HTTP 429."""


# ─── Decorator de retry ────────────────────────────────────────────────────────


def retry_with_backoff(func):
    """
    Retry exponencial: 3 tentativas, 2s → 4s → 8s (máx 30s).
    Não retenta AtlasConnectorAuthError.
    """
    return retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(
            (AtlasConnectorError, AtlasConnectorRateLimitError)
        ),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )(func)


# ─── Classe base ───────────────────────────────────────────────────────────────


class AtlasConnector(ABC):
    """
    Base ABC para conectores de ingestão Atlas.

    Cada conector é responsável por uma fonte específica
    (DOU, LexML, SEI, DataJud, TCU) e converte respostas brutas em
    ``AtlasObservation`` (LAI by default, provenance via SHA3-256).

    Uso obrigatório como context manager async::

        async with DOUConnector() as c:
            observations = await c.fetch(since=since)
    """

    SOURCE_ID: ClassVar[str]
    DEFAULT_CLASSIFICATION: ClassVar[str] = "PUBLIC"

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AtlasConnector":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            headers={"User-Agent": "ProjetoAtlantico-Atlas/1.0"},
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
    ) -> list[AtlasObservation]:
        """
        Busca observações regulatórias da fonte desde ``since``.

        Args:
            since: Timestamp mínimo (timezone-aware).
            limit: Máximo de registros retornados.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """True se a fonte está acessível. Nunca lança."""
        ...

    def _check_rate_limit(self, response: httpx.Response) -> None:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "desconhecido")
            raise AtlasConnectorRateLimitError(
                f"Rate limit em {self.SOURCE_ID}. Retry-After: {retry_after}s"
            )

    def _check_auth(self, response: httpx.Response) -> None:
        if response.status_code in (401, 403):
            raise AtlasConnectorAuthError(
                f"Autenticação falhou em {self.SOURCE_ID} (HTTP {response.status_code})"
            )
