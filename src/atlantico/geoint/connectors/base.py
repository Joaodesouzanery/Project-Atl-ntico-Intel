"""
Interface base para conectores GEOINT.

Define o contrato que todos os conectores devem implementar e provê
infraestrutura de resiliência (retry exponencial via tenacity).
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

from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)


# ─── Exceções ──────────────────────────────────────────────────────────────────


class ConnectorError(Exception):
    """Falha de rede ou API recuperável (após retries esgotados)."""


class ConnectorAuthError(ConnectorError):
    """Falha de autenticação não-recuperável na API externa."""


class ConnectorParseError(ConnectorError):
    """Resposta da API não pôde ser parseada para GeointObservation."""


# ─── Decorator de retry ────────────────────────────────────────────────────────


def retry_with_backoff(func):
    """
    Decorator que aplica retry exponencial a métodos de conector.

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


class GeointConnector(ABC):
    """
    Interface base para todos os conectores GEOINT.

    Cada conector implementa fetch() para uma fonte específica,
    retornando observações normalizadas como lista de GeointObservation.

    Resiliência:
        Usar @retry_with_backoff em fetch() nas subclasses concretas.
        Circuit breaker opcional via circuitbreaker.circuit decorator.

    Segurança:
        Conectores NÃO tocam em crypto — apenas normalizam dados brutos.
        O pipeline de ingestão chama SourceRecordRepository.store() que
        aplica o envelope PQC a cada observação.
    """

    SOURCE_ID: ClassVar[str]
    DEFAULT_CLASSIFICATION: ClassVar[str] = "PUBLIC"

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "GeointConnector":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            headers={"User-Agent": "ProjetoAtlantico-GEOINT/1.0"},
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
        bbox: tuple[float, float, float, float],
    ) -> list[GeointObservation]:
        """
        Busca observações da fonte externa desde `since` dentro de `bbox`.

        Args:
            since: Timestamp mínimo de aquisição (timezone-aware, UTC)
            bbox:  Bounding box (min_lon, min_lat, max_lon, max_lat) WGS-84

        Returns:
            Lista de GeointObservation normalizadas (pode ser vazia).

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
            Nunca deve lançar exceção — circuit breaker usa este método.
        """
        ...

    def _make_bbox_polygon_wkt(
        self,
        min_lon: float,
        min_lat: float,
        max_lon: float,
        max_lat: float,
    ) -> str:
        """Gera WKT POLYGON para uma bounding box."""
        return (
            f"POLYGON(("
            f"{min_lon} {min_lat}, "
            f"{max_lon} {min_lat}, "
            f"{max_lon} {max_lat}, "
            f"{min_lon} {max_lat}, "
            f"{min_lon} {min_lat}"
            f"))"
        )

    def _point_to_bbox_wkt(
        self,
        lon: float,
        lat: float,
        buffer_deg: float = 0.001,
    ) -> str:
        """
        Gera WKT POLYGON de bounding box para uma coordenada ponto.
        Necessário pois SourceRecord.geo_bounds é POLYGON.
        buffer_deg padrão ≈ 111 metros no equador.
        """
        return self._make_bbox_polygon_wkt(
            min_lon=lon - buffer_deg,
            min_lat=lat - buffer_deg,
            max_lon=lon + buffer_deg,
            max_lat=lat + buffer_deg,
        )
