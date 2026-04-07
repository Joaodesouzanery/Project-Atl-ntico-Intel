"""Testes da base de conectores Atlas."""

from datetime import datetime, timezone

import httpx
import pytest

from atlantico.atlas.connectors.base import (
    AtlasConnector,
    AtlasConnectorAuthError,
    AtlasConnectorRateLimitError,
)
from atlantico.atlas.observations import AtlasObservation


class _DummyConnector(AtlasConnector):
    SOURCE_ID = "dummy.v1"

    async def fetch(self, since: datetime, limit: int = 100):
        return []

    async def health_check(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_context_manager_creates_and_closes_client():
    async with _DummyConnector() as c:
        assert c.client is not None
        assert isinstance(c.client, httpx.AsyncClient)
    assert c._client is None


def test_client_without_context_manager_raises():
    c = _DummyConnector()
    with pytest.raises(RuntimeError, match="context manager"):
        _ = c.client


def test_check_rate_limit_raises_429():
    c = _DummyConnector()
    response = httpx.Response(429, headers={"Retry-After": "30"})
    with pytest.raises(AtlasConnectorRateLimitError, match="Rate limit"):
        c._check_rate_limit(response)


def test_check_rate_limit_passes_200():
    c = _DummyConnector()
    c._check_rate_limit(httpx.Response(200))


@pytest.mark.parametrize("status", [401, 403])
def test_check_auth_raises(status):
    c = _DummyConnector()
    with pytest.raises(AtlasConnectorAuthError):
        c._check_auth(httpx.Response(status))


def test_check_auth_passes_200():
    c = _DummyConnector()
    c._check_auth(httpx.Response(200))


@pytest.mark.asyncio
async def test_fetch_returns_observations_type():
    """Sanidade: subclasse implementa interface correta."""
    async with _DummyConnector() as c:
        result = await c.fetch(datetime(2026, 4, 7, tzinfo=timezone.utc))
        assert isinstance(result, list)


def test_observation_subclass_can_construct():
    """Garante import isolado de AtlasObservation no módulo de conectores."""
    obs = AtlasObservation(
        source_id="dummy.v1",
        external_id="x",
        observation_type="norma",
        reference_date=datetime(2026, 4, 7, tzinfo=timezone.utc),
    )
    assert obs.source_id == "dummy.v1"
