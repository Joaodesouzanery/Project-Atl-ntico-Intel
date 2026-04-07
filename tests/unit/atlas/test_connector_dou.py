"""Testes do DOUConnector."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import httpx
import pytest

from atlantico.atlas.connectors.base import (
    AtlasConnectorAuthError,
    AtlasConnectorError,
    AtlasConnectorParseError,
    AtlasConnectorRateLimitError,
)
from atlantico.atlas.connectors.dou import DOUConnector


# ─── Construção / config ─────────────────────────────────────────────────────


def test_init_default_secao():
    c = DOUConnector()
    assert c._secoes == ("do1",)
    assert c.SOURCE_ID == "br.gov.in.dou.v1"


def test_init_rejects_invalid_secao():
    with pytest.raises(ValueError, match="Seção DOU"):
        DOUConnector(secoes=("do9",))


# ─── Inferência de tipo normativo ────────────────────────────────────────────


@pytest.mark.parametrize(
    "title,expected",
    [
        ("LEI Nº 14.500, DE 7 DE ABRIL DE 2026", "lei"),
        ("LEI COMPLEMENTAR Nº 200", "lei_complementar"),
        ("DECRETO Nº 12.000", "decreto"),
        ("DECRETO LEGISLATIVO Nº 5", "decreto_legislativo"),
        ("MEDIDA PROVISÓRIA Nº 1.317", "medida_provisoria"),
        ("RESOLUÇÃO ANM Nº 123", "resolucao"),
        ("INSTRUÇÃO NORMATIVA RFB Nº 2.000", "instrucao_normativa"),
        ("PORTARIA SEPRT Nº 100", "portaria"),
        ("DELIBERAÇÃO Nº 5", "deliberacao"),
        ("CIRCULAR BCB Nº 50", "circular"),
        ("EDITAL DE NOTIFICAÇÃO", "edital"),
        ("Aviso de licitação", None),
    ],
)
def test_infer_norma_tipo(title, expected):
    assert DOUConnector._infer_norma_tipo(title) == expected


# ─── _build_observation ──────────────────────────────────────────────────────


def test_build_observation_norma():
    c = DOUConnector()
    raw = {
        "id": "abc123",
        "title": "RESOLUÇÃO ANM Nº 123, DE 7 DE ABRIL DE 2026",
        "orgao": "Agência Nacional de Mineração",
    }
    obs = c._build_observation(raw, "do1", datetime(2026, 4, 7).date())
    assert obs is not None
    assert obs.observation_type == "norma"
    assert obs.norma_tipo == "resolucao"
    assert obs.orgao_publicador == "Agência Nacional de Mineração"
    assert obs.text_hash_sha3_256 is not None
    assert obs.tags == ["secao:do1"]
    assert obs.reference_date.tzinfo is not None


def test_build_observation_documento_bruto_when_no_match():
    c = DOUConnector()
    raw = {"id": "x", "title": "Aviso geral"}
    obs = c._build_observation(raw, "do1", datetime(2026, 4, 7).date())
    assert obs is not None
    assert obs.observation_type == "documento_bruto"
    assert obs.norma_tipo is None


def test_build_observation_returns_none_without_id():
    c = DOUConnector()
    obs = c._build_observation({}, "do1", datetime(2026, 4, 7).date())
    assert obs is None


# ─── _parse_response ─────────────────────────────────────────────────────────


def _json_response(payload, content_type="application/json"):
    return httpx.Response(
        200,
        content=json.dumps(payload).encode("utf-8"),
        headers={"content-type": content_type},
    )


def test_parse_response_json_list():
    c = DOUConnector()
    items = c._parse_response(_json_response([{"id": "1"}, {"id": "2"}]))
    assert len(items) == 2


def test_parse_response_json_dict_with_jsonarray():
    c = DOUConnector()
    items = c._parse_response(_json_response({"jsonArray": [{"id": "1"}]}))
    assert items == [{"id": "1"}]


def test_parse_response_json_invalid_format_raises():
    c = DOUConnector()
    with pytest.raises(AtlasConnectorParseError, match="Formato"):
        c._parse_response(_json_response({"foo": "bar"}))


def test_parse_response_json_malformed_raises():
    c = DOUConnector()
    response = httpx.Response(
        200,
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    with pytest.raises(AtlasConnectorParseError, match="JSON inválido"):
        c._parse_response(response)


def test_parse_response_html_with_embedded_jsonarray():
    c = DOUConnector()
    html = """
    <html><body><script>
    var data = { jsonArray: [{"id":"abc","title":"DECRETO Nº 1"}], total: 1 };
    </script></body></html>
    """
    response = httpx.Response(
        200, content=html.encode("utf-8"), headers={"content-type": "text/html"}
    )
    items = c._parse_response(response)
    assert items == [{"id": "abc", "title": "DECRETO Nº 1"}]


def test_parse_response_html_without_match_returns_empty():
    c = DOUConnector()
    response = httpx.Response(
        200, content=b"<html>nada</html>", headers={"content-type": "text/html"}
    )
    assert c._parse_response(response) == []


# ─── _fetch_day (com client mockado) ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_day_handles_404():
    c = DOUConnector()
    async with c:
        c._client.get = AsyncMock(return_value=httpx.Response(404))
        items = await c._fetch_day(datetime(2026, 4, 7).date(), "do1")
    assert items == []


@pytest.mark.asyncio
async def test_fetch_day_raises_on_500():
    c = DOUConnector()
    async with c:
        c._client.get = AsyncMock(return_value=httpx.Response(500))
        with pytest.raises(AtlasConnectorError, match="HTTP 500"):
            await c._fetch_day(datetime(2026, 4, 7).date(), "do1")


@pytest.mark.asyncio
async def test_fetch_day_raises_on_429():
    c = DOUConnector()
    async with c:
        c._client.get = AsyncMock(
            return_value=httpx.Response(429, headers={"Retry-After": "60"})
        )
        with pytest.raises(AtlasConnectorRateLimitError):
            await c._fetch_day(datetime(2026, 4, 7).date(), "do1")


@pytest.mark.asyncio
async def test_fetch_day_raises_on_403():
    c = DOUConnector()
    async with c:
        c._client.get = AsyncMock(return_value=httpx.Response(403))
        with pytest.raises(AtlasConnectorAuthError):
            await c._fetch_day(datetime(2026, 4, 7).date(), "do1")


@pytest.mark.asyncio
async def test_fetch_day_wraps_network_error():
    c = DOUConnector()
    async with c:
        c._client.get = AsyncMock(
            side_effect=httpx.ConnectError("rede caiu")
        )
        with pytest.raises(AtlasConnectorError, match="rede"):
            await c._fetch_day(datetime(2026, 4, 7).date(), "do1")


# ─── fetch() integração com mock ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_rejects_naive_since():
    c = DOUConnector()
    async with c:
        with pytest.raises(ValueError, match="timezone-aware"):
            await c.fetch(datetime(2026, 4, 7))


@pytest.mark.asyncio
async def test_fetch_returns_observations_from_mock():
    c = DOUConnector()
    payload = [
        {"id": "1", "title": "DECRETO Nº 1", "orgao": "Casa Civil"},
        {"id": "2", "title": "RESOLUÇÃO ANM Nº 5", "orgao": "ANM"},
        {"id": "3", "title": "Aviso", "orgao": "INMETRO"},
    ]
    response = _json_response(payload)
    async with c:
        c._client.get = AsyncMock(return_value=response)
        # since = hoje para limitar a uma única iteração de dia
        since = datetime.now(timezone.utc)
        observations = await c.fetch(since=since, limit=10)

    assert len(observations) == 3
    types = {o.observation_type for o in observations}
    assert "norma" in types
    assert "documento_bruto" in types
    norma_obs = next(o for o in observations if o.external_id == "1")
    assert norma_obs.norma_tipo == "decreto"


@pytest.mark.asyncio
async def test_fetch_respects_limit():
    c = DOUConnector()
    payload = [{"id": str(i), "title": "DECRETO Nº x"} for i in range(50)]
    async with c:
        c._client.get = AsyncMock(return_value=_json_response(payload))
        observations = await c.fetch(
            since=datetime.now(timezone.utc), limit=5
        )
    assert len(observations) == 5
