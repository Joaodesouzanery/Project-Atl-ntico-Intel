"""Testes do LexMLConnector (OAI-PMH)."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import httpx
import pytest

from atlantico.atlas.connectors.base import (
    AtlasConnectorError,
    AtlasConnectorParseError,
)
from atlantico.atlas.connectors.lexml import LexMLConnector


# ─── Fixtures XML ────────────────────────────────────────────────────────────


def _oai_envelope(records_xml: str = "", token: str = "") -> str:
    token_xml = (
        f'<resumptionToken>{token}</resumptionToken>' if token else ""
    )
    return f"""<?xml version="1.0"?>
<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">
  <ListRecords>
    {records_xml}
    {token_xml}
  </ListRecords>
</OAI-PMH>"""


def _record_xml(
    *,
    identifier: str = "oai:lexml:res-anm-123-2026",
    datestamp: str = "2026-04-07",
    urn: str = "urn:lex:br:agencia.nacional.mineracao:resolucao:2026;123",
    titulo: str = "Resolução ANM nº 123, de 2026",
    data: str = "2026-04-07",
    tipo: str = "Resolução",
    creator: str = "Agência Nacional de Mineração",
    deleted: bool = False,
) -> str:
    status = ' status="deleted"' if deleted else ""
    return f"""
    <record>
      <header{status}>
        <identifier>{identifier}</identifier>
        <datestamp>{datestamp}</datestamp>
      </header>
      <metadata>
        <oai_dc:dc xmlns:oai_dc="http://www.openarchives.org/OAI/2.0/oai_dc/"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
          <dc:identifier>{urn}</dc:identifier>
          <dc:identifier>https://www.lexml.gov.br/urn/{urn}</dc:identifier>
          <dc:title>{titulo}</dc:title>
          <dc:date>{data}</dc:date>
          <dc:type>{tipo}</dc:type>
          <dc:creator>{creator}</dc:creator>
        </oai_dc:dc>
      </metadata>
    </record>
    """


def _xml_response(body: str) -> httpx.Response:
    return httpx.Response(
        200,
        content=body.encode("utf-8"),
        headers={"content-type": "application/xml"},
    )


# ─── Init / config ───────────────────────────────────────────────────────────


def test_init_defaults():
    c = LexMLConnector()
    assert c.SOURCE_ID == "br.gov.lexml.oai.v1"
    assert c._metadata_prefix == "oai_dc"
    assert c._set is None


# ─── _infer_norma_tipo ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "dc_type,expected",
    [
        ("Lei", "lei"),
        ("Lei Complementar", "lei_complementar"),
        ("Decreto", "decreto"),
        ("Decreto Legislativo", "decreto_legislativo"),
        ("Medida Provisória", "medida_provisoria"),
        ("Resolução", "resolucao"),
        ("Portaria", "portaria"),
        ("Instrução Normativa", "instrucao_normativa"),
        ("Lei federal nº 14000", "lei"),  # substring fallback
        ("texto livre", None),
        ("", None),
        (None, None),
    ],
)
def test_infer_norma_tipo(dc_type, expected):
    assert LexMLConnector._infer_norma_tipo(dc_type) == expected


# ─── _parse_date ─────────────────────────────────────────────────────────────


def test_parse_date_iso():
    dt = LexMLConnector._parse_date("2026-04-07")
    assert dt.tzinfo is not None
    assert dt.year == 2026 and dt.month == 4 and dt.day == 7


def test_parse_date_with_time():
    dt = LexMLConnector._parse_date("2026-04-07T10:30:00Z")
    assert dt.year == 2026


def test_parse_date_year_only():
    dt = LexMLConnector._parse_date("2026")
    assert dt.year == 2026


def test_parse_date_fallback_now():
    dt = LexMLConnector._parse_date("formato bizarro")
    assert dt.tzinfo is not None  # caiu no fallback datetime.now(UTC)


def test_parse_date_none():
    dt = LexMLConnector._parse_date(None)
    assert dt.tzinfo is not None


# ─── _parse_list_records ─────────────────────────────────────────────────────


def test_parse_list_records_happy():
    c = LexMLConnector()
    xml = _oai_envelope(records_xml=_record_xml() + _record_xml(identifier="oai:lexml:dec-1"))
    records, token = c._parse_list_records(xml)
    assert len(records) == 2
    assert token is None
    assert records[0]["urn_lex"].startswith("urn:lex:br:")
    assert records[0]["tipo"] == "Resolução"


def test_parse_list_records_with_token():
    c = LexMLConnector()
    xml = _oai_envelope(records_xml=_record_xml(), token="ABC123")
    records, token = c._parse_list_records(xml)
    assert len(records) == 1
    assert token == "ABC123"


def test_parse_list_records_skips_deleted():
    c = LexMLConnector()
    xml = _oai_envelope(
        records_xml=_record_xml() + _record_xml(identifier="oai:lexml:gone", deleted=True)
    )
    records, _ = c._parse_list_records(xml)
    assert len(records) == 1


def test_parse_list_records_no_records_match():
    c = LexMLConnector()
    xml = """<?xml version="1.0"?>
    <OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">
      <error code="noRecordsMatch">No records</error>
    </OAI-PMH>"""
    records, token = c._parse_list_records(xml)
    assert records == []
    assert token is None


def test_parse_list_records_oai_error_raises():
    c = LexMLConnector()
    xml = """<?xml version="1.0"?>
    <OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">
      <error code="badArgument">Bad arg</error>
    </OAI-PMH>"""
    with pytest.raises(AtlasConnectorError, match="badArgument"):
        c._parse_list_records(xml)


def test_parse_list_records_invalid_xml():
    c = LexMLConnector()
    with pytest.raises(AtlasConnectorParseError, match="XML inválido"):
        c._parse_list_records("<not xml")


# ─── _build_observation ──────────────────────────────────────────────────────


def test_build_observation_norma_with_urn():
    c = LexMLConnector()
    xml = _oai_envelope(records_xml=_record_xml())
    records, _ = c._parse_list_records(xml)
    obs = c._build_observation(records[0])
    assert obs is not None
    assert obs.observation_type == "norma"
    assert obs.urn_lex.startswith("urn:lex:br:")
    assert obs.norma_tipo == "resolucao"
    assert obs.orgao_publicador == "Agência Nacional de Mineração"
    assert obs.text_hash_sha3_256 is not None
    assert obs.tags == ["fonte:lexml"]


def test_build_observation_returns_none_without_id():
    c = LexMLConnector()
    obs = c._build_observation({})
    assert obs is None


# ─── _fetch_page (mock httpx) ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_page_raises_on_500():
    c = LexMLConnector()
    async with c:
        c._client.get = AsyncMock(return_value=httpx.Response(500))
        with pytest.raises(AtlasConnectorError, match="HTTP 500"):
            await c._fetch_page({"verb": "ListRecords"})


@pytest.mark.asyncio
async def test_fetch_page_wraps_network_error():
    c = LexMLConnector()
    async with c:
        c._client.get = AsyncMock(side_effect=httpx.ConnectError("offline"))
        with pytest.raises(AtlasConnectorError, match="rede"):
            await c._fetch_page({"verb": "ListRecords"})


# ─── fetch() integração ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_rejects_naive_since():
    c = LexMLConnector()
    async with c:
        with pytest.raises(ValueError, match="timezone-aware"):
            await c.fetch(datetime(2026, 4, 7))


@pytest.mark.asyncio
async def test_fetch_returns_observations_single_page():
    c = LexMLConnector()
    xml = _oai_envelope(
        records_xml=_record_xml() + _record_xml(
            identifier="oai:lexml:lei-1",
            urn="urn:lex:br:federal:lei:2026;14500",
            titulo="Lei nº 14.500",
            tipo="Lei",
            creator="Congresso Nacional",
        )
    )
    async with c:
        c._client.get = AsyncMock(return_value=_xml_response(xml))
        observations = await c.fetch(
            since=datetime(2026, 4, 1, tzinfo=timezone.utc), limit=10
        )

    assert len(observations) == 2
    tipos = {o.norma_tipo for o in observations}
    assert "resolucao" in tipos and "lei" in tipos
    assert all(o.urn_lex and o.urn_lex.startswith("urn:lex:br:") for o in observations)


@pytest.mark.asyncio
async def test_fetch_follows_resumption_token():
    c = LexMLConnector()
    page1 = _xml_response(
        _oai_envelope(records_xml=_record_xml(identifier="oai:lexml:r1"), token="TOKEN-XYZ")
    )
    page2 = _xml_response(
        _oai_envelope(records_xml=_record_xml(identifier="oai:lexml:r2"))
    )

    calls: list[dict] = []

    async def fake_get(url, params=None):
        calls.append(dict(params or {}))
        return page1 if len(calls) == 1 else page2

    async with c:
        c._client.get = AsyncMock(side_effect=fake_get)
        observations = await c.fetch(
            since=datetime(2026, 4, 1, tzinfo=timezone.utc), limit=10
        )

    assert len(observations) == 2
    # 1ª chamada: verb + metadataPrefix + from
    assert calls[0]["verb"] == "ListRecords"
    assert calls[0]["metadataPrefix"] == "oai_dc"
    assert "from" in calls[0]
    # 2ª chamada: APENAS verb + resumptionToken (regra OAI-PMH)
    assert calls[1] == {"verb": "ListRecords", "resumptionToken": "TOKEN-XYZ"}


@pytest.mark.asyncio
async def test_fetch_respects_limit():
    c = LexMLConnector()
    body = "".join(
        _record_xml(identifier=f"oai:lexml:r{i}", urn=f"urn:lex:br:x:lei:2026;{i}")
        for i in range(10)
    )
    async with c:
        c._client.get = AsyncMock(return_value=_xml_response(_oai_envelope(records_xml=body)))
        observations = await c.fetch(
            since=datetime(2026, 4, 1, tzinfo=timezone.utc), limit=3
        )
    assert len(observations) == 3


@pytest.mark.asyncio
async def test_fetch_no_records_match_returns_empty():
    c = LexMLConnector()
    xml = """<?xml version="1.0"?>
    <OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">
      <error code="noRecordsMatch">empty</error>
    </OAI-PMH>"""
    async with c:
        c._client.get = AsyncMock(return_value=_xml_response(xml))
        observations = await c.fetch(
            since=datetime(2026, 4, 1, tzinfo=timezone.utc)
        )
    assert observations == []
