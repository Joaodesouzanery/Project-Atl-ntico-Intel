"""Testes do normalizador AtlasObservation → Norma."""

from datetime import datetime, timezone

import pytest

from atlantico.atlas.ingestion.normalizer import (
    _parse_ano,
    _parse_numero,
    observation_to_norma,
)
from atlantico.atlas.observations import AtlasObservation

UTC = timezone.utc
NOW = datetime(2026, 4, 7, tzinfo=UTC)


# ─── _parse_numero ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "title,expected",
    [
        ("RESOLUÇÃO ANM Nº 123", 123),
        ("LEI Nº 14.500, DE 2026", 14500),
        ("Decreto nº 12.345/2026", 12345),
        ("PORTARIA No 50", 50),
        ("Aviso geral", None),
        ("RESOLUÇÃO Nº 1.234.567", 1234567),
    ],
)
def test_parse_numero(title, expected):
    assert _parse_numero(title) == expected


# ─── _parse_ano ──────────────────────────────────────────────────────────────


def test_parse_ano_from_title():
    assert _parse_ano("LEI Nº 14.500, DE 7 DE ABRIL DE 2026", NOW) == 2026


def test_parse_ano_fallback_reference_date():
    assert _parse_ano("RESOLUÇÃO Nº 5", NOW) == 2026


def test_parse_ano_ignores_out_of_range():
    # 1500 está fora do range válido [1900, 2100] → cai no fallback (NOW.year)
    assert _parse_ano("Algo nº 1 ano 1500", NOW) == 2026


# ─── observation_to_norma — fluxos felizes ───────────────────────────────────


def _obs(
    *,
    title: str = "RESOLUÇÃO ANM Nº 123, DE 7 DE ABRIL DE 2026",
    norma_tipo: str | None = "resolucao",
    orgao: str | None = "ANM",
    urn_lex: str | None = None,
    obs_type: str = "norma",
) -> AtlasObservation:
    return AtlasObservation(
        source_id="br.gov.in.dou.v1",
        external_id="abc123",
        observation_type=obs_type,
        reference_date=NOW,
        payload={"title": title},
        norma_tipo=norma_tipo,
        orgao_publicador=orgao,
        urn_lex=urn_lex,
        tags=["secao:do1"],
    )


def test_normalize_dou_resolucao():
    result = observation_to_norma(_obs())
    assert result.norma is not None
    n = result.norma
    assert n.tipo == "resolucao"
    assert n.numero == 123
    assert n.ano == 2026
    assert n.orgao == "ANM"
    assert n.urn_lex is None  # DOU não traz URN
    assert n.text_hash_sha3_256 is not None


def test_normalize_lexml_with_urn():
    obs = _obs(
        title="Resolução ANM nº 123, de 2026",
        urn_lex="urn:lex:br:agencia.nacional.mineracao:resolucao:2026;123",
    )
    obs.source_id = "br.gov.lexml.oai.v1"
    result = observation_to_norma(obs)
    assert result.norma is not None
    assert result.norma.urn_lex.startswith("urn:lex:br:")
    assert result.norma.numero == 123


# ─── observation_to_norma — skips ────────────────────────────────────────────


def test_skip_non_norma_observation_type():
    result = observation_to_norma(_obs(obs_type="documento_bruto", norma_tipo=None))
    assert result.norma is None
    assert "non" in result.reason or "norma" in result.reason


def test_skip_missing_norma_tipo():
    result = observation_to_norma(_obs(norma_tipo=None))
    assert result.norma is None
    assert "norma_tipo" in result.reason


def test_skip_missing_orgao():
    result = observation_to_norma(_obs(orgao=None))
    assert result.norma is None
    assert "orgao" in result.reason


def test_skip_unparseable_numero():
    result = observation_to_norma(_obs(title="RESOLUÇÃO sem número"))
    assert result.norma is None
    assert "número" in result.reason
