"""
Testes do AtlasIngestionPipeline.

Inclui o **caso de uso central do PR5**: entity resolution DOU↔LexML.
Uma observação do DOU (sem URN) e a observação LexML correspondente
(com URN) são ingeridas pelo pipeline e convergem para a mesma linha
no banco — primeiro caso real do entity resolution Gotham-style.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from atlantico.atlas.ingestion.pipeline import AtlasIngestionPipeline
from atlantico.atlas.observations import AtlasObservation
from atlantico.atlas.storage.repositories import NormaRepository

UTC = timezone.utc
NOW = datetime(2026, 4, 7, tzinfo=UTC)

pytestmark = pytest.mark.asyncio


def _make_connector(observations):
    """Cria um stub de AtlasConnector que retorna observations fixas."""
    connector = AsyncMock()
    connector.fetch = AsyncMock(return_value=observations)
    return connector


def _dou_obs(numero: int = 123) -> AtlasObservation:
    return AtlasObservation(
        source_id="br.gov.in.dou.v1",
        external_id=f"dou-{numero}",
        observation_type="norma",
        reference_date=NOW,
        payload={"title": f"RESOLUÇÃO ANM Nº {numero}, DE 7 DE ABRIL DE 2026"},
        norma_tipo="resolucao",
        orgao_publicador="ANM",
        urn_lex=None,
        tags=["secao:do1"],
    )


def _lexml_obs(numero: int = 123) -> AtlasObservation:
    return AtlasObservation(
        source_id="br.gov.lexml.oai.v1",
        external_id=f"oai:lexml:res-anm-{numero}-2026",
        observation_type="norma",
        reference_date=NOW,
        payload={"titulo": f"Resolução ANM nº {numero}, de 2026"},
        norma_tipo="resolucao",
        orgao_publicador="ANM",
        urn_lex=f"urn:lex:br:agencia.nacional.mineracao:resolucao:2026;{numero}",
        tags=["fonte:lexml"],
    )


# ─── Caminhos básicos ────────────────────────────────────────────────────────


async def test_pipeline_stores_normas(atlas_session):
    repo = NormaRepository(atlas_session)
    connector = _make_connector(
        [_dou_obs(1), _dou_obs(2), _dou_obs(3)]
    )
    pipeline = AtlasIngestionPipeline(connector, repo)
    stats = await pipeline.run(since=NOW, limit=10)

    assert stats.fetched == 3
    assert stats.converted == 3
    assert stats.stored == 3
    assert stats.skipped == 0
    assert stats.errors == 0


async def test_pipeline_records_skip_reasons(atlas_session):
    repo = NormaRepository(atlas_session)
    bad = AtlasObservation(
        source_id="x",
        external_id="bad-1",
        observation_type="norma",
        reference_date=NOW,
        payload={"title": "Aviso geral"},
        norma_tipo=None,  # vai cair em "norma_tipo ausente"
        orgao_publicador="ANM",
    )
    connector = _make_connector([_dou_obs(10), bad])
    pipeline = AtlasIngestionPipeline(connector, repo)
    stats = await pipeline.run(since=NOW)

    assert stats.fetched == 2
    assert stats.stored == 1
    assert stats.skipped == 1
    assert any("norma_tipo" in k for k in stats.skip_reasons)


async def test_pipeline_idempotent_on_rerun(atlas_session):
    repo = NormaRepository(atlas_session)
    pipeline = AtlasIngestionPipeline(_make_connector([_dou_obs(50)]), repo)
    s1 = await pipeline.run(since=NOW)
    s2 = await pipeline.run(since=NOW)
    assert s1.stored == 1
    assert s2.stored == 1
    # Mesmo natural key — segunda execução não duplica linha
    all_normas = await repo.list_by_orgao("ANM", since=NOW.replace(year=2020))
    assert len(all_normas) == 1


async def test_pipeline_handles_connector_failure(atlas_session):
    repo = NormaRepository(atlas_session)
    connector = AsyncMock()
    connector.fetch = AsyncMock(side_effect=RuntimeError("rede caiu"))
    pipeline = AtlasIngestionPipeline(connector, repo)
    stats = await pipeline.run(since=NOW)
    assert stats.errors == 1
    assert "rede caiu" in stats.error_messages[0]
    assert stats.fetched == 0


# ─── ⭐ Entity resolution DOU ↔ LexML ────────────────────────────────────────


async def test_entity_resolution_dou_then_lexml_converge(atlas_session):
    """
    Cenário: o DOU publica a Resolução ANM nº 7/2026 sem URN canônica.
    Horas depois, o LexML federa o mesmo ato com a URN.
    O pipeline ingere ambos. Resultado: **uma única linha** no banco
    (matched por chave natural orgao+tipo+numero+ano).

    Este é o teste mais importante do Sprint 4 — prova que a fundação
    permite entity resolution na fronteira da ingestão.
    """
    repo = NormaRepository(atlas_session)

    # 1ª ingestão — DOU sem URN
    dou_pipe = AtlasIngestionPipeline(_make_connector([_dou_obs(7)]), repo)
    s1 = await dou_pipe.run(since=NOW)
    assert s1.stored == 1
    first = await repo.list_by_orgao("ANM", since=NOW.replace(year=2020))
    assert len(first) == 1
    assert first[0].urn_lex is None  # DOU não trouxe URN

    # 2ª ingestão — LexML com URN
    lex_pipe = AtlasIngestionPipeline(_make_connector([_lexml_obs(7)]), repo)
    s2 = await lex_pipe.run(since=NOW)
    assert s2.stored == 1

    # ⭐ Convergência: ainda é UMA linha (idempotente na chave natural)
    after = await repo.list_by_orgao("ANM", since=NOW.replace(year=2020))
    assert len(after) == 1
    # O id é o mesmo da 1ª ingestão
    assert after[0].id == first[0].id


async def test_entity_resolution_does_not_collapse_distinct_normas(atlas_session):
    """Sanity: normas com numero/ano diferentes NÃO são unificadas."""
    repo = NormaRepository(atlas_session)
    pipe = AtlasIngestionPipeline(
        _make_connector([_dou_obs(1), _lexml_obs(2), _dou_obs(3)]), repo
    )
    await pipe.run(since=NOW)
    all_n = await repo.list_by_orgao("ANM", since=NOW.replace(year=2020))
    assert len(all_n) == 3
