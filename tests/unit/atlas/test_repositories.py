"""
Testes de repositórios Atlas (SQLite in-memory).

Garantem store + idempotência (on_conflict_do_nothing) + queries básicas
para os 5 repos. Para PG-only, use tests/integration.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from atlantico.atlas.ontology import (
    ContratoConcessao,
    Deliberacao,
    Norma,
    ProcessoAdministrativo,
    Regulado,
    Voto,
)
from atlantico.atlas.storage.repositories import (
    ContratoConcessaoRepository,
    DeliberacaoRepository,
    NormaRepository,
    ProcessoAdministrativoRepository,
    ReguladoRepository,
)

UTC = timezone.utc
NOW = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)

pytestmark = pytest.mark.asyncio


# ─── NormaRepository ─────────────────────────────────────────────────────────


def _norma(numero: int = 123, urn: str | None = "urn:lex:br:anm:resolucao:2026;123") -> Norma:
    return Norma(
        tipo="resolucao",
        numero=numero,
        ano=2026,
        orgao="ANM",
        ementa="Dispõe sobre lavra.",
        data_publicacao_dou=NOW,
        urn_lex=urn,
        tags=["dou:do1"],
    )


async def test_norma_store_and_get_by_urn(atlas_session):
    repo = NormaRepository(atlas_session)
    n = _norma()
    model = await repo.store(n)
    assert model.urn_lex == n.urn_lex
    assert model.id is not None

    fetched = await repo.get_by_urn(n.urn_lex)
    assert fetched is not None
    assert fetched.numero == 123


async def test_norma_store_idempotent(atlas_session):
    repo = NormaRepository(atlas_session)
    n = _norma()
    m1 = await repo.store(n)
    m2 = await repo.store(n)
    # Mesma chave natural → mesma linha (sem duplicata)
    assert m1.id == m2.id


async def test_norma_list_by_orgao(atlas_session):
    repo = NormaRepository(atlas_session)
    await repo.store(_norma(numero=1, urn="urn:lex:br:anm:resolucao:2026;1"))
    await repo.store(_norma(numero=2, urn="urn:lex:br:anm:resolucao:2026;2"))
    results = await repo.list_by_orgao("ANM", since=NOW - timedelta(days=10))
    assert len(results) == 2


async def test_norma_count_by_tipo(atlas_session):
    repo = NormaRepository(atlas_session)
    await repo.store(_norma(numero=1, urn="urn:lex:br:anm:resolucao:2026;1"))
    await repo.store(_norma(numero=2, urn="urn:lex:br:anm:resolucao:2026;2"))
    counts = await repo.count_by_tipo(since=NOW - timedelta(days=10))
    assert counts.get("resolucao") == 2


async def test_norma_fetch_dataclass(atlas_session):
    repo = NormaRepository(atlas_session)
    await repo.store(_norma())
    dc = await repo.fetch_dataclass("urn:lex:br:anm:resolucao:2026;123")
    assert dc is not None
    assert isinstance(dc, Norma)
    assert dc.identificador_humano.startswith("Resolucao ANM")


# ─── ProcessoAdministrativoRepository ────────────────────────────────────────


async def test_processo_store_and_idempotent(atlas_session):
    repo = ProcessoAdministrativoRepository(atlas_session)
    p = ProcessoAdministrativo(
        numero_sei="48400.123456/2026-01",
        orgao="ANM",
        assunto="Outorga",
        data_autuacao=NOW,
    )
    m1 = await repo.store(p)
    m2 = await repo.store(p)
    assert m1.id == m2.id
    assert m1.numero_sei == "48400.123456/2026-01"


async def test_processo_list_ativos_excludes_arquivado(atlas_session):
    repo = ProcessoAdministrativoRepository(atlas_session)
    await repo.store(
        ProcessoAdministrativo(
            numero_sei="48400.000001/2026-01",
            orgao="ANM",
            assunto="x",
            data_autuacao=NOW,
            fase="instrucao",
        )
    )
    await repo.store(
        ProcessoAdministrativo(
            numero_sei="48400.000002/2026-01",
            orgao="ANM",
            assunto="y",
            data_autuacao=NOW,
            fase="arquivado",
        )
    )
    ativos = await repo.list_ativos("ANM")
    assert len(ativos) == 1
    assert ativos[0].numero_sei == "48400.000001/2026-01"


async def test_processo_fetch_dataclass(atlas_session):
    repo = ProcessoAdministrativoRepository(atlas_session)
    await repo.store(
        ProcessoAdministrativo(
            numero_sei="48400.999999/2026-01",
            orgao="ANM",
            assunto="x",
            data_autuacao=NOW,
        )
    )
    dc = await repo.fetch_dataclass("48400.999999/2026-01")
    assert dc is not None
    assert isinstance(dc, ProcessoAdministrativo)


# ─── DeliberacaoRepository ───────────────────────────────────────────────────


def _delib(numero: int = 10, dispositivo: str = "deferido") -> Deliberacao:
    return Deliberacao(
        orgao="ANM",
        colegiado="diretoria_colegiada",
        numero=numero,
        ano=2026,
        data_sessao=NOW,
        relator_id="d1",
        dispositivo=dispositivo,
        ementa="...",
        votos=[Voto("d1", "favoravel")],
    )


async def test_deliberacao_store_idempotent_and_votos_persist(atlas_session):
    repo = DeliberacaoRepository(atlas_session)
    m1 = await repo.store(_delib())
    m2 = await repo.store(_delib())
    assert m1.id == m2.id
    assert m1.votos[0]["sentido"] == "favoravel"


async def test_deliberacao_list_by_dispositivo(atlas_session):
    repo = DeliberacaoRepository(atlas_session)
    await repo.store(_delib(numero=1, dispositivo="deferido"))
    await repo.store(_delib(numero=2, dispositivo="indeferido"))
    deferidos = await repo.list_by_dispositivo(
        "ANM", "deferido", since=NOW - timedelta(days=10)
    )
    assert len(deferidos) == 1


async def test_deliberacao_list_by_relator(atlas_session):
    repo = DeliberacaoRepository(atlas_session)
    await repo.store(_delib(numero=1))
    relator = await repo.list_by_relator("d1", since=NOW - timedelta(days=10))
    assert len(relator) == 1


async def test_deliberacao_fetch_dataclass(atlas_session):
    repo = DeliberacaoRepository(atlas_session)
    await repo.store(_delib())
    dc = await repo.fetch_dataclass("ANM", "diretoria_colegiada", 10, 2026)
    assert dc is not None
    assert dc.votos[0].sentido == "favoravel"


# ─── ReguladoRepository ──────────────────────────────────────────────────────


async def test_regulado_store_pj_idempotent(atlas_session):
    repo = ReguladoRepository(atlas_session)
    r = Regulado(razao_social="JLR S.A.", setor="rodovias", cnpj="12345678000195")
    m1 = await repo.store(r)
    m2 = await repo.store(r)
    assert m1.id == m2.id


async def test_regulado_store_pf(atlas_session):
    repo = ReguladoRepository(atlas_session)
    r = Regulado(razao_social="João", setor="garimpo", cpf_hash="b" * 64)
    m = await repo.store(r)
    assert m.cnpj is None
    assert m.cpf_hash == "b" * 64


async def test_regulado_list_by_setor_tier(atlas_session):
    repo = ReguladoRepository(atlas_session)
    await repo.store(
        Regulado(
            razao_social="A",
            setor="rodovias",
            cnpj="12345678000101",
            tier_risco="ALTO",
        )
    )
    await repo.store(
        Regulado(
            razao_social="B",
            setor="rodovias",
            cnpj="12345678000202",
            tier_risco="BAIXO",
        )
    )
    altos = await repo.list_by_setor_tier("rodovias", "ALTO")
    assert len(altos) == 1
    assert altos[0].razao_social == "A"


async def test_regulado_fetch_dataclass(atlas_session):
    repo = ReguladoRepository(atlas_session)
    await repo.store(
        Regulado(razao_social="X", setor="energia", cnpj="98765432000100")
    )
    dc = await repo.fetch_dataclass("98765432000100")
    assert dc is not None
    assert isinstance(dc, Regulado)


# ─── ContratoConcessaoRepository ─────────────────────────────────────────────


async def test_contrato_store_idempotent(atlas_session):
    repo = ContratoConcessaoRepository(atlas_session)
    c = ContratoConcessao(
        numero_contrato="001/2026",
        orgao="ANTT",
        modalidade="concessao_comum",
        objeto="BR-101",
        regulado_id="12345678000195",
        data_assinatura=NOW,
        prazo_anos=30,
        valor_total=Decimal("1000000000"),
    )
    m1 = await repo.store(c)
    m2 = await repo.store(c)
    assert m1.id == m2.id


async def test_contrato_list_by_regulado(atlas_session):
    repo = ContratoConcessaoRepository(atlas_session)
    await repo.store(
        ContratoConcessao(
            numero_contrato="001/2026",
            orgao="ANTT",
            modalidade="concessao_comum",
            objeto="BR-101",
            regulado_id="GRUPO-1",
            data_assinatura=NOW,
            prazo_anos=30,
        )
    )
    await repo.store(
        ContratoConcessao(
            numero_contrato="002/2026",
            orgao="ANTT",
            modalidade="permissao",
            objeto="BR-102",
            regulado_id="GRUPO-1",
            data_assinatura=NOW,
            prazo_anos=15,
        )
    )
    results = await repo.list_by_regulado("GRUPO-1")
    assert len(results) == 2


async def test_contrato_fetch_dataclass_with_decimal(atlas_session):
    repo = ContratoConcessaoRepository(atlas_session)
    await repo.store(
        ContratoConcessao(
            numero_contrato="003/2026",
            orgao="ANTT",
            modalidade="concessao_comum",
            objeto="BR-103",
            regulado_id="X",
            data_assinatura=NOW,
            prazo_anos=20,
            valor_total=Decimal("500000000.50"),
        )
    )
    dc = await repo.fetch_dataclass("ANTT", "003/2026")
    assert dc is not None
    assert dc.valor_total == Decimal("500000000.50")
