"""Testes dos mappers dataclass ↔ model (sem DB)."""

from datetime import datetime, timezone
from decimal import Decimal

from atlantico.atlas.ontology import (
    ContratoConcessao,
    Deliberacao,
    Norma,
    ProcessoAdministrativo,
    Regulado,
    Voto,
)
from atlantico.atlas.storage.mappers import (
    contrato_from_model,
    contrato_to_kwargs,
    deliberacao_from_model,
    deliberacao_to_kwargs,
    norma_from_model,
    norma_to_kwargs,
    processo_from_model,
    processo_to_kwargs,
    regulado_from_model,
    regulado_to_kwargs,
)
from atlantico.atlas.storage.models import (
    ContratoConcessaoModel,
    DeliberacaoModel,
    NormaModel,
    ProcessoAdministrativoModel,
    ReguladoModel,
)

UTC = timezone.utc
NOW = datetime(2026, 4, 7, tzinfo=UTC)


# ─── Norma ────────────────────────────────────────────────────────────────────


def test_norma_to_kwargs_contains_all_fields():
    n = Norma(
        tipo="resolucao",
        numero=123,
        ano=2026,
        orgao="ANM",
        ementa="x",
        data_publicacao_dou=NOW,
        urn_lex="urn:lex:br:anm:resolucao:2026;123",
        tags=["a", "b"],
    )
    kw = norma_to_kwargs(n)
    assert kw["urn_lex"] == n.urn_lex
    assert kw["tags"] == ["a", "b"]
    assert kw["data_publicacao_dou"] is NOW
    assert kw["confidence"] == 1.0


def test_norma_roundtrip():
    n = Norma(
        tipo="decreto",
        numero=10,
        ano=2026,
        orgao="Casa Civil",
        ementa="dispoe sobre x",
        data_publicacao_dou=NOW,
        urn_lex="urn:lex:br:federal:decreto:2026;10",
        tags=["dou:do1"],
    )
    model = NormaModel(**norma_to_kwargs(n))
    back = norma_from_model(model)
    assert back.tipo == n.tipo
    assert back.numero == n.numero
    assert back.ano == n.ano
    assert back.urn_lex == n.urn_lex
    assert back.tags == n.tags
    assert back.is_vigente


# ─── Processo ─────────────────────────────────────────────────────────────────


def test_processo_roundtrip():
    p = ProcessoAdministrativo(
        numero_sei="48400.123456/2026-01",
        orgao="ANM",
        assunto="Outorga",
        data_autuacao=NOW,
        partes=["JLR S.A."],
        fase="instrucao",
    )
    model = ProcessoAdministrativoModel(**processo_to_kwargs(p))
    back = processo_from_model(model)
    assert back.numero_sei == p.numero_sei
    assert back.fase == "instrucao"
    assert back.partes == ["JLR S.A."]
    assert back.is_ativa


# ─── Deliberacao ──────────────────────────────────────────────────────────────


def test_deliberacao_roundtrip_with_votos():
    d = Deliberacao(
        orgao="ANM",
        colegiado="diretoria_colegiada",
        numero=10,
        ano=2026,
        data_sessao=NOW,
        relator_id="d1",
        dispositivo="deferido",
        ementa="...",
        votos=[Voto("d1", "favoravel", "voto técnico"), Voto("d2", "contrario")],
        norma_citada_urns=["urn:lex:br:anm:resolucao:2025;5"],
    )
    kw = deliberacao_to_kwargs(d)
    # Votos devem virar lista de dicts JSON-serializáveis
    assert isinstance(kw["votos"], list)
    assert kw["votos"][0] == {
        "diretor_id": "d1",
        "sentido": "favoravel",
        "fundamento_resumo": "voto técnico",
    }

    model = DeliberacaoModel(**kw)
    back = deliberacao_from_model(model)
    assert len(back.votos) == 2
    assert back.votos[0].sentido == "favoravel"
    assert back.norma_citada_urns == d.norma_citada_urns


# ─── Regulado ─────────────────────────────────────────────────────────────────


def test_regulado_roundtrip_pj():
    r = Regulado(
        razao_social="JLR S.A.",
        setor="rodovias",
        cnpj="12.345.678/0001-95",
        grupo_economico="Holding XPTO",
        tier_risco="ALTO",
    )
    model = ReguladoModel(**regulado_to_kwargs(r))
    back = regulado_from_model(model)
    assert back.cnpj == "12345678000195"
    assert back.tier_risco == "ALTO"
    assert back.grupo_economico == "Holding XPTO"


def test_regulado_roundtrip_pf():
    r = Regulado(
        razao_social="João da Silva",
        setor="garimpo",
        cpf_hash="a" * 64,
    )
    model = ReguladoModel(**regulado_to_kwargs(r))
    back = regulado_from_model(model)
    assert back.cnpj is None
    assert back.cpf_hash == "a" * 64


# ─── Contrato ─────────────────────────────────────────────────────────────────


def test_contrato_roundtrip_with_decimal():
    c = ContratoConcessao(
        numero_contrato="001/2026",
        orgao="ANTT",
        modalidade="concessao_comum",
        objeto="BR-101",
        regulado_id="12345678000195",
        data_assinatura=NOW,
        prazo_anos=30,
        valor_total=Decimal("1500000000.50"),
        contraprestacao=Decimal("100.00"),
        cronograma_marcos=["m1", "m2"],
    )
    model = ContratoConcessaoModel(**contrato_to_kwargs(c))
    back = contrato_from_model(model)
    assert back.valor_total == Decimal("1500000000.50")
    assert back.contraprestacao == Decimal("100.00")
    assert back.cronograma_marcos == ["m1", "m2"]
    assert back.is_vigente


def test_contrato_roundtrip_handles_null_money():
    c = ContratoConcessao(
        numero_contrato="002/2026",
        orgao="ANTT",
        modalidade="permissao",
        objeto="x",
        regulado_id="x",
        data_assinatura=NOW,
        prazo_anos=10,
    )
    model = ContratoConcessaoModel(**contrato_to_kwargs(c))
    back = contrato_from_model(model)
    assert back.valor_total is None
    assert back.contraprestacao is None
