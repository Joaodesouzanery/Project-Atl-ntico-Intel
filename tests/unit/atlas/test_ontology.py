"""
Testes das 15 dataclasses da ontologia Atlas.

Padrão por classe (mínimo 3): construção feliz, rejeição de datetime naive,
rejeição de identificador/enum inválido. Casos extra onde houver lógica.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from atlantico.atlas.ontology import (
    AIR,
    AcaoJudicial,
    AcordaoTCU,
    AutoInfracao,
    ConsultaPublica,
    ContratoConcessao,
    Deliberacao,
    DiretorServidor,
    DocumentoBruto,
    EventoRegulatorio,
    IndicadorMercado,
    Norma,
    ProcessoAdministrativo,
    Regulado,
    StakeholderPolitico,
    Voto,
)
from atlantico.atlas.ontology._common import compute_sha3_256, hash_cpf

UTC = timezone.utc
NOW = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)
NAIVE = datetime(2026, 4, 7, 12, 0)


# ---------------------------------------------------------------------------
# Norma
# ---------------------------------------------------------------------------


def test_norma_happy():
    n = Norma(
        tipo="resolucao",
        numero=123,
        ano=2026,
        orgao="ANM",
        ementa="Dispõe sobre lavra.",
        data_publicacao_dou=NOW,
        urn_lex="urn:lex:br:agencia.nacional.mineracao:resolucao:2026;123",
    )
    assert n.is_vigente
    assert "Resolucao ANM" in n.identificador_humano
    h = n.compute_text_hash("conteúdo")
    assert len(h) == 64


def test_norma_rejects_naive():
    with pytest.raises(ValueError):
        Norma(
            tipo="resolucao",
            numero=1,
            ano=2026,
            orgao="ANM",
            ementa="x",
            data_publicacao_dou=NAIVE,
        )


def test_norma_rejects_invalid_tipo():
    with pytest.raises(ValueError, match="tipo de norma"):
        Norma(
            tipo="manifesto",
            numero=1,
            ano=2026,
            orgao="ANM",
            ementa="x",
            data_publicacao_dou=NOW,
        )


def test_norma_rejects_bad_urn():
    with pytest.raises(ValueError, match="urn_lex"):
        Norma(
            tipo="resolucao",
            numero=1,
            ano=2026,
            orgao="ANM",
            ementa="x",
            data_publicacao_dou=NOW,
            urn_lex="urn:bad",
        )


# ---------------------------------------------------------------------------
# ProcessoAdministrativo
# ---------------------------------------------------------------------------


def test_processo_happy():
    p = ProcessoAdministrativo(
        numero_sei="48400.123456/2026-01",
        orgao="ANM",
        assunto="Outorga",
        data_autuacao=NOW,
    )
    assert p.is_ativa
    assert "48400" in p.identificador_humano


def test_processo_rejects_bad_sei():
    with pytest.raises(ValueError):
        ProcessoAdministrativo(
            numero_sei="123",
            orgao="ANM",
            assunto="x",
            data_autuacao=NOW,
        )


def test_processo_rejects_naive():
    with pytest.raises(ValueError):
        ProcessoAdministrativo(
            numero_sei="48400.123456/2026-01",
            orgao="ANM",
            assunto="x",
            data_autuacao=NAIVE,
        )


def test_processo_rejects_bad_fase():
    with pytest.raises(ValueError, match="fase"):
        ProcessoAdministrativo(
            numero_sei="48400.123456/2026-01",
            orgao="ANM",
            assunto="x",
            data_autuacao=NOW,
            fase="lala",
        )


# ---------------------------------------------------------------------------
# Deliberacao + Voto
# ---------------------------------------------------------------------------


def test_voto_happy_and_invalid():
    Voto(diretor_id="d1", sentido="favoravel")
    with pytest.raises(ValueError):
        Voto(diretor_id="d1", sentido="talvez")


def test_deliberacao_happy():
    d = Deliberacao(
        orgao="ANM",
        colegiado="diretoria_colegiada",
        numero=10,
        ano=2026,
        data_sessao=NOW,
        relator_id="d1",
        dispositivo="deferido",
        ementa="...",
        votos=[Voto("d1", "favoravel"), Voto("d2", "contrario")],
    )
    assert "10/2026" in d.identificador_humano
    d.compute_text_hash("ata")
    assert d.text_hash_sha3_256 is not None


def test_deliberacao_rejects_bad_dispositivo():
    with pytest.raises(ValueError, match="dispositivo"):
        Deliberacao(
            orgao="ANM",
            colegiado="dc",
            numero=1,
            ano=2026,
            data_sessao=NOW,
            relator_id="d1",
            dispositivo="talvez",
            ementa="x",
        )


def test_deliberacao_rejects_naive():
    with pytest.raises(ValueError):
        Deliberacao(
            orgao="ANM",
            colegiado="dc",
            numero=1,
            ano=2026,
            data_sessao=NAIVE,
            relator_id="d1",
            dispositivo="deferido",
            ementa="x",
        )


# ---------------------------------------------------------------------------
# DiretorServidor (LGPD)
# ---------------------------------------------------------------------------


def test_diretor_from_cpf_hashes():
    d = DiretorServidor.from_cpf(
        cpf="123.456.789-09",
        nome_publico="Fulano",
        orgao="ANM",
        papel="diretor",
        inicio_mandato=NOW,
    )
    assert d.cpf_hash == hash_cpf("12345678909")
    assert d.is_em_mandato
    assert "Fulano" in d.identificador_humano


def test_diretor_rejects_bad_hash_length():
    with pytest.raises(ValueError, match="cpf_hash"):
        DiretorServidor(
            cpf_hash="abc",
            nome_publico="X",
            orgao="ANM",
            papel="diretor",
            inicio_mandato=NOW,
        )


def test_diretor_rejects_bad_papel():
    with pytest.raises(ValueError, match="papel"):
        DiretorServidor(
            cpf_hash="a" * 64,
            nome_publico="X",
            orgao="ANM",
            papel="cacique",
            inicio_mandato=NOW,
        )


# ---------------------------------------------------------------------------
# Regulado
# ---------------------------------------------------------------------------


def test_regulado_happy_cnpj():
    r = Regulado(razao_social="JLR S.A.", setor="rodovias", cnpj="12.345.678/0001-95")
    assert r.cnpj == "12345678000195"
    assert "JLR" in r.identificador_humano


def test_regulado_requires_cnpj_or_cpf():
    with pytest.raises(ValueError, match="cnpj OU cpf_hash"):
        Regulado(razao_social="X", setor="y")


def test_regulado_rejects_bad_tier():
    with pytest.raises(ValueError, match="tier_risco"):
        Regulado(
            razao_social="X",
            setor="y",
            cnpj="12345678000195",
            tier_risco="EXTREMO",
        )


# ---------------------------------------------------------------------------
# ContratoConcessao
# ---------------------------------------------------------------------------


def test_contrato_happy():
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
    assert c.is_vigente
    assert "001/2026" in c.identificador_humano


def test_contrato_rejects_bad_modalidade():
    with pytest.raises(ValueError, match="modalidade"):
        ContratoConcessao(
            numero_contrato="x",
            orgao="ANTT",
            modalidade="aluguel",
            objeto="x",
            regulado_id="x",
            data_assinatura=NOW,
            prazo_anos=10,
        )


def test_contrato_rejects_zero_prazo():
    with pytest.raises(ValueError, match="prazo_anos"):
        ContratoConcessao(
            numero_contrato="x",
            orgao="ANTT",
            modalidade="concessao_comum",
            objeto="x",
            regulado_id="x",
            data_assinatura=NOW,
            prazo_anos=0,
        )


# ---------------------------------------------------------------------------
# AutoInfracao
# ---------------------------------------------------------------------------


def test_auto_happy():
    a = AutoInfracao(
        numero_auto="AI-001/2026",
        orgao="ANM",
        regulado_id="12345678000195",
        data_lavratura=NOW,
        fundamento_norma_urn="urn:lex:br:anm:resolucao:2025;10",
        descricao="Lavra sem título",
        valor_multa=Decimal("50000"),
    )
    assert "AI-001" in a.identificador_humano


def test_auto_rejects_negative_multa():
    with pytest.raises(ValueError, match="valor_multa"):
        AutoInfracao(
            numero_auto="x",
            orgao="ANM",
            regulado_id="x",
            data_lavratura=NOW,
            fundamento_norma_urn="x",
            descricao="x",
            valor_multa=Decimal("-1"),
        )


def test_auto_rejects_bad_fase():
    with pytest.raises(ValueError, match="fase_recursal"):
        AutoInfracao(
            numero_auto="x",
            orgao="ANM",
            regulado_id="x",
            data_lavratura=NOW,
            fundamento_norma_urn="x",
            descricao="x",
            valor_multa=Decimal("1"),
            fase_recursal="ze",
        )


# ---------------------------------------------------------------------------
# IndicadorMercado
# ---------------------------------------------------------------------------


def test_indicador_happy():
    i = IndicadorMercado(
        setor="energia",
        codigo="DEC",
        periodo=NOW,
        valor=Decimal("12.5"),
        unidade="horas",
        orgao_publicador="ANEEL",
    )
    assert "DEC" in i.identificador_humano


def test_indicador_rejects_naive():
    with pytest.raises(ValueError):
        IndicadorMercado(
            setor="energia",
            codigo="DEC",
            periodo=NAIVE,
            valor=Decimal("1"),
            unidade="h",
            orgao_publicador="ANEEL",
        )


def test_indicador_rejects_bad_classification():
    with pytest.raises(ValueError, match="data_classification"):
        IndicadorMercado(
            setor="energia",
            codigo="DEC",
            periodo=NOW,
            valor=Decimal("1"),
            unidade="h",
            orgao_publicador="ANEEL",
            data_classification="LEAK",
        )


# ---------------------------------------------------------------------------
# ConsultaPublica
# ---------------------------------------------------------------------------


def test_consulta_happy():
    cp = ConsultaPublica(
        orgao="ANM",
        numero=5,
        ano=2026,
        objeto="Revisão CFEM",
        data_abertura=NOW,
        data_encerramento=NOW + timedelta(days=30),
    )
    assert "5/2026" in cp.identificador_humano


def test_consulta_rejects_inverted_dates():
    with pytest.raises(ValueError, match="data_encerramento"):
        ConsultaPublica(
            orgao="ANM",
            numero=1,
            ano=2026,
            objeto="x",
            data_abertura=NOW,
            data_encerramento=NOW - timedelta(days=1),
        )


def test_consulta_rejects_negative_contrib():
    with pytest.raises(ValueError, match="contribuicoes"):
        ConsultaPublica(
            orgao="ANM",
            numero=1,
            ano=2026,
            objeto="x",
            data_abertura=NOW,
            data_encerramento=NOW + timedelta(days=1),
            contribuicoes_recebidas=-1,
        )


# ---------------------------------------------------------------------------
# AIR
# ---------------------------------------------------------------------------


def test_air_happy():
    a = AIR(
        orgao="ANM",
        problema="Sub-aplicação",
        alternativas=["status quo", "norma A", "norma B"],
        data_inicio=NOW,
        alternativa_recomendada_idx=1,
    )
    assert "ANM" in a.identificador_humano
    assert len(a.id_air) == 36


def test_air_rejects_empty_alternativas():
    with pytest.raises(ValueError, match="alternativa"):
        AIR(orgao="ANM", problema="x", alternativas=[], data_inicio=NOW)


def test_air_rejects_bad_idx():
    with pytest.raises(ValueError, match="alternativa_recomendada_idx"):
        AIR(
            orgao="ANM",
            problema="x",
            alternativas=["a"],
            data_inicio=NOW,
            alternativa_recomendada_idx=5,
        )


# ---------------------------------------------------------------------------
# AcaoJudicial
# ---------------------------------------------------------------------------


def test_acao_judicial_happy():
    a = AcaoJudicial(
        numero_cnj="00000010120238260100",
        tribunal="TJSP",
        classe="ADI",
        data_distribuicao=NOW,
    )
    assert a.numero_cnj == "0000001-01.2023.8.26.0100"
    assert "TJSP" in a.identificador_humano


def test_acao_judicial_rejects_bad_cnj():
    with pytest.raises(ValueError):
        AcaoJudicial(
            numero_cnj="123",
            tribunal="x",
            classe="x",
            data_distribuicao=NOW,
        )


def test_acao_judicial_rejects_bad_status():
    with pytest.raises(ValueError, match="status"):
        AcaoJudicial(
            numero_cnj="00000010120238260100",
            tribunal="x",
            classe="x",
            data_distribuicao=NOW,
            status="zumbi",
        )


# ---------------------------------------------------------------------------
# AcordaoTCU
# ---------------------------------------------------------------------------


def test_acordao_happy():
    a = AcordaoTCU(
        numero=1234,
        ano=2026,
        colegiado="plenario",
        data_sessao=NOW,
        relator="Min. X",
        area_tematica="infraestrutura",
        ementa="...",
    )
    assert "1234/2026" in a.identificador_humano
    a.compute_text_hash("acordao")
    assert a.text_hash_sha3_256


def test_acordao_rejects_bad_colegiado():
    with pytest.raises(ValueError, match="colegiado"):
        AcordaoTCU(
            numero=1,
            ano=2026,
            colegiado="terceira_camara",
            data_sessao=NOW,
            relator="x",
            area_tematica="x",
            ementa="x",
        )


def test_acordao_rejects_negative_prazo():
    with pytest.raises(ValueError, match="prazo"):
        AcordaoTCU(
            numero=1,
            ano=2026,
            colegiado="plenario",
            data_sessao=NOW,
            relator="x",
            area_tematica="x",
            ementa="x",
            prazo_cumprimento_dias=-1,
        )


# ---------------------------------------------------------------------------
# StakeholderPolitico
# ---------------------------------------------------------------------------


def test_stakeholder_happy():
    s = StakeholderPolitico(
        id_externo="cam-204554",
        nome="Fulano",
        tipo="deputado",
        fonte="camara",
        sigla_partido="XXX",
        uf="SP",
    )
    assert "(XXX/SP)" in s.identificador_humano


def test_stakeholder_rejects_bad_tipo():
    with pytest.raises(ValueError, match="tipo"):
        StakeholderPolitico(
            id_externo="x", nome="x", tipo="cacique", fonte="camara"
        )


def test_stakeholder_rejects_bad_uf():
    with pytest.raises(ValueError, match="uf"):
        StakeholderPolitico(
            id_externo="x",
            nome="x",
            tipo="deputado",
            fonte="camara",
            uf="SAO",
        )


# ---------------------------------------------------------------------------
# EventoRegulatorio
# ---------------------------------------------------------------------------


def test_evento_happy():
    e = EventoRegulatorio(
        tipo="apagao",
        titulo="Blackout SE",
        data_evento=NOW,
        setor_afetado="energia",
        descricao="...",
        geo_uf=["SP", "RJ"],
        severidade="ALTA",
    )
    assert "Apagao" in e.identificador_humano


def test_evento_rejects_bad_tipo():
    with pytest.raises(ValueError, match="tipo"):
        EventoRegulatorio(
            tipo="festa",
            titulo="x",
            data_evento=NOW,
            setor_afetado="x",
            descricao="x",
        )


def test_evento_rejects_bad_uf():
    with pytest.raises(ValueError, match="UF"):
        EventoRegulatorio(
            tipo="apagao",
            titulo="x",
            data_evento=NOW,
            setor_afetado="x",
            descricao="x",
            geo_uf=["SAO"],
        )


# ---------------------------------------------------------------------------
# DocumentoBruto
# ---------------------------------------------------------------------------


def test_documento_from_text():
    d = DocumentoBruto.from_text(
        text="conteúdo bruto",
        source_url="https://x/y.pdf",
        mime_type="application/pdf",
        fetched_at=NOW,
    )
    assert d.text_hash_sha3_256 == compute_sha3_256("conteúdo bruto")
    assert "Doc[" in d.identificador_humano


def test_documento_rejects_bad_hash():
    with pytest.raises(ValueError, match="text_hash_sha3_256"):
        DocumentoBruto(
            text_hash_sha3_256="abc",
            source_url="x",
            mime_type="application/pdf",
            fetched_at=NOW,
        )


def test_documento_rejects_bad_mime():
    with pytest.raises(ValueError, match="mime_type"):
        DocumentoBruto(
            text_hash_sha3_256="a" * 64,
            source_url="x",
            mime_type="image/png",
            fetched_at=NOW,
        )


def test_documento_rejects_bad_ocr_confidence():
    with pytest.raises(ValueError, match="ocr_confidence"):
        DocumentoBruto(
            text_hash_sha3_256="a" * 64,
            source_url="x",
            mime_type="application/pdf",
            fetched_at=NOW,
            ocr_confidence=1.5,
        )
