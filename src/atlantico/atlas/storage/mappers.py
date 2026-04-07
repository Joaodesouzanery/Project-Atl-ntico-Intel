"""
Mappers dataclass ↔ SQLAlchemy model para os 5 objetos core do Atlas.

Cada par tem duas funções: ``<obj>_to_model(dc) -> ModelKwargs`` (dict
pronto para insert/update) e ``<obj>_from_model(row) -> dataclass``.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any


def _ensure_utc(value: datetime | None) -> datetime | None:
    """
    Reanexa tzinfo=UTC quando o backend devolve datetime naive.

    SQLite (usado em testes unitários) descarta tzinfo mesmo quando a
    coluna é declarada como ``DateTime(timezone=True)``. PostgreSQL
    preserva. Esta função normaliza ambos os casos para que a ontologia
    receba sempre datetimes timezone-aware (lição NVD do SIGINT).
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value

from atlantico.atlas.ontology import (
    ContratoConcessao,
    Deliberacao,
    Norma,
    ProcessoAdministrativo,
    Regulado,
    Voto,
)
from atlantico.atlas.storage.models import (
    ContratoConcessaoModel,
    DeliberacaoModel,
    NormaModel,
    ProcessoAdministrativoModel,
    ReguladoModel,
)


# ─── Norma ────────────────────────────────────────────────────────────────────


def norma_to_kwargs(n: Norma) -> dict[str, Any]:
    return {
        "urn_lex": n.urn_lex,
        "tipo": n.tipo,
        "numero": n.numero,
        "ano": n.ano,
        "orgao": n.orgao,
        "ementa": n.ementa,
        "data_publicacao_dou": n.data_publicacao_dou,
        "vigencia_inicio": n.vigencia_inicio,
        "vigencia_fim": n.vigencia_fim,
        "revogada_por_urn": n.revogada_por_urn,
        "air_vinculada_id": n.air_vinculada_id,
        "texto_canonico_url": n.texto_canonico_url,
        "dou_url": n.dou_url,
        "text_hash_sha3_256": n.text_hash_sha3_256,
        "confidence": n.confidence,
        "data_classification": n.data_classification,
        "source_id": n.source_id,
        "tags": list(n.tags),
    }


def norma_from_model(m: NormaModel) -> Norma:
    return Norma(
        tipo=m.tipo,
        numero=m.numero,
        ano=m.ano,
        orgao=m.orgao,
        ementa=m.ementa,
        data_publicacao_dou=_ensure_utc(m.data_publicacao_dou),
        urn_lex=m.urn_lex,
        vigencia_inicio=_ensure_utc(m.vigencia_inicio),
        vigencia_fim=_ensure_utc(m.vigencia_fim),
        revogada_por_urn=m.revogada_por_urn,
        air_vinculada_id=m.air_vinculada_id,
        texto_canonico_url=m.texto_canonico_url,
        dou_url=m.dou_url,
        text_hash_sha3_256=m.text_hash_sha3_256,
        confidence=m.confidence,
        data_classification=m.data_classification,
        source_id=m.source_id,
        tags=list(m.tags or []),
    )


# ─── ProcessoAdministrativo ───────────────────────────────────────────────────


def processo_to_kwargs(p: ProcessoAdministrativo) -> dict[str, Any]:
    return {
        "numero_sei": p.numero_sei,
        "orgao": p.orgao,
        "assunto": p.assunto,
        "data_autuacao": p.data_autuacao,
        "fase": p.fase,
        "partes": list(p.partes),
        "prazo_legal": p.prazo_legal,
        "data_conclusao": p.data_conclusao,
        "norma_relacionada_urn": p.norma_relacionada_urn,
        "source_url": p.source_url,
        "source_id": p.source_id,
        "text_hash_sha3_256": p.text_hash_sha3_256,
        "confidence": p.confidence,
        "data_classification": p.data_classification,
        "tags": list(p.tags),
    }


def processo_from_model(m: ProcessoAdministrativoModel) -> ProcessoAdministrativo:
    return ProcessoAdministrativo(
        numero_sei=m.numero_sei,
        orgao=m.orgao,
        assunto=m.assunto,
        data_autuacao=_ensure_utc(m.data_autuacao),
        fase=m.fase,
        partes=list(m.partes or []),
        prazo_legal=_ensure_utc(m.prazo_legal),
        data_conclusao=_ensure_utc(m.data_conclusao),
        norma_relacionada_urn=m.norma_relacionada_urn,
        source_url=m.source_url,
        source_id=m.source_id,
        text_hash_sha3_256=m.text_hash_sha3_256,
        confidence=m.confidence,
        data_classification=m.data_classification,
        tags=list(m.tags or []),
    )


# ─── Deliberacao ──────────────────────────────────────────────────────────────


def deliberacao_to_kwargs(d: Deliberacao) -> dict[str, Any]:
    votos_serial = [asdict(v) for v in d.votos]
    return {
        "orgao": d.orgao,
        "colegiado": d.colegiado,
        "numero": d.numero,
        "ano": d.ano,
        "data_sessao": d.data_sessao,
        "relator_id": d.relator_id,
        "dispositivo": d.dispositivo,
        "ementa": d.ementa,
        "fundamento": d.fundamento,
        "processo_sei": d.processo_sei,
        "votos": votos_serial,
        "norma_citada_urns": list(d.norma_citada_urns),
        "text_hash_sha3_256": d.text_hash_sha3_256,
        "source_url": d.source_url,
        "source_id": d.source_id,
        "confidence": d.confidence,
        "data_classification": d.data_classification,
        "tags": list(d.tags),
    }


def deliberacao_from_model(m: DeliberacaoModel) -> Deliberacao:
    votos = [Voto(**v) for v in (m.votos or [])]
    return Deliberacao(
        orgao=m.orgao,
        colegiado=m.colegiado,
        numero=m.numero,
        ano=m.ano,
        data_sessao=_ensure_utc(m.data_sessao),
        relator_id=m.relator_id,
        dispositivo=m.dispositivo,
        ementa=m.ementa,
        processo_sei=m.processo_sei,
        votos=votos,
        fundamento=m.fundamento or "",
        norma_citada_urns=list(m.norma_citada_urns or []),
        text_hash_sha3_256=m.text_hash_sha3_256,
        source_url=m.source_url,
        source_id=m.source_id,
        confidence=m.confidence,
        data_classification=m.data_classification,
        tags=list(m.tags or []),
    )


# ─── Regulado ─────────────────────────────────────────────────────────────────


def regulado_to_kwargs(r: Regulado) -> dict[str, Any]:
    return {
        "razao_social": r.razao_social,
        "setor": r.setor,
        "cnpj": r.cnpj,
        "cpf_hash": r.cpf_hash,
        "nome_fantasia": r.nome_fantasia,
        "grupo_economico": r.grupo_economico,
        "contratos_ativos": list(r.contratos_ativos),
        "historico_sancoes_ids": list(r.historico_sancoes_ids),
        "tier_risco": r.tier_risco,
        "source_url": r.source_url,
        "source_id": r.source_id,
        "confidence": r.confidence,
        "data_classification": r.data_classification,
        "tags": list(r.tags),
    }


def regulado_from_model(m: ReguladoModel) -> Regulado:
    return Regulado(
        razao_social=m.razao_social,
        setor=m.setor,
        cnpj=m.cnpj,
        cpf_hash=m.cpf_hash,
        nome_fantasia=m.nome_fantasia,
        grupo_economico=m.grupo_economico,
        contratos_ativos=list(m.contratos_ativos or []),
        historico_sancoes_ids=list(m.historico_sancoes_ids or []),
        tier_risco=m.tier_risco,
        source_url=m.source_url,
        source_id=m.source_id,
        confidence=m.confidence,
        data_classification=m.data_classification,
        tags=list(m.tags or []),
    )


# ─── ContratoConcessao ────────────────────────────────────────────────────────


def contrato_to_kwargs(c: ContratoConcessao) -> dict[str, Any]:
    return {
        "numero_contrato": c.numero_contrato,
        "orgao": c.orgao,
        "modalidade": c.modalidade,
        "objeto": c.objeto,
        "regulado_id": c.regulado_id,
        "data_assinatura": c.data_assinatura,
        "prazo_anos": c.prazo_anos,
        "valor_total": c.valor_total,
        "contraprestacao": c.contraprestacao,
        "cronograma_marcos": list(c.cronograma_marcos),
        "garantias": list(c.garantias),
        "data_termino_prevista": c.data_termino_prevista,
        "rescisao_motivo": c.rescisao_motivo,
        "source_url": c.source_url,
        "source_id": c.source_id,
        "confidence": c.confidence,
        "data_classification": c.data_classification,
        "tags": list(c.tags),
    }


def _coerce_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def contrato_from_model(m: ContratoConcessaoModel) -> ContratoConcessao:
    return ContratoConcessao(
        numero_contrato=m.numero_contrato,
        orgao=m.orgao,
        modalidade=m.modalidade,
        objeto=m.objeto,
        regulado_id=m.regulado_id,
        data_assinatura=_ensure_utc(m.data_assinatura),
        prazo_anos=m.prazo_anos,
        valor_total=_coerce_decimal(m.valor_total),
        contraprestacao=_coerce_decimal(m.contraprestacao),
        cronograma_marcos=list(m.cronograma_marcos or []),
        garantias=list(m.garantias or []),
        data_termino_prevista=_ensure_utc(m.data_termino_prevista),
        rescisao_motivo=m.rescisao_motivo,
        source_url=m.source_url,
        source_id=m.source_id,
        confidence=m.confidence,
        data_classification=m.data_classification,
        tags=list(m.tags or []),
    )
