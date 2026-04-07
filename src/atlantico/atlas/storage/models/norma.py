"""Modelo SQLAlchemy: NormaModel — ato normativo (tabela atlas_normas)."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class NormaModel(UUIDPKMixin, TimestampMixin, Base):
    """
    Ato normativo brasileiro materializado.

    Identificador canônico: ``urn_lex`` (LexML). ``(orgao, tipo, numero, ano)``
    é uma chave alternativa usada para entity-resolution quando matérias do
    DOU chegam sem URN canônica e precisam ser pareadas com registros LexML.
    """

    __tablename__ = "atlas_normas"

    # Identificadores
    urn_lex = Column(String(255), nullable=True, unique=True, index=True)
    tipo = Column(String(32), nullable=False)
    numero = Column(Integer, nullable=False)
    ano = Column(Integer, nullable=False)
    orgao = Column(String(64), nullable=False, index=True)

    # Conteúdo
    ementa = Column(Text, nullable=False)
    data_publicacao_dou = Column(DateTime(timezone=True), nullable=False)
    vigencia_inicio = Column(DateTime(timezone=True), nullable=True)
    vigencia_fim = Column(DateTime(timezone=True), nullable=True)
    revogada_por_urn = Column(String(255), nullable=True)
    air_vinculada_id = Column(String(36), nullable=True)

    # Provenance
    texto_canonico_url = Column(Text, nullable=True)
    dou_url = Column(Text, nullable=True)
    text_hash_sha3_256 = Column(String(64), nullable=True, index=True)

    # Metadados
    confidence = Column(Float, nullable=False, default=1.0)
    data_classification = Column(String(32), nullable=False, default="PUBLIC")
    source_id = Column(String(64), nullable=True)
    tags = Column(JSON, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint(
            "orgao", "tipo", "numero", "ano",
            name="uq_atlas_norma_orgao_tipo_num_ano",
        ),
        CheckConstraint(
            "data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')",
            name="ck_atlas_norma_classification",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_atlas_norma_confidence",
        ),
        Index("ix_atlas_norma_publicacao", "data_publicacao_dou"),
        Index("ix_atlas_norma_tipo_ano", "tipo", "ano"),
    )

    def __repr__(self) -> str:
        return f"NormaModel(urn={self.urn_lex!r}, tipo={self.tipo!r}, num={self.numero}/{self.ano})"
