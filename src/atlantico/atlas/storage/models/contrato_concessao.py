"""Modelo SQLAlchemy: ContratoConcessaoModel."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class ContratoConcessaoModel(UUIDPKMixin, TimestampMixin, Base):
    """Contrato de concessão / outorga (tabela atlas_contratos)."""

    __tablename__ = "atlas_contratos"

    numero_contrato = Column(String(64), nullable=False)
    orgao = Column(String(64), nullable=False, index=True)
    modalidade = Column(String(32), nullable=False)
    objeto = Column(Text, nullable=False)
    regulado_id = Column(String(64), nullable=False, index=True)
    data_assinatura = Column(DateTime(timezone=True), nullable=False)
    prazo_anos = Column(Integer, nullable=False)
    valor_total = Column(Numeric(20, 2), nullable=True)
    contraprestacao = Column(Numeric(20, 2), nullable=True)
    cronograma_marcos = Column(JSON, nullable=False, default=list)
    garantias = Column(JSON, nullable=False, default=list)
    data_termino_prevista = Column(DateTime(timezone=True), nullable=True)
    rescisao_motivo = Column(Text, nullable=True)
    source_url = Column(Text, nullable=True)
    source_id = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    data_classification = Column(String(32), nullable=False, default="PUBLIC")
    tags = Column(JSON, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint(
            "orgao", "numero_contrato",
            name="uq_atlas_contrato_orgao_numero",
        ),
        CheckConstraint("prazo_anos > 0", name="ck_atlas_contrato_prazo"),
        CheckConstraint(
            "data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')",
            name="ck_atlas_contrato_classification",
        ),
        Index("ix_atlas_contrato_assinatura", "data_assinatura"),
        Index("ix_atlas_contrato_modalidade", "modalidade"),
    )

    def __repr__(self) -> str:
        return f"ContratoConcessaoModel({self.orgao} {self.numero_contrato!r})"
