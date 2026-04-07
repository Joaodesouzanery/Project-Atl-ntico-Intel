"""Modelo SQLAlchemy: DeliberacaoModel — decisão de colegiado."""

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


class DeliberacaoModel(UUIDPKMixin, TimestampMixin, Base):
    """
    Deliberação colegiada (tabela atlas_deliberacoes).

    Os votos são armazenados como JSON inline (lista de dicts) para
    simplicidade do Sprint 4. Sprints futuros podem promovê-los a tabela
    própria se for necessário consultar voto-por-voto.
    """

    __tablename__ = "atlas_deliberacoes"

    orgao = Column(String(64), nullable=False, index=True)
    colegiado = Column(String(64), nullable=False)
    numero = Column(Integer, nullable=False)
    ano = Column(Integer, nullable=False)
    data_sessao = Column(DateTime(timezone=True), nullable=False)
    relator_id = Column(String(64), nullable=False)
    dispositivo = Column(String(32), nullable=False)
    ementa = Column(Text, nullable=False)
    fundamento = Column(Text, nullable=False, default="")
    processo_sei = Column(String(32), nullable=True, index=True)
    votos = Column(JSON, nullable=False, default=list)
    norma_citada_urns = Column(JSON, nullable=False, default=list)
    text_hash_sha3_256 = Column(String(64), nullable=True)
    source_url = Column(Text, nullable=True)
    source_id = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    data_classification = Column(String(32), nullable=False, default="PUBLIC")
    tags = Column(JSON, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint(
            "orgao", "colegiado", "numero", "ano",
            name="uq_atlas_deliberacao_natural",
        ),
        CheckConstraint(
            "data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')",
            name="ck_atlas_delib_classification",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_atlas_delib_confidence",
        ),
        Index("ix_atlas_delib_data", "data_sessao"),
    )

    def __repr__(self) -> str:
        return (
            f"DeliberacaoModel({self.colegiado} {self.orgao} "
            f"{self.numero}/{self.ano} {self.dispositivo})"
        )
