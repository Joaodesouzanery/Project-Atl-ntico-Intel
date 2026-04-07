"""Modelo SQLAlchemy: ProcessoAdministrativoModel — processo SEI."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    Index,
    String,
    Text,
    UniqueConstraint,
)

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class ProcessoAdministrativoModel(UUIDPKMixin, TimestampMixin, Base):
    """Processo administrativo no SEI (tabela atlas_processos)."""

    __tablename__ = "atlas_processos"

    numero_sei = Column(String(32), nullable=False, unique=True)
    orgao = Column(String(64), nullable=False, index=True)
    assunto = Column(Text, nullable=False)
    data_autuacao = Column(DateTime(timezone=True), nullable=False)
    fase = Column(String(32), nullable=False, default="autuacao")
    partes = Column(JSON, nullable=False, default=list)
    prazo_legal = Column(DateTime(timezone=True), nullable=True)
    data_conclusao = Column(DateTime(timezone=True), nullable=True)
    norma_relacionada_urn = Column(String(255), nullable=True, index=True)
    source_url = Column(Text, nullable=True)
    source_id = Column(String(64), nullable=True)
    text_hash_sha3_256 = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    data_classification = Column(String(32), nullable=False, default="PUBLIC")
    tags = Column(JSON, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint("numero_sei", name="uq_atlas_processo_sei"),
        CheckConstraint(
            "data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')",
            name="ck_atlas_processo_classification",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_atlas_processo_confidence",
        ),
        Index("ix_atlas_processo_orgao_fase", "orgao", "fase"),
        Index("ix_atlas_processo_autuacao", "data_autuacao"),
    )

    def __repr__(self) -> str:
        return f"ProcessoAdministrativoModel(sei={self.numero_sei!r}, fase={self.fase!r})"
