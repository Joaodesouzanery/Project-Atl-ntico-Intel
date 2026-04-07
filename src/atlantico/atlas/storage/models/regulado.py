"""Modelo SQLAlchemy: ReguladoModel — empresa/PF sob regulação."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    Float,
    Index,
    String,
    Text,
)

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class ReguladoModel(UUIDPKMixin, TimestampMixin, Base):
    """
    Entidade regulada (tabela atlas_regulados).

    Identificador canônico: ``cnpj`` (14 dígitos) ou ``cpf_hash`` para PF.
    Pelo menos um dos dois é obrigatório (validado pela camada de domínio).
    """

    __tablename__ = "atlas_regulados"

    razao_social = Column(Text, nullable=False)
    setor = Column(String(64), nullable=False, index=True)
    cnpj = Column(String(14), nullable=True, unique=True, index=True)
    cpf_hash = Column(String(64), nullable=True, unique=True, index=True)
    nome_fantasia = Column(Text, nullable=True)
    grupo_economico = Column(String(255), nullable=True, index=True)
    contratos_ativos = Column(JSON, nullable=False, default=list)
    historico_sancoes_ids = Column(JSON, nullable=False, default=list)
    tier_risco = Column(String(16), nullable=False, default="MEDIO")
    source_url = Column(Text, nullable=True)
    source_id = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    data_classification = Column(String(32), nullable=False, default="PUBLIC")
    tags = Column(JSON, nullable=False, default=list)

    __table_args__ = (
        CheckConstraint(
            "cnpj IS NOT NULL OR cpf_hash IS NOT NULL",
            name="ck_atlas_regulado_cnpj_or_cpf",
        ),
        CheckConstraint(
            "tier_risco IN ('BAIXO','MEDIO','ALTO','CRITICO')",
            name="ck_atlas_regulado_tier",
        ),
        CheckConstraint(
            "data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')",
            name="ck_atlas_regulado_classification",
        ),
        Index("ix_atlas_regulado_setor_tier", "setor", "tier_risco"),
    )

    def __repr__(self) -> str:
        return f"ReguladoModel({self.razao_social!r}, cnpj={self.cnpj!r})"
