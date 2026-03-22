"""
FinancialEntity — Entidades financeiras (empresas, pessoas) para análise de rede.

Campos sensíveis (nome, CPF/CNPJ) são criptografados com AES-256-GCM
via EncryptedBytes TypeDecorator — nenhum plaintext no banco.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Index,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.encrypted_field import EncryptedBytes
from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class FinancialEntity(UUIDPKMixin, TimestampMixin, Base):
    """
    Entidade financeira participante da rede de relacionamentos FININT.

    Pode representar empresa, pessoa física, município ou outro ator.
    Campos nome e documento são criptografados — análise de rede usa
    apenas IDs, scores e flags (não o plaintext).
    """

    __tablename__ = "finint_financial_entities"
    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('empresa', 'pessoa', 'municipio', 'fundo', 'outro')",
            name="ck_entity_type",
        ),
        Index("idx_entity_external_id", "external_id", unique=True),
        Index("idx_entity_type_state", "entity_type", "state"),
        Index("idx_entity_risk_score", "risk_score"),
        Index("idx_entity_active", "active"),
    )

    external_id: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        unique=True,
        comment="ID único da entidade na fonte (CNPJ formatado, código IBGE, etc.)",
    )
    entity_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="'empresa' | 'pessoa' | 'municipio' | 'fundo' | 'outro'",
    )

    # Campos criptografados — dados operacionais sensíveis
    name_enc: Mapped[bytes] = mapped_column(
        EncryptedBytes("finint_financial_entities.name"),
        nullable=False,
        comment="Nome/razão social criptografado AES-256-GCM",
    )
    document_enc: Mapped[bytes | None] = mapped_column(
        EncryptedBytes("finint_financial_entities.document"),
        nullable=True,
        comment="CPF ou CNPJ criptografado AES-256-GCM",
    )

    # Localização
    state: Mapped[str | None] = mapped_column(String(2), nullable=True)
    municipality_code: Mapped[str | None] = mapped_column(String(7), nullable=True)

    # Status e métricas de risco
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    risk_score: Mapped[float] = mapped_column(
        Numeric(5, 4),
        nullable=False,
        default=0.0,
        comment="Score de risco [0, 1] — calculado pelo RiskScorer",
    )
    centrality_score: Mapped[float] = mapped_column(
        Numeric(10, 8),
        nullable=False,
        default=0.0,
        comment="PageRank no grafo de relacionamentos",
    )

    # Flags de risco (JSONB para queries flexíveis)
    flags: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Lista de flags de risco ex: ['garimpo_ilegal', 'conta_laranja']",
    )
