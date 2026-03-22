"""
EntityRelationship — Arestas do grafo de rede financeira.

Relacionamentos entre entidades financeiras (fornecedor→contratante,
exportador→importador, sócio→empresa). Usado pelo NetworkAnalyzer
para construir o DiGraph networkx e calcular PageRank/betweenness.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class EntityRelationship(UUIDPKMixin, TimestampMixin, Base):
    """
    Aresta do grafo de rede financeira entre duas FinancialEntity.

    Peso da aresta: strength * log1p(total_value_brl)
    Direção: source → target (ex: fornecedor → contratante público)
    """

    __tablename__ = "finint_entity_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_entity_id",
            "target_entity_id",
            "relationship_type",
            name="uq_entity_relationship",
        ),
        CheckConstraint(
            "relationship_type IN ('fornecedor', 'contratante', 'socio', 'exportador', 'importador', 'controlador', 'outro')",
            name="ck_relationship_type",
        ),
        Index("idx_rel_source", "source_entity_id"),
        Index("idx_rel_target", "target_entity_id"),
        Index("idx_rel_type", "relationship_type"),
    )

    source_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK para finint_financial_entities (entidade de origem)",
    )
    target_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK para finint_financial_entities (entidade de destino)",
    )
    relationship_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Tipo de relacionamento: fornecedor | contratante | socio | exportador | ...",
    )

    # Métricas da relação
    strength: Mapped[float] = mapped_column(
        Numeric(5, 4),
        nullable=False,
        default=1.0,
        comment="Força do relacionamento [0, 1]",
    )
    transaction_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="Número de transações observadas",
    )
    total_value_brl: Mapped[float] = mapped_column(
        Numeric(18, 2),
        nullable=False,
        default=0.0,
        comment="Valor total das transações em BRL",
    )

    # Temporalidade
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Primeira transação observada",
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Última transação observada",
    )
