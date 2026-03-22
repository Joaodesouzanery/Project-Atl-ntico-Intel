"""
FinancialFlow — Fluxos financeiros suspeitos agregados.

Modelo genérico para fluxos monetários que não se encaixam nas categorias
específicas (não são contratos públicos nem comércio exterior), como
transferências bancárias agregadas ou dados de operações do BCB.

Campos sensíveis (valor, contraparte) são criptografados.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Numeric,
    String,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.encrypted_field import EncryptedBytes
from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class FinancialFlow(UUIDPKMixin, TimestampMixin, Base):
    """
    Fluxo financeiro agregado para análise de padrões suspeitos.

    Usado principalmente para dados BCB que representam movimentações
    financeiras (não apenas indicadores macroeconômicos).
    """

    __tablename__ = "finint_financial_flows"
    __table_args__ = (
        CheckConstraint(
            "flow_type IN ('export', 'import', 'contract', 'transfer', 'investment', 'other')",
            name="ck_flow_type",
        ),
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'suspicious', 'alerted')",
            name="ck_flow_status",
        ),
        Index("idx_flow_external_id", "external_id", unique=True),
        Index("idx_flow_municipality_date", "municipality_code", "reference_date"),
        Index("idx_flow_state_type_date", "state", "flow_type", "reference_date"),
        Index("idx_flow_source_record", "source_record_id"),
        Index("idx_flow_status", "analysis_status"),
    )

    # Referência PQC
    source_record_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Identificação
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Dados do fluxo
    reference_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str | None] = mapped_column(String(2), nullable=True)
    municipality_code: Mapped[str | None] = mapped_column(String(7), nullable=True)
    flow_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="BRL")
    commodity_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    commodity_desc: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Campos criptografados
    amount_enc: Mapped[bytes | None] = mapped_column(
        EncryptedBytes("finint_financial_flows.amount"),
        nullable=True,
        comment="Valor do fluxo criptografado AES-256-GCM",
    )
    counterpart_enc: Mapped[bytes | None] = mapped_column(
        EncryptedBytes("finint_financial_flows.counterpart"),
        nullable=True,
        comment="CNPJ/nome da contraparte criptografado AES-256-GCM",
    )

    # Análise
    anomaly_score: Mapped[float] = mapped_column(Numeric(5, 4), nullable=False, default=0.0)
    analysis_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
