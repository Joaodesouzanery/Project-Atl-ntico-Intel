"""
PublicContract — Contratos públicos federais (Portal da Transparência).

CNPJ do fornecedor e valor do contrato são criptografados via EncryptedBytes.
Análise detecta anomalias de volume e concentração de fornecedores por município.
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
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.encrypted_field import EncryptedBytes
from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class PublicContract(UUIDPKMixin, TimestampMixin, Base):
    """
    Contrato público federal do Portal da Transparência.

    CNPJ e valor são criptografados. Análise de anomalias usa métricas
    históricas por município/estado agregadas no repositório.
    """

    __tablename__ = "finint_public_contracts"
    __table_args__ = (
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'suspicious', 'alerted')",
            name="ck_contract_status",
        ),
        Index("idx_contract_external_id", "external_id", unique=True),
        Index("idx_contract_municipality_date", "municipality_code", "reference_date"),
        Index("idx_contract_state_date", "state", "reference_date"),
        Index("idx_contract_source_record", "source_record_id"),
        Index("idx_contract_status", "analysis_status"),
    )

    # Referência PQC
    source_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    # Identificação
    external_id: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        unique=True,
        comment="Número do contrato (deduplication)",
    )
    source_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Dados públicos (não criptografados)
    reference_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str | None] = mapped_column(String(2), nullable=True)
    municipality_code: Mapped[str | None] = mapped_column(String(7), nullable=True)
    contracting_entity: Mapped[str | None] = mapped_column(String(512), nullable=True)
    contract_object: Mapped[str | None] = mapped_column(Text, nullable=True)
    modality: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Campos criptografados (operacionalmente sensíveis)
    supplier_cnpj_enc: Mapped[bytes | None] = mapped_column(
        EncryptedBytes("finint_public_contracts.supplier_cnpj"),
        nullable=True,
        comment="CNPJ do fornecedor criptografado AES-256-GCM",
    )
    contract_value_enc: Mapped[bytes | None] = mapped_column(
        EncryptedBytes("finint_public_contracts.contract_value"),
        nullable=True,
        comment="Valor do contrato em BRL criptografado AES-256-GCM",
    )

    # Análise
    anomaly_score: Mapped[float] = mapped_column(
        Numeric(5, 4),
        nullable=False,
        default=0.0,
        comment="Score de anomalia [0, 1] calculado pelo AnomalyDetector",
    )
    analysis_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
    )
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
