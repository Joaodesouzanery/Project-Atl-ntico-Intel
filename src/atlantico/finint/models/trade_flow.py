"""
TradeFlow — Fluxos de comércio exterior (ComexStat MDIC).

Monitora exportações de minerais estratégicos (ouro, prata, estanho)
por NCM, estado e período para detectar spikes associados a garimpo.
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
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class TradeFlow(UUIDPKMixin, TimestampMixin, Base):
    """
    Fluxo de exportação/importação de mineral estratégico via ComexStat.

    Um registro por (ncm_code, state, year, month).
    Análise detecta spikes acima de mean + N*stddev histórico.
    """

    __tablename__ = "finint_trade_flows"
    __table_args__ = (
        UniqueConstraint("external_id", name="uq_trade_external_id"),
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'suspicious', 'alerted')",
            name="ck_trade_status",
        ),
        Index("idx_trade_ncm_date", "ncm_code", "reference_date"),
        Index("idx_trade_state_ncm", "state", "ncm_code"),
        Index("idx_trade_source_record", "source_record_id"),
        Index("idx_trade_status", "analysis_status"),
    )

    # Referência PQC
    source_record_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Identificação
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Dados do fluxo
    reference_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str | None] = mapped_column(String(2), nullable=True)
    ncm_code: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        comment="Código NCM (ex: '7108' para ouro)",
    )
    ncm_desc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sh2_code: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
        comment="Primeiros 2 dígitos do NCM (capítulo SH)",
    )
    export_value_usd: Mapped[float] = mapped_column(
        Numeric(18, 2),
        nullable=False,
        default=0.0,
        comment="Valor FOB exportado em USD",
    )
    net_weight_kg: Mapped[float] = mapped_column(
        Numeric(18, 3),
        nullable=False,
        default=0.0,
        comment="Peso líquido em kg",
    )
    country_code: Mapped[str | None] = mapped_column(String(4), nullable=True)

    # Análise
    anomaly_score: Mapped[float] = mapped_column(Numeric(5, 4), nullable=False, default=0.0)
    analysis_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Correlação com GEOINT
    geoint_correlation_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="ID do evento GEOINT correlacionado (DeforestationEvent ou FireCluster)",
    )
