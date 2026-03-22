"""
MarketIndicator — Indicadores de mercado (séries temporais BCB/CVM/IBGE).

Armazena valores de séries temporais para análise Z-score e Isolation Forest.
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


class MarketIndicator(UUIDPKMixin, TimestampMixin, Base):
    """
    Indicador de mercado de uma série temporal (BCB SGS, CVM, IBGE SIDRA).

    Um registro por (series_code, reference_date).
    Anomalia detectada por Z-score ou Isolation Forest após `analyze_indicators` task.
    """

    __tablename__ = "finint_market_indicators"
    __table_args__ = (
        UniqueConstraint("series_code", "reference_date", name="uq_indicator_series_date"),
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'anomaly', 'alerted')",
            name="ck_indicator_status",
        ),
        CheckConstraint(
            "anomaly_severity IN ('MEDIUM', 'HIGH', 'CRITICAL') OR anomaly_severity IS NULL",
            name="ck_indicator_severity",
        ),
        Index("idx_indicator_series_date", "series_code", "reference_date"),
        Index("idx_indicator_source_record", "source_record_id"),
        Index("idx_indicator_status", "analysis_status"),
    )

    # Referência PQC
    source_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK ao SourceRecord com payload PQC",
    )

    # Identificação da série
    series_code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Código da série (ex: 'bcb-1', 'bcb-13522', 'ibge-5938-1504208')",
    )
    series_name: Mapped[str] = mapped_column(String(256), nullable=False)
    source_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SOURCE_ID do conector (ex: 'bcb.sgs.v1')",
    )

    # Dado
    reference_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    value: Mapped[float] = mapped_column(Numeric(20, 6), nullable=False)
    unit: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Análise Z-score / Isolation Forest
    z_score: Mapped[float | None] = mapped_column(Numeric(8, 4), nullable=True)
    anomaly_type: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="'spike_up' | 'spike_down' | 'isolation_forest'",
    )
    anomaly_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    analysis_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
    )
