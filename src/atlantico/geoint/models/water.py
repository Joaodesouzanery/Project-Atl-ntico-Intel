"""
WaterObservation — Modelo SQLAlchemy para observações hídricas.

Registra leituras de estações fluviométricas e pluviométricas (ANA HidroWeb).
Inclui campos para análise estatística de anomalias (Z-score).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from geoalchemy2 import Geometry
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


class WaterObservation(UUIDPKMixin, TimestampMixin, Base):
    """
    Leitura de estação fluviométrica ou pluviométrica.

    measurement_type:
        "nivel"  — nível d'água em cm
        "vazao"  — vazão em m³/s
        "chuva"  — precipitação em mm

    anomaly_type (preenchido pelo WaterProcessor):
        None            — sem anomalia
        "drought"       — seca (z_score < -threshold)
        "flood"         — cheia (z_score > +threshold)
        "rapid_change"  — variação rápida (numpy.gradient)
        "extreme_precipitation" — chuva extrema

    anomaly_severity (preenchido pelo WaterProcessor):
        None | "MEDIUM" | "HIGH" | "CRITICAL"
    """

    __tablename__ = "geoint_water_observations"
    __table_args__ = (
        CheckConstraint(
            "measurement_type IN ('nivel', 'vazao', 'chuva')",
            name="ck_water_measurement_type",
        ),
        CheckConstraint(
            "data_quality IN (1, 2)",
            name="ck_water_data_quality",
        ),
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'alerted')",
            name="ck_water_analysis_status",
        ),
        UniqueConstraint(
            "station_code", "acquired_at", "measurement_type",
            name="uq_water_station_time_type",
        ),
        Index("idx_water_station_acquired", "station_code", "acquired_at"),
        Index("idx_water_geom", "geom", postgresql_using="gist"),
        Index("idx_water_anomaly_type", "anomaly_type"),
        Index("idx_water_analysis_status", "analysis_status"),
    )

    # Referência ao SourceRecord
    source_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK ao SourceRecord com payload PQC da leitura",
    )

    # Estação
    station_code: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Código da estação ANA",
    )
    station_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Temporalidade e geometria
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Timestamp da leitura (UTC)",
    )
    geom: Mapped[object] = mapped_column(
        Geometry("POINT", srid=4326),
        nullable=False,
        comment="Localização da estação, EPSG:4326",
    )

    # Medição
    measurement_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="'nivel', 'vazao' ou 'chuva'",
    )
    value: Mapped[float] = mapped_column(
        Numeric(14, 4),
        nullable=False,
    )
    unit: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="'cm', 'm3/s' ou 'mm'",
    )
    data_quality: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="1=bruto, 2=consistido (ANA)",
    )

    # Estatísticas históricas (preenchidas pelo WaterProcessor)
    historical_mean: Mapped[float | None] = mapped_column(
        Numeric(14, 4),
        nullable=True,
    )
    historical_stddev: Mapped[float | None] = mapped_column(
        Numeric(14, 4),
        nullable=True,
    )
    z_score: Mapped[float | None] = mapped_column(
        Numeric(8, 4),
        nullable=True,
        comment="Z-score vs. histórico dos últimos N dias",
    )

    # Anomalia (preenchida pelo WaterProcessor)
    anomaly_type: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment="Tipo de anomalia detectada ou None",
    )
    anomaly_severity: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        comment="Severidade da anomalia: MEDIUM, HIGH, CRITICAL",
    )

    # Estado de análise
    analysis_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
    )
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
