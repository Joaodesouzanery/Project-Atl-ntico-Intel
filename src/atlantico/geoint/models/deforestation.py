"""
DeforestationEvent — Modelo SQLAlchemy para eventos de desmatamento.

Registra polígonos de desmatamento detectados por PRODES (anual) e
DETER (near-real-time). Geometria armazenada em PostGIS como POLYGON EPSG:4326.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from geoalchemy2 import Geometry
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

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class DeforestationEvent(UUIDPKMixin, TimestampMixin, Base):
    """
    Evento de desmatamento detectado por INPE PRODES ou DETER.

    Severity derivado de area_ha:
        < 25 ha    → LOW
        25-100 ha  → MEDIUM
        100-500 ha → HIGH
        ≥ 500 ha   → CRITICAL

    source_record_id liga a observação bruta (envelope PQC no storage/).
    """

    __tablename__ = "geoint_deforestation_events"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('prodes', 'deter')",
            name="ck_defor_source_type",
        ),
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_defor_severity",
        ),
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'alerted')",
            name="ck_defor_analysis_status",
        ),
        Index("idx_defor_source_record", "source_record_id"),
        Index("idx_defor_acquired_severity", "acquired_at", "severity"),
        Index("idx_defor_biome_state", "biome", "state"),
        Index("idx_defor_geom", "geom", postgresql_using="gist"),
        Index("idx_defor_external_id", "external_id", unique=True),
    )

    # Referência ao SourceRecord com o payload bruto (envelope PQC)
    source_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK ao SourceRecord com payload PQC do evento",
    )

    # Identificação
    external_id: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        unique=True,
        comment="ID único do registro na fonte (PRODES/DETER) para deduplication",
    )
    source_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="'prodes' ou 'deter'",
    )

    # Temporalidade
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Data de aquisição da imagem que detectou o evento",
    )

    # Métricas geoespaciais
    area_ha: Mapped[float] = mapped_column(
        Numeric(12, 4),
        nullable=False,
        comment="Área do polígono em hectares",
    )
    geom: Mapped[object] = mapped_column(
        Geometry("POLYGON", srid=4326),
        nullable=False,
        comment="Polígono de desmatamento, EPSG:4326",
    )

    # Localização
    biome: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Bioma (Amazônia, Cerrado, etc.)",
    )
    state: Mapped[str] = mapped_column(
        String(2),
        nullable=False,
        comment="UF (código de 2 letras)",
    )
    municipality: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    classname: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="Classe DETER: DESMATAMENTO_VEG, MINERACAO, etc.",
    )

    # Análise
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="LOW",
        comment="Severidade derivada de area_ha",
    )
    ndvi_before: Mapped[float | None] = mapped_column(
        Numeric(6, 4),
        nullable=True,
        comment="NDVI médio antes do evento (de imagem Sentinel-2)",
    )
    ndvi_after: Mapped[float | None] = mapped_column(
        Numeric(6, 4),
        nullable=True,
        comment="NDVI médio após o evento (de imagem Sentinel-2)",
    )
    analysis_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        comment="Estado: pending → processed → alerted",
    )
    alert_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="alert_id do alerta gerado (se houver)",
    )
