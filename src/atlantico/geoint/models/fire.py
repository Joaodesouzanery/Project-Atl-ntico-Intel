"""
FireHotspot e FireCluster — Modelos SQLAlchemy para focos de calor e clusters.

FireHotspot: ponto de foco individual detectado por satélite (BDQueimadas).
FireCluster: agrupamento DBSCAN de focos próximos no espaço-tempo.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from geoalchemy2 import Geometry
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class FireCluster(UUIDPKMixin, TimestampMixin, Base):
    """
    Cluster DBSCAN de focos de incêndio próximos.

    Severity:
        < 5 hotspots           → LOW
        5–15 hotspots          → MEDIUM
        15–50 hotspots         → HIGH
        ≥ 50 OU FRP ≥ 1000 MW → CRITICAL
    """

    __tablename__ = "geoint_fire_clusters"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_fcluster_severity",
        ),
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'alerted')",
            name="ck_fcluster_analysis_status",
        ),
        Index("idx_fcluster_created_at", "created_at"),
        Index("idx_fcluster_centroid", "centroid_geom", postgresql_using="gist"),
        Index("idx_fcluster_convex_hull", "convex_hull", postgresql_using="gist"),
        Index("idx_fcluster_severity", "severity"),
        Index("idx_fcluster_run_id", "cluster_run_id"),
    )

    # Identificação do run DBSCAN
    cluster_run_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="UUID do run DBSCAN que gerou este cluster",
    )

    # Estatísticas do cluster
    hotspot_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Número de focos no cluster",
    )

    # Geometrias
    centroid_geom: Mapped[object] = mapped_column(
        Geometry("POINT", srid=4326),
        nullable=False,
        comment="Centroide do cluster",
    )
    convex_hull: Mapped[object | None] = mapped_column(
        Geometry("POLYGON", srid=4326),
        nullable=True,
        comment="Envoltória convexa dos focos",
    )

    # FRP
    total_frp_mw: Mapped[float | None] = mapped_column(
        Numeric(12, 2),
        nullable=True,
        comment="Soma de FRP do cluster em MW",
    )
    max_frp_mw: Mapped[float | None] = mapped_column(
        Numeric(10, 2),
        nullable=True,
    )
    mean_frp_mw: Mapped[float | None] = mapped_column(
        Numeric(10, 2),
        nullable=True,
    )

    # Temporalidade
    min_acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Foco mais antigo do cluster",
    )
    max_acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Foco mais recente do cluster",
    )

    # Localização
    biome: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str | None] = mapped_column(String(2), nullable=True)

    # Análise
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="LOW",
    )
    near_infrastructure: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True se cluster está dentro do buffer de algum ativo crítico",
    )
    infra_asset_ids: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="UUIDs de InfrastructureAssets próximos",
    )
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analysis_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
    )


class FireHotspot(UUIDPKMixin, TimestampMixin, Base):
    """
    Foco de calor individual detectado por satélite (BDQueimadas/INPE).

    Cada hotspot é um ponto (POINT) com atributos de intensidade (FRP, brightness)
    e contexto ambiental (bioma, dias sem chuva, risco de fogo).
    """

    __tablename__ = "geoint_fire_hotspots"
    __table_args__ = (
        CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'clustered', 'alerted')",
            name="ck_hotspot_analysis_status",
        ),
        UniqueConstraint("external_id", "source_id", name="uq_hotspot_external_source"),
        Index("idx_hotspot_source_record", "source_record_id"),
        Index("idx_hotspot_acquired_at", "acquired_at"),
        Index("idx_hotspot_geom", "geom", postgresql_using="gist"),
        Index("idx_hotspot_cluster", "cluster_id"),
        Index("idx_hotspot_biome", "biome"),
        Index("idx_hotspot_analysis_status", "analysis_status"),
    )

    # Referência ao SourceRecord
    source_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK ao SourceRecord com payload PQC do foco",
    )

    # Identificação
    external_id: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        comment="ID único na fonte (BDQueimadas)",
    )
    source_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SOURCE_ID do conector (ex: 'inpe.bdqueimadas.v1')",
    )

    # Temporalidade e geometria
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    geom: Mapped[object] = mapped_column(
        Geometry("POINT", srid=4326),
        nullable=False,
        comment="Coordenada do foco de calor, EPSG:4326",
    )

    # Atributos do satélite
    satellite: Mapped[str | None] = mapped_column(String(64), nullable=True)
    frp: Mapped[float | None] = mapped_column(
        Numeric(10, 2),
        nullable=True,
        comment="Fire Radiative Power em MW",
    )
    brightness: Mapped[float | None] = mapped_column(
        Numeric(8, 2),
        nullable=True,
        comment="Temperatura de brilho em Kelvin",
    )
    confidence: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Confiança da detecção 0-100%",
    )

    # Contexto ambiental
    biome: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str | None] = mapped_column(String(2), nullable=True)
    municipality: Mapped[str | None] = mapped_column(String(128), nullable=True)
    days_without_rain: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fire_risk: Mapped[float | None] = mapped_column(
        Numeric(5, 2),
        nullable=True,
        comment="Risco de fogo 0.0–1.0",
    )

    # Clustering
    cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="FK ao FireCluster (preenchido após DBSCAN)",
    )

    # Estado de análise
    analysis_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
    )
