"""
SatelliteImagery — Modelo SQLAlchemy para metadados de imagens de satélite.

Registra produtos Sentinel-2 disponíveis no Copernicus Data Space.
Não armazena pixels — apenas metadados para correlação com eventos GEOINT
e cálculo de NDVI posterior.
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
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class SatelliteImagery(UUIDPKMixin, TimestampMixin, Base):
    """
    Metadados de produto Sentinel-2 disponível no Copernicus Data Space.

    analysis_status:
        "pending"        — recém-ingerido, aguardando análise
        "ndvi_computed"  — NDVI calculado e associado a eventos
        "correlated"     — correlacionado com eventos de desmatamento

    Não baixamos pixels — apenas registramos o product_id para download
    on-demand quando NDVI precisa ser calculado para um evento específico.
    """

    __tablename__ = "geoint_satellite_imagery"
    __table_args__ = (
        CheckConstraint(
            "analysis_status IN ('pending', 'ndvi_computed', 'correlated')",
            name="ck_imagery_analysis_status",
        ),
        UniqueConstraint("product_id", name="uq_imagery_product_id"),
        Index("idx_imagery_acquired_at", "acquired_at"),
        Index("idx_imagery_footprint", "footprint", postgresql_using="gist"),
        Index("idx_imagery_tile", "tile_id"),
        Index("idx_imagery_cloud_cover", "cloud_cover_pct"),
        Index("idx_imagery_analysis_status", "analysis_status"),
        Index("idx_imagery_satellite_type", "satellite", "product_type"),
    )

    # Referência ao SourceRecord
    source_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK ao SourceRecord com metadados brutos (envelope PQC)",
    )

    # Identificação do produto
    product_id: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        unique=True,
        comment="UUID do produto no Copernicus Data Space",
    )
    product_name: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        comment="Nome do arquivo (ex: S2A_MSIL2A_20240115T...)",
    )

    # Temporalidade
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Data de aquisição da imagem (ContentDate.Start)",
    )

    # Metadados do satélite
    satellite: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="'Sentinel-2A' ou 'Sentinel-2B'",
    )
    product_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="'S2MSI2A' (L2A) ou 'S2MSI1C' (L1C)",
    )
    tile_id: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment="MGRS tile (ex: '21KTQ')",
    )
    relative_orbit: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    cloud_cover_pct: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        comment="Cobertura de nuvens em %",
    )

    # Geometria do footprint
    footprint: Mapped[object] = mapped_column(
        Geometry("POLYGON", srid=4326),
        nullable=False,
        comment="Footprint do produto, EPSG:4326",
    )

    # Disponibilidade
    size_bytes: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        comment="Tamanho do produto em bytes",
    )
    online: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Disponível para download imediato",
    )

    # Estado de análise
    analysis_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
    )
    ndvi_computed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Quando o NDVI foi calculado para este produto",
    )
