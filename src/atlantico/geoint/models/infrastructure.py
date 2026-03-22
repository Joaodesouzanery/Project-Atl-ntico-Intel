"""
InfrastructureAsset — Modelo SQLAlchemy para ativos de infraestrutura crítica.

Tabela de referência estática — carregada uma vez e monitorada continuamente
pelos processadores de análise geoespacial.

Campos sensíveis (nome e operador) são criptografados com EncryptedBytes
para proteger dados operacionalmente sensíveis em repouso.
"""

from __future__ import annotations

from datetime import datetime

from geoalchemy2 import Geometry
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Numeric,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from atlantico.storage.encrypted_field import EncryptedBytes
from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin

_ASSET_TYPES = (
    "hydroelectric",
    "pipeline",
    "transmission_line",
    "substation",
    "dam",
    "port",
    "railroad",
    "water_treatment",
    "gas_terminal",
)

_CRITICALITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class InfrastructureAsset(UUIDPKMixin, TimestampMixin, Base):
    """
    Ativo de infraestrutura crítica monitorado pelo GEOINT.

    Segurança:
        name_enc e operator_enc são criptografados com EncryptedBytes
        (AES-256-GCM, chave derivada por coluna via HKDF-SHA3-512).
        A identidade do operador é dado operacionalmente sensível — não deve
        estar em texto claro no banco de dados.

    geom suporta qualquer tipo de geometria:
        - POINT para subestações, usinas
        - LINESTRING para dutos, linhas de transmissão
        - POLYGON para barragens, áreas de operação
    """

    __tablename__ = "geoint_infrastructure_assets"
    __table_args__ = (
        CheckConstraint(
            f"asset_type IN {_ASSET_TYPES}",
            name="ck_infra_asset_type",
        ),
        CheckConstraint(
            f"criticality IN {_CRITICALITY_LEVELS}",
            name="ck_infra_criticality",
        ),
        Index("idx_infra_geom", "geom", postgresql_using="gist"),
        Index("idx_infra_type_criticality", "asset_type", "criticality"),
        Index("idx_infra_external_id", "external_id", unique=True),
        Index("idx_infra_active", "active"),
    )

    # Identificação
    external_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        comment="ID na fonte original (ANEEL, ANTT, ANP, etc.)",
    )
    asset_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Tipo do ativo de infraestrutura",
    )
    criticality: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="Nível de criticidade: LOW | MEDIUM | HIGH | CRITICAL",
    )

    # Geometria (tipo variável: POINT, LINESTRING, POLYGON)
    geom: Mapped[object] = mapped_column(
        Geometry("GEOMETRY", srid=4326),
        nullable=False,
        comment="Geometria do ativo, EPSG:4326",
    )

    # Campos sensíveis — criptografados em repouso
    name_enc: Mapped[bytes] = mapped_column(
        EncryptedBytes("geoint_infrastructure_assets.name"),
        nullable=False,
        comment="Nome do ativo (criptografado com AES-256-GCM)",
    )
    operator_enc: Mapped[bytes | None] = mapped_column(
        EncryptedBytes("geoint_infrastructure_assets.operator"),
        nullable=True,
        comment="Operador/concessionária (criptografado com AES-256-GCM)",
    )

    # Metadados não sensíveis
    state: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
        comment="UF (código de 2 letras)",
    )
    capacity_mw: Mapped[float | None] = mapped_column(
        Numeric(12, 2),
        nullable=True,
        comment="Capacidade em MW (para usinas e subestações)",
    )
    length_km: Mapped[float | None] = mapped_column(
        Numeric(10, 2),
        nullable=True,
        comment="Comprimento em km (para dutos e linhas de transmissão)",
    )

    # Monitoramento
    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Ativo em operação",
    )
    monitoring_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Habilita monitoramento GEOINT para este ativo",
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Última verificação de eventos próximos",
    )
