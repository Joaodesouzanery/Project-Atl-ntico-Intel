"""Modelo SQLAlchemy: ThreatIndicator — IOCs (Indicators of Compromise)."""
from __future__ import annotations

from sqlalchemy import Column, DateTime, Float, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class ThreatIndicator(UUIDPKMixin, TimestampMixin, Base):
    """
    Indicador de comprometimento (IOC): IP, domínio, hash, URL, YARA rule.

    confidence ∈ [0.0, 1.0] — nível de confiança na maliciosidade.
    ioc_type: "ip" | "domain" | "url" | "hash_md5" | "hash_sha1" |
              "hash_sha256" | "email" | "yara_rule" | "cidr" | "cve"
    """

    __tablename__ = "sigint_threat_indicators"

    source_record_id = Column(String(36), nullable=False)
    external_id      = Column(String(128), nullable=False, unique=True)
    source_id        = Column(String(64),  nullable=False)

    ioc_type     = Column(String(32),  nullable=False)
    ioc_value    = Column(Text,        nullable=False)
    description  = Column(Text,        nullable=True)
    reference_date = Column(DateTime(timezone=True), nullable=False)

    # Origem e confiança
    threat_actor = Column(String(128), nullable=True)
    malware_family = Column(String(128), nullable=True)
    confidence   = Column(Float,       nullable=False, default=0.5)
    severity     = Column(String(16),  nullable=False, default="INFO")

    # VirusTotal stats
    vt_malicious_count  = Column(String(8), nullable=True)
    vt_detection_rate   = Column(Float,     nullable=True)

    # Estado
    is_active       = Column(String(8),  nullable=False, default="true")
    analysis_status = Column(String(16), nullable=False, default="pending")

    tags          = Column(ARRAY(String), nullable=False, default=list)
    geo_relevance = Column(ARRAY(String), nullable=False, default=list)
    metadata_json = Column(JSONB,         nullable=False, default=dict)

    # Link para ameaça pai
    cyber_threat_id = Column(String(36), nullable=True)

    __table_args__ = (
        UniqueConstraint("external_id", name="uq_indicator_external_id"),
        Index("ix_indicator_type_value", "ioc_type", "ioc_value"),
        Index("ix_indicator_severity",   "severity", "reference_date"),
        Index("ix_indicator_active",     "is_active", "ioc_type"),
    )
