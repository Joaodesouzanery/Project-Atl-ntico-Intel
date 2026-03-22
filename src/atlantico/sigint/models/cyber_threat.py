"""Modelo SQLAlchemy: CyberThreat — vulnerabilidades CVE e campanhas de ameaça."""
from __future__ import annotations

from sqlalchemy import (
    Column, DateTime, Float, Index, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class CyberThreat(UUIDPKMixin, TimestampMixin, Base):
    """
    Ameaça cibernética: CVE, exploit ativo, campanha de malware/APT.

    Campos de análise (preenchidos pelo ThreatAnalyzer):
        cvss_score, severity, mitre_techniques, affected_products
        analysis_status: "pending" | "analyzed" | "correlated"
    """

    __tablename__ = "sigint_cyber_threats"

    source_record_id = Column(
        String(36), nullable=False, comment="FK lógica → source_records.id (PQC envelope)"
    )
    external_id = Column(String(128), nullable=False, unique=True)
    source_id   = Column(String(64),  nullable=False)

    # Identificação
    threat_type = Column(
        String(32), nullable=False,
        comment="cve | malware_campaign | apt | exploit | ransomware | phishing"
    )
    title       = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    reference_date = Column(DateTime(timezone=True), nullable=False)

    # CVE específico
    cve_id       = Column(String(20),  nullable=True, index=True)
    cvss_score   = Column(Float,       nullable=True)
    cvss_vector  = Column(String(128), nullable=True)
    attack_vector = Column(String(32), nullable=True, comment="NETWORK|ADJACENT|LOCAL|PHYSICAL")

    # Severidade e status
    severity        = Column(String(16), nullable=False, default="INFO")
    analysis_status = Column(String(16), nullable=False, default="pending")

    # Estruturas ricas (JSONB)
    cwes              = Column(ARRAY(String), nullable=False, default=list)
    mitre_techniques  = Column(ARRAY(String), nullable=False, default=list)
    affected_products = Column(JSONB, nullable=False, default=list)
    references        = Column(JSONB, nullable=False, default=list)
    tags              = Column(ARRAY(String), nullable=False, default=list)
    geo_relevance     = Column(ARRAY(String), nullable=False, default=list)

    # Correlação FININT/GEOINT
    finint_correlation_id = Column(String(36), nullable=True)
    geoint_correlation_id = Column(String(36), nullable=True)

    # Score de risco calculado
    risk_score = Column(Float, nullable=True)

    __table_args__ = (
        UniqueConstraint("external_id", name="uq_cyber_threat_external_id"),
        Index("ix_cyber_threat_severity_date", "severity", "reference_date"),
        Index("ix_cyber_threat_cve",           "cve_id"),
        Index("ix_cyber_threat_source_status", "source_id", "analysis_status"),
    )
