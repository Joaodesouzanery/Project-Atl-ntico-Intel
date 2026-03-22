"""Modelo SQLAlchemy: NarrativeCampaign — clusters de desinformação."""
from __future__ import annotations

from sqlalchemy import Column, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class NarrativeCampaign(UUIDPKMixin, TimestampMixin, Base):
    """
    Campanha de desinformação/narrativa detectada por clustering de NewsItems.

    Representa um cluster de artigos com narrativa comum — possível
    operação de influência coordenada ou campanha de desinformação.

    campaign_type:
        "disinfo"       — desinformação factual (fatos falsos)
        "influence_op"  — operação de influência (narrativa fabricada)
        "amplification" — amplificação coordenada de conteúdo
        "fear_campaign" — campanha de pânico/medo
        "tech_disinfo"  — desinformação sobre tecnologia/segurança
    """

    __tablename__ = "sigint_narrative_campaigns"

    # Identificação
    campaign_name = Column(String(256), nullable=False)
    campaign_type = Column(String(32),  nullable=False, default="disinfo")
    description   = Column(Text,        nullable=True)

    # Período de atividade
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen  = Column(DateTime(timezone=True), nullable=False)

    # Métricas do cluster
    item_count         = Column(Integer, nullable=False, default=0)
    source_count       = Column(Integer, nullable=False, default=0)
    amplification_score = Column(Float,  nullable=True,
                                 comment="Quão amplificada é a narrativa (0-1)")
    disinfo_score      = Column(Float,   nullable=True,
                                comment="Probabilidade de desinformação (0-1)")
    confidence         = Column(Float,   nullable=False, default=0.5)

    # Análise NLP
    central_narrative  = Column(Text,          nullable=True)
    key_topics         = Column(ARRAY(String), nullable=False, default=list)
    key_entities       = Column(JSONB,         nullable=False, default=dict)
    target_audience    = Column(ARRAY(String), nullable=False, default=list)
    geo_targets        = Column(ARRAY(String), nullable=False, default=list)

    # Atribuição (quando possível)
    suspected_origin   = Column(String(128), nullable=True)
    suspected_actor    = Column(String(128), nullable=True)

    # Estado
    severity        = Column(String(16), nullable=False, default="INFO")
    analysis_status = Column(String(16), nullable=False, default="active")
    alert_generated = Column(String(8),  nullable=False, default="false")

    # Correlação
    related_cyber_threat_ids = Column(ARRAY(String), nullable=False, default=list)

    __table_args__ = (
        Index("ix_narrative_type_date",    "campaign_type", "first_seen"),
        Index("ix_narrative_severity",     "severity", "last_seen"),
        Index("ix_narrative_disinfo_score","disinfo_score"),
    )
