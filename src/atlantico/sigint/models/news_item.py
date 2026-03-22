"""Modelo SQLAlchemy: NewsItem — artigos de notícia e posts de segurança."""
from __future__ import annotations

from sqlalchemy import Column, DateTime, Float, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from atlantico.storage.models.base import Base, TimestampMixin, UUIDPKMixin


class NewsItem(UUIDPKMixin, TimestampMixin, Base):
    """
    Artigo de notícia, post de blog de segurança, relatório público.

    Campos de NLP (preenchidos pelo NarrativeAnalyzer):
        sentiment_score ∈ [-1.0, 1.0]  (negativo = ameaça/alerta, positivo = neutro/positivo)
        topics: lista de tópicos detectados (TF-IDF NMF)
        entities: entidades nomeadas extraídas (CVEs, IPs, organizações)
        is_disinfo_signal: flag de possível desinformação
        disinfo_score ∈ [0.0, 1.0]
    """

    __tablename__ = "sigint_news_items"

    source_record_id = Column(String(36), nullable=False)
    external_id      = Column(String(128), nullable=False, unique=True)
    source_id        = Column(String(64),  nullable=False)
    feed_name        = Column(String(64),  nullable=True)

    title          = Column(String(512), nullable=False)
    content        = Column(Text,        nullable=True)
    url            = Column(Text,        nullable=True)
    reference_date = Column(DateTime(timezone=True), nullable=False)
    language       = Column(String(8),   nullable=False, default="en")

    # NLP — preenchido após análise
    sentiment_score    = Column(Float,   nullable=True)
    sentiment_label    = Column(String(16), nullable=True,
                                comment="positive | negative | neutral | threat")
    topics             = Column(ARRAY(String), nullable=False, default=list)
    entities           = Column(JSONB,   nullable=False, default=dict,
                                comment='{"cves": [], "ips": [], "domains": [], "orgs": []}')
    keywords           = Column(ARRAY(String), nullable=False, default=list)
    is_disinfo_signal  = Column(String(8), nullable=False, default="false")
    disinfo_score      = Column(Float,   nullable=True)
    narrative_cluster_id = Column(String(36), nullable=True)

    # Classificação
    severity        = Column(String(16), nullable=False, default="INFO")
    analysis_status = Column(String(16), nullable=False, default="pending")
    tags            = Column(ARRAY(String), nullable=False, default=list)
    geo_relevance   = Column(ARRAY(String), nullable=False, default=list)

    # CVEs mencionados
    mentioned_cves = Column(ARRAY(String), nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint("external_id", name="uq_news_external_id"),
        Index("ix_news_date_lang",     "reference_date", "language"),
        Index("ix_news_disinfo",       "is_disinfo_signal", "reference_date"),
        Index("ix_news_cluster",       "narrative_cluster_id"),
        Index("ix_news_severity",      "severity", "reference_date"),
    )
