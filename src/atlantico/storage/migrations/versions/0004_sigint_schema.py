"""
Migration Alembic: 0004 — Schema SIGINT

Cria tabelas do módulo SIGINT:
  1. sigint_cyber_threats
  2. sigint_threat_indicators
  3. sigint_news_items
  4. sigint_narrative_campaigns

revision:      "0004"
down_revision: "0003"
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. sigint_cyber_threats
    op.create_table(
        "sigint_cyber_threats",
        sa.Column("id",                 sa.String(36),  primary_key=True),
        sa.Column("created_at",         sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at",         sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source_record_id",   sa.String(36),  nullable=False),
        sa.Column("external_id",        sa.String(128), nullable=False, unique=True),
        sa.Column("source_id",          sa.String(64),  nullable=False),
        sa.Column("threat_type",        sa.String(32),  nullable=False),
        sa.Column("title",              sa.String(512), nullable=False),
        sa.Column("description",        sa.Text,        nullable=True),
        sa.Column("reference_date",     sa.DateTime(timezone=True), nullable=False),
        sa.Column("cve_id",             sa.String(20),  nullable=True),
        sa.Column("cvss_score",         sa.Float,       nullable=True),
        sa.Column("cvss_vector",        sa.String(128), nullable=True),
        sa.Column("attack_vector",      sa.String(32),  nullable=True),
        sa.Column("severity",           sa.String(16),  nullable=False, server_default="INFO"),
        sa.Column("analysis_status",    sa.String(16),  nullable=False, server_default="pending"),
        sa.Column("cwes",               postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("mitre_techniques",   postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("affected_products",  postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("references",         postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("tags",               postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("geo_relevance",      postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("finint_correlation_id", sa.String(36), nullable=True),
        sa.Column("geoint_correlation_id", sa.String(36), nullable=True),
        sa.Column("risk_score",         sa.Float,       nullable=True),
    )
    op.create_index("ix_cyber_threat_severity_date", "sigint_cyber_threats", ["severity", "reference_date"])
    op.create_index("ix_cyber_threat_cve",           "sigint_cyber_threats", ["cve_id"])
    op.create_index("ix_cyber_threat_source_status", "sigint_cyber_threats", ["source_id", "analysis_status"])

    # 2. sigint_threat_indicators
    op.create_table(
        "sigint_threat_indicators",
        sa.Column("id",                 sa.String(36),  primary_key=True),
        sa.Column("created_at",         sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at",         sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source_record_id",   sa.String(36),  nullable=False),
        sa.Column("external_id",        sa.String(128), nullable=False, unique=True),
        sa.Column("source_id",          sa.String(64),  nullable=False),
        sa.Column("ioc_type",           sa.String(32),  nullable=False),
        sa.Column("ioc_value",          sa.Text,        nullable=False),
        sa.Column("description",        sa.Text,        nullable=True),
        sa.Column("reference_date",     sa.DateTime(timezone=True), nullable=False),
        sa.Column("threat_actor",       sa.String(128), nullable=True),
        sa.Column("malware_family",     sa.String(128), nullable=True),
        sa.Column("confidence",         sa.Float,       nullable=False, server_default="0.5"),
        sa.Column("severity",           sa.String(16),  nullable=False, server_default="INFO"),
        sa.Column("vt_malicious_count", sa.String(8),   nullable=True),
        sa.Column("vt_detection_rate",  sa.Float,       nullable=True),
        sa.Column("is_active",          sa.String(8),   nullable=False, server_default="true"),
        sa.Column("analysis_status",    sa.String(16),  nullable=False, server_default="pending"),
        sa.Column("tags",               postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("geo_relevance",      postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("metadata_json",      postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("cyber_threat_id",    sa.String(36),  nullable=True),
    )
    op.create_index("ix_indicator_type_value", "sigint_threat_indicators", ["ioc_type", "ioc_value"])
    op.create_index("ix_indicator_severity",   "sigint_threat_indicators", ["severity", "reference_date"])
    op.create_index("ix_indicator_active",     "sigint_threat_indicators", ["is_active", "ioc_type"])

    # 3. sigint_news_items
    op.create_table(
        "sigint_news_items",
        sa.Column("id",                   sa.String(36),  primary_key=True),
        sa.Column("created_at",           sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at",           sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source_record_id",     sa.String(36),  nullable=False),
        sa.Column("external_id",          sa.String(128), nullable=False, unique=True),
        sa.Column("source_id",            sa.String(64),  nullable=False),
        sa.Column("feed_name",            sa.String(64),  nullable=True),
        sa.Column("title",                sa.String(512), nullable=False),
        sa.Column("content",              sa.Text,        nullable=True),
        sa.Column("url",                  sa.Text,        nullable=True),
        sa.Column("reference_date",       sa.DateTime(timezone=True), nullable=False),
        sa.Column("language",             sa.String(8),   nullable=False, server_default="en"),
        sa.Column("sentiment_score",      sa.Float,       nullable=True),
        sa.Column("sentiment_label",      sa.String(16),  nullable=True),
        sa.Column("topics",               postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("entities",             postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("keywords",             postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("is_disinfo_signal",    sa.String(8),   nullable=False, server_default="false"),
        sa.Column("disinfo_score",        sa.Float,       nullable=True),
        sa.Column("narrative_cluster_id", sa.String(36),  nullable=True),
        sa.Column("severity",             sa.String(16),  nullable=False, server_default="INFO"),
        sa.Column("analysis_status",      sa.String(16),  nullable=False, server_default="pending"),
        sa.Column("tags",                 postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("geo_relevance",        postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("mentioned_cves",       postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
    )
    op.create_index("ix_news_date_lang",  "sigint_news_items", ["reference_date", "language"])
    op.create_index("ix_news_disinfo",    "sigint_news_items", ["is_disinfo_signal", "reference_date"])
    op.create_index("ix_news_cluster",    "sigint_news_items", ["narrative_cluster_id"])
    op.create_index("ix_news_severity",   "sigint_news_items", ["severity", "reference_date"])

    # 4. sigint_narrative_campaigns
    op.create_table(
        "sigint_narrative_campaigns",
        sa.Column("id",                       sa.String(36),  primary_key=True),
        sa.Column("created_at",               sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at",               sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("campaign_name",            sa.String(256), nullable=False),
        sa.Column("campaign_type",            sa.String(32),  nullable=False, server_default="disinfo"),
        sa.Column("description",              sa.Text,        nullable=True),
        sa.Column("first_seen",               sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen",                sa.DateTime(timezone=True), nullable=False),
        sa.Column("item_count",               sa.Integer,     nullable=False, server_default="0"),
        sa.Column("source_count",             sa.Integer,     nullable=False, server_default="0"),
        sa.Column("amplification_score",      sa.Float,       nullable=True),
        sa.Column("disinfo_score",            sa.Float,       nullable=True),
        sa.Column("confidence",               sa.Float,       nullable=False, server_default="0.5"),
        sa.Column("central_narrative",        sa.Text,        nullable=True),
        sa.Column("key_topics",               postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("key_entities",             postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("target_audience",          postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("geo_targets",              postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("suspected_origin",         sa.String(128), nullable=True),
        sa.Column("suspected_actor",          sa.String(128), nullable=True),
        sa.Column("severity",                 sa.String(16),  nullable=False, server_default="INFO"),
        sa.Column("analysis_status",          sa.String(16),  nullable=False, server_default="active"),
        sa.Column("alert_generated",          sa.String(8),   nullable=False, server_default="false"),
        sa.Column("related_cyber_threat_ids", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
    )
    op.create_index("ix_narrative_type_date",     "sigint_narrative_campaigns", ["campaign_type", "first_seen"])
    op.create_index("ix_narrative_severity",      "sigint_narrative_campaigns", ["severity", "last_seen"])
    op.create_index("ix_narrative_disinfo_score", "sigint_narrative_campaigns", ["disinfo_score"])


def downgrade() -> None:
    op.drop_table("sigint_narrative_campaigns")
    op.drop_table("sigint_news_items")
    op.drop_table("sigint_threat_indicators")
    op.drop_table("sigint_cyber_threats")
