"""
0003 — Schema FININT: tabelas de inteligência financeira.

Cria 6 tabelas para o módulo FININT:
  - finint_financial_entities     (entidades financeiras — nós do grafo)
  - finint_entity_relationships   (arestas do grafo de rede financeira)
  - finint_financial_flows        (fluxos financeiros genéricos)
  - finint_market_indicators      (séries temporais BCB/CVM/IBGE)
  - finint_public_contracts       (contratos Portal Transparência)
  - finint_trade_flows            (exportações ComexStat)

Campos criptografados (EncryptedBytes AES-256-GCM):
  - finint_financial_entities.name_enc, document_enc
  - finint_financial_flows.amount_enc, counterpart_enc
  - finint_public_contracts.supplier_cnpj_enc, contract_value_enc

Revisão: 0003
Down-revision: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─── finint_financial_entities ─────────────────────────────────────────────
    op.create_table(
        "finint_financial_entities",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("external_id", sa.String(256), nullable=False, unique=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("name_enc", sa.LargeBinary(), nullable=False, comment="Nome criptografado AES-256-GCM"),
        sa.Column("document_enc", sa.LargeBinary(), nullable=True, comment="CPF/CNPJ criptografado AES-256-GCM"),
        sa.Column("state", sa.String(2), nullable=True),
        sa.Column("municipality_code", sa.String(7), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("risk_score", sa.Numeric(5, 4), nullable=False, server_default=sa.text("0")),
        sa.Column("centrality_score", sa.Numeric(10, 8), nullable=False, server_default=sa.text("0")),
        sa.Column("flags", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "entity_type IN ('empresa', 'pessoa', 'municipio', 'fundo', 'outro')",
            name="ck_entity_type",
        ),
    )
    op.execute("CREATE UNIQUE INDEX idx_entity_external_id ON finint_financial_entities(external_id)")
    op.execute("CREATE INDEX idx_entity_type_state ON finint_financial_entities(entity_type, state)")
    op.execute("CREATE INDEX idx_entity_risk_score ON finint_financial_entities(risk_score)")
    op.execute("CREATE INDEX idx_entity_flags ON finint_financial_entities USING GIN(flags)")
    op.execute("""
        CREATE TRIGGER update_finint_financial_entities_updated_at
        BEFORE UPDATE ON finint_financial_entities
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── finint_entity_relationships ───────────────────────────────────────────
    op.create_table(
        "finint_entity_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("relationship_type", sa.String(32), nullable=False),
        sa.Column("strength", sa.Numeric(5, 4), nullable=False, server_default=sa.text("1")),
        sa.Column("transaction_count", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("total_value_brl", sa.Numeric(18, 2), nullable=False, server_default=sa.text("0")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "relationship_type IN ('fornecedor', 'contratante', 'socio', 'exportador', 'importador', 'controlador', 'outro')",
            name="ck_relationship_type",
        ),
        sa.UniqueConstraint("source_entity_id", "target_entity_id", "relationship_type", name="uq_entity_relationship"),
        sa.ForeignKeyConstraint(["source_entity_id"], ["finint_financial_entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_entity_id"], ["finint_financial_entities.id"], ondelete="CASCADE"),
    )
    op.execute("CREATE INDEX idx_rel_source ON finint_entity_relationships(source_entity_id)")
    op.execute("CREATE INDEX idx_rel_target ON finint_entity_relationships(target_entity_id)")
    op.execute("CREATE INDEX idx_rel_type ON finint_entity_relationships(relationship_type)")
    op.execute("""
        CREATE TRIGGER update_finint_entity_relationships_updated_at
        BEFORE UPDATE ON finint_entity_relationships
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── finint_financial_flows ────────────────────────────────────────────────
    op.create_table(
        "finint_financial_flows",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False, unique=True),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("reference_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(2), nullable=True),
        sa.Column("municipality_code", sa.String(7), nullable=True),
        sa.Column("flow_type", sa.String(32), nullable=False, server_default=sa.text("'other'")),
        sa.Column("currency", sa.String(3), nullable=False, server_default=sa.text("'BRL'")),
        sa.Column("commodity_code", sa.String(16), nullable=True),
        sa.Column("commodity_desc", sa.String(256), nullable=True),
        sa.Column("amount_enc", sa.LargeBinary(), nullable=True, comment="Valor criptografado AES-256-GCM"),
        sa.Column("counterpart_enc", sa.LargeBinary(), nullable=True, comment="Contraparte criptografada AES-256-GCM"),
        sa.Column("anomaly_score", sa.Numeric(5, 4), nullable=False, server_default=sa.text("0")),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("alert_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "flow_type IN ('export', 'import', 'contract', 'transfer', 'investment', 'other')",
            name="ck_flow_type",
        ),
        sa.CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'suspicious', 'alerted')",
            name="ck_flow_status",
        ),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
    )
    op.execute("CREATE UNIQUE INDEX idx_flow_external_id ON finint_financial_flows(external_id)")
    op.execute("CREATE INDEX idx_flow_municipality_date ON finint_financial_flows(municipality_code, reference_date)")
    op.execute("CREATE INDEX idx_flow_state_type_date ON finint_financial_flows(state, flow_type, reference_date)")
    op.execute("CREATE INDEX idx_flow_source_record ON finint_financial_flows(source_record_id)")
    op.execute("CREATE INDEX idx_flow_status ON finint_financial_flows(analysis_status)")
    op.execute("""
        CREATE TRIGGER update_finint_financial_flows_updated_at
        BEFORE UPDATE ON finint_financial_flows
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── finint_market_indicators ──────────────────────────────────────────────
    op.create_table(
        "finint_market_indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("series_code", sa.String(64), nullable=False),
        sa.Column("series_name", sa.String(256), nullable=False),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("reference_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("value", sa.Numeric(20, 6), nullable=False),
        sa.Column("unit", sa.String(64), nullable=True),
        sa.Column("z_score", sa.Numeric(8, 4), nullable=True),
        sa.Column("anomaly_type", sa.String(64), nullable=True),
        sa.Column("anomaly_severity", sa.String(16), nullable=True),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.UniqueConstraint("series_code", "reference_date", name="uq_indicator_series_date"),
        sa.CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'anomaly', 'alerted')",
            name="ck_indicator_status",
        ),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
    )
    op.execute("CREATE INDEX idx_indicator_series_date ON finint_market_indicators(series_code, reference_date)")
    op.execute("CREATE INDEX idx_indicator_source_record ON finint_market_indicators(source_record_id)")
    op.execute("CREATE INDEX idx_indicator_status ON finint_market_indicators(analysis_status)")
    op.execute("""
        CREATE TRIGGER update_finint_market_indicators_updated_at
        BEFORE UPDATE ON finint_market_indicators
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── finint_public_contracts ───────────────────────────────────────────────
    op.create_table(
        "finint_public_contracts",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False, unique=True),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("reference_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(2), nullable=True),
        sa.Column("municipality_code", sa.String(7), nullable=True),
        sa.Column("contracting_entity", sa.String(512), nullable=True),
        sa.Column("contract_object", sa.Text(), nullable=True),
        sa.Column("modality", sa.String(128), nullable=True),
        sa.Column("supplier_cnpj_enc", sa.LargeBinary(), nullable=True, comment="CNPJ criptografado AES-256-GCM"),
        sa.Column("contract_value_enc", sa.LargeBinary(), nullable=True, comment="Valor criptografado AES-256-GCM"),
        sa.Column("anomaly_score", sa.Numeric(5, 4), nullable=False, server_default=sa.text("0")),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("alert_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'suspicious', 'alerted')",
            name="ck_contract_status",
        ),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
    )
    op.execute("CREATE UNIQUE INDEX idx_contract_external_id ON finint_public_contracts(external_id)")
    op.execute("CREATE INDEX idx_contract_municipality_date ON finint_public_contracts(municipality_code, reference_date)")
    op.execute("CREATE INDEX idx_contract_state_date ON finint_public_contracts(state, reference_date)")
    op.execute("CREATE INDEX idx_contract_source_record ON finint_public_contracts(source_record_id)")
    op.execute("CREATE INDEX idx_contract_status ON finint_public_contracts(analysis_status)")
    op.execute("""
        CREATE TRIGGER update_finint_public_contracts_updated_at
        BEFORE UPDATE ON finint_public_contracts
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── finint_trade_flows ────────────────────────────────────────────────────
    op.create_table(
        "finint_trade_flows",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False, primary_key=True),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False, unique=True),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("reference_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(2), nullable=True),
        sa.Column("ncm_code", sa.String(10), nullable=False),
        sa.Column("ncm_desc", sa.String(512), nullable=True),
        sa.Column("sh2_code", sa.String(2), nullable=True),
        sa.Column("export_value_usd", sa.Numeric(18, 2), nullable=False, server_default=sa.text("0")),
        sa.Column("net_weight_kg", sa.Numeric(18, 3), nullable=False, server_default=sa.text("0")),
        sa.Column("country_code", sa.String(4), nullable=True),
        sa.Column("anomaly_score", sa.Numeric(5, 4), nullable=False, server_default=sa.text("0")),
        sa.Column("analysis_status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("alert_id", sa.String(64), nullable=True),
        sa.Column("geoint_correlation_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "analysis_status IN ('pending', 'processed', 'suspicious', 'alerted')",
            name="ck_trade_status",
        ),
        sa.ForeignKeyConstraint(["source_record_id"], ["source_records.id"], ondelete="RESTRICT"),
    )
    op.execute("CREATE UNIQUE INDEX uq_trade_external_id ON finint_trade_flows(external_id)")
    op.execute("CREATE INDEX idx_trade_ncm_date ON finint_trade_flows(ncm_code, reference_date)")
    op.execute("CREATE INDEX idx_trade_state_ncm ON finint_trade_flows(state, ncm_code)")
    op.execute("CREATE INDEX idx_trade_source_record ON finint_trade_flows(source_record_id)")
    op.execute("CREATE INDEX idx_trade_status ON finint_trade_flows(analysis_status)")
    op.execute("""
        CREATE TRIGGER update_finint_trade_flows_updated_at
        BEFORE UPDATE ON finint_trade_flows
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)


def downgrade() -> None:
    # Drop em ordem inversa de FK
    op.execute("DROP TABLE IF EXISTS finint_trade_flows CASCADE")
    op.execute("DROP TABLE IF EXISTS finint_public_contracts CASCADE")
    op.execute("DROP TABLE IF EXISTS finint_market_indicators CASCADE")
    op.execute("DROP TABLE IF EXISTS finint_financial_flows CASCADE")
    op.execute("DROP TABLE IF EXISTS finint_entity_relationships CASCADE")
    op.execute("DROP TABLE IF EXISTS finint_financial_entities CASCADE")
