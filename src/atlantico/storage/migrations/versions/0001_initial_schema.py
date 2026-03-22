"""Schema inicial do Projeto Atlântico — Sprint 2

Revision ID: 0001
Revises: None
Create Date: 2026-03-21

Cria:
    - Extensões: uuid-ossp, postgis
    - Tabela: key_store (chaves criptográficas)
    - Tabela: source_records (dados OSINT com envelope PQC)
    - Tabela: alerts (alertas de correlação assinados)
    - Tabela: audit_log (append-only, encadeado SHA3-256)
    - Índices: tipo+status, geoespaciais GIST, temporais
    - Row-Level Security: audit_log bloqueado para UPDATE/DELETE
    - Função e Trigger: atualização automática de updated_at
"""

from __future__ import annotations

from typing import Sequence, Union

import geoalchemy2
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ─── Extensões PostgreSQL ─────────────────────────────────────────────────
    op.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
    op.execute("CREATE EXTENSION IF NOT EXISTS postgis")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")  # gen_random_uuid()

    # ─── Função para atualizar updated_at automaticamente ────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql'
    """)

    # ─── Tabela: key_store ────────────────────────────────────────────────────
    op.create_table(
        "key_store",
        sa.Column("key_id", sa.String(64), primary_key=True, nullable=False,
                  comment="ID único da chave (32 hex chars)"),
        sa.Column("suite", sa.String(128), nullable=False,
                  comment="Suite criptográfica (ex: hybrid-kyber768-x25519)"),
        sa.Column("key_type", sa.String(16), nullable=False,
                  comment="kem | signing"),
        sa.Column("public_key", sa.LargeBinary(), nullable=False,
                  comment="Chave pública em bytes"),
        sa.Column("private_key_enc", sa.LargeBinary(), nullable=False,
                  comment="Chave privada duplamente criptografada (KEK + TypeDecorator)"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active",
                  comment="active | deprecated | retired"),
        sa.Column("created_at", sa.BigInteger(), nullable=False,
                  comment="Unix timestamp de criação"),
        sa.Column("deprecated_at", sa.BigInteger(), nullable=True,
                  comment="Unix timestamp de deprecação"),
        sa.Column("retired_at", sa.BigInteger(), nullable=True,
                  comment="Unix timestamp de aposentadoria"),
        sa.Column("rotation_reason", sa.Text(), nullable=False, server_default="",
                  comment="Motivo da rotação"),

        sa.CheckConstraint("key_type IN ('kem', 'signing')", name="ck_key_store_key_type"),
        sa.CheckConstraint("status IN ('active', 'deprecated', 'retired')", name="ck_key_store_status"),

        comment="Armazenamento persistente de chaves criptográficas",
    )
    op.create_index(
        "idx_key_store_type_status",
        "key_store",
        ["key_type", "status"],
    )

    # ─── Tabela: source_records ───────────────────────────────────────────────
    op.create_table(
        "source_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()"),
                  comment="UUID gerado pelo PostgreSQL"),
        sa.Column("record_id", sa.String(128), unique=True, nullable=False,
                  comment="ID externo único da fonte"),
        sa.Column("source_id", sa.String(64), nullable=False,
                  comment="Identificador da fonte OSINT"),
        sa.Column("data_classification", sa.String(32), nullable=False,
                  comment="PUBLIC | RESTRICTED | CONFIDENTIAL | SECRET"),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False,
                  comment="Timestamp de aquisição na fonte (UTC)"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()"),
                  comment="Timestamp de ingestão (UTC)"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()"),
                  comment="Timestamp de atualização (UTC)"),
        sa.Column("kem_key_id", sa.String(64), nullable=False,
                  comment="key_id da chave KEM usada no envelope"),
        sa.Column("sig_key_id", sa.String(64), nullable=False,
                  comment="key_id da chave de assinatura usada no envelope"),
        sa.Column("payload_envelope", sa.LargeBinary(), nullable=False,
                  comment="Envelope PQC binário completo"),
        sa.Column("geo_bounds",
                  geoalchemy2.types.Geometry("POLYGON", srid=4326, nullable=True),
                  nullable=True,
                  comment="Bounding box geoespacial WGS-84 (PostGIS)"),
        sa.Column("provenance_hash", sa.String(128), nullable=False,
                  comment="SHA3-256 do envelope + metadados para integridade"),
        sa.Column("source_metadata", sa.Text(), nullable=True,
                  comment="Metadados extras da fonte (JSON texto)"),

        sa.CheckConstraint(
            "data_classification IN ('PUBLIC', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')",
            name="ck_source_records_classification",
        ),
        sa.ForeignKeyConstraint(
            ["kem_key_id"], ["key_store.key_id"],
            name="fk_source_records_kem_key", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["sig_key_id"], ["key_store.key_id"],
            name="fk_source_records_sig_key", ondelete="RESTRICT",
        ),

        comment="Dados OSINT ingeridos, protegidos por envelope PQC por registro",
    )
    op.create_index(
        "idx_source_records_source_time",
        "source_records",
        ["source_id", "acquired_at"],
    )
    op.create_index(
        "idx_source_records_geo",
        "source_records",
        ["geo_bounds"],
        postgresql_using="gist",
    )
    op.execute("""
        CREATE TRIGGER update_source_records_updated_at
        BEFORE UPDATE ON source_records
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── Tabela: alerts ───────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()"),
                  comment="UUID gerado pelo PostgreSQL"),
        sa.Column("alert_id", sa.String(64), unique=True, nullable=False,
                  comment="ID único do alerta (gerado pela aplicação)"),
        sa.Column("severity", sa.String(16), nullable=False,
                  comment="LOW | MEDIUM | HIGH | CRITICAL"),
        sa.Column("rule_id", sa.String(128), nullable=False,
                  comment="ID da regra de correlação"),
        sa.Column("title_enc", sa.LargeBinary(), nullable=False,
                  comment="Título criptografado (AES-256-GCM via EncryptedBytes)"),
        sa.Column("description_enc", sa.LargeBinary(), nullable=False,
                  comment="Descrição criptografada (AES-256-GCM via EncryptedBytes)"),
        sa.Column("source_record_ids", postgresql.JSONB(), nullable=False,
                  server_default="[]", comment="UUIDs dos SourceRecords correlacionados"),
        sa.Column("geo_location",
                  geoalchemy2.types.Geometry("POINT", srid=4326, nullable=True),
                  nullable=True,
                  comment="Localização geoespacial central (PostGIS Point)"),
        sa.Column("status", sa.String(16), nullable=False, server_default="open",
                  comment="open | investigating | closed | false_positive"),
        sa.Column("signature", sa.LargeBinary(), nullable=False,
                  comment="Assinatura Dilithium3+Ed25519 do conteúdo"),
        sa.Column("kem_key_id", sa.String(64), nullable=False,
                  comment="key_id da chave KEM (referência)"),
        sa.Column("sig_key_id", sa.String(64), nullable=False,
                  comment="key_id da chave de assinatura"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False,
                  comment="Timestamp do evento (UTC)"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()"),
                  comment="Timestamp de criação do registro (UTC)"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()"),
                  comment="Timestamp de atualização (UTC)"),
        sa.Column("assigned_to", sa.String(128), nullable=True,
                  comment="Analista responsável"),
        sa.Column("investigation_notes", sa.Text(), nullable=True,
                  comment="Notas de investigação"),

        sa.CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_alerts_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'closed', 'false_positive')",
            name="ck_alerts_status",
        ),
        sa.ForeignKeyConstraint(
            ["kem_key_id"], ["key_store.key_id"],
            name="fk_alerts_kem_key", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["sig_key_id"], ["key_store.key_id"],
            name="fk_alerts_sig_key", ondelete="RESTRICT",
        ),

        comment="Alertas de correlação assinados com Dilithium3+Ed25519",
    )
    op.create_index(
        "idx_alerts_severity_status",
        "alerts",
        ["severity", "status", "occurred_at"],
    )
    op.create_index(
        "idx_alerts_geo",
        "alerts",
        ["geo_location"],
        postgresql_using="gist",
    )
    op.execute("""
        CREATE TRIGGER update_alerts_updated_at
        BEFORE UPDATE ON alerts
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    """)

    # ─── Tabela: audit_log (APPEND-ONLY) ──────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("seq", sa.BigInteger(), primary_key=True, autoincrement=True,
                  comment="Número de sequência monotônico (BIGSERIAL)"),
        sa.Column("event_id", sa.String(64), unique=True, nullable=False,
                  comment="UUID único do evento (gerado pela aplicação)"),
        sa.Column("event_type", sa.String(128), nullable=False,
                  comment="Tipo do evento (ex: KEY_GENERATED)"),
        sa.Column("actor_id", sa.String(128), nullable=False,
                  comment="Identificador do ator"),
        sa.Column("target_id", sa.String(128), nullable=True,
                  comment="ID do objeto alvo (nullable)"),
        sa.Column("event_data", postgresql.JSONB(), nullable=False,
                  server_default="{}", comment="Dados contextuais (sem dados sensíveis)"),
        sa.Column("occurred_at", sa.Text(), nullable=False,
                  comment="Timestamp ISO 8601 UTC do evento"),
        sa.Column("prev_hash", sa.String(128), nullable=False,
                  comment="SHA3-256 da entrada anterior (ou GENESIS_HASH)"),
        sa.Column("entry_hash", sa.String(128), nullable=False,
                  comment="SHA3-256 desta entrada"),
        sa.Column("entry_signature", sa.LargeBinary(), nullable=False,
                  comment="Assinatura Dilithium3+Ed25519 do entry_hash"),
        sa.Column("signer_key_id", sa.String(64), nullable=False,
                  comment="key_id da chave de assinatura"),

        comment=(
            "Audit log append-only encadeado SHA3-256 + assinatura Dilithium. "
            "Row-Level Security bloqueia UPDATE e DELETE."
        ),
    )
    op.create_index(
        "idx_audit_log_event_type_seq",
        "audit_log",
        ["event_type", "seq"],
    )
    op.create_index(
        "idx_audit_log_actor_seq",
        "audit_log",
        ["actor_id", "seq"],
    )

    # ─── Row-Level Security: audit_log APPEND-ONLY ────────────────────────────
    # Bloqueia UPDATE e DELETE para TODOS os usuários (incluindo o owner da tabela
    # ao acessar via regras RLS). A tabela só aceita INSERT e SELECT.
    #
    # NOTA: O superuser do PostgreSQL pode sempre contornar RLS com SET SESSION.
    # A segurança definitiva do audit log requer:
    # 1. Acesso ao superuser restrito (sem acesso ao usuário da aplicação)
    # 2. Replicação para sistema externo de audit imutável
    op.execute("ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_log FORCE ROW LEVEL SECURITY")  # Afeta owner também

    # Política de INSERT: qualquer insert é permitido (aplicação insere normalmente)
    op.execute("""
        CREATE POLICY audit_log_insert_only ON audit_log
            FOR INSERT
            WITH CHECK (true)
    """)

    # Política de SELECT: leitura irrestrita
    op.execute("""
        CREATE POLICY audit_log_select_all ON audit_log
            FOR SELECT
            USING (true)
    """)

    # Nenhuma política para UPDATE e DELETE → operações bloqueadas por RLS
    # Tentativas resultam em: ERROR: new row violates row-level security policy


def downgrade() -> None:
    # Remove Row-Level Security antes de drop
    op.execute("DROP POLICY IF EXISTS audit_log_select_all ON audit_log")
    op.execute("DROP POLICY IF EXISTS audit_log_insert_only ON audit_log")
    op.execute("ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY")

    op.drop_table("audit_log")
    op.drop_table("alerts")
    op.drop_table("source_records")
    op.drop_table("key_store")

    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE")
    op.execute("DROP EXTENSION IF EXISTS postgis CASCADE")
    op.execute("DROP EXTENSION IF EXISTS pgcrypto")
    op.execute('DROP EXTENSION IF EXISTS "uuid-ossp"')
