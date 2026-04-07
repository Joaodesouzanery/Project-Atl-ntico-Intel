"""
Migration Alembic: 0005 — Schema Atlas (vertical regulatória)

Cria as tabelas dos 5 objetos core do Atlântico Atlas (Sprint 4):

  1. atlas_normas
  2. atlas_processos
  3. atlas_deliberacoes
  4. atlas_regulados
  5. atlas_contratos

Princípios:
  - Default público (LAI by design): data_classification default 'PUBLIC'
  - Provenance: text_hash_sha3_256 para chain-of-custody
  - Timezone-aware sempre (TIMESTAMPTZ)
  - JSON portátil (compatível com PG e SQLite de teste)
  - PK UUID server-side via gen_random_uuid() (mesmo padrão Atlântico)

revision:      "0005"
down_revision: "0004"
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. atlas_normas
    op.create_table(
        "atlas_normas",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("urn_lex", sa.String(255), nullable=True),
        sa.Column("tipo", sa.String(32), nullable=False),
        sa.Column("numero", sa.Integer, nullable=False),
        sa.Column("ano", sa.Integer, nullable=False),
        sa.Column("orgao", sa.String(64), nullable=False),
        sa.Column("ementa", sa.Text, nullable=False),
        sa.Column("data_publicacao_dou", sa.DateTime(timezone=True), nullable=False),
        sa.Column("vigencia_inicio", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vigencia_fim", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revogada_por_urn", sa.String(255), nullable=True),
        sa.Column("air_vinculada_id", sa.String(36), nullable=True),
        sa.Column("texto_canonico_url", sa.Text, nullable=True),
        sa.Column("dou_url", sa.Text, nullable=True),
        sa.Column("text_hash_sha3_256", sa.String(64), nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default=sa.text("1.0")),
        sa.Column("data_classification", sa.String(32), nullable=False, server_default=sa.text("'PUBLIC'")),
        sa.Column("source_id", sa.String(64), nullable=True),
        sa.Column("tags", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.UniqueConstraint("urn_lex", name="uq_atlas_norma_urn"),
        sa.UniqueConstraint("orgao", "tipo", "numero", "ano", name="uq_atlas_norma_orgao_tipo_num_ano"),
        sa.CheckConstraint("data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')", name="ck_atlas_norma_classification"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_atlas_norma_confidence"),
    )
    op.create_index("ix_atlas_normas_urn_lex", "atlas_normas", ["urn_lex"])
    op.create_index("ix_atlas_normas_orgao", "atlas_normas", ["orgao"])
    op.create_index("ix_atlas_normas_text_hash_sha3_256", "atlas_normas", ["text_hash_sha3_256"])
    op.create_index("ix_atlas_norma_publicacao", "atlas_normas", ["data_publicacao_dou"])
    op.create_index("ix_atlas_norma_tipo_ano", "atlas_normas", ["tipo", "ano"])

    # 2. atlas_processos
    op.create_table(
        "atlas_processos",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("numero_sei", sa.String(32), nullable=False),
        sa.Column("orgao", sa.String(64), nullable=False),
        sa.Column("assunto", sa.Text, nullable=False),
        sa.Column("data_autuacao", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fase", sa.String(32), nullable=False, server_default=sa.text("'autuacao'")),
        sa.Column("partes", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("prazo_legal", sa.DateTime(timezone=True), nullable=True),
        sa.Column("data_conclusao", sa.DateTime(timezone=True), nullable=True),
        sa.Column("norma_relacionada_urn", sa.String(255), nullable=True),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("source_id", sa.String(64), nullable=True),
        sa.Column("text_hash_sha3_256", sa.String(64), nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default=sa.text("1.0")),
        sa.Column("data_classification", sa.String(32), nullable=False, server_default=sa.text("'PUBLIC'")),
        sa.Column("tags", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.UniqueConstraint("numero_sei", name="uq_atlas_processo_sei"),
        sa.CheckConstraint("data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')", name="ck_atlas_processo_classification"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_atlas_processo_confidence"),
    )
    op.create_index("ix_atlas_processos_orgao", "atlas_processos", ["orgao"])
    op.create_index("ix_atlas_processos_norma_relacionada_urn", "atlas_processos", ["norma_relacionada_urn"])
    op.create_index("ix_atlas_processo_orgao_fase", "atlas_processos", ["orgao", "fase"])
    op.create_index("ix_atlas_processo_autuacao", "atlas_processos", ["data_autuacao"])

    # 3. atlas_deliberacoes
    op.create_table(
        "atlas_deliberacoes",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("orgao", sa.String(64), nullable=False),
        sa.Column("colegiado", sa.String(64), nullable=False),
        sa.Column("numero", sa.Integer, nullable=False),
        sa.Column("ano", sa.Integer, nullable=False),
        sa.Column("data_sessao", sa.DateTime(timezone=True), nullable=False),
        sa.Column("relator_id", sa.String(64), nullable=False),
        sa.Column("dispositivo", sa.String(32), nullable=False),
        sa.Column("ementa", sa.Text, nullable=False),
        sa.Column("fundamento", sa.Text, nullable=False, server_default=sa.text("''")),
        sa.Column("processo_sei", sa.String(32), nullable=True),
        sa.Column("votos", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("norma_citada_urns", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("text_hash_sha3_256", sa.String(64), nullable=True),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("source_id", sa.String(64), nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default=sa.text("1.0")),
        sa.Column("data_classification", sa.String(32), nullable=False, server_default=sa.text("'PUBLIC'")),
        sa.Column("tags", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.UniqueConstraint("orgao", "colegiado", "numero", "ano", name="uq_atlas_deliberacao_natural"),
        sa.CheckConstraint("data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')", name="ck_atlas_delib_classification"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_atlas_delib_confidence"),
    )
    op.create_index("ix_atlas_deliberacoes_orgao", "atlas_deliberacoes", ["orgao"])
    op.create_index("ix_atlas_deliberacoes_processo_sei", "atlas_deliberacoes", ["processo_sei"])
    op.create_index("ix_atlas_delib_data", "atlas_deliberacoes", ["data_sessao"])

    # 4. atlas_regulados
    op.create_table(
        "atlas_regulados",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("razao_social", sa.Text, nullable=False),
        sa.Column("setor", sa.String(64), nullable=False),
        sa.Column("cnpj", sa.String(14), nullable=True),
        sa.Column("cpf_hash", sa.String(64), nullable=True),
        sa.Column("nome_fantasia", sa.Text, nullable=True),
        sa.Column("grupo_economico", sa.String(255), nullable=True),
        sa.Column("contratos_ativos", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("historico_sancoes_ids", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("tier_risco", sa.String(16), nullable=False, server_default=sa.text("'MEDIO'")),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("source_id", sa.String(64), nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default=sa.text("1.0")),
        sa.Column("data_classification", sa.String(32), nullable=False, server_default=sa.text("'PUBLIC'")),
        sa.Column("tags", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.UniqueConstraint("cnpj", name="uq_atlas_regulado_cnpj"),
        sa.UniqueConstraint("cpf_hash", name="uq_atlas_regulado_cpf_hash"),
        sa.CheckConstraint("cnpj IS NOT NULL OR cpf_hash IS NOT NULL", name="ck_atlas_regulado_cnpj_or_cpf"),
        sa.CheckConstraint("tier_risco IN ('BAIXO','MEDIO','ALTO','CRITICO')", name="ck_atlas_regulado_tier"),
        sa.CheckConstraint("data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')", name="ck_atlas_regulado_classification"),
    )
    op.create_index("ix_atlas_regulados_cnpj", "atlas_regulados", ["cnpj"])
    op.create_index("ix_atlas_regulados_cpf_hash", "atlas_regulados", ["cpf_hash"])
    op.create_index("ix_atlas_regulados_setor", "atlas_regulados", ["setor"])
    op.create_index("ix_atlas_regulados_grupo_economico", "atlas_regulados", ["grupo_economico"])
    op.create_index("ix_atlas_regulado_setor_tier", "atlas_regulados", ["setor", "tier_risco"])

    # 5. atlas_contratos
    op.create_table(
        "atlas_contratos",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("numero_contrato", sa.String(64), nullable=False),
        sa.Column("orgao", sa.String(64), nullable=False),
        sa.Column("modalidade", sa.String(32), nullable=False),
        sa.Column("objeto", sa.Text, nullable=False),
        sa.Column("regulado_id", sa.String(64), nullable=False),
        sa.Column("data_assinatura", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prazo_anos", sa.Integer, nullable=False),
        sa.Column("valor_total", sa.Numeric(20, 2), nullable=True),
        sa.Column("contraprestacao", sa.Numeric(20, 2), nullable=True),
        sa.Column("cronograma_marcos", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("garantias", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("data_termino_prevista", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rescisao_motivo", sa.Text, nullable=True),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("source_id", sa.String(64), nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default=sa.text("1.0")),
        sa.Column("data_classification", sa.String(32), nullable=False, server_default=sa.text("'PUBLIC'")),
        sa.Column("tags", sa.JSON, nullable=False, server_default=sa.text("'[]'::json")),
        sa.UniqueConstraint("orgao", "numero_contrato", name="uq_atlas_contrato_orgao_numero"),
        sa.CheckConstraint("prazo_anos > 0", name="ck_atlas_contrato_prazo"),
        sa.CheckConstraint("data_classification IN ('PUBLIC','RESTRICTED','CONFIDENTIAL')", name="ck_atlas_contrato_classification"),
    )
    op.create_index("ix_atlas_contratos_orgao", "atlas_contratos", ["orgao"])
    op.create_index("ix_atlas_contratos_regulado_id", "atlas_contratos", ["regulado_id"])
    op.create_index("ix_atlas_contrato_assinatura", "atlas_contratos", ["data_assinatura"])
    op.create_index("ix_atlas_contrato_modalidade", "atlas_contratos", ["modalidade"])


def downgrade() -> None:
    op.drop_table("atlas_contratos")
    op.drop_table("atlas_regulados")
    op.drop_table("atlas_deliberacoes")
    op.drop_table("atlas_processos")
    op.drop_table("atlas_normas")
