"""
Alembic env.py — Configuração do ambiente de migrations.

Suporta dois modos:
- offline: Gera SQL sem conexão ao banco (útil para revisão)
- online: Aplica migrations em conexão real (produção/testes)

O modo online usa a URL síncrona (psycopg) porque o Alembic
não tem suporte nativo a async. Para contextos async, a aplicação
usa o runner em scripts/migrate.py que executa Alembic em thread.

IMPORTANTE: Os modelos devem ser importados ANTES de chamar
autogenerate, para que o metadata do SQLAlchemy reflita o schema.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Garante que o pacote atlantico é encontrado mesmo sem instalar
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

# Importa o metadata de todos os modelos para autogenerate funcionar
from atlantico.storage.models.base import Base  # noqa: E402
from atlantico.storage.models.alert import Alert  # noqa: E402, F401
from atlantico.storage.models.audit_log import AuditLogEntry  # noqa: E402, F401
from atlantico.storage.models.key_store import KeyStoreEntry  # noqa: E402, F401
from atlantico.storage.models.source_record import SourceRecord  # noqa: E402, F401

# Alembic Config — lê alembic.ini
config = context.config

# Configura logging via alembic.ini se disponível
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata para autogenerate (detecta diferenças entre modelos e DB)
target_metadata = Base.metadata

# Sobrescreve sqlalchemy.url com a URL de settings se disponível
# (evita colocar senha em alembic.ini)
def get_url() -> str:
    """
    Retorna a URL do banco de dados.
    Prioridade: variável de ambiente ATLANTICO_DB_URL > alembic.ini
    """
    db_url = os.environ.get("ATLANTICO_DB_URL")
    if db_url:
        return db_url

    # Tenta construir a partir das variáveis individuais de settings
    try:
        from atlantico.config.settings import get_settings
        return get_settings().database_url_sync
    except Exception:
        pass

    # Fallback para o valor em alembic.ini
    return config.get_main_option("sqlalchemy.url", "")


def run_migrations_offline() -> None:
    """
    Modo offline: gera SQL sem conexão ao banco.

    Útil para revisar migrations antes de aplicar em produção.
    Comando: alembic upgrade head --sql
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Inclui schemas não-padrão (como postgis)
        include_schemas=True,
        # Compara tipos de colunas para detectar mudanças
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Modo online: aplica migrations em conexão real.

    Usa pool NullPool para evitar conexões residuais após a migration.
    """
    # Configura URL dinamicamente
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            compare_type=True,
            compare_server_default=True,
            # Renderiza itens como ADD COLUMN em vez de DROP + ADD
            render_as_batch=False,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
