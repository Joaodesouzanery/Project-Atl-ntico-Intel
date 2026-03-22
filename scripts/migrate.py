"""
Runner de Migrations Alembic para o Projeto Atlântico.

Uso:
    # Aplicar todas as migrations pendentes
    PYTHONPATH=src python scripts/migrate.py

    # Aplicar até uma revisão específica
    PYTHONPATH=src python scripts/migrate.py --revision 0001

    # Voltar para uma revisão anterior (downgrade)
    PYTHONPATH=src python scripts/migrate.py --downgrade --revision 0001

    # Ver status atual
    PYTHONPATH=src python scripts/migrate.py --status

    # Gerar nova migration automaticamente (autogenerate)
    PYTHONPATH=src python scripts/migrate.py --generate "descrição da mudança"

VARIÁVEIS DE AMBIENTE:
    ATLANTICO_DB_URL — URL síncrona completa (prioridade máxima)
    ATLANTICO_DB_HOST, ATLANTICO_DB_PORT, ATLANTICO_DB_NAME,
    ATLANTICO_DB_USER, ATLANTICO_DB_PASSWORD — campos individuais

SEGURANÇA:
    Em produção, injete ATLANTICO_DB_PASSWORD via Docker Secret:
        ATLANTICO_DB_PASSWORD=$(cat /run/secrets/db_password) python scripts/migrate.py
"""

from __future__ import annotations

import argparse
import os
import sys

# Garante que o pacote atlantico é encontrado
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from alembic import command
from alembic.config import Config


def _get_alembic_config() -> Config:
    """
    Constrói a configuração do Alembic com a URL correta do banco.

    Prioridade da URL:
    1. Variável de ambiente ATLANTICO_DB_URL
    2. Construída a partir das variáveis individuais (ATLANTICO_DB_*)
    3. get_settings().database_url_sync
    """
    alembic_cfg = Config(
        os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
    )

    # Determina URL do banco
    db_url = os.environ.get("ATLANTICO_DB_URL")

    if not db_url:
        # Tenta construir a partir de variáveis individuais
        db_host = os.environ.get("ATLANTICO_DB_HOST", "localhost")
        db_port = os.environ.get("ATLANTICO_DB_PORT", "5432")
        db_name = os.environ.get("ATLANTICO_DB_NAME", "atlantico")
        db_user = os.environ.get("ATLANTICO_DB_USER", "atlantico_app")
        db_pass = os.environ.get("ATLANTICO_DB_PASSWORD", "")

        if db_pass:
            db_url = (
                f"postgresql+psycopg://{db_user}:{db_pass}"
                f"@{db_host}:{db_port}/{db_name}"
            )

    if not db_url:
        # Fallback para settings
        try:
            from atlantico.config.settings import get_settings
            db_url = get_settings().database_url_sync
        except Exception as exc:
            print(f"ERRO: Não foi possível determinar a URL do banco: {exc}", file=sys.stderr)
            print(
                "Configure ATLANTICO_DB_URL ou ATLANTICO_DB_PASSWORD.",
                file=sys.stderr,
            )
            sys.exit(1)

    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    return alembic_cfg


def cmd_upgrade(revision: str = "head") -> None:
    """Aplica migrations até a revisão especificada."""
    cfg = _get_alembic_config()
    print(f"Aplicando migrations até: {revision}")
    command.upgrade(cfg, revision)
    print("Migrations aplicadas com sucesso.")


def cmd_downgrade(revision: str) -> None:
    """Reverte migrations até a revisão especificada."""
    cfg = _get_alembic_config()
    print(f"Revertendo migrations para: {revision}")
    command.downgrade(cfg, revision)
    print("Downgrade concluído.")


def cmd_status() -> None:
    """Exibe o status atual das migrations."""
    cfg = _get_alembic_config()
    print("=== Status atual das migrations ===")
    command.current(cfg, verbose=True)
    print()
    print("=== Histórico de migrations ===")
    command.history(cfg, verbose=False)


def cmd_generate(message: str) -> None:
    """Gera uma nova migration via autogenerate."""
    cfg = _get_alembic_config()
    print(f"Gerando migration: '{message}'")
    command.revision(cfg, message=message, autogenerate=True)
    print("Migration gerada. Revise o arquivo antes de aplicar.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Runner de Migrations Alembic — Projeto Atlântico",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--revision", "-r",
        default="head",
        help="Revisão alvo (default: head = última migration)",
    )
    parser.add_argument(
        "--downgrade", "-d",
        action="store_true",
        help="Reverter migrations (requer --revision)",
    )
    parser.add_argument(
        "--status", "-s",
        action="store_true",
        help="Exibir status atual das migrations",
    )
    parser.add_argument(
        "--generate", "-g",
        metavar="MESSAGE",
        help="Gerar nova migration via autogenerate",
    )

    args = parser.parse_args()

    if args.status:
        cmd_status()
    elif args.generate:
        cmd_generate(args.generate)
    elif args.downgrade:
        if args.revision == "head":
            print(
                "ERRO: --downgrade requer --revision explícito (ex: --revision -1).",
                file=sys.stderr,
            )
            sys.exit(1)
        cmd_downgrade(args.revision)
    else:
        cmd_upgrade(args.revision)


if __name__ == "__main__":
    main()
