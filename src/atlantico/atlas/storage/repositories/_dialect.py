"""
Helper de dialeto para upserts portáveis (PostgreSQL e SQLite).

Tanto ``sqlalchemy.dialects.postgresql.insert`` quanto
``sqlalchemy.dialects.sqlite.insert`` expõem ``.on_conflict_do_nothing()``
com a mesma assinatura. Esta função despacha em runtime para que o mesmo
código de repositório funcione em produção (PG) e em testes (SQLite).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession


def insert_for(session: AsyncSession, table: Any):
    """
    Retorna a função ``insert`` adequada ao dialeto da sessão.

    Uso::

        stmt = insert_for(session, NormaModel).values(...).on_conflict_do_nothing(
            index_elements=["urn_lex"]
        )
    """
    bind = session.get_bind()
    name = bind.dialect.name
    if name == "postgresql":
        return pg_insert(table)
    if name == "sqlite":
        return sqlite_insert(table)
    # Fallback: tenta postgresql (qualquer dialeto não-suportado falhará claramente)
    return pg_insert(table)
