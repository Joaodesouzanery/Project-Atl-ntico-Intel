"""
Fixtures de DB para testes unitários do Atlas.

Estratégia: SQLite in-memory async (aiosqlite). Registramos uma função
``gen_random_uuid()`` user-defined no driver para que o ``server_default``
das colunas UUID (originalmente PostgreSQL ``gen_random_uuid()``)
funcione em sqlite. As tabelas Atlas são criadas explicitamente
(sem tocar nas tabelas PostgreSQL-only do core).
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from atlantico.atlas.storage.models import (
    ContratoConcessaoModel,
    DeliberacaoModel,
    NormaModel,
    ProcessoAdministrativoModel,
    ReguladoModel,
)

ATLAS_TABLES = [
    NormaModel.__table__,
    ProcessoAdministrativoModel.__table__,
    DeliberacaoModel.__table__,
    ReguladoModel.__table__,
    ContratoConcessaoModel.__table__,
]


@pytest_asyncio.fixture
async def atlas_session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)

    # Registra gen_random_uuid() user-defined no SQLite (PG default das PKs)
    @event.listens_for(engine.sync_engine, "connect")
    def _register_uuid_func(dbapi_conn, _record):
        dbapi_conn.create_function(
            "gen_random_uuid", 0, lambda: str(uuid.uuid4())
        )

    async with engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: NormaModel.metadata.create_all(
                sync_conn, tables=ATLAS_TABLES
            )
        )

    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        yield session

    await engine.dispose()
