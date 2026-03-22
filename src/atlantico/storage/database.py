"""
Engine SQLAlchemy Async + PostGIS para o Projeto Atlântico.

Fornece:
- Engine async (asyncpg) com pool configurável e TLS em produção
- AsyncSessionLocal — session factory para uso na aplicação
- get_db_session() — dependency injection FastAPI (gerenciador de contexto)
- init_db() — cria tabelas (apenas em development/testes; produção usa Alembic)

SEGURANÇA:
    - ssl="require" em produção: TLS mesmo em rede Docker interna
    - pool_pre_ping: detecta conexões mortas antes de usar
    - pool_recycle: evita conexões zumbis após inatividade longa
    - echo=False em produção: nunca loga SQL (pode expor dados sensíveis)
    - Sem interpolação de strings em queries: sempre bound parameters via ORM/Core
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

if TYPE_CHECKING:
    from atlantico.config.settings import Settings


def _build_engine(settings: "Settings"):
    """
    Constrói o engine SQLAlchemy async com configurações de segurança e pool.

    SSL:
        - production/staging: ssl="require" — TLS obrigatório
        - development: ssl="prefer" — usa TLS se disponível, não falha se não

    Pool:
        - pool_size: conexões persistentes no pool
        - max_overflow: conexões extras além do pool em pico de carga
        - pool_pre_ping: SELECT 1 antes de usar conexão (detecta mortas)
        - pool_recycle: máximo de segundos que uma conexão vive no pool
        - pool_timeout: tempo máximo para obter conexão do pool (evita deadlock)
    """
    ssl_mode = "require" if settings.is_production or settings.env.value == "staging" else "prefer"

    return create_async_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
        pool_recycle=3600,          # Recicla conexões a cada hora
        pool_timeout=30,            # Timeout para obter conexão do pool
        echo=settings.is_development,  # Log SQL apenas em development
        connect_args={
            "ssl": ssl_mode,
            "server_settings": {
                # Garante que PostGIS está carregado na sessão
                "search_path": "public",
                # Statement timeout: evita queries longas bloqueando o pool
                "statement_timeout": "30000",  # 30 segundos
            },
        },
    )


# ─── Engine e Session Factory globais ────────────────────────────────────────
# Inicializados lazy em init_engine() para suportar testes sem settings reais.
_engine = None
_AsyncSessionLocal: async_sessionmaker[AsyncSession] | None = None


def init_engine(settings: "Settings") -> None:
    """
    Inicializa o engine e session factory com as configurações fornecidas.

    Deve ser chamado UMA VEZ no startup da aplicação (lifespan FastAPI),
    APÓS EncryptionContext.initialize().

    Args:
        settings: Instância de Settings com database_url e pool configs.
    """
    global _engine, _AsyncSessionLocal

    _engine = _build_engine(settings)
    _AsyncSessionLocal = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,  # Evita lazy-loads após commit em código async
        autobegin=True,
    )


def get_engine():
    """
    Retorna o engine inicializado.

    Raises:
        RuntimeError: Se init_engine() não foi chamado.
    """
    if _engine is None:
        msg = (
            "Engine não inicializado. "
            "Chame init_engine(settings) no startup da aplicação."
        )
        raise RuntimeError(msg)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """
    Retorna a session factory inicializada.

    Raises:
        RuntimeError: Se init_engine() não foi chamado.
    """
    if _AsyncSessionLocal is None:
        msg = (
            "Session factory não inicializada. "
            "Chame init_engine(settings) no startup da aplicação."
        )
        raise RuntimeError(msg)
    return _AsyncSessionLocal


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency injection FastAPI para obter sessão de banco de dados.

    Gerencia commit/rollback automaticamente:
    - Commit no final bem-sucedido do request
    - Rollback em qualquer exceção
    - Close garantido em todos os casos (async context manager)

    Uso em rotas FastAPI:
        @router.get("/endpoint")
        async def endpoint(session: AsyncSession = Depends(get_db_session)):
            ...

    Uso em código direto:
        async for session in get_db_session():
            result = await session.execute(...)
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """
    Cria todas as tabelas definidas nos modelos SQLAlchemy.

    ATENÇÃO: Use apenas em development e testes.
    Em produção e staging, use Alembic para migrations controladas.

    Importa todos os modelos para que metadata os registre automaticamente.
    """
    # Import tardio para evitar imports circulares durante inicialização
    from atlantico.storage.models.base import Base  # noqa: F401
    from atlantico.storage.models.alert import Alert  # noqa: F401
    from atlantico.storage.models.audit_log import AuditLogEntry  # noqa: F401
    from atlantico.storage.models.key_store import KeyStoreEntry  # noqa: F401
    from atlantico.storage.models.source_record import SourceRecord  # noqa: F401

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_db() -> None:
    """
    Remove todas as tabelas. APENAS PARA TESTES.
    Nunca chame em produção.
    """
    from atlantico.storage.models.base import Base  # noqa: F401
    from atlantico.storage.models.alert import Alert  # noqa: F401
    from atlantico.storage.models.audit_log import AuditLogEntry  # noqa: F401
    from atlantico.storage.models.key_store import KeyStoreEntry  # noqa: F401
    from atlantico.storage.models.source_record import SourceRecord  # noqa: F401

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def _reset_engine_for_testing() -> None:
    """APENAS PARA TESTES. Reseta o engine e session factory globais."""
    global _engine, _AsyncSessionLocal
    _engine = None
    _AsyncSessionLocal = None
