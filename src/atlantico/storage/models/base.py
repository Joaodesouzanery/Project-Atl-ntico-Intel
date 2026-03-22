"""
Base SQLAlchemy e mixins compartilhados para todos os modelos do Projeto Atlântico.

DeclarativeBase centraliza o metadata — todos os modelos herdam desta base para
que Alembic e create_all() possam descobrir o schema completo automaticamente.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    Base declarativa compartilhada por todos os modelos SQLAlchemy.

    Usar type_annotation_map para customizar mapeamentos de tipos Python → SQL.
    datetime sem timezone é banido — sempre usar datetime com UTC.
    """

    type_annotation_map = {
        # Força TIMESTAMPTZ no PostgreSQL para todas as colunas datetime
        datetime: DateTime(timezone=True),
    }


class UUIDPKMixin:
    """
    Mixin que adiciona coluna UUID como chave primária gerada pelo servidor.

    Usa gen_random_uuid() do PostgreSQL (extensão pgcrypto) — mais eficiente
    e mais seguro que gerar UUID no cliente, pois evita colisões em inserts
    paralelos e não expõe estado interno do gerador no cliente.

    Nota: Para tabelas com chave primária não-UUID (ex: key_store com key_id
    VARCHAR, audit_log com BIGSERIAL), NÃO use este mixin — defina a PK
    diretamente no modelo.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
        comment="UUID gerado pelo PostgreSQL (gen_random_uuid)",
    )


class TimestampMixin:
    """
    Mixin que adiciona colunas de timestamp de criação e atualização.

    created_at: Preenchido automaticamente pelo PostgreSQL no INSERT.
    updated_at: Atualizado automaticamente pelo PostgreSQL no UPDATE.

    Ambos usam TIMESTAMPTZ (com fuso horário) — nunca armazene timestamps
    sem timezone no PostgreSQL, pois isso causa bugs sutis em sistemas
    distribuídos com servidores em fusos diferentes.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Timestamp de criação (UTC, gerado pelo PostgreSQL)",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        comment="Timestamp de última atualização (UTC, atualizado automaticamente)",
    )


def utcnow() -> datetime:
    """Retorna datetime atual em UTC com timezone (timezone-aware)."""
    return datetime.now(timezone.utc)
