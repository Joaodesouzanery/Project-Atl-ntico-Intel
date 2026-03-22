"""
EntityRepository — entidades e relacionamentos financeiros para análise de rede.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.finint.models.entity_relationship import EntityRelationship
from atlantico.finint.models.financial_entity import FinancialEntity

if TYPE_CHECKING:
    import uuid

logger = logging.getLogger(__name__)


class EntityRepository:
    """Repositório para FinancialEntity e EntityRelationship."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_or_update(self, entity_data: dict) -> FinancialEntity:
        """
        Upsert de entidade financeira por external_id.

        entity_data deve conter: external_id, entity_type, name_enc (plaintext,
        TypeDecorator criptografa automaticamente), e campos opcionais.
        """
        stmt = (
            pg_insert(FinancialEntity)
            .values(**entity_data)
            .on_conflict_do_update(
                index_elements=["external_id"],
                set_={
                    k: entity_data[k]
                    for k in entity_data
                    if k not in ("id", "external_id", "created_at")
                },
            )
            .returning(FinancialEntity)
        )
        result = await self._session.execute(stmt)
        entity = result.scalar_one()
        await self._session.flush()
        return entity

    async def get_by_external_id(self, external_id: str) -> FinancialEntity | None:
        """Busca entidade por external_id."""
        stmt = select(FinancialEntity).where(FinancialEntity.external_id == external_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_relationship(
        self,
        source_id: "uuid.UUID",
        target_id: "uuid.UUID",
        relationship_type: str,
        strength: float = 1.0,
        total_value_brl: float = 0.0,
    ) -> EntityRelationship:
        """
        Cria ou atualiza relacionamento entre entidades.

        ON CONFLICT DO UPDATE para acumular transaction_count e total_value_brl.
        """
        stmt = (
            pg_insert(EntityRelationship)
            .values(
                source_entity_id=source_id,
                target_entity_id=target_id,
                relationship_type=relationship_type,
                strength=strength,
                transaction_count=1,
                total_value_brl=total_value_brl,
            )
            .on_conflict_do_update(
                constraint="uq_entity_relationship",
                set_={
                    "transaction_count": EntityRelationship.transaction_count + 1,
                    "total_value_brl": EntityRelationship.total_value_brl + total_value_brl,
                    "strength": strength,
                },
            )
            .returning(EntityRelationship)
        )
        result = await self._session.execute(stmt)
        rel = result.scalar_one()
        await self._session.flush()
        return rel

    async def get_relationships(
        self,
        entity_id: "uuid.UUID",
        depth: int = 1,
    ) -> list[EntityRelationship]:
        """
        Retorna relacionamentos de uma entidade (depth=1).

        Para depth > 1, use NetworkAnalyzer.build_graph() + BFS.
        """
        stmt = select(EntityRelationship).where(
            (EntityRelationship.source_entity_id == entity_id)
            | (EntityRelationship.target_entity_id == entity_id)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update_risk_score(
        self,
        entity_id: "uuid.UUID",
        risk_score: float,
        flags: list[str] | None = None,
        centrality_score: float | None = None,
    ) -> None:
        """Atualiza score de risco e flags da entidade."""
        values: dict = {"risk_score": risk_score}
        if flags is not None:
            values["flags"] = flags
        if centrality_score is not None:
            values["centrality_score"] = centrality_score

        stmt = update(FinancialEntity).where(FinancialEntity.id == entity_id).values(**values)
        await self._session.execute(stmt)
        await self._session.flush()

    async def list_high_risk(
        self,
        risk_threshold: float = 0.7,
        limit: int = 100,
    ) -> list[FinancialEntity]:
        """Lista entidades com score de risco acima do limiar."""
        stmt = (
            select(FinancialEntity)
            .where(
                FinancialEntity.risk_score >= risk_threshold,
                FinancialEntity.active.is_(True),
            )
            .order_by(FinancialEntity.risk_score.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_all_relationships(self) -> list[EntityRelationship]:
        """Retorna todos os relacionamentos para construir o grafo completo."""
        stmt = select(EntityRelationship)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
