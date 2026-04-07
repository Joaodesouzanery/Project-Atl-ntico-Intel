"""Repositório async para Regulado."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.atlas.ontology import Regulado
from atlantico.atlas.storage.mappers import (
    regulado_from_model,
    regulado_to_kwargs,
)
from atlantico.atlas.storage.models import ReguladoModel
from atlantico.atlas.storage.repositories._dialect import insert_for


class ReguladoRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(self, regulado: Regulado) -> ReguladoModel:
        kwargs = regulado_to_kwargs(regulado)
        # Conflito por CNPJ se PJ; por CPF hash se PF
        index_elements = ["cnpj"] if regulado.cnpj else ["cpf_hash"]
        stmt = (
            insert_for(self._session, ReguladoModel)
            .values(**kwargs)
            .on_conflict_do_nothing(index_elements=index_elements)
        )
        await self._session.execute(stmt)
        await self._session.flush()
        if regulado.cnpj:
            cond = ReguladoModel.cnpj == regulado.cnpj
        else:
            cond = ReguladoModel.cpf_hash == regulado.cpf_hash
        result = await self._session.execute(select(ReguladoModel).where(cond))
        return result.scalar_one()

    async def get_by_cnpj(self, cnpj: str) -> ReguladoModel | None:
        result = await self._session.execute(
            select(ReguladoModel).where(ReguladoModel.cnpj == cnpj)
        )
        return result.scalar_one_or_none()

    async def list_by_setor_tier(
        self, setor: str, tier: str, limit: int = 100
    ) -> list[ReguladoModel]:
        result = await self._session.execute(
            select(ReguladoModel)
            .where(
                ReguladoModel.setor == setor,
                ReguladoModel.tier_risco == tier,
            )
            .limit(limit)
        )
        return list(result.scalars().all())

    async def fetch_dataclass(self, cnpj: str) -> Regulado | None:
        model = await self.get_by_cnpj(cnpj)
        return regulado_from_model(model) if model else None
