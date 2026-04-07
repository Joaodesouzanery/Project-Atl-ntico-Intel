"""Repositório async para ContratoConcessao."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.atlas.ontology import ContratoConcessao
from atlantico.atlas.storage.mappers import (
    contrato_from_model,
    contrato_to_kwargs,
)
from atlantico.atlas.storage.models import ContratoConcessaoModel
from atlantico.atlas.storage.repositories._dialect import insert_for


class ContratoConcessaoRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self, contrato: ContratoConcessao
    ) -> ContratoConcessaoModel:
        kwargs = contrato_to_kwargs(contrato)
        stmt = (
            insert_for(self._session, ContratoConcessaoModel)
            .values(**kwargs)
            .on_conflict_do_nothing(
                index_elements=["orgao", "numero_contrato"]
            )
        )
        await self._session.execute(stmt)
        await self._session.flush()
        result = await self._session.execute(
            select(ContratoConcessaoModel).where(
                ContratoConcessaoModel.orgao == contrato.orgao,
                ContratoConcessaoModel.numero_contrato == contrato.numero_contrato,
            )
        )
        return result.scalar_one()

    async def list_by_regulado(
        self, regulado_id: str, limit: int = 100
    ) -> list[ContratoConcessaoModel]:
        result = await self._session.execute(
            select(ContratoConcessaoModel)
            .where(ContratoConcessaoModel.regulado_id == regulado_id)
            .order_by(ContratoConcessaoModel.data_assinatura.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def fetch_dataclass(
        self, orgao: str, numero_contrato: str
    ) -> ContratoConcessao | None:
        result = await self._session.execute(
            select(ContratoConcessaoModel).where(
                ContratoConcessaoModel.orgao == orgao,
                ContratoConcessaoModel.numero_contrato == numero_contrato,
            )
        )
        model = result.scalar_one_or_none()
        return contrato_from_model(model) if model else None
