"""Repositório async para Deliberacao."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.atlas.ontology import Deliberacao
from atlantico.atlas.storage.mappers import (
    deliberacao_from_model,
    deliberacao_to_kwargs,
)
from atlantico.atlas.storage.models import DeliberacaoModel
from atlantico.atlas.storage.repositories._dialect import insert_for


class DeliberacaoRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(self, delib: Deliberacao) -> DeliberacaoModel:
        kwargs = deliberacao_to_kwargs(delib)
        stmt = (
            insert_for(self._session, DeliberacaoModel)
            .values(**kwargs)
            .on_conflict_do_nothing(
                index_elements=["orgao", "colegiado", "numero", "ano"]
            )
        )
        await self._session.execute(stmt)
        await self._session.flush()
        result = await self._session.execute(
            select(DeliberacaoModel).where(
                DeliberacaoModel.orgao == delib.orgao,
                DeliberacaoModel.colegiado == delib.colegiado,
                DeliberacaoModel.numero == delib.numero,
                DeliberacaoModel.ano == delib.ano,
            )
        )
        return result.scalar_one()

    async def list_by_relator(
        self, relator_id: str, since: datetime, limit: int = 100
    ) -> list[DeliberacaoModel]:
        result = await self._session.execute(
            select(DeliberacaoModel)
            .where(
                DeliberacaoModel.relator_id == relator_id,
                DeliberacaoModel.data_sessao >= since,
            )
            .order_by(DeliberacaoModel.data_sessao.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_by_dispositivo(
        self, orgao: str, dispositivo: str, since: datetime
    ) -> list[DeliberacaoModel]:
        result = await self._session.execute(
            select(DeliberacaoModel)
            .where(
                DeliberacaoModel.orgao == orgao,
                DeliberacaoModel.dispositivo == dispositivo,
                DeliberacaoModel.data_sessao >= since,
            )
            .order_by(DeliberacaoModel.data_sessao.desc())
        )
        return list(result.scalars().all())

    async def fetch_dataclass(
        self, orgao: str, colegiado: str, numero: int, ano: int
    ) -> Deliberacao | None:
        result = await self._session.execute(
            select(DeliberacaoModel).where(
                DeliberacaoModel.orgao == orgao,
                DeliberacaoModel.colegiado == colegiado,
                DeliberacaoModel.numero == numero,
                DeliberacaoModel.ano == ano,
            )
        )
        model = result.scalar_one_or_none()
        return deliberacao_from_model(model) if model else None
