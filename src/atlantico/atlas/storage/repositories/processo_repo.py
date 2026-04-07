"""Repositório async para ProcessoAdministrativo."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.atlas.ontology import ProcessoAdministrativo
from atlantico.atlas.storage.mappers import (
    processo_from_model,
    processo_to_kwargs,
)
from atlantico.atlas.storage.models import ProcessoAdministrativoModel
from atlantico.atlas.storage.repositories._dialect import insert_for


class ProcessoAdministrativoRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self, processo: ProcessoAdministrativo
    ) -> ProcessoAdministrativoModel:
        kwargs = processo_to_kwargs(processo)
        stmt = (
            insert_for(self._session, ProcessoAdministrativoModel)
            .values(**kwargs)
            .on_conflict_do_nothing(index_elements=["numero_sei"])
        )
        await self._session.execute(stmt)
        await self._session.flush()
        result = await self._session.execute(
            select(ProcessoAdministrativoModel).where(
                ProcessoAdministrativoModel.numero_sei == processo.numero_sei
            )
        )
        return result.scalar_one()

    async def get_by_numero_sei(
        self, numero_sei: str
    ) -> ProcessoAdministrativoModel | None:
        result = await self._session.execute(
            select(ProcessoAdministrativoModel).where(
                ProcessoAdministrativoModel.numero_sei == numero_sei
            )
        )
        return result.scalar_one_or_none()

    async def list_ativos(
        self, orgao: str, limit: int = 100
    ) -> list[ProcessoAdministrativoModel]:
        result = await self._session.execute(
            select(ProcessoAdministrativoModel)
            .where(
                ProcessoAdministrativoModel.orgao == orgao,
                ProcessoAdministrativoModel.fase != "arquivado",
                ProcessoAdministrativoModel.data_conclusao.is_(None),
            )
            .order_by(ProcessoAdministrativoModel.data_autuacao.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def fetch_dataclass(
        self, numero_sei: str
    ) -> ProcessoAdministrativo | None:
        model = await self.get_by_numero_sei(numero_sei)
        return processo_from_model(model) if model else None
