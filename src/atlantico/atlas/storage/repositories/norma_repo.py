"""Repositório async para Norma."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.atlas.ontology import Norma
from atlantico.atlas.storage.mappers import norma_from_model, norma_to_kwargs
from atlantico.atlas.storage.models import NormaModel
from atlantico.atlas.storage.repositories._dialect import insert_for


class NormaRepository:
    """
    Persistência de Normas.

    Estratégia de upsert: ``on_conflict_do_nothing`` na chave natural
    ``(orgao, tipo, numero, ano)``. Se o registro já existe, o store é
    silencioso (idempotente) e retorna a versão persistida.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(self, norma: Norma) -> NormaModel:
        kwargs = norma_to_kwargs(norma)
        stmt = (
            insert_for(self._session, NormaModel)
            .values(**kwargs)
            .on_conflict_do_nothing(
                index_elements=["orgao", "tipo", "numero", "ano"]
            )
        )
        await self._session.execute(stmt)
        await self._session.flush()
        # SQLite e PG têm comportamentos diferentes para .returning() em conflict;
        # buscamos por chave natural sempre, pra um caminho único.
        result = await self._session.execute(
            select(NormaModel).where(
                NormaModel.orgao == norma.orgao,
                NormaModel.tipo == norma.tipo,
                NormaModel.numero == norma.numero,
                NormaModel.ano == norma.ano,
            )
        )
        return result.scalar_one()

    async def get_by_urn(self, urn_lex: str) -> NormaModel | None:
        result = await self._session.execute(
            select(NormaModel).where(NormaModel.urn_lex == urn_lex)
        )
        return result.scalar_one_or_none()

    async def list_by_orgao(
        self, orgao: str, since: datetime, limit: int = 100
    ) -> list[NormaModel]:
        result = await self._session.execute(
            select(NormaModel)
            .where(
                NormaModel.orgao == orgao,
                NormaModel.data_publicacao_dou >= since,
            )
            .order_by(NormaModel.data_publicacao_dou.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def count_by_tipo(self, since: datetime) -> dict[str, int]:
        from sqlalchemy import func

        result = await self._session.execute(
            select(NormaModel.tipo, func.count(NormaModel.id))
            .where(NormaModel.data_publicacao_dou >= since)
            .group_by(NormaModel.tipo)
        )
        return {row[0]: int(row[1]) for row in result.all()}

    async def fetch_dataclass(self, urn_lex: str) -> Norma | None:
        model = await self.get_by_urn(urn_lex)
        return norma_from_model(model) if model else None
