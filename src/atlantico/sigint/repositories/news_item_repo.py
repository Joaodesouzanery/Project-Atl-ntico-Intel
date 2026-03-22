"""Repositório async para NewsItem."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.sigint.models.news_item import NewsItem
from atlantico.sigint.observations import SigintObservation


class NewsItemRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: SigintObservation,
        source_record_id: str,
    ) -> NewsItem:
        p = obs.payload
        stmt = (
            insert(NewsItem)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_id=obs.source_id,
                feed_name=p.get("feed"),
                title=p.get("title", obs.external_id)[:512],
                content=p.get("description", "")[:8000],
                url=p.get("link", "")[:2000],
                reference_date=obs.reference_date,
                language=obs.language,
                severity=obs.severity,
                is_disinfo_signal="true" if p.get("is_disinfo_signal") else "false",
                tags=obs.tags,
                geo_relevance=obs.geo_relevance,
                mentioned_cves=p.get("cve_ids", []),
                analysis_status="pending",
            )
            .on_conflict_do_nothing(index_elements=["external_id"])
            .returning(NewsItem)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        row = result.fetchone()
        if row:
            return row[0]
        existing = await self._session.execute(
            select(NewsItem).where(NewsItem.external_id == obs.external_id)
        )
        return existing.scalar_one()

    async def list_unanalyzed(self, limit: int = 200) -> list[NewsItem]:
        result = await self._session.execute(
            select(NewsItem)
            .where(NewsItem.analysis_status == "pending")
            .order_by(NewsItem.reference_date.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_disinfo_signals(
        self, since: datetime, limit: int = 100
    ) -> list[NewsItem]:
        result = await self._session.execute(
            select(NewsItem)
            .where(
                NewsItem.is_disinfo_signal == "true",
                NewsItem.reference_date >= since,
            )
            .order_by(NewsItem.reference_date.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def update_nlp_results(
        self,
        item_id: str,
        sentiment_score: float,
        sentiment_label: str,
        topics: list[str],
        entities: dict,
        keywords: list[str],
        disinfo_score: float,
        cluster_id: str | None = None,
    ) -> None:
        await self._session.execute(
            update(NewsItem)
            .where(NewsItem.id == item_id)
            .values(
                sentiment_score=sentiment_score,
                sentiment_label=sentiment_label,
                topics=topics,
                entities=entities,
                keywords=keywords,
                disinfo_score=disinfo_score,
                narrative_cluster_id=cluster_id,
                analysis_status="analyzed",
            )
        )
        await self._session.flush()

    async def list_by_cluster(self, cluster_id: str) -> list[NewsItem]:
        result = await self._session.execute(
            select(NewsItem).where(
                NewsItem.narrative_cluster_id == cluster_id
            )
        )
        return list(result.scalars().all())
