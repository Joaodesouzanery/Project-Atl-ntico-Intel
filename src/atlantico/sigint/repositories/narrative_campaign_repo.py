"""Repositório async para NarrativeCampaign."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.sigint.models.narrative_campaign import NarrativeCampaign


class NarrativeCampaignRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_or_update(
        self, campaign_data: dict
    ) -> NarrativeCampaign:
        existing = await self._session.execute(
            select(NarrativeCampaign).where(
                NarrativeCampaign.campaign_name == campaign_data["campaign_name"]
            )
        )
        campaign = existing.scalar_one_or_none()

        if campaign:
            await self._session.execute(
                update(NarrativeCampaign)
                .where(NarrativeCampaign.id == campaign.id)
                .values(
                    last_seen=campaign_data.get("last_seen", datetime.utcnow()),
                    item_count=campaign_data.get("item_count", campaign.item_count),
                    disinfo_score=campaign_data.get("disinfo_score"),
                    amplification_score=campaign_data.get("amplification_score"),
                    key_topics=campaign_data.get("key_topics", campaign.key_topics),
                    analysis_status="active",
                )
            )
            await self._session.flush()
            await self._session.refresh(campaign)
            return campaign

        stmt = (
            insert(NarrativeCampaign)
            .values(**campaign_data)
            .returning(NarrativeCampaign)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.fetchone()[0]

    async def list_active(
        self, min_disinfo_score: float = 0.3, limit: int = 50
    ) -> list[NarrativeCampaign]:
        result = await self._session.execute(
            select(NarrativeCampaign)
            .where(
                NarrativeCampaign.analysis_status == "active",
                NarrativeCampaign.disinfo_score >= min_disinfo_score,
            )
            .order_by(NarrativeCampaign.disinfo_score.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def mark_alert_generated(self, campaign_id: str) -> None:
        await self._session.execute(
            update(NarrativeCampaign)
            .where(NarrativeCampaign.id == campaign_id)
            .values(alert_generated="true")
        )
        await self._session.flush()
