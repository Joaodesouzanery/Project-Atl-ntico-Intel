"""Repositório async para ThreatIndicator (IOCs)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.sigint.models.threat_indicator import ThreatIndicator
from atlantico.sigint.observations import SigintObservation


class ThreatIndicatorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: SigintObservation,
        source_record_id: str,
    ) -> ThreatIndicator:
        p = obs.payload
        stmt = (
            insert(ThreatIndicator)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_id=obs.source_id,
                ioc_type=p.get("ioc_type", "unknown"),
                ioc_value=p.get("ioc_value", ""),
                description=p.get("description", "")[:2000],
                reference_date=obs.reference_date,
                threat_actor=p.get("adversary"),
                malware_family=p.get("threat_label"),
                confidence=float(p.get("confidence", 0.5)),
                severity=obs.severity,
                vt_malicious_count=str(p.get("malicious_count", "")),
                vt_detection_rate=p.get("detection_rate"),
                is_active="true",
                analysis_status="pending",
                tags=obs.tags,
                geo_relevance=obs.geo_relevance,
                metadata_json=p,
            )
            .on_conflict_do_nothing(index_elements=["external_id"])
            .returning(ThreatIndicator)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        row = result.fetchone()
        if row:
            return row[0]
        existing = await self._session.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.external_id == obs.external_id
            )
        )
        return existing.scalar_one()

    async def list_by_type(
        self, ioc_type: str, since: datetime, limit: int = 200
    ) -> list[ThreatIndicator]:
        result = await self._session.execute(
            select(ThreatIndicator)
            .where(
                ThreatIndicator.ioc_type == ioc_type,
                ThreatIndicator.reference_date >= since,
                ThreatIndicator.is_active == "true",
            )
            .order_by(ThreatIndicator.confidence.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_by_value(self, ioc_value: str) -> ThreatIndicator | None:
        result = await self._session.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.ioc_value == ioc_value,
                ThreatIndicator.is_active == "true",
            )
        )
        return result.scalar_one_or_none()

    async def list_high_confidence(
        self, min_confidence: float = 0.7, limit: int = 100
    ) -> list[ThreatIndicator]:
        result = await self._session.execute(
            select(ThreatIndicator)
            .where(
                ThreatIndicator.confidence >= min_confidence,
                ThreatIndicator.is_active == "true",
            )
            .order_by(ThreatIndicator.confidence.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
