"""Repositório async para CyberThreat."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.sigint.models.cyber_threat import CyberThreat
from atlantico.sigint.observations import SigintObservation


class CyberThreatRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: SigintObservation,
        source_record_id: str,
    ) -> CyberThreat:
        payload = obs.payload
        stmt = (
            insert(CyberThreat)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_id=obs.source_id,
                threat_type=payload.get("threat_type", "cve"),
                title=payload.get("cve_id") or payload.get("name") or obs.external_id,
                description=payload.get("description", "")[:4000],
                reference_date=obs.reference_date,
                cve_id=payload.get("cve_id"),
                cvss_score=payload.get("cvss_score"),
                cvss_vector=payload.get("cvss_vector"),
                attack_vector=payload.get("attack_vector"),
                severity=obs.severity,
                cwes=payload.get("cwes", []),
                mitre_techniques=payload.get("mitre_techniques", []),
                affected_products=payload.get("affected_products", []),
                references=payload.get("references", []),
                tags=obs.tags,
                geo_relevance=obs.geo_relevance,
                analysis_status="pending",
            )
            .on_conflict_do_nothing(index_elements=["external_id"])
            .returning(CyberThreat)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        row = result.fetchone()
        if row:
            return row[0]
        existing = await self._session.execute(
            select(CyberThreat).where(CyberThreat.external_id == obs.external_id)
        )
        return existing.scalar_one()

    async def list_unanalyzed(self, limit: int = 200) -> list[CyberThreat]:
        result = await self._session.execute(
            select(CyberThreat)
            .where(CyberThreat.analysis_status == "pending")
            .order_by(CyberThreat.reference_date.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_by_severity(
        self, severity: str, since: datetime, limit: int = 100
    ) -> list[CyberThreat]:
        result = await self._session.execute(
            select(CyberThreat)
            .where(
                CyberThreat.severity == severity,
                CyberThreat.reference_date >= since,
            )
            .order_by(CyberThreat.reference_date.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_by_cve(self, cve_id: str) -> CyberThreat | None:
        result = await self._session.execute(
            select(CyberThreat).where(CyberThreat.cve_id == cve_id)
        )
        return result.scalar_one_or_none()

    async def update_risk_score(self, threat_id: str, risk_score: float) -> None:
        await self._session.execute(
            update(CyberThreat)
            .where(CyberThreat.id == threat_id)
            .values(risk_score=risk_score, analysis_status="analyzed")
        )
        await self._session.flush()

    async def get_cvss_stats(
        self, since: datetime
    ) -> tuple[float, float]:
        """Retorna (mean_cvss, stddev_cvss) para correlação."""
        from sqlalchemy import func
        result = await self._session.execute(
            select(
                func.avg(CyberThreat.cvss_score),
                func.stddev(CyberThreat.cvss_score),
            ).where(
                CyberThreat.cvss_score.isnot(None),
                CyberThreat.reference_date >= since,
            )
        )
        row = result.fetchone()
        mean   = float(row[0] or 0.0)
        stddev = float(row[1] or 1.0)
        return mean, stddev
