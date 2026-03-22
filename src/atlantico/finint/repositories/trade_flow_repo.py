"""
TradeFlowRepository — persistência de fluxos de comércio exterior FININT.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.finint.models.trade_flow import TradeFlow
from atlantico.finint.observations import FinintObservation

if TYPE_CHECKING:
    import uuid

logger = logging.getLogger(__name__)


class TradeFlowRepository:
    """Repositório para TradeFlow — exportações ComexStat por NCM/estado."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: FinintObservation,
        source_record_id: "uuid.UUID",
    ) -> TradeFlow | None:
        """Persiste fluxo de comércio. ON CONFLICT DO NOTHING em external_id."""
        payload = obs.payload
        stmt = (
            pg_insert(TradeFlow)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_id=obs.source_id,
                reference_date=obs.reference_date,
                state=obs.state_code,
                ncm_code=str(payload.get("ncm_code", "")),
                ncm_desc=payload.get("ncm_desc"),
                sh2_code=payload.get("sh2_code"),
                export_value_usd=float(payload.get("export_value_usd", 0)),
                net_weight_kg=float(payload.get("net_weight_kg", 0)),
                country_code=payload.get("country_code"),
                analysis_status="pending",
            )
            .on_conflict_do_nothing(constraint="uq_trade_external_id")
            .returning(TradeFlow)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        await self._session.flush()
        return row

    async def list_by_ncm(
        self,
        ncm_codes: list[str],
        since: datetime,
        state: str | None = None,
    ) -> list[TradeFlow]:
        """Retorna fluxos para NCMs específicos para análise de tendência."""
        conditions = [
            TradeFlow.ncm_code.in_(ncm_codes),
            TradeFlow.reference_date >= since,
        ]
        if state:
            conditions.append(TradeFlow.state == state)

        stmt = (
            select(TradeFlow)
            .where(*conditions)
            .order_by(TradeFlow.reference_date.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_export_trend(
        self,
        ncm_code: str,
        state: str | None,
        lookback_months: int = 12,
    ) -> list[TradeFlow]:
        """Retorna série temporal de exportação para análise de spike."""
        since = datetime.now(tz=timezone.utc) - timedelta(days=lookback_months * 30)
        conditions = [
            TradeFlow.ncm_code == ncm_code,
            TradeFlow.reference_date >= since,
        ]
        if state:
            conditions.append(TradeFlow.state == state)

        stmt = (
            select(TradeFlow)
            .where(*conditions)
            .order_by(TradeFlow.reference_date.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_unanalyzed(self, since: datetime | None = None, limit: int = 500) -> list[TradeFlow]:
        """Retorna fluxos pendentes de análise."""
        since = since or (datetime.now(tz=timezone.utc) - timedelta(days=90))
        stmt = (
            select(TradeFlow)
            .where(
                TradeFlow.analysis_status == "pending",
                TradeFlow.reference_date >= since,
            )
            .order_by(TradeFlow.reference_date.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def link_geoint_correlation(
        self,
        trade_flow_id: "uuid.UUID",
        geoint_event_id: str,
    ) -> None:
        """Registra correlação com evento GEOINT."""
        stmt = (
            update(TradeFlow)
            .where(TradeFlow.id == trade_flow_id)
            .values(geoint_correlation_id=geoint_event_id)
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def mark_analyzed(
        self,
        trade_flow_id: "uuid.UUID",
        anomaly_score: float,
        status: str = "processed",
        alert_id: str | None = None,
    ) -> None:
        """Atualiza resultado da análise."""
        stmt = (
            update(TradeFlow)
            .where(TradeFlow.id == trade_flow_id)
            .values(anomaly_score=anomaly_score, analysis_status=status, alert_id=alert_id)
        )
        await self._session.execute(stmt)
        await self._session.flush()
