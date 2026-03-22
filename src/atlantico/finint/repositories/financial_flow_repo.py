"""
FinancialFlowRepository — persistência de fluxos financeiros genéricos FININT.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.finint.models.financial_flow import FinancialFlow
from atlantico.finint.observations import FinintObservation

if TYPE_CHECKING:
    import uuid

logger = logging.getLogger(__name__)


class FinancialFlowRepository:
    """Repositório para FinancialFlow — fluxos financeiros genéricos."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: FinintObservation,
        source_record_id: "uuid.UUID",
    ) -> FinancialFlow | None:
        """Persiste fluxo financeiro. ON CONFLICT DO NOTHING em external_id."""
        payload = obs.payload
        stmt = (
            pg_insert(FinancialFlow)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_id=obs.source_id,
                reference_date=obs.reference_date,
                state=obs.state_code,
                municipality_code=obs.municipality_code,
                flow_type=payload.get("flow_type", "other"),
                currency=payload.get("currency", "BRL"),
                commodity_code=payload.get("commodity_code"),
                commodity_desc=payload.get("commodity_desc"),
                # TypeDecorator criptografa automaticamente
                amount_enc=str(payload.get("amount", 0)),
                counterpart_enc=payload.get("counterpart", ""),
                analysis_status="pending",
            )
            .on_conflict_do_nothing(constraint="idx_flow_external_id")
            .returning(FinancialFlow)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        await self._session.flush()
        return row

    async def list_unanalyzed(
        self,
        since: datetime | None = None,
        limit: int = 500,
    ) -> list[FinancialFlow]:
        """Retorna fluxos pendentes de análise."""
        since = since or (datetime.now(tz=timezone.utc) - timedelta(days=90))
        stmt = (
            select(FinancialFlow)
            .where(
                FinancialFlow.analysis_status == "pending",
                FinancialFlow.reference_date >= since,
            )
            .order_by(FinancialFlow.reference_date.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_municipality(
        self,
        municipality_code: str,
        since: datetime,
        until: datetime | None = None,
    ) -> list[FinancialFlow]:
        """Retorna fluxos de um município (correlação GEOINT por código IBGE)."""
        until = until or datetime.now(tz=timezone.utc)
        stmt = (
            select(FinancialFlow)
            .where(
                FinancialFlow.municipality_code == municipality_code,
                FinancialFlow.reference_date >= since,
                FinancialFlow.reference_date <= until,
            )
            .order_by(FinancialFlow.reference_date.desc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_anomaly_stats(
        self,
        state: str,
        flow_type: str,
        lookback_days: int = 365,
    ) -> tuple[float | None, float | None]:
        """Retorna (mean, stddev) do anomaly_score histórico por estado/tipo."""
        since = datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)
        stmt = select(
            func.avg(FinancialFlow.anomaly_score).label("mean"),
            func.stddev_pop(FinancialFlow.anomaly_score).label("stddev"),
        ).where(
            FinancialFlow.state == state,
            FinancialFlow.flow_type == flow_type,
            FinancialFlow.reference_date >= since,
        )
        result = await self._session.execute(stmt)
        row = result.one()
        mean = float(row.mean) if row.mean is not None else None
        stddev = float(row.stddev) if row.stddev is not None else None
        return mean, stddev

    async def mark_analyzed(
        self,
        flow_id: "uuid.UUID",
        anomaly_score: float,
        status: str = "processed",
        alert_id: str | None = None,
    ) -> None:
        """Atualiza resultado da análise."""
        stmt = (
            update(FinancialFlow)
            .where(FinancialFlow.id == flow_id)
            .values(anomaly_score=anomaly_score, analysis_status=status, alert_id=alert_id)
        )
        await self._session.execute(stmt)
        await self._session.flush()
