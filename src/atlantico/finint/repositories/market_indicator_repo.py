"""
MarketIndicatorRepository — persistência de indicadores de mercado FININT.

Padrão Sprint 2/3: async, ON CONFLICT DO NOTHING para idempotência,
queries PostgreSQL nativas para stats históricas (AVG + STDDEV_POP).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.finint.models.market_indicator import MarketIndicator
from atlantico.finint.observations import FinintObservation

if TYPE_CHECKING:
    import uuid

logger = logging.getLogger(__name__)


class MarketIndicatorRepository:
    """Repositório para MarketIndicator — séries temporais FININT."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: FinintObservation,
        source_record_id: "uuid.UUID",
    ) -> MarketIndicator | None:
        """
        Persiste indicador de mercado.

        ON CONFLICT DO NOTHING em (series_code, reference_date).
        Retorna None se registro já existia (deduplication).
        """
        series_code = str(obs.payload.get("series_code", obs.external_id))
        series_name = str(obs.payload.get("series_name", ""))
        value = float(obs.payload.get("value", 0.0))
        unit = str(obs.payload.get("unit", ""))

        stmt = (
            pg_insert(MarketIndicator)
            .values(
                source_record_id=source_record_id,
                series_code=series_code,
                series_name=series_name,
                source_id=obs.source_id,
                reference_date=obs.reference_date,
                value=value,
                unit=unit,
                analysis_status="pending",
            )
            .on_conflict_do_nothing(constraint="uq_indicator_series_date")
            .returning(MarketIndicator)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        await self._session.flush()
        return row

    async def get_series(
        self,
        series_code: str,
        since: datetime,
        until: datetime | None = None,
    ) -> list[MarketIndicator]:
        """Retorna série temporal para análise Z-score/Isolation Forest."""
        until = until or datetime.now(tz=timezone.utc)
        stmt = (
            select(MarketIndicator)
            .where(
                MarketIndicator.series_code == series_code,
                MarketIndicator.reference_date >= since,
                MarketIndicator.reference_date <= until,
            )
            .order_by(MarketIndicator.reference_date.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_historical_stats(
        self,
        series_code: str,
        lookback_days: int = 365,
    ) -> tuple[float | None, float | None]:
        """
        Retorna (mean, stddev) histórico via PostgreSQL AVG + STDDEV_POP.

        Exclui dados recentes (últimos 30 dias) para evitar contaminação
        do baseline com valores anômalos recentes.
        """
        now = datetime.now(tz=timezone.utc)
        baseline_end = now - timedelta(days=30)
        baseline_start = now - timedelta(days=lookback_days + 30)

        stmt = select(
            func.avg(MarketIndicator.value).label("mean"),
            func.stddev_pop(MarketIndicator.value).label("stddev"),
        ).where(
            MarketIndicator.series_code == series_code,
            MarketIndicator.reference_date >= baseline_start,
            MarketIndicator.reference_date <= baseline_end,
        )
        result = await self._session.execute(stmt)
        row = result.one()
        mean = float(row.mean) if row.mean is not None else None
        stddev = float(row.stddev) if row.stddev is not None else None
        return mean, stddev

    async def list_unanalyzed(self, limit: int = 500) -> list[MarketIndicator]:
        """Retorna indicadores pendentes de análise."""
        stmt = (
            select(MarketIndicator)
            .where(MarketIndicator.analysis_status == "pending")
            .order_by(MarketIndicator.reference_date.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_analyzed(
        self,
        indicator_id: "uuid.UUID",
        z_score: float | None,
        anomaly_type: str | None,
        anomaly_severity: str | None,
        status: str = "processed",
    ) -> None:
        """Atualiza resultado da análise no indicador."""
        stmt = (
            update(MarketIndicator)
            .where(MarketIndicator.id == indicator_id)
            .values(
                z_score=z_score,
                anomaly_type=anomaly_type,
                anomaly_severity=anomaly_severity,
                analysis_status=status,
            )
        )
        await self._session.execute(stmt)
        await self._session.flush()
