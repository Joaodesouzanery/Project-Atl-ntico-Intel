"""
WaterRepository — acesso assíncrono a WaterObservation.

Deduplication por (station_code, acquired_at, measurement_type).
Queries de estatísticas históricas (AVG + STDDEV) para Z-score.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.geoint.models.water import WaterObservation
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)


class WaterRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: GeointObservation,
        source_record_id: uuid.UUID,
    ) -> WaterObservation | None:
        """
        Persiste leitura hídrica. Idempotente: ON CONFLICT DO NOTHING.
        """
        payload = obs.payload
        measurement_type = payload.get("measurement_type", "nivel")
        value = float(payload.get("value") or 0)
        unit = payload.get("unit", "cm")
        data_quality = int(payload.get("data_quality") or 1)

        stmt = (
            insert(WaterObservation)
            .values(
                source_record_id=source_record_id,
                station_code=payload.get("station_code", ""),
                station_name=payload.get("station_name"),
                acquired_at=obs.acquired_at,
                geom=f"SRID=4326;{obs.geometry_wkt}",
                measurement_type=measurement_type,
                value=value,
                unit=unit,
                data_quality=data_quality,
                analysis_status="pending",
            )
            .on_conflict_do_nothing(
                constraint="uq_water_station_time_type",
            )
            .returning(WaterObservation)
        )

        result = await self._session.execute(stmt)
        row = result.first()
        if row is None:
            logger.debug(
                "WaterObservation já existe: estação %s @ %s",
                payload.get("station_code"),
                obs.acquired_at.isoformat(),
            )
            return None
        return row[0]

    async def get_historical_stats(
        self,
        station_code: str,
        measurement_type: str,
        lookback_days: int = 365,
    ) -> tuple[float | None, float | None]:
        """
        Retorna (média, desvio_padrão) histórico para uma estação.

        Usa AVG e STDDEV do PostgreSQL sobre os últimos lookback_days dias.
        Retorna (None, None) se menos de 5 registros disponíveis.
        """
        since = datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)

        stmt = select(
            func.avg(WaterObservation.value).label("mean"),
            func.stddev_pop(WaterObservation.value).label("stddev"),
            func.count().label("count"),
        ).where(
            WaterObservation.station_code == station_code,
            WaterObservation.measurement_type == measurement_type,
            WaterObservation.acquired_at >= since,
        )

        result = await self._session.execute(stmt)
        row = result.first()

        if row is None or row.count < 5:
            return None, None

        mean = float(row.mean) if row.mean is not None else None
        stddev = float(row.stddev) if row.stddev is not None else None
        return mean, stddev

    async def list_unanalyzed(
        self,
        since: datetime,
        limit: int = 500,
    ) -> list[WaterObservation]:
        """Retorna observações com analysis_status='pending' desde since."""
        stmt = (
            select(WaterObservation)
            .where(
                WaterObservation.analysis_status == "pending",
                WaterObservation.acquired_at >= since,
            )
            .order_by(WaterObservation.acquired_at.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def save_anomaly_analysis(
        self,
        observation_id: uuid.UUID,
        historical_mean: float | None,
        historical_stddev: float | None,
        z_score: float | None,
        anomaly_type: str | None,
        anomaly_severity: str | None,
        alert_id: str | None = None,
    ) -> None:
        """Persiste resultado da análise de anomalia pelo WaterProcessor."""
        values: dict = {
            "historical_mean": historical_mean,
            "historical_stddev": historical_stddev,
            "z_score": z_score,
            "anomaly_type": anomaly_type,
            "anomaly_severity": anomaly_severity,
            "analysis_status": "alerted" if alert_id else "processed",
        }
        if alert_id is not None:
            values["alert_id"] = alert_id

        stmt = (
            update(WaterObservation)
            .where(WaterObservation.id == observation_id)
            .values(**values)
        )
        await self._session.execute(stmt)

    async def get_recent_station_readings(
        self,
        station_code: str,
        measurement_type: str,
        hours: int = 24,
    ) -> list[WaterObservation]:
        """Retorna leituras recentes de uma estação (para detecção de variação rápida)."""
        since = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
        stmt = (
            select(WaterObservation)
            .where(
                WaterObservation.station_code == station_code,
                WaterObservation.measurement_type == measurement_type,
                WaterObservation.acquired_at >= since,
            )
            .order_by(WaterObservation.acquired_at.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
