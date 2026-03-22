"""
DeforestationRepository — acesso assíncrono a DeforestationEvent.

Deduplication automática via external_id (ON CONFLICT DO NOTHING).
Queries geoespaciais via PostGIS ST_Intersects e ST_Area.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.geoint.models.deforestation import DeforestationEvent
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)


class DeforestationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: GeointObservation,
        source_record_id: uuid.UUID,
    ) -> DeforestationEvent | None:
        """
        Persiste evento de desmatamento. Idempotente: ON CONFLICT DO NOTHING.
        Retorna None se já existia (duplicata pelo external_id).
        """
        payload = obs.payload
        area_ha = float(payload.get("area_ha") or 0)
        biome = payload.get("biome") or payload.get("bioma") or "Desconhecido"
        state = (payload.get("state") or payload.get("uf") or "BR")[:2].upper()
        source_type = "prodes" if "prodes" in obs.source_id else "deter"

        # Severity derivada de area_ha
        if area_ha >= 500:
            severity = "CRITICAL"
        elif area_ha >= 100:
            severity = "HIGH"
        elif area_ha >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        stmt = (
            insert(DeforestationEvent)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_type=source_type,
                acquired_at=obs.acquired_at,
                area_ha=area_ha,
                biome=biome,
                state=state,
                municipality=payload.get("municipality") or payload.get("county"),
                classname=payload.get("classname"),
                severity=severity,
                geom=f"SRID=4326;{obs.geometry_wkt}",
                analysis_status="pending",
            )
            .on_conflict_do_nothing(index_elements=["external_id"])
            .returning(DeforestationEvent)
        )

        result = await self._session.execute(stmt)
        row = result.first()
        if row is None:
            logger.debug("DeforestationEvent já existe: %s", obs.external_id)
            return None
        return row[0]

    async def list_unprocessed(
        self,
        limit: int = 100,
    ) -> list[DeforestationEvent]:
        """Retorna eventos com analysis_status='pending'."""
        stmt = (
            select(DeforestationEvent)
            .where(DeforestationEvent.analysis_status == "pending")
            .order_by(DeforestationEvent.acquired_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_by_area(
        self,
        polygon_wkt: str,
        since: datetime,
        severity: str | None = None,
    ) -> list[DeforestationEvent]:
        """
        Busca eventos que intersectam polygon_wkt desde since.
        Usa PostGIS ST_Intersects com índice GIST.
        """
        stmt = (
            select(DeforestationEvent)
            .where(
                func.ST_Intersects(
                    DeforestationEvent.geom,
                    func.ST_GeomFromText(polygon_wkt, 4326),
                ),
                DeforestationEvent.acquired_at >= since,
            )
        )
        if severity:
            stmt = stmt.where(DeforestationEvent.severity == severity)
        stmt = stmt.order_by(DeforestationEvent.acquired_at.desc())

        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_area_ha_total_by_biome(
        self,
        since: datetime,
        until: datetime,
    ) -> dict[str, float]:
        """
        Soma de área em ha por bioma, projetada em SIRGAS 2000 / Brazil Polyconic (EPSG:5880)
        para cálculo de área em m² → ha.
        """
        # ST_Area(ST_Transform(geom, 5880)) em m² → / 10000 → ha
        stmt = select(
            DeforestationEvent.biome,
            func.sum(
                func.ST_Area(func.ST_Transform(DeforestationEvent.geom, 5880)) / 10000.0
            ).label("total_ha"),
        ).where(
            DeforestationEvent.acquired_at >= since,
            DeforestationEvent.acquired_at <= until,
        ).group_by(DeforestationEvent.biome)

        result = await self._session.execute(stmt)
        return {row.biome: float(row.total_ha or 0) for row in result}

    async def mark_processed(
        self,
        event_id: uuid.UUID,
        analysis_status: str,
        alert_id: str | None = None,
    ) -> None:
        """Atualiza analysis_status (e opcionalmente alert_id) de um evento."""
        values: dict = {"analysis_status": analysis_status}
        if alert_id is not None:
            values["alert_id"] = alert_id

        stmt = (
            update(DeforestationEvent)
            .where(DeforestationEvent.id == event_id)
            .values(**values)
        )
        await self._session.execute(stmt)

    async def update_ndvi(
        self,
        event_id: uuid.UUID,
        ndvi_before: float | None,
        ndvi_after: float | None,
    ) -> None:
        """Atualiza valores de NDVI calculados pelo DeforestationProcessor."""
        stmt = (
            update(DeforestationEvent)
            .where(DeforestationEvent.id == event_id)
            .values(ndvi_before=ndvi_before, ndvi_after=ndvi_after)
        )
        await self._session.execute(stmt)
