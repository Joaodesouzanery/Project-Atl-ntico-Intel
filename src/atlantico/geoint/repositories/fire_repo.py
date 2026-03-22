"""
FireRepository — acesso assíncrono a FireHotspot e FireCluster.

Deduplication de hotspots por (external_id, source_id).
Queries geoespaciais para proximidade a infraestrutura via ST_DWithin.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.geoint.models.fire import FireCluster, FireHotspot
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)


class FireRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store_hotspot(
        self,
        obs: GeointObservation,
        source_record_id: uuid.UUID,
    ) -> FireHotspot | None:
        """
        Persiste foco de calor. Idempotente: ON CONFLICT DO NOTHING por (external_id, source_id).
        """
        payload = obs.payload

        def _safe_float(val) -> float | None:
            try:
                return float(val) if val is not None else None
            except (TypeError, ValueError):
                return None

        def _safe_int(val) -> int | None:
            try:
                return int(val) if val is not None else None
            except (TypeError, ValueError):
                return None

        stmt = (
            insert(FireHotspot)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_id=obs.source_id,
                acquired_at=obs.acquired_at,
                geom=f"SRID=4326;{obs.geometry_wkt}",
                satellite=payload.get("satelite") or payload.get("satellite"),
                frp=_safe_float(payload.get("frp")),
                brightness=_safe_float(
                    payload.get("brightness") or payload.get("brilho")
                ),
                confidence=_safe_int(
                    payload.get("confidence") or payload.get("confianca")
                ),
                biome=payload.get("bioma") or payload.get("biome"),
                state=(payload.get("estado") or payload.get("state") or "")[:2].upper() or None,
                municipality=payload.get("municipio"),
                days_without_rain=_safe_int(payload.get("numero_dias_sem_chuva")),
                fire_risk=_safe_float(payload.get("risco_fogo")),
                analysis_status="pending",
            )
            .on_conflict_do_nothing(
                index_elements=None,
                constraint="uq_hotspot_external_source",
            )
            .returning(FireHotspot)
        )

        result = await self._session.execute(stmt)
        row = result.first()
        if row is None:
            logger.debug("FireHotspot já existe: %s/%s", obs.external_id, obs.source_id)
            return None
        return row[0]

    async def store_cluster(self, cluster: FireCluster) -> FireCluster:
        """Persiste um FireCluster."""
        self._session.add(cluster)
        await self._session.flush()
        return cluster

    async def list_hotspots_unprocessed(
        self,
        since: datetime,
        limit: int = 1000,
    ) -> list[FireHotspot]:
        """Retorna hotspots sem cluster atribuído desde `since`."""
        stmt = (
            select(FireHotspot)
            .where(
                FireHotspot.cluster_id.is_(None),
                FireHotspot.acquired_at >= since,
                FireHotspot.analysis_status == "pending",
            )
            .order_by(FireHotspot.acquired_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_hotspots_near_point(
        self,
        lon: float,
        lat: float,
        radius_km: float,
    ) -> list[FireHotspot]:
        """
        Retorna hotspots dentro de radius_km de (lon, lat).
        Usa ST_DWithin em SIRGAS 2000 projetado (EPSG:5880) para distância métrica precisa.
        """
        radius_m = radius_km * 1000.0
        point_geom = func.ST_SetSRID(func.ST_MakePoint(lon, lat), 4326)

        stmt = (
            select(FireHotspot)
            .where(
                func.ST_DWithin(
                    func.ST_Transform(FireHotspot.geom, 5880),
                    func.ST_Transform(point_geom, 5880),
                    radius_m,
                )
            )
            .order_by(FireHotspot.acquired_at.desc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def assign_cluster(
        self,
        hotspot_ids: list[uuid.UUID],
        cluster_id: uuid.UUID,
    ) -> None:
        """Associa hotspots a um cluster após DBSCAN."""
        stmt = (
            update(FireHotspot)
            .where(FireHotspot.id.in_(hotspot_ids))
            .values(cluster_id=cluster_id, analysis_status="clustered")
        )
        await self._session.execute(stmt)

    async def get_clusters_near_infrastructure(
        self,
        buffer_km: float,
    ) -> list[FireCluster]:
        """
        Retorna clusters dentro de buffer_km de qualquer InfrastructureAsset ativo.
        """
        from atlantico.geoint.models.infrastructure import InfrastructureAsset

        buffer_m = buffer_km * 1000.0
        stmt = (
            select(FireCluster)
            .where(
                func.ST_DWithin(
                    func.ST_Transform(FireCluster.centroid_geom, 5880),
                    func.ST_Transform(
                        select(InfrastructureAsset.geom)
                        .where(InfrastructureAsset.active.is_(True))
                        .scalar_subquery(),
                        5880,
                    ),
                    buffer_m,
                )
            )
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_cluster_alerted(
        self,
        cluster_id: uuid.UUID,
        alert_id: str,
    ) -> None:
        stmt = (
            update(FireCluster)
            .where(FireCluster.id == cluster_id)
            .values(alert_id=alert_id, analysis_status="alerted")
        )
        await self._session.execute(stmt)
