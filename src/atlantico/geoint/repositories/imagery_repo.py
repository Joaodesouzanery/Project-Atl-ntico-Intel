"""
ImageryRepository — acesso assíncrono a SatelliteImagery.

Deduplication por product_id. Queries geoespaciais via ST_Intersects.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.geoint.models.imagery import SatelliteImagery
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)


class ImageryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: GeointObservation,
        source_record_id: uuid.UUID,
    ) -> SatelliteImagery | None:
        """
        Persiste metadados de produto Sentinel-2.
        Idempotente: ON CONFLICT DO NOTHING por product_id.
        """
        payload = obs.payload
        product_id = payload.get("product_id", "")

        if not product_id:
            logger.warning("ImageryRepository.store: product_id vazio, ignorando.")
            return None

        stmt = (
            insert(SatelliteImagery)
            .values(
                source_record_id=source_record_id,
                product_id=product_id,
                product_name=payload.get("product_name", ""),
                acquired_at=obs.acquired_at,
                satellite=payload.get("satellite", "Sentinel-2"),
                product_type=payload.get("product_type", "S2MSI2A"),
                tile_id=payload.get("tile_id"),
                relative_orbit=payload.get("relative_orbit"),
                cloud_cover_pct=float(payload.get("cloud_cover_pct") or 0),
                footprint=f"SRID=4326;{obs.geometry_wkt}",
                size_bytes=payload.get("size_bytes"),
                online=bool(payload.get("online", True)),
                analysis_status="pending",
            )
            .on_conflict_do_nothing(constraint="uq_imagery_product_id")
            .returning(SatelliteImagery)
        )

        result = await self._session.execute(stmt)
        row = result.first()
        if row is None:
            logger.debug("SatelliteImagery já existe: %s", product_id)
            return None
        return row[0]

    async def list_for_area(
        self,
        polygon_wkt: str,
        since: datetime,
        max_cloud_cover: float = 20.0,
    ) -> list[SatelliteImagery]:
        """
        Lista imagens que intersectam polygon_wkt, com cloud_cover <= max_cloud_cover.
        Usa PostGIS ST_Intersects com índice GIST no footprint.
        """
        stmt = (
            select(SatelliteImagery)
            .where(
                func.ST_Intersects(
                    SatelliteImagery.footprint,
                    func.ST_GeomFromText(polygon_wkt, 4326),
                ),
                SatelliteImagery.acquired_at >= since,
                SatelliteImagery.cloud_cover_pct <= max_cloud_cover,
                SatelliteImagery.online.is_(True),
            )
            .order_by(SatelliteImagery.acquired_at.desc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_ndvi_computed(
        self,
        imagery_id: uuid.UUID,
    ) -> None:
        """Atualiza analysis_status para 'ndvi_computed'."""
        from datetime import timezone
        now = datetime.now(tz=timezone.utc)
        stmt = (
            update(SatelliteImagery)
            .where(SatelliteImagery.id == imagery_id)
            .values(
                analysis_status="ndvi_computed",
                ndvi_computed_at=now,
            )
        )
        await self._session.execute(stmt)

    async def get_by_product_id(
        self,
        product_id: str,
    ) -> SatelliteImagery | None:
        stmt = select(SatelliteImagery).where(
            SatelliteImagery.product_id == product_id
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
