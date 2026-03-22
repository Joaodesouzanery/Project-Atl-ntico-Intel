"""
InfrastructureRepository — acesso assíncrono a InfrastructureAsset.

Upsert por external_id. Queries de proximidade via ST_DWithin (PostGIS).
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.geoint.models.infrastructure import InfrastructureAsset

logger = logging.getLogger(__name__)


class InfrastructureRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_or_update(
        self,
        external_id: str,
        asset_type: str,
        criticality: str,
        geometry_wkt: str,
        name: bytes,
        operator: bytes | None = None,
        state: str | None = None,
        capacity_mw: float | None = None,
        length_km: float | None = None,
        active: bool = True,
        monitoring_enabled: bool = True,
    ) -> InfrastructureAsset:
        """
        Cria ou atualiza um ativo de infraestrutura (upsert por external_id).

        name e operator devem ser passados já como bytes plaintext —
        o EncryptedBytes TypeDecorator aplica criptografia automaticamente.
        """
        stmt = (
            insert(InfrastructureAsset)
            .values(
                external_id=external_id,
                asset_type=asset_type,
                criticality=criticality,
                geom=f"SRID=4326;{geometry_wkt}",
                name_enc=name,
                operator_enc=operator,
                state=state,
                capacity_mw=capacity_mw,
                length_km=length_km,
                active=active,
                monitoring_enabled=monitoring_enabled,
            )
            .on_conflict_do_update(
                index_elements=["external_id"],
                set_={
                    "asset_type": asset_type,
                    "criticality": criticality,
                    "geom": f"SRID=4326;{geometry_wkt}",
                    "name_enc": name,
                    "operator_enc": operator,
                    "state": state,
                    "capacity_mw": capacity_mw,
                    "length_km": length_km,
                    "active": active,
                    "monitoring_enabled": monitoring_enabled,
                },
            )
            .returning(InfrastructureAsset)
        )

        result = await self._session.execute(stmt)
        row = result.first()
        await self._session.flush()
        return row[0]

    async def list_active(
        self,
        asset_type: str | None = None,
        criticality: str | None = None,
    ) -> list[InfrastructureAsset]:
        """Lista ativos ativos, com filtros opcionais por tipo e criticidade."""
        stmt = select(InfrastructureAsset).where(
            InfrastructureAsset.active.is_(True),
            InfrastructureAsset.monitoring_enabled.is_(True),
        )
        if asset_type:
            stmt = stmt.where(InfrastructureAsset.asset_type == asset_type)
        if criticality:
            stmt = stmt.where(InfrastructureAsset.criticality == criticality)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_within_buffer(
        self,
        geometry_wkt: str,
        buffer_km: float,
    ) -> list[InfrastructureAsset]:
        """
        Retorna ativos dentro de buffer_km da geometria fornecida.
        Usa ST_DWithin em SIRGAS 2000 (EPSG:5880) para precisão métrica.
        """
        buffer_m = buffer_km * 1000.0
        ref_geom = func.ST_GeomFromText(geometry_wkt, 4326)

        stmt = (
            select(InfrastructureAsset)
            .where(
                InfrastructureAsset.active.is_(True),
                func.ST_DWithin(
                    func.ST_Transform(InfrastructureAsset.geom, 5880),
                    func.ST_Transform(ref_geom, 5880),
                    buffer_m,
                ),
            )
            .order_by(InfrastructureAsset.criticality.desc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_external_id(
        self,
        external_id: str,
    ) -> InfrastructureAsset | None:
        stmt = select(InfrastructureAsset).where(
            InfrastructureAsset.external_id == external_id
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
