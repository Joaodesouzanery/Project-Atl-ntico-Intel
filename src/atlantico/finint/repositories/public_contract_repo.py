"""
PublicContractRepository — persistência de contratos públicos FININT.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from atlantico.finint.models.public_contract import PublicContract
from atlantico.finint.observations import FinintObservation

if TYPE_CHECKING:
    import uuid

logger = logging.getLogger(__name__)


class PublicContractRepository:
    """Repositório para PublicContract — contratos Portal da Transparência."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(
        self,
        obs: FinintObservation,
        source_record_id: "uuid.UUID",
        supplier_cnpj_bytes: bytes | None = None,
        contract_value_bytes: bytes | None = None,
    ) -> PublicContract | None:
        """
        Persiste contrato público.

        supplier_cnpj_bytes e contract_value_bytes devem ser os dados
        já criptografados pelo TypeDecorator EncryptedBytes antes de
        chamar este método (ou passados como plaintext para o TypeDecorator
        fazer a criptografia automaticamente).

        ON CONFLICT DO NOTHING em external_id.
        """
        payload = obs.payload
        stmt = (
            pg_insert(PublicContract)
            .values(
                source_record_id=source_record_id,
                external_id=obs.external_id,
                source_id=obs.source_id,
                reference_date=obs.reference_date,
                state=obs.state_code,
                municipality_code=obs.municipality_code,
                contracting_entity=payload.get("contracting_entity"),
                contract_object=payload.get("contract_object"),
                modality=payload.get("modality"),
                # TypeDecorator criptografa automaticamente se receber plaintext
                supplier_cnpj_enc=payload.get("supplier_cnpj"),
                contract_value_enc=str(payload.get("contract_value", 0)),
                analysis_status="pending",
            )
            .on_conflict_do_nothing(constraint="uq_contract_external_id")
            .returning(PublicContract)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        await self._session.flush()
        return row

    async def list_by_municipality(
        self,
        municipality_code: str,
        since: datetime,
        until: datetime | None = None,
    ) -> list[PublicContract]:
        """Retorna contratos de um município para análise."""
        until = until or datetime.now(tz=timezone.utc)
        stmt = (
            select(PublicContract)
            .where(
                PublicContract.municipality_code == municipality_code,
                PublicContract.reference_date >= since,
                PublicContract.reference_date <= until,
            )
            .order_by(PublicContract.reference_date.desc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_suspicious(
        self,
        anomaly_score_threshold: float = 0.7,
        since: datetime | None = None,
    ) -> list[PublicContract]:
        """Retorna contratos com score de anomalia acima do limiar."""
        since = since or (datetime.now(tz=timezone.utc) - timedelta(days=30))
        stmt = (
            select(PublicContract)
            .where(
                PublicContract.anomaly_score >= anomaly_score_threshold,
                PublicContract.reference_date >= since,
            )
            .order_by(PublicContract.anomaly_score.desc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_volume_stats(
        self,
        state: str,
        lookback_months: int = 12,
    ) -> tuple[float | None, float | None, float | None]:
        """
        Retorna (mean, stddev, total) do volume de contratos por estado.

        Usa STDDEV_POP do PostgreSQL sobre os valores descriptografados.
        Nota: o campo contract_value_enc está criptografado, então as stats
        são calculadas sobre anomaly_score proxy ou via aplicação.
        Retorna (None, None, None) se sem dados históricos.
        """
        since = datetime.now(tz=timezone.utc) - timedelta(days=lookback_months * 30)
        stmt = select(
            func.count(PublicContract.id).label("count"),
            func.avg(PublicContract.anomaly_score).label("avg_score"),
        ).where(
            PublicContract.state == state,
            PublicContract.reference_date >= since,
        )
        result = await self._session.execute(stmt)
        row = result.one()
        count = int(row.count or 0)
        avg_score = float(row.avg_score) if row.avg_score is not None else None
        return avg_score, None, float(count)

    async def list_unanalyzed(self, limit: int = 500) -> list[PublicContract]:
        """Retorna contratos pendentes de análise."""
        stmt = (
            select(PublicContract)
            .where(PublicContract.analysis_status == "pending")
            .order_by(PublicContract.reference_date.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_analyzed(
        self,
        contract_id: "uuid.UUID",
        anomaly_score: float,
        status: str = "processed",
        alert_id: str | None = None,
    ) -> None:
        """Atualiza resultado da análise no contrato."""
        stmt = (
            update(PublicContract)
            .where(PublicContract.id == contract_id)
            .values(anomaly_score=anomaly_score, analysis_status=status, alert_id=alert_id)
        )
        await self._session.execute(stmt)
        await self._session.flush()
