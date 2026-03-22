"""
Tarefas Celery de ingestão FININT.

Pattern: asyncio.run(_async_impl(...)) dentro de tasks síncronas Celery.
Idempotência: ON CONFLICT DO NOTHING em todos os repositórios.
Segurança: payload bruto sempre passa por SourceRecordRepository.store() (PQC).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from atlantico.finint.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

_DEFAULT_LOOKBACK_DAYS = 30


def _parse_since(since_iso: str | None, default_days: int = _DEFAULT_LOOKBACK_DAYS) -> datetime:
    """Parseia ISO datetime ou retorna default_days atrás."""
    if since_iso:
        return datetime.fromisoformat(since_iso)
    return datetime.now(tz=timezone.utc) - timedelta(days=default_days)


@celery_app.task(name="finint.ingest_bcb_sgs", bind=True, max_retries=3)
def ingest_bcb_sgs(self, since_iso: str | None = None) -> dict:
    """Ingere séries temporais BCB SGS."""
    return asyncio.run(_ingest_bcb_sgs_async(since_iso))


async def _ingest_bcb_sgs_async(since_iso: str | None) -> dict:
    from atlantico.finint.connectors.bcb_sgs import BCBSgsConnector
    from atlantico.storage.database import get_async_session
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository
    from atlantico.finint.repositories.market_indicator_repo import MarketIndicatorRepository

    since = _parse_since(since_iso, default_days=365)

    async with BCBSgsConnector() as connector:
        observations = await connector.fetch(since=since)

    stored = 0
    async with get_async_session() as session:
        source_repo = SourceRecordRepository(session)
        indicator_repo = MarketIndicatorRepository(session)
        for obs in observations:
            sr = await source_repo.store(
                source_id=obs.source_id,
                external_id=obs.external_id,
                acquired_at=obs.reference_date,
                payload=obs.payload,
                geo_bounds_wkt=None,
                data_classification=obs.data_classification,
            )
            if sr:
                result = await indicator_repo.store(obs, sr.id)
                if result:
                    stored += 1
        await session.commit()

    logger.info("finint.ingest_bcb_sgs: %d/%d observações armazenadas.", stored, len(observations))
    return {"ingested": len(observations), "stored": stored}


@celery_app.task(name="finint.ingest_contratos", bind=True, max_retries=3)
def ingest_contratos(
    self,
    since_iso: str | None = None,
    state_code: str | None = None,
) -> dict:
    """Ingere contratos do Portal da Transparência."""
    return asyncio.run(_ingest_contratos_async(since_iso, state_code))


async def _ingest_contratos_async(since_iso: str | None, state_code: str | None) -> dict:
    from atlantico.finint.connectors.transparencia_contratos import TransparenciaContratosConnector
    from atlantico.storage.database import get_async_session
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository
    from atlantico.finint.repositories.public_contract_repo import PublicContractRepository

    since = _parse_since(since_iso, default_days=7)
    state_codes = [state_code] if state_code else None

    async with TransparenciaContratosConnector() as connector:
        observations = await connector.fetch(since=since, state_codes=state_codes)

    stored = 0
    async with get_async_session() as session:
        source_repo = SourceRecordRepository(session)
        contract_repo = PublicContractRepository(session)
        for obs in observations:
            sr = await source_repo.store(
                source_id=obs.source_id,
                external_id=obs.external_id,
                acquired_at=obs.reference_date,
                payload={k: v for k, v in obs.payload.items() if k not in ("supplier_cnpj", "contract_value")},
                geo_bounds_wkt=None,
                data_classification=obs.data_classification,
            )
            if sr:
                result = await contract_repo.store(obs, sr.id)
                if result:
                    stored += 1
        await session.commit()

    logger.info("finint.ingest_contratos: %d/%d contratos armazenados.", stored, len(observations))
    return {"ingested": len(observations), "stored": stored}


@celery_app.task(name="finint.ingest_trade_flows", bind=True, max_retries=3)
def ingest_trade_flows(self, since_iso: str | None = None) -> dict:
    """Ingere fluxos de comércio exterior (ComexStat)."""
    return asyncio.run(_ingest_trade_flows_async(since_iso))


async def _ingest_trade_flows_async(since_iso: str | None) -> dict:
    from atlantico.finint.connectors.siscomex_comex_stat import SiscomexComexStatConnector
    from atlantico.storage.database import get_async_session
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository
    from atlantico.finint.repositories.trade_flow_repo import TradeFlowRepository

    since = _parse_since(since_iso, default_days=90)

    async with SiscomexComexStatConnector() as connector:
        observations = await connector.fetch(since=since)

    stored = 0
    async with get_async_session() as session:
        source_repo = SourceRecordRepository(session)
        trade_repo = TradeFlowRepository(session)
        for obs in observations:
            sr = await source_repo.store(
                source_id=obs.source_id,
                external_id=obs.external_id,
                acquired_at=obs.reference_date,
                payload=obs.payload,
                geo_bounds_wkt=None,
                data_classification=obs.data_classification,
            )
            if sr:
                result = await trade_repo.store(obs, sr.id)
                if result:
                    stored += 1
        await session.commit()

    logger.info("finint.ingest_trade_flows: %d/%d fluxos armazenados.", stored, len(observations))
    return {"ingested": len(observations), "stored": stored}


@celery_app.task(name="finint.ingest_cvm", bind=True, max_retries=3)
def ingest_cvm(self, since_iso: str | None = None) -> dict:
    """Ingere dados abertos CVM."""
    return asyncio.run(_ingest_cvm_async(since_iso))


async def _ingest_cvm_async(since_iso: str | None) -> dict:
    from atlantico.finint.connectors.cvm_dados_abertos import CVMDadosAbertosConnector
    from atlantico.storage.database import get_async_session
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository
    from atlantico.finint.repositories.market_indicator_repo import MarketIndicatorRepository

    since = _parse_since(since_iso, default_days=60)

    async with CVMDadosAbertosConnector() as connector:
        observations = await connector.fetch(since=since)

    stored = 0
    async with get_async_session() as session:
        source_repo = SourceRecordRepository(session)
        indicator_repo = MarketIndicatorRepository(session)
        for obs in observations:
            sr = await source_repo.store(
                source_id=obs.source_id,
                external_id=obs.external_id,
                acquired_at=obs.reference_date,
                payload=obs.payload,
                geo_bounds_wkt=None,
                data_classification=obs.data_classification,
            )
            if sr:
                result = await indicator_repo.store(obs, sr.id)
                if result:
                    stored += 1
        await session.commit()

    logger.info("finint.ingest_cvm: %d/%d observações armazenadas.", stored, len(observations))
    return {"ingested": len(observations), "stored": stored}


@celery_app.task(name="finint.ingest_ibge", bind=True, max_retries=3)
def ingest_ibge(
    self,
    since_iso: str | None = None,
    state_codes: list[str] | None = None,
) -> dict:
    """Ingere dados IBGE SIDRA por estado."""
    return asyncio.run(_ingest_ibge_async(since_iso, state_codes))


async def _ingest_ibge_async(since_iso: str | None, state_codes: list[str] | None) -> dict:
    from atlantico.finint.connectors.ibge_sidra import IBGESidraConnector
    from atlantico.storage.database import get_async_session
    from atlantico.storage.repositories.source_record_repo import SourceRecordRepository
    from atlantico.finint.repositories.market_indicator_repo import MarketIndicatorRepository

    # IBGE SIDRA é anual — default: 3 anos atrás
    since = _parse_since(since_iso, default_days=3 * 365)

    async with IBGESidraConnector() as connector:
        observations = await connector.fetch(since=since, state_codes=state_codes)

    stored = 0
    async with get_async_session() as session:
        source_repo = SourceRecordRepository(session)
        indicator_repo = MarketIndicatorRepository(session)
        for obs in observations:
            sr = await source_repo.store(
                source_id=obs.source_id,
                external_id=obs.external_id,
                acquired_at=obs.reference_date,
                payload=obs.payload,
                geo_bounds_wkt=None,
                data_classification=obs.data_classification,
            )
            if sr:
                result = await indicator_repo.store(obs, sr.id)
                if result:
                    stored += 1
        await session.commit()

    logger.info("finint.ingest_ibge: %d/%d observações armazenadas.", stored, len(observations))
    return {"ingested": len(observations), "stored": stored}
