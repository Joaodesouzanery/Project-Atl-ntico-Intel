"""Tasks de ingestão SIGINT."""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


async def _ingest_nvd_cve_async(lookback_days: int = 1) -> dict:
    from atlantico.sigint.connectors.nvd_cve import NvdCveConnector
    since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    async with NvdCveConnector() as connector:
        observations = await connector.fetch(since=since, limit=200)
    logger.info("sigint_ingest_nvd_cve: %d observações", len(observations))
    return {"count": len(observations), "source": "nvd.cve.v2"}


async def _ingest_certbr_async(lookback_days: int = 1) -> dict:
    from atlantico.sigint.connectors.certbr_rss import CertBrRssConnector
    since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    async with CertBrRssConnector() as connector:
        observations = await connector.fetch(since=since)
    logger.info("sigint_ingest_certbr: %d observações", len(observations))
    return {"count": len(observations), "source": "certbr.rss.v1"}


async def _ingest_news_async(lookback_hours: int = 6) -> dict:
    from atlantico.sigint.connectors.news_rss import NewsRssConnector
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    async with NewsRssConnector() as connector:
        observations = await connector.fetch(since=since, limit=300)
    logger.info("sigint_ingest_news: %d observações", len(observations))
    return {"count": len(observations), "source": "news.rss.v1"}


def sigint_ingest_nvd_cve(lookback_days: int = 1) -> dict:
    return asyncio.run(_ingest_nvd_cve_async(lookback_days))


def sigint_ingest_certbr(lookback_days: int = 1) -> dict:
    return asyncio.run(_ingest_certbr_async(lookback_days))


def sigint_ingest_otx(lookback_days: int = 1) -> dict:
    logger.info("sigint_ingest_otx: OTX requer API key — configure ATLANTICO_OTX_API_KEY")
    return {"count": 0, "source": "otx.alienvault.v1", "status": "no_api_key"}


def sigint_ingest_news(lookback_hours: int = 6) -> dict:
    return asyncio.run(_ingest_news_async(lookback_hours))
