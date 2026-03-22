"""
Celery app factory para o módulo FININT.

Configuração idêntica ao GEOINT:
- task_acks_late=True para idempotência
- worker_prefetch_multiplier=1 para processamento sequencial
- Beat schedule com intervalos configuráveis via Settings
"""

from __future__ import annotations

from celery import Celery

from atlantico.config.settings import get_settings


def make_celery() -> Celery:
    """Cria e configura a instância Celery do módulo FININT."""
    settings = get_settings()

    app = Celery(
        "atlantico.finint",
        broker=settings.redis_url,
        backend=settings.redis_url,
    )

    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_soft_time_limit=600,
        task_time_limit=900,
        task_reject_on_worker_lost=True,
        broker_connection_retry_on_startup=True,
    )

    app.conf.beat_schedule = {
        # ─── Ingestão ─────────────────────────────────────────────────
        "finint-ingest-bcb-sgs": {
            "task": "finint.ingest_bcb_sgs",
            "schedule": settings.finint_ingest_bcb_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "finint_ingestion"},
        },
        "finint-ingest-contratos": {
            "task": "finint.ingest_contratos",
            "schedule": settings.finint_ingest_contratos_interval_s,
            "kwargs": {"since_iso": None, "state_code": None},
            "options": {"queue": "finint_ingestion"},
        },
        "finint-ingest-trade-flows": {
            "task": "finint.ingest_trade_flows",
            "schedule": settings.finint_ingest_trade_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "finint_ingestion"},
        },
        "finint-ingest-cvm": {
            "task": "finint.ingest_cvm",
            "schedule": settings.finint_ingest_cvm_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "finint_ingestion"},
        },
        "finint-ingest-ibge": {
            "task": "finint.ingest_ibge",
            "schedule": settings.finint_ingest_ibge_interval_s,
            "kwargs": {"since_iso": None, "state_codes": None},
            "options": {"queue": "finint_ingestion"},
        },
        # ─── Análise ─────────────────────────────────────────────────
        "finint-analyze-indicators": {
            "task": "finint.analyze_indicators",
            "schedule": 3600,  # 1h
            "kwargs": {},
            "options": {"queue": "finint_analysis"},
        },
        "finint-analyze-contracts": {
            "task": "finint.analyze_contracts",
            "schedule": 7200,  # 2h
            "kwargs": {},
            "options": {"queue": "finint_analysis"},
        },
        "finint-analyze-network": {
            "task": "finint.analyze_network",
            "schedule": 21600,  # 6h
            "kwargs": {},
            "options": {"queue": "finint_analysis"},
        },
        "finint-correlate-geoint": {
            "task": "finint.correlate_geoint",
            "schedule": 7200,  # 2h
            "kwargs": {},
            "options": {"queue": "finint_analysis"},
        },
    }

    return app


# Instância singleton usada pelos workers e pelo Beat
celery_app = make_celery()
