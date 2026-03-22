"""
Celery app factory para o módulo GEOINT.

Configuração segura:
- task_acks_late=True para idempotência (ack após conclusão, não antes)
- worker_prefetch_multiplier=1 para processamento sequencial por worker
- Soft limit: 10min, Hard limit: 15min (suficiente para ingestão + DBSCAN)
- Beat schedule com intervalos configuráveis via Settings
"""

from __future__ import annotations

from celery import Celery

from atlantico.config.settings import get_settings


def make_celery() -> Celery:
    """Cria e configura a instância Celery do módulo GEOINT."""
    settings = get_settings()

    app = Celery(
        "atlantico.geoint",
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
        task_acks_late=True,           # Idempotência: ack após conclusão
        worker_prefetch_multiplier=1,  # Um task por vez por worker
        task_soft_time_limit=600,      # 10 min soft limit → SoftTimeLimitExceeded
        task_time_limit=900,           # 15 min hard limit → worker killed
        task_reject_on_worker_lost=True,  # Re-enfileira se worker morrer
        broker_connection_retry_on_startup=True,
    )

    # Beat schedule — intervalos configuráveis via Settings
    app.conf.beat_schedule = {
        "geoint-ingest-bdqueimadas": {
            "task": "geoint.ingest_bdqueimadas",
            "schedule": settings.geoint_ingest_bdqueimadas_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "geoint_ingestion"},
        },
        "geoint-ingest-deter": {
            "task": "geoint.ingest_deter",
            "schedule": settings.geoint_ingest_deter_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "geoint_ingestion"},
        },
        "geoint-ingest-hidroweb": {
            "task": "geoint.ingest_hidroweb",
            "schedule": settings.geoint_ingest_hidroweb_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "geoint_ingestion"},
        },
        "geoint-ingest-sentinel2": {
            "task": "geoint.ingest_sentinel2",
            "schedule": settings.geoint_ingest_sentinel2_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "geoint_ingestion"},
        },
        "geoint-ingest-prodes": {
            "task": "geoint.ingest_prodes",
            "schedule": settings.geoint_ingest_prodes_interval_s,
            "kwargs": {"since_iso": None},
            "options": {"queue": "geoint_ingestion"},
        },
        "geoint-cluster-fires": {
            "task": "geoint.cluster_fires",
            "schedule": 1800,  # 30 min — não configurável, é limite de clustering
            "kwargs": {"since_iso": None},
            "options": {"queue": "geoint_analysis"},
        },
        "geoint-detect-water-anomalies": {
            "task": "geoint.detect_water_anomalies",
            "schedule": 3600,  # 1h
            "kwargs": {},
            "options": {"queue": "geoint_analysis"},
        },
        "geoint-analyze-deforestation": {
            "task": "geoint.analyze_deforestation",
            "schedule": 3600,  # 1h
            "kwargs": {},
            "options": {"queue": "geoint_analysis"},
        },
    }

    return app


# Instância singleton usada pelos workers e pelo Beat
celery_app = make_celery()
