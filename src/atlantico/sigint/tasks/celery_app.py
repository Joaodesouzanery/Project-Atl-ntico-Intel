"""Factory Celery + beat schedule SIGINT."""
from __future__ import annotations
from celery import Celery


def create_sigint_celery(broker_url: str, backend_url: str) -> Celery:
    app = Celery("sigint", broker=broker_url, backend=backend_url)
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        beat_schedule={
            "sigint.ingest_nvd_cve": {
                "task": "atlantico.sigint.tasks.ingestion.sigint_ingest_nvd_cve",
                "schedule": 3600,
            },
            "sigint.ingest_certbr": {
                "task": "atlantico.sigint.tasks.ingestion.sigint_ingest_certbr",
                "schedule": 1800,
            },
            "sigint.ingest_otx": {
                "task": "atlantico.sigint.tasks.ingestion.sigint_ingest_otx",
                "schedule": 3600,
            },
            "sigint.ingest_news": {
                "task": "atlantico.sigint.tasks.ingestion.sigint_ingest_news",
                "schedule": 900,
            },
            "sigint.analyze_threats": {
                "task": "atlantico.sigint.tasks.analysis.sigint_analyze_threats",
                "schedule": 3600,
            },
            "sigint.analyze_narratives": {
                "task": "atlantico.sigint.tasks.analysis.sigint_analyze_narratives",
                "schedule": 1800,
            },
            "sigint.simulate_incidents": {
                "task": "atlantico.sigint.tasks.analysis.sigint_simulate_incidents",
                "schedule": 7200,
            },
        },
    )
    return app
