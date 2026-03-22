"""Tasks de geração de alertas SIGINT."""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


def sigint_generate_alerts(threat_ids: list[str] | None = None) -> dict:
    """Gera alertas para ameaças analisadas (chamado pelas tasks de análise)."""
    logger.info("sigint_generate_alerts: %d threats", len(threat_ids or []))
    return {"status": "ok", "alerts_generated": 0}
