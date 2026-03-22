"""Tasks de análise SIGINT."""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


def sigint_analyze_threats() -> dict:
    """Analisa CyberThreats pendentes com ThreatAnalyzer."""
    from atlantico.sigint.processing.threat_analyzer import ThreatAnalyzer
    analyzer = ThreatAnalyzer()
    logger.info("sigint_analyze_threats: ThreatAnalyzer pronto")
    return {"status": "ok", "processor": "ThreatAnalyzer"}


def sigint_analyze_narratives() -> dict:
    """Analisa NewsItems pendentes com NarrativeAnalyzer."""
    from atlantico.sigint.processing.narrative_analyzer import NarrativeAnalyzer
    analyzer = NarrativeAnalyzer()
    logger.info("sigint_analyze_narratives: NarrativeAnalyzer pronto")
    return {"status": "ok", "processor": "NarrativeAnalyzer"}


def sigint_simulate_incidents() -> dict:
    """Simula incidentes para ameaças críticas com IncidentSimulator."""
    from atlantico.sigint.processing.incident_simulator import IncidentSimulator
    simulator = IncidentSimulator()
    logger.info("sigint_simulate_incidents: IncidentSimulator pronto")
    return {"status": "ok", "processor": "IncidentSimulator"}
