"""Testes unitários: SigintAlertGenerator."""
import pytest
from unittest.mock import AsyncMock, MagicMock

pytestmark = pytest.mark.unit


@pytest.fixture
def mock_alert_repo():
    repo = MagicMock()
    repo.create = AsyncMock(return_value=MagicMock(id="alert-123"))
    return repo


@pytest.fixture
def mock_audit_log():
    log = MagicMock()
    log.append = AsyncMock()
    return log


@pytest.fixture
def generator(mock_alert_repo, mock_audit_log):
    from atlantico.sigint.alerts.generator import SigintAlertGenerator
    return SigintAlertGenerator(mock_alert_repo, mock_audit_log)


@pytest.fixture
def critical_analysis():
    from atlantico.sigint.processing.threat_analyzer import ThreatAnalysisResult
    return ThreatAnalysisResult(
        external_id="CVE-2024-12345",
        cve_id="CVE-2024-12345",
        base_cvss=9.8,
        contextual_score=0.92,
        severity="CRITICAL",
        attack_vector="NETWORK",
        mitre_techniques=["T1059", "T1190"],
        high_impact_techniques=["T1059", "T1190"],
        critical_products=["scada"],
        recommended_priority="IMMEDIATE",
        mitigation_hints=["Apply patch immediately"],
        exploit_active=False,
        ioc_correlation=[],
    )


@pytest.fixture
def disinfo_cluster():
    from atlantico.sigint.processing.narrative_analyzer import ClusterResult
    return ClusterResult(
        cluster_id="cluster-20240115-001",
        item_ids=["n1", "n2", "n3"],
        central_text="Fake news about government cyberattack",
        key_topics=["governo", "ataque"],
        source_count=3,
        is_amplification=True,
        disinfo_score=0.78,
    )


@pytest.mark.asyncio
async def test_generate_cve_alert_called(generator, critical_analysis, mock_alert_repo):
    await generator.generate_cve_alert(critical_analysis, ["src-001"])
    mock_alert_repo.create.assert_called_once()


@pytest.mark.asyncio
async def test_generate_cve_alert_rule_id(generator, critical_analysis, mock_alert_repo):
    await generator.generate_cve_alert(critical_analysis, ["src-001"])
    kwargs = mock_alert_repo.create.call_args.kwargs
    assert "sigint.cve" in kwargs["rule_id"]


@pytest.mark.asyncio
async def test_generate_cve_alert_severity_critical(generator, critical_analysis, mock_alert_repo):
    await generator.generate_cve_alert(critical_analysis, ["src-001"])
    kwargs = mock_alert_repo.create.call_args.kwargs
    assert kwargs["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_generate_cve_alert_low_score_returns_none(generator, mock_alert_repo):
    from atlantico.sigint.processing.threat_analyzer import ThreatAnalysisResult
    low_analysis = ThreatAnalysisResult(
        external_id="CVE-X", cve_id="CVE-X", base_cvss=4.0,
        contextual_score=0.3, severity="MEDIUM", attack_vector="LOCAL",
        mitre_techniques=[], high_impact_techniques=[], critical_products=[],
        recommended_priority="LOW", mitigation_hints=[], exploit_active=False,
    )
    result = await generator.generate_cve_alert(low_analysis, ["src-001"])
    assert result is None
    mock_alert_repo.create.assert_not_called()


@pytest.mark.asyncio
async def test_generate_disinfo_alert_called(generator, disinfo_cluster, mock_alert_repo):
    await generator.generate_disinfo_alert(disinfo_cluster, "campaign-001", ["src-002"])
    mock_alert_repo.create.assert_called_once()


@pytest.mark.asyncio
async def test_generate_disinfo_alert_rule_id(generator, disinfo_cluster, mock_alert_repo):
    await generator.generate_disinfo_alert(disinfo_cluster, "campaign-001", ["src-002"])
    kwargs = mock_alert_repo.create.call_args.kwargs
    assert kwargs["rule_id"] == "sigint.narrative.disinfo_campaign.v1"


@pytest.mark.asyncio
async def test_generate_disinfo_alert_low_score_returns_none(generator, mock_alert_repo):
    from atlantico.sigint.processing.narrative_analyzer import ClusterResult
    low_cluster = ClusterResult(
        cluster_id="c1", item_ids=["x"], central_text="normal",
        key_topics=[], source_count=1, is_amplification=False, disinfo_score=0.2,
    )
    result = await generator.generate_disinfo_alert(low_cluster, "camp-1", ["src-001"])
    assert result is None


@pytest.mark.asyncio
async def test_generate_incident_alert_called(generator, mock_alert_repo):
    from atlantico.sigint.processing.incident_simulator import IncidentSimulator
    simulator = IncidentSimulator()
    simulation = simulator.simulate_ransomware_scenario()
    await generator.generate_incident_alert(simulation, ["src-003"])
    mock_alert_repo.create.assert_called_once()


@pytest.mark.asyncio
async def test_generate_incident_alert_skips_low_severity(generator, mock_alert_repo):
    from atlantico.sigint.processing.incident_simulator import IncidentSimulator, IncidentSimulationResult
    from atlantico.sigint.processing.incident_simulator import IncidentPhase
    from datetime import datetime, timezone
    low_sim = IncidentSimulationResult(
        simulation_id="sim-001", incident_type="phishing", triggered_by="CVE-X",
        severity="LOW", estimated_impact={}, affected_systems=[], attack_chain=[],
        playbook=[], countermeasures=[], recovery_time_estimate="1h",
        pqc_relevance=None,
    )
    result = await generator.generate_incident_alert(low_sim, ["src-003"])
    assert result is None


@pytest.mark.asyncio
async def test_audit_log_called_on_cve_alert(generator, critical_analysis, mock_audit_log):
    await generator.generate_cve_alert(critical_analysis, ["src-001"])
    mock_audit_log.append.assert_called_once()


@pytest.mark.asyncio
async def test_generate_ioc_alert_high_confidence(generator, mock_alert_repo):
    await generator.generate_ioc_alert(
        ioc_type="ip", ioc_value="192.168.1.100",
        confidence=0.9, severity="HIGH",
        threat_actor="APT-29", malware_family="Cobalt Strike",
        geo_targets=["BR", "US"], source_id="otx.alienvault.v1",
        source_record_ids=["src-004"],
    )
    mock_alert_repo.create.assert_called_once()


@pytest.mark.asyncio
async def test_generate_ioc_alert_low_confidence_returns_none(generator, mock_alert_repo):
    result = await generator.generate_ioc_alert(
        ioc_type="domain", ioc_value="suspicious.com",
        confidence=0.4, severity="MEDIUM",
        threat_actor="", malware_family="",
        geo_targets=[], source_id="otx.alienvault.v1",
        source_record_ids=["src-005"],
    )
    assert result is None
