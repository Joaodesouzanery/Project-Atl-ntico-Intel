"""
Teste de integração: Pipeline SIGINT end-to-end.

Gates de aceitação:
1. SigintObservation bem formada (reference_date timezone-aware, observation_type válido)
2. NvdCveConnector._parse_cve() gera observação para CVE CRITICAL
3. ThreatAnalyzer detecta score > 0.5 para CVE CVSS=9.8 + SCADA + recente
4. NarrativeAnalyzer.cluster_items() agrupa artigos similares
5. NarrativeAnalyzer detecta desinformação (score > 0.3) em corpus de disinfo
6. IncidentSimulator gera playbook com >= 5 passos para ransomware
7. SigintAlertGenerator.generate_cve_alert() chama alert_repo.create() para score > 0.6
8. PQC relevance detectada para ataque criptográfico (T1600)
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

pytestmark = pytest.mark.integration


# Gate 1: DTO timezone-aware e tipo válido
def test_sigint_observation_dto():
    from atlantico.sigint.observations import SigintObservation
    obs = SigintObservation(
        source_id="nvd.cve.v2",
        external_id="test-001",
        observation_type="cyber_threat",
        reference_date=datetime.now(timezone.utc),
        severity="CRITICAL",
        source_type="cve_feed",
    )
    assert obs.reference_date.tzinfo is not None
    assert obs.observation_type == "cyber_threat"
    assert obs.severity == "CRITICAL"


def test_sigint_observation_rejects_naive_datetime():
    from atlantico.sigint.observations import SigintObservation
    with pytest.raises(ValueError, match="timezone-aware"):
        SigintObservation(
            source_id="test", external_id="x",
            observation_type="cyber_threat",
            reference_date=datetime(2024, 1, 1),  # sem timezone
        )


def test_sigint_observation_rejects_invalid_type():
    from atlantico.sigint.observations import SigintObservation
    with pytest.raises(ValueError):
        SigintObservation(
            source_id="test", external_id="x",
            observation_type="invalid_type",
            reference_date=datetime.now(timezone.utc),
        )


# Gate 2: NvdCveConnector parseia CVE crítico
def test_nvd_parse_critical_cve():
    from atlantico.sigint.connectors.nvd_cve import NvdCveConnector
    connector = NvdCveConnector(min_cvss_score=7.0)
    item = {
        "cve": {
            "id": "CVE-2024-99999",
            "published": "2024-06-01T10:00:00.000",
            "descriptions": [{"lang": "en", "value": "Critical SCADA remote code execution"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {
                    "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N",
                    "attackVector": "NETWORK"
                }}]
            },
            "weaknesses": [],
            "configurations": [],
            "references": [],
        }
    }
    obs = connector._parse_cve(item)
    assert obs is not None
    assert obs.severity == "CRITICAL"
    assert obs.payload["cvss_score"] == 9.8


# Gate 3: ThreatAnalyzer score alto para CVE crítico recente
def test_threat_analyzer_critical_score():
    from atlantico.sigint.processing.threat_analyzer import ThreatAnalyzer
    analyzer = ThreatAnalyzer()
    payload = {
        "cve_id": "CVE-2024-99999",
        "description": "Remote code execution in SCADA system without authentication",
        "cvss_score": 9.8,
        "attack_vector": "NETWORK",
        "mitre_techniques": ["T1059", "T1190"],
        "affected_products": ["industrial scada v1.0"],
        "references": [],
    }
    result = analyzer.analyze_threat(payload, reference_date=datetime.now(timezone.utc))
    assert result.contextual_score > 0.5


# Gate 4: NarrativeAnalyzer agrupa artigos similares
def test_narrative_analyzer_clusters_similar():
    from atlantico.sigint.processing.narrative_analyzer import NarrativeAnalyzer
    analyzer = NarrativeAnalyzer(similarity_threshold=0.1, min_cluster_size=2)
    items = [
        {"id": "a", "title": "LockBit ransomware encrypts hospital files", "content": "Ransomware LockBit attack hospital", "feed_name": "f1"},
        {"id": "b", "title": "Hospital attacked by LockBit ransomware", "content": "LockBit ransomware encrypted hospital data", "feed_name": "f2"},
        {"id": "c", "title": "Apache security patch released", "content": "Apache vulnerability fix patch update", "feed_name": "f3"},
    ]
    clusters = analyzer.cluster_items(items)
    assert len(clusters) >= 1
    # items a e b devem estar no mesmo cluster
    found = any("a" in c.item_ids and "b" in c.item_ids for c in clusters)
    assert found


# Gate 5: NarrativeAnalyzer detecta desinformação
def test_narrative_analyzer_detects_disinfo():
    from atlantico.sigint.processing.narrative_analyzer import NarrativeAnalyzer
    analyzer = NarrativeAnalyzer()
    result = analyzer.analyze_item(
        "d1",
        "Coordinated disinformation fake news propaganda manipulation unverified",
        "Bot network astroturfing conspiracy fabricated influence operation state-sponsored troll",
        "en"
    )
    assert result.disinfo_score > 0.3


# Gate 6: IncidentSimulator playbook >= 5 passos
def test_incident_simulator_playbook_steps():
    from atlantico.sigint.processing.incident_simulator import IncidentSimulator
    simulator = IncidentSimulator()
    result = simulator.simulate_ransomware_scenario()
    assert len(result.playbook) >= 5


# Gate 7: SigintAlertGenerator chama create() para score alto
@pytest.mark.asyncio
async def test_alert_generator_creates_alert_for_critical():
    from atlantico.sigint.alerts.generator import SigintAlertGenerator
    from atlantico.sigint.processing.threat_analyzer import ThreatAnalysisResult

    mock_repo = MagicMock()
    mock_repo.create = AsyncMock(return_value=MagicMock(id="alert-001"))
    mock_audit = MagicMock()
    mock_audit.append = AsyncMock()

    gen = SigintAlertGenerator(mock_repo, mock_audit)
    analysis = ThreatAnalysisResult(
        external_id="CVE-2024-X", cve_id="CVE-2024-X", base_cvss=9.8,
        contextual_score=0.92, severity="CRITICAL", attack_vector="NETWORK",
        mitre_techniques=["T1190"], high_impact_techniques=["T1190"],
        critical_products=["scada"], recommended_priority="IMMEDIATE",
        mitigation_hints=["patch now"], exploit_active=False,
    )
    alert = await gen.generate_cve_alert(analysis, ["src-001"])
    mock_repo.create.assert_called_once()


# Gate 8: PQC relevance para T1600
def test_incident_simulator_pqc_relevance_for_crypto():
    from atlantico.sigint.processing.incident_simulator import IncidentSimulator
    simulator = IncidentSimulator()
    payload = {
        "cve_id": "CVE-2024-CRYPTO",
        "description": "Cryptographic weakness in TLS implementation allows key recovery",
        "cvss_score": 8.5,
    }
    result = simulator.simulate(payload, ["T1600"], contextual_score=0.85)
    assert result.pqc_relevance is not None
    assert "PQC" in result.pqc_relevance or "Kyber" in result.pqc_relevance or "pqc" in result.pqc_relevance.lower()
