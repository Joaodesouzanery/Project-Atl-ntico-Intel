"""Testes unitários: ThreatAnalyzer."""
import pytest
from datetime import datetime, timezone

pytestmark = pytest.mark.unit


@pytest.fixture
def analyzer():
    from atlantico.sigint.processing.threat_analyzer import ThreatAnalyzer
    return ThreatAnalyzer()


@pytest.fixture
def critical_cve_payload():
    return {
        "cve_id": "CVE-2024-12345",
        "description": "Remote code execution in SCADA system allows network attacker to execute commands without authentication.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attack_vector": "NETWORK",
        "mitre_techniques": ["T1059", "T1190"],
        "affected_products": ["industrial scada firmware 1.0"],
        "references": ["https://example.com"],
    }


def test_analyze_threat_returns_result(analyzer, critical_cve_payload):
    ref = datetime(2024, 1, 15, tzinfo=timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)
    assert result is not None
    assert result.cve_id == "CVE-2024-12345"


def test_contextual_score_above_zero(analyzer, critical_cve_payload):
    ref = datetime(2024, 1, 15, tzinfo=timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)
    assert result.contextual_score > 0.0


def test_contextual_score_le_one(analyzer, critical_cve_payload):
    ref = datetime(2024, 1, 15, tzinfo=timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)
    assert result.contextual_score <= 1.0


def test_critical_cvss_gives_critical_or_high_severity(analyzer, critical_cve_payload):
    ref = datetime.now(timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)
    assert result.severity in ("CRITICAL", "HIGH")


def test_network_attack_vector_increases_score(analyzer, critical_cve_payload):
    ref = datetime.now(timezone.utc)
    result_network = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)

    local_payload = critical_cve_payload.copy()
    local_payload["attack_vector"] = "LOCAL"
    result_local = analyzer.analyze_threat(local_payload, reference_date=ref)

    assert result_network.contextual_score >= result_local.contextual_score


def test_scada_product_detected_as_critical(analyzer, critical_cve_payload):
    ref = datetime.now(timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)
    assert "scada" in result.critical_products


def test_high_impact_techniques_identified(analyzer, critical_cve_payload):
    ref = datetime.now(timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)
    # T1059 e T1190 são high impact
    assert len(result.high_impact_techniques) >= 1


def test_mitigation_hints_not_empty(analyzer, critical_cve_payload):
    ref = datetime.now(timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref)
    assert len(result.mitigation_hints) > 0


def test_exploit_not_active_without_iocs(analyzer, critical_cve_payload):
    ref = datetime.now(timezone.utc)
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref, known_iocs=[])
    assert result.exploit_active == False


def test_exploit_active_when_ioc_matches(analyzer, critical_cve_payload):
    ref = datetime.now(timezone.utc)
    critical_cve_payload["description"] += " IOC: 192.168.1.100"
    known_iocs = [{"ioc_type": "ip", "ioc_value": "192.168.1.100"}]
    result = analyzer.analyze_threat(critical_cve_payload, reference_date=ref, known_iocs=known_iocs)
    assert result.exploit_active == True


def test_recency_recent_date_high_score(analyzer):
    from datetime import timedelta
    recent = datetime.now(timezone.utc) - timedelta(hours=2)
    score = analyzer._compute_recency(recent)
    assert score >= 0.8


def test_recency_old_date_low_score(analyzer):
    from datetime import timedelta
    old = datetime.now(timezone.utc) - timedelta(days=200)
    score = analyzer._compute_recency(old)
    assert score <= 0.3


def test_compute_threat_landscape(analyzer):
    threats = [
        {"mitre_techniques": ["T1059", "T1078"], "attack_vector": "NETWORK", "severity": "HIGH", "affected_products": []},
        {"mitre_techniques": ["T1059", "T1190"], "attack_vector": "NETWORK", "severity": "CRITICAL", "affected_products": ["scada"]},
        {"mitre_techniques": ["T1068"],          "attack_vector": "LOCAL",   "severity": "MEDIUM", "affected_products": []},
    ]
    landscape = analyzer.compute_threat_landscape(threats)
    assert landscape["total_threats"] == 3
    top_tech = dict(landscape["top_mitre_techniques"])
    assert top_tech.get("T1059", 0) == 2  # mais frequente


def test_detect_exploit_trend_finds_overlap(analyzer):
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    threats = [{"cve_id": "CVE-2024-1234", "reference_date": now - timedelta(hours=1)}]
    iocs    = [{"description": "indicator for CVE-2024-1234 exploitation", "tags": []}]
    result  = analyzer.detect_exploit_trend(threats, iocs, window_days=7)
    assert "CVE-2024-1234" in result
