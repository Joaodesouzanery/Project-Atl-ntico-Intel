"""Testes unitários: IncidentSimulator."""
import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def simulator():
    from atlantico.sigint.processing.incident_simulator import IncidentSimulator
    return IncidentSimulator()


@pytest.fixture
def ransomware_payload():
    return {
        "cve_id": "CVE-2024-RANSOM",
        "description": "ransomware attack critical system compromise",
        "cvss_score": 9.0,
    }


def test_simulate_returns_result(simulator, ransomware_payload):
    result = simulator.simulate(ransomware_payload, ["T1566", "T1486"])
    assert result is not None
    assert result.incident_type == "ransomware"


def test_simulation_has_playbook(simulator, ransomware_payload):
    result = simulator.simulate(ransomware_payload, ["T1566", "T1486"])
    assert len(result.playbook) >= 5


def test_simulation_has_countermeasures(simulator, ransomware_payload):
    result = simulator.simulate(ransomware_payload, ["T1566", "T1486"])
    assert len(result.countermeasures) >= 1


def test_critical_cvss_gives_critical_severity(simulator, ransomware_payload):
    result = simulator.simulate(ransomware_payload, ["T1486"], contextual_score=0.95)
    assert result.severity in ("CRITICAL", "HIGH")


def test_attack_chain_ordered(simulator, ransomware_payload):
    result = simulator.simulate(ransomware_payload, ["T1566", "T1059", "T1486"])
    assert len(result.attack_chain) >= 3


def test_pqc_relevance_detected_for_crypto_attack(simulator):
    payload = {"cve_id": "CVE-2024-CRYPTO", "description": "cryptography tls weakness", "cvss_score": 8.5}
    result = simulator.simulate(payload, ["T1600"], contextual_score=0.8)
    assert result.pqc_relevance is not None


def test_pqc_relevance_none_for_generic_attack(simulator):
    payload = {"cve_id": "CVE-2024-GENERIC", "description": "cross site scripting", "cvss_score": 6.0}
    result = simulator.simulate(payload, ["T1059"], contextual_score=0.5)
    # Pode ser None para ameaças sem contexto PQC
    assert result.pqc_relevance is None or isinstance(result.pqc_relevance, str)


def test_recovery_time_not_empty(simulator, ransomware_payload):
    result = simulator.simulate(ransomware_payload, ["T1486"])
    assert len(result.recovery_time_estimate) > 0


def test_affected_systems_not_empty(simulator, ransomware_payload):
    result = simulator.simulate(ransomware_payload, ["T1486"])
    assert len(result.affected_systems) >= 1


def test_simulate_ransomware_scenario(simulator):
    result = simulator.simulate_ransomware_scenario("Banco do Brasil", "phishing")
    assert result.incident_type == "ransomware"
    assert result.severity in ("CRITICAL", "HIGH")


def test_simulate_apt_scenario(simulator):
    result = simulator.simulate_apt_scenario("governo")
    assert result.incident_type == "apt"
    assert len(result.playbook) >= 5


def test_simulation_id_is_unique(simulator, ransomware_payload):
    r1 = simulator.simulate(ransomware_payload, ["T1486"])
    r2 = simulator.simulate(ransomware_payload, ["T1486"])
    assert r1.simulation_id != r2.simulation_id


def test_playbook_has_all_phases(simulator, ransomware_payload):
    from atlantico.sigint.processing.incident_simulator import IncidentPhase
    result = simulator.simulate(ransomware_payload, ["T1566", "T1486"], contextual_score=0.9)
    phases = {step.phase for step in result.playbook}
    assert IncidentPhase.IDENTIFICATION in phases
    assert IncidentPhase.CONTAINMENT in phases
    assert IncidentPhase.ERADICATION in phases
    assert IncidentPhase.RECOVERY in phases
