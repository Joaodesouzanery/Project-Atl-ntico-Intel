"""Testes unitários: NvdCveConnector."""
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_nvd_response():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "published": "2024-01-15T10:00:00.000",
                    "lastModified": "2024-01-16T12:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Remote code execution vulnerability in SCADA system allows network attacker to execute arbitrary commands without authentication."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "attackVector": "NETWORK",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-78"}]}
                    ],
                    "configurations": [],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }
        ]
    }


@pytest.fixture
def connector():
    from atlantico.sigint.connectors.nvd_cve import NvdCveConnector
    return NvdCveConnector(min_cvss_score=7.0)


def test_cvss_to_severity_critical(connector):
    assert connector._cvss_to_severity(9.5) == "CRITICAL"


def test_cvss_to_severity_high(connector):
    assert connector._cvss_to_severity(8.0) == "HIGH"


def test_cvss_to_severity_medium(connector):
    assert connector._cvss_to_severity(5.0) == "MEDIUM"


def test_cvss_to_severity_low(connector):
    assert connector._cvss_to_severity(2.0) == "LOW"


def test_cvss_to_severity_info(connector):
    assert connector._cvss_to_severity(0.0) == "INFO"


def test_parse_cve_returns_observation(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    obs = connector._parse_cve(item)
    assert obs is not None
    assert obs.observation_type == "cyber_threat"
    assert obs.severity == "CRITICAL"
    assert obs.payload["cve_id"] == "CVE-2024-12345"
    assert obs.payload["cvss_score"] == 9.8
    assert obs.payload["attack_vector"] == "NETWORK"


def test_parse_cve_extracts_cwes(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    obs = connector._parse_cve(item)
    assert "CWE-78" in obs.payload["cwes"]


def test_parse_cve_maps_mitre_techniques(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    obs = connector._parse_cve(item)
    # "remote code execution" → T1059
    assert "T1059" in obs.payload["mitre_techniques"]


def test_parse_cve_below_threshold_returns_none(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 4.0
    obs = connector._parse_cve(item)
    assert obs is None


def test_parse_cve_scada_keyword_adds_tag(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    obs = connector._parse_cve(item)
    # "scada" in description → atlantico_relevante + remote_exploitable
    assert "atlantico_relevante" in obs.tags


def test_parse_cve_reference_date_is_timezone_aware(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    obs = connector._parse_cve(item)
    assert obs.reference_date.tzinfo is not None


def test_infer_geo_relevance_global_default(connector, sample_nvd_response):
    geo = connector._infer_geo_relevance("generic vulnerability description", [])
    assert "GLOBAL" in geo


def test_infer_geo_relevance_brazil_detected(connector):
    geo = connector._infer_geo_relevance("vulnerability affecting brazil government", [])
    assert "BR" in geo


def test_cvss_threshold_to_param_critical(connector):
    connector._min_cvss = 9.0
    assert connector._cvss_threshold_to_param() == "CRITICAL"


def test_cvss_threshold_to_param_high(connector):
    connector._min_cvss = 7.0
    assert connector._cvss_threshold_to_param() == "HIGH"


def test_observation_has_source_id(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    obs = connector._parse_cve(item)
    assert obs.source_id == "nvd.cve.v2"


def test_observation_source_type(connector, sample_nvd_response):
    item = sample_nvd_response["vulnerabilities"][0]
    obs = connector._parse_cve(item)
    assert obs.source_type == "cve_feed"
