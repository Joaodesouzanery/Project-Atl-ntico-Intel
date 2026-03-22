"""Testes unitários: CertBrRssConnector."""
import pytest
from datetime import datetime, timezone

pytestmark = pytest.mark.unit

SAMPLE_RDF = """<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <item>
    <title>Alerta crítico: Ransomware afeta governo brasileiro</title>
    <link>https://www.cert.br/alertas/2024/001</link>
    <description>Ransomware exploit comprometimento urgente emergência</description>
    <pubDate>Mon, 15 Jan 2024 10:00:00 +0000</pubDate>
  </item>
  <item>
    <title>Vulnerabilidade CVE-2024-99999 no Apache</title>
    <link>https://www.cert.br/alertas/2024/002</link>
    <description>Falha grave de autenticação no Apache. CVE-2024-99999 patch disponível.</description>
    <pubDate>Mon, 15 Jan 2024 09:00:00 +0000</pubDate>
  </item>
</rdf:RDF>"""


@pytest.fixture
def connector():
    from atlantico.sigint.connectors.certbr_rss import CertBrRssConnector
    return CertBrRssConnector()


def test_parse_rdf_returns_observations(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    assert len(obs_list) == 2


def test_observation_type_is_cyber_threat(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    for obs in obs_list:
        assert obs.observation_type == "cyber_threat"


def test_high_severity_keywords_detected(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    # "Ransomware...crítico...emergência" → HIGH
    assert obs_list[0].severity == "HIGH"


def test_cve_extracted_from_description(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    second = obs_list[1]
    assert "CVE-2024-99999" in second.payload["cve_ids"]


def test_geo_relevance_is_brazil(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    for obs in obs_list:
        assert "BR" in obs.geo_relevance


def test_language_is_portuguese(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    for obs in obs_list:
        assert obs.language == "pt"


def test_source_id(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    for obs in obs_list:
        assert obs.source_id == "certbr.rss.v1"


def test_since_filter_excludes_old_items(connector):
    since = datetime(2025, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    assert len(obs_list) == 0


def test_reference_date_timezone_aware(connector):
    since = datetime(2024, 1, 1, tzinfo=timezone.utc)
    obs_list = connector._parse_rdf("alertas", SAMPLE_RDF, since)
    for obs in obs_list:
        assert obs.reference_date.tzinfo is not None


def test_infer_severity_high_keywords(connector):
    assert connector._infer_severity("alerta crítico ransomware emergência exploit") == "HIGH"


def test_infer_severity_medium_keywords(connector):
    assert connector._infer_severity("vulnerabilidade patch necessário atualização") == "MEDIUM"


def test_infer_severity_info_no_keywords(connector):
    assert connector._infer_severity("artigo genérico sem termos relevantes") == "INFO"
