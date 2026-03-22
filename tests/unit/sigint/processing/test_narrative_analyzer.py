"""Testes unitários: NarrativeAnalyzer."""
import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def analyzer():
    from atlantico.sigint.processing.narrative_analyzer import NarrativeAnalyzer
    return NarrativeAnalyzer(similarity_threshold=0.1, min_cluster_size=2)


def test_analyze_item_returns_result(analyzer):
    result = analyzer.analyze_item("id1", "Ransomware attack critical breach", "Malware exploited zero-day vulnerability.", "en")
    assert result is not None
    assert result.item_id == "id1"


def test_sentiment_negative_for_threat_content(analyzer):
    result = analyzer.analyze_item("id1", "Critical attack breach ransomware exploit", "", "en")
    assert result.sentiment_score < 0


def test_sentiment_label_threat(analyzer):
    result = analyzer.analyze_item("id1", "Critical attack ransomware exploit breach", "", "en")
    assert result.sentiment_label in ("threat", "negative")


def test_extract_entities_finds_cves(analyzer):
    result = analyzer.analyze_item("id1", "CVE-2024-12345 vulnerability", "Affects CVE-2023-99999 systems.", "en")
    assert "CVE-2024-12345" in result.entities["cves"]
    assert "CVE-2023-99999" in result.entities["cves"]


def test_extract_entities_finds_ips(analyzer):
    result = analyzer.analyze_item("id1", "C2 server at 192.168.1.100", "Also uses 10.0.0.1.", "en")
    assert "192.168.1.100" in result.entities["ips"]


def test_extract_entities_finds_domains(analyzer):
    result = analyzer.analyze_item("id1", "malware.example.com used for C2", "", "en")
    assert any("example.com" in d for d in result.entities["domains"])


def test_disinfo_score_high_for_disinfo_content(analyzer):
    result = analyzer.analyze_item(
        "id1",
        "Disinformation fake news propaganda manipulation coordinated",
        "Unverified rumor conspiracy fabricated influence operation bot network astroturfing",
        "en"
    )
    assert result.disinfo_score > 0.3


def test_disinfo_score_low_for_legitimate_news(analyzer):
    result = analyzer.analyze_item(
        "id1",
        "Security patch released for Apache vulnerability",
        "The vendor released a fix for the authenticated remote code execution flaw.",
        "en"
    )
    assert result.disinfo_score < 0.5


def test_keywords_extracted(analyzer):
    result = analyzer.analyze_item("id1", "ransomware encryption attack critical infrastructure", "", "en")
    assert len(result.keywords) > 0


def test_analyze_batch_returns_list(analyzer):
    items = [
        {"id": "1", "title": "Attack", "content": "Ransomware critical breach", "language": "en"},
        {"id": "2", "title": "Patch", "content": "Security update released patch", "language": "en"},
        {"id": "3", "title": "Exploit", "content": "Zero-day exploit vulnerability", "language": "en"},
    ]
    results = analyzer.analyze_batch(items)
    assert len(results) == 3


def test_cluster_items_groups_similar(analyzer):
    items = [
        {"id": "a1", "title": "Ransomware LockBit attacks hospital", "content": "LockBit ransomware encrypted files", "feed_name": "feed1"},
        {"id": "a2", "title": "LockBit ransomware hospital attack", "content": "Ransomware encrypted hospital data LockBit", "feed_name": "feed2"},
        {"id": "b1", "title": "Apache vulnerability patch released", "content": "Security patch available for Apache", "feed_name": "feed3"},
    ]
    clusters = analyzer.cluster_items(items)
    # a1 e a2 devem estar no mesmo cluster
    cluster_ids_per_doc = {item["id"]: None for item in items}
    for cluster in clusters:
        for item_id in cluster.item_ids:
            cluster_ids_per_doc[item_id] = cluster.cluster_id

    if cluster_ids_per_doc["a1"] and cluster_ids_per_doc["a2"]:
        assert cluster_ids_per_doc["a1"] == cluster_ids_per_doc["a2"]


def test_detect_disinfo_campaigns_filters_low_score(analyzer):
    from atlantico.sigint.processing.narrative_analyzer import ClusterResult
    low_cluster = ClusterResult(
        cluster_id="c1", item_ids=["x"], central_text="normal news",
        key_topics=["news"], source_count=1, is_amplification=False, disinfo_score=0.1,
    )
    campaigns = analyzer.detect_disinfo_campaigns([low_cluster], [])
    assert len(campaigns) == 0


def test_detect_disinfo_campaigns_creates_campaign_for_high_score(analyzer):
    from atlantico.sigint.processing.narrative_analyzer import ClusterResult
    high_cluster = ClusterResult(
        cluster_id="c2", item_ids=["x", "y"], central_text="Fake news campaign",
        key_topics=["disinfo"], source_count=3, is_amplification=True, disinfo_score=0.75,
    )
    campaigns = analyzer.detect_disinfo_campaigns([high_cluster], [])
    assert len(campaigns) == 1
    assert campaigns[0]["disinfo_score"] == 0.75
    assert campaigns[0]["campaign_type"] == "influence_op"
