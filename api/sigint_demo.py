"""GET /api/sigint_demo — Demo SIGINT: análise de ameaças, narrativas e incidentes."""
from http.server import BaseHTTPRequestHandler
import json
from datetime import datetime, timezone


def _build_demo() -> dict:
    """Executa análise real com ThreatAnalyzer, NarrativeAnalyzer e IncidentSimulator."""
    from atlantico.sigint.processing.threat_analyzer import ThreatAnalyzer
    from atlantico.sigint.processing.narrative_analyzer import NarrativeAnalyzer
    from atlantico.sigint.processing.incident_simulator import IncidentSimulator

    analyzer  = ThreatAnalyzer()
    narrative = NarrativeAnalyzer(similarity_threshold=0.15, min_cluster_size=2)
    simulator = IncidentSimulator()

    # 1. CVE crítico — SCADA brasileiro
    cve_payload = {
        "cve_id": "CVE-2024-12345",
        "description": (
            "Remote code execution in industrial SCADA firmware allows unauthenticated "
            "network attacker to execute arbitrary commands. Affects critical infrastructure "
            "systems used in Brazilian energy sector."
        ),
        "cvss_score": 9.8,
        "attack_vector": "NETWORK",
        "mitre_techniques": ["T1059", "T1190", "T1068"],
        "affected_products": ["scada firmware 3.2", "industrial controller v5"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
    }
    threat_result = analyzer.analyze_threat(
        cve_payload, reference_date=datetime.now(timezone.utc)
    )

    # 2. Landscape de ameaças (últimos 30 dias simulado)
    sample_threats = [
        {"mitre_techniques": ["T1059", "T1078"], "attack_vector": "NETWORK",   "severity": "CRITICAL", "affected_products": ["scada", "vpn"]},
        {"mitre_techniques": ["T1486"],           "attack_vector": "NETWORK",   "severity": "CRITICAL", "affected_products": ["file_server"]},
        {"mitre_techniques": ["T1566"],           "attack_vector": "NETWORK",   "severity": "HIGH",     "affected_products": ["email"]},
        {"mitre_techniques": ["T1190"],           "attack_vector": "NETWORK",   "severity": "HIGH",     "affected_products": ["web_app"]},
        {"mitre_techniques": ["T1068"],           "attack_vector": "LOCAL",     "severity": "MEDIUM",   "affected_products": ["workstation"]},
        {"mitre_techniques": ["T1600"],           "attack_vector": "NETWORK",   "severity": "HIGH",     "affected_products": ["tls", "cryptography"]},
    ]
    landscape = analyzer.compute_threat_landscape(sample_threats)

    # 3. NLP em corpus de notícias/desinformação
    news_corpus = [
        {"id": "n1", "title": "Ransomware LockBit ataca hospitais brasileiros", "content": "Ataque ransomware comprometeu sistemas hospitalares no Brasil. Crítico emergência.", "language": "pt"},
        {"id": "n2", "title": "Hospitais sob ataque LockBit ransomware", "content": "Ransomware LockBit criptografou dados de hospitais brasileiros emergência urgente.", "language": "pt"},
        {"id": "n3", "title": "Desinformação coordenada sobre vacinas fake news", "content": "Campanha de desinformação fake news propaganda manipulação coordenada robôs boato não verificado operação de influência fabricado.", "language": "pt"},
        {"id": "n4", "title": "Fake news sobre sistema eleitoral", "content": "Narrativa falsa desinformação propaganda manipulação coordenada robôs boato não verificado operação de influência fabricado astroturfing.", "language": "pt"},
        {"id": "n5", "title": "Patch de segurança Apache liberado", "content": "Atualização corrige vulnerabilidade crítica no Apache. Patch disponível.", "language": "pt"},
    ]
    nlp_results = narrative.analyze_batch(news_corpus, language="pt")
    clusters    = narrative.cluster_items(news_corpus)
    disinfo_campaigns = narrative.detect_disinfo_campaigns(clusters, news_corpus)

    # 4. Simulação de incidente ransomware
    incident = simulator.simulate_ransomware_scenario("Ministério da Saúde", "phishing")

    # 5. Simulação APT espionagem
    apt_incident = simulator.simulate_apt_scenario("governo")

    return {
        "scenario": "Operação Vigilância Atlântico",
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "threat_analysis": {
            "cve_id":           threat_result.cve_id,
            "base_cvss":        threat_result.base_cvss,
            "contextual_score": threat_result.contextual_score,
            "severity":         threat_result.severity,
            "priority":         threat_result.recommended_priority,
            "exploit_active":   threat_result.exploit_active,
            "attack_vector":    threat_result.attack_vector,
            "mitre_techniques": threat_result.mitre_techniques,
            "critical_products": threat_result.critical_products,
            "mitigation_hints": threat_result.mitigation_hints,
        },

        "threat_landscape": {
            "total_threats":            landscape["total_threats"],
            "top_mitre_techniques":     landscape["top_mitre_techniques"][:5],
            "severity_distribution":    landscape["severity_distribution"],
            "critical_product_exposure": landscape["critical_product_exposure"][:5],
        },

        "nlp_analysis": [
            {
                "item_id":        r.item_id,
                "title":          next((n["title"] for n in news_corpus if n["id"] == r.item_id), ""),
                "sentiment_score": r.sentiment_score,
                "sentiment_label": r.sentiment_label,
                "disinfo_score":   r.disinfo_score,
                "keywords":        r.keywords[:5],
                "entities":        r.entities,
            }
            for r in nlp_results
        ],

        "clusters":  [
            {
                "cluster_id":      c.cluster_id,
                "item_ids":        c.item_ids,
                "central_text":    c.central_text[:100],
                "source_count":    c.source_count,
                "is_amplification": c.is_amplification,
                "disinfo_score":   c.disinfo_score,
            }
            for c in clusters
        ],

        "disinfo_campaigns": [
            {
                "campaign_name":   d["campaign_name"],
                "campaign_type":   d["campaign_type"],
                "disinfo_score":   d["disinfo_score"],
                "severity":        d["severity"],
                "item_count":      d["item_count"],
            }
            for d in disinfo_campaigns
        ],

        "incident_simulation": {
            "ransomware": {
                "incident_type":       incident.incident_type,
                "severity":            incident.severity,
                "affected_systems":    incident.affected_systems[:4],
                "attack_chain":        incident.attack_chain[:4],
                "recovery_time":       incident.recovery_time_estimate,
                "playbook_steps":      len(incident.playbook),
                "countermeasures":     incident.countermeasures[:4],
                "pqc_relevance":       incident.pqc_relevance,
            },
            "apt": {
                "incident_type":    apt_incident.incident_type,
                "severity":         apt_incident.severity,
                "attack_chain":     apt_incident.attack_chain[:4],
                "playbook_steps":   len(apt_incident.playbook),
                "pqc_relevance":    apt_incident.pqc_relevance,
            },
        },

        "alert_preview": {
            "rule_id":     "sigint.cve.critical.v1",
            "severity":    threat_result.severity,
            "title":       f"CVE CRÍTICO: {threat_result.cve_id} (CVSS {threat_result.base_cvss}) — NETWORK",
            "pqc_signed":  "Dilithium3+Ed25519 (requer liboqs no stack completo)",
        },
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            data = _build_demo()
            body = json.dumps(data, ensure_ascii=False, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            error = json.dumps({"error": str(exc)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(error)

    def log_message(self, *_):
        pass
