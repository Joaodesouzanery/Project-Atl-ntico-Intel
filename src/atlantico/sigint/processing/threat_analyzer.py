"""
ThreatAnalyzer — Análise de ameaças cibernéticas SIGINT.

Responsabilidades:
  - Pontuar e classificar CVEs por impacto (CVSS + contexto)
  - Correlacionar IOCs com ameaças conhecidas
  - Identificar padrões de ataque (MITRE ATT&CK)
  - Cruzar ameaças com contexto GEOINT/FININT
  - Detectar exploits ativos (CVE em tendência + IOC concorrente)
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ─── CVE / MITRE ATT&CK ────────────────────────────────────────────────────────

# Pesos de impacto por vetor de ataque (CVSS AV)
_ATTACK_VECTOR_WEIGHTS = {
    "NETWORK":   1.0,
    "ADJACENT":  0.7,
    "LOCAL":     0.5,
    "PHYSICAL":  0.3,
}

# Técnicas de alto impacto que elevam o score
_HIGH_IMPACT_TECHNIQUES = {
    "T1059",   # Command & Scripting Interpreter
    "T1078",   # Valid Accounts
    "T1190",   # Exploit Public-Facing Application
    "T1203",   # Exploitation for Client Execution
    "T1068",   # Exploitation for Privilege Escalation
    "T1499",   # Endpoint Denial of Service
    "T1600",   # Weaken Encryption
}

# Setores críticos: produto → peso de criticidade
_CRITICAL_PRODUCT_KEYWORDS = {
    "scada": 1.5, "ics": 1.5, "industrial": 1.4,
    "satellite": 1.3, "gps": 1.3, "gnss": 1.3,
    "firewall": 1.2, "router": 1.2, "switch": 1.2,
    "cryptography": 1.4, "kyber": 1.5, "tls": 1.2,
    "vpn": 1.3, "authentication": 1.2,
    "government": 1.4, "military": 1.5, "defense": 1.4,
    "banking": 1.3, "financial": 1.3,
}

# Regex para extrair CVE IDs de texto livre
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class ThreatAnalysisResult:
    """Resultado da análise de uma ameaça cibernética."""
    external_id:       str
    cve_id:            str | None
    base_cvss:         float
    contextual_score:  float          # score ponderado por contexto Atlântico
    severity:          str
    attack_vector:     str
    mitre_techniques:  list[str]
    high_impact_techniques: list[str]
    critical_products: list[str]      # produtos de infra crítica afetados
    recommended_priority: str         # "IMMEDIATE" | "HIGH" | "MEDIUM" | "LOW"
    mitigation_hints:  list[str]
    exploit_active:    bool = False
    ioc_correlation:   list[str] = field(default_factory=list)  # IOC values ligados


@dataclass
class IocCorrelationResult:
    """Resultado de correlação entre IOC e ameaças."""
    ioc_value:     str
    ioc_type:      str
    confidence:    float
    linked_threats: list[str]  # external_ids de CyberThreat
    malware_families: list[str]
    threat_actors: list[str]
    geo_targets:   list[str]


class ThreatAnalyzer:
    """
    Analisa ameaças cibernéticas, pontua CVEs por contexto e correlaciona IOCs.

    Uso:
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_threat(payload_dict)
        ioc_result = analyzer.correlate_ioc(ioc_value, ioc_type, context_threats)
    """

    def __init__(
        self,
        cvss_weight: float = 0.5,
        context_weight: float = 0.3,
        recency_weight: float = 0.2,
        exploit_window_days: int = 30,
    ) -> None:
        self._cvss_weight    = cvss_weight
        self._context_weight = context_weight
        self._recency_weight = recency_weight
        self._exploit_window = timedelta(days=exploit_window_days)

    def analyze_threat(
        self,
        payload: dict,
        reference_date: datetime | None = None,
        known_iocs: list[dict] | None = None,
    ) -> ThreatAnalysisResult:
        """
        Gera análise contextualizada de uma ameaça SIGINT.

        Args:
            payload:       Payload bruto da SigintObservation
            reference_date: Data de referência para cálculo de recência
            known_iocs:    IOCs conhecidos para correlação (lista de dicts)

        Returns:
            ThreatAnalysisResult com score contextual e recomendações
        """
        cve_id          = payload.get("cve_id")
        cvss_score      = float(payload.get("cvss_score") or 0.0)
        attack_vector   = payload.get("attack_vector", "UNKNOWN")
        mitre_techniques = list(payload.get("mitre_techniques") or [])
        affected_products = payload.get("affected_products", [])
        description      = payload.get("description", "")
        references       = payload.get("references", [])

        # 1. Score base normalizado [0, 1]
        base_norm = cvss_score / 10.0

        # 2. Score contextual: vetor de ataque + técnicas de alto impacto + produtos críticos
        av_weight       = _ATTACK_VECTOR_WEIGHTS.get(attack_vector, 0.5)
        high_impact     = [t for t in mitre_techniques if t in _HIGH_IMPACT_TECHNIQUES]
        technique_boost = min(len(high_impact) * 0.05, 0.2)

        critical_prods = self._find_critical_products(affected_products, description)
        crit_boost     = min(
            sum(_CRITICAL_PRODUCT_KEYWORDS.get(p, 1.0) - 1.0 for p in critical_prods),
            0.3,
        )

        context_score = min(av_weight + technique_boost + crit_boost, 1.0)

        # 3. Score de recência [0, 1] — mais novo = mais urgente
        recency_score = self._compute_recency(reference_date)

        # 4. Score final ponderado
        contextual_score = min(
            self._cvss_weight * base_norm
            + self._context_weight * context_score
            + self._recency_weight * recency_score,
            1.0,
        )

        severity = self._score_to_severity(contextual_score)
        priority = self._score_to_priority(contextual_score)

        # 5. Correlação com IOCs conhecidos
        ioc_correlation: list[str] = []
        exploit_active  = False
        if known_iocs:
            ioc_correlation = self._find_ioc_matches(description, references, known_iocs)
            exploit_active  = len(ioc_correlation) > 0

        # 6. Hints de mitigação baseados em técnicas MITRE
        mitigation_hints = self._generate_mitigations(
            mitre_techniques, attack_vector, cvss_score
        )

        return ThreatAnalysisResult(
            external_id=payload.get("cve_id", "unknown"),
            cve_id=cve_id,
            base_cvss=cvss_score,
            contextual_score=round(contextual_score, 4),
            severity=severity,
            attack_vector=attack_vector,
            mitre_techniques=mitre_techniques,
            high_impact_techniques=high_impact,
            critical_products=critical_prods,
            recommended_priority=priority,
            mitigation_hints=mitigation_hints,
            exploit_active=exploit_active,
            ioc_correlation=ioc_correlation,
        )

    def detect_exploit_trend(
        self,
        threats: list[dict],
        iocs: list[dict],
        window_days: int = 7,
    ) -> list[str]:
        """
        Detecta CVEs que têm tanto atividade recente de IOC quanto publicação recente.

        Retorna lista de cve_ids onde exploit ativo é provável.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

        # CVEs publicados na janela
        recent_cves: set[str] = set()
        for t in threats:
            cve = t.get("cve_id")
            ref_date = t.get("reference_date")
            if cve and ref_date:
                if isinstance(ref_date, str):
                    ref_date = datetime.fromisoformat(ref_date.replace("Z", "+00:00"))
                if ref_date >= cutoff:
                    recent_cves.add(cve)

        # CVEs mencionados nos IOCs
        ioc_mentioned_cves: set[str] = set()
        for ioc in iocs:
            desc = ioc.get("description", "") + " ".join(ioc.get("tags", []))
            for cve in _CVE_RE.findall(desc):
                ioc_mentioned_cves.add(cve.upper())

        exploited = list(recent_cves & ioc_mentioned_cves)
        if exploited:
            logger.warning(
                "ThreatAnalyzer: %d CVEs com possível exploit ativo: %s",
                len(exploited), exploited,
            )
        return exploited

    def correlate_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        context_threats: list[dict],
        context_iocs: list[dict] | None = None,
    ) -> IocCorrelationResult:
        """
        Correlaciona um IOC com ameaças e outros IOCs conhecidos.
        """
        linked_threats: list[str] = []
        malware_families: list[str] = []
        threat_actors: list[str] = []
        geo_targets: set[str] = set()

        ioc_lower = ioc_value.lower()

        for threat in context_threats:
            desc = (threat.get("description") or "").lower()
            refs = " ".join(threat.get("references", [])).lower()
            if ioc_lower in desc or ioc_lower in refs:
                linked_threats.append(threat.get("cve_id") or threat.get("external_id", ""))
            if mf := threat.get("malware_family"):
                malware_families.append(mf)
            if actor := threat.get("threat_actor"):
                threat_actors.append(actor)
            geo_targets.update(threat.get("geo_relevance", []))

        # Confidence: sobe com número de ameaças vinculadas
        confidence = min(0.5 + len(linked_threats) * 0.1, 0.95)

        return IocCorrelationResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            confidence=confidence,
            linked_threats=list(set(linked_threats))[:10],
            malware_families=list(set(malware_families))[:5],
            threat_actors=list(set(threat_actors))[:5],
            geo_targets=list(geo_targets),
        )

    def compute_threat_landscape(
        self, threats: list[dict], window_days: int = 30
    ) -> dict:
        """
        Sumariza o panorama de ameaças para o período.

        Returns dict com: top_techniques, top_attack_vectors,
        severity_distribution, critical_product_exposure.
        """
        technique_counter: Counter = Counter()
        vector_counter:    Counter = Counter()
        severity_dist:     Counter = Counter()
        product_exposure:  Counter = Counter()

        for t in threats:
            for tech in t.get("mitre_techniques", []):
                technique_counter[tech] += 1
            av = t.get("attack_vector", "UNKNOWN")
            vector_counter[av] += 1
            severity_dist[t.get("severity", "INFO")] += 1
            for prod in t.get("affected_products", [])[:5]:
                for keyword in _CRITICAL_PRODUCT_KEYWORDS:
                    if keyword in prod.lower():
                        product_exposure[keyword] += 1

        return {
            "window_days": window_days,
            "total_threats": len(threats),
            "top_mitre_techniques": technique_counter.most_common(10),
            "attack_vector_distribution": dict(vector_counter),
            "severity_distribution": dict(severity_dist),
            "critical_product_exposure": product_exposure.most_common(10),
        }

    # ── Métodos auxiliares ───────────────────────────────────────────────────

    def _compute_recency(self, ref_date: datetime | None) -> float:
        if not ref_date:
            return 0.5
        if ref_date.tzinfo is None:
            ref_date = ref_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - ref_date).days
        if age_days <= 1:
            return 1.0
        if age_days <= 7:
            return 0.8
        if age_days <= 30:
            return 0.5
        if age_days <= 90:
            return 0.3
        return 0.1

    def _find_critical_products(
        self, products: list, description: str
    ) -> list[str]:
        found: list[str] = []
        combined = " ".join(str(p) for p in products).lower() + " " + description.lower()
        for keyword in _CRITICAL_PRODUCT_KEYWORDS:
            if keyword in combined:
                found.append(keyword)
        return list(set(found))

    def _find_ioc_matches(
        self,
        description: str,
        references: list[str],
        known_iocs: list[dict],
    ) -> list[str]:
        combined = (description + " " + " ".join(references)).lower()
        matched: list[str] = []
        for ioc in known_iocs:
            value = str(ioc.get("ioc_value", "")).lower()
            if value and len(value) > 4 and value in combined:
                matched.append(value)
        return matched[:10]

    def _generate_mitigations(
        self,
        techniques: list[str],
        attack_vector: str,
        cvss_score: float,
    ) -> list[str]:
        hints: list[str] = []

        if attack_vector == "NETWORK":
            hints.append("Aplicar regras de firewall para bloquear acesso externo ao serviço afetado.")
        if "T1190" in techniques:
            hints.append("Aplicar patch imediatamente — exploração remota de aplicação pública.")
        if "T1078" in techniques:
            hints.append("Revisar contas privilegiadas; ativar MFA; rotacionar credenciais.")
        if "T1059" in techniques:
            hints.append("Restringir execução de scripts; monitorar PowerShell/bash com SIEM.")
        if "T1068" in techniques:
            hints.append("Aplicar princípio de menor privilégio; verificar sudo/SUID configs.")
        if "T1600" in techniques:
            hints.append("Migrar para suítes criptográficas pós-quânticas (Kyber768+X25519).")
        if "T1499" in techniques:
            hints.append("Configurar rate limiting e proteção DDoS na camada de aplicação.")
        if cvss_score >= 9.0:
            hints.insert(0, "CRÍTICO: Isolar sistema afetado e aplicar patch de emergência.")
        if not hints:
            hints.append("Monitorar logs; aplicar patch do fornecedor assim que disponível.")
        return hints[:5]

    def _score_to_severity(self, score: float) -> str:
        if score >= 0.8:
            return "CRITICAL"
        if score >= 0.6:
            return "HIGH"
        if score >= 0.35:
            return "MEDIUM"
        if score >= 0.1:
            return "LOW"
        return "INFO"

    def _score_to_priority(self, score: float) -> str:
        if score >= 0.8:
            return "IMMEDIATE"
        if score >= 0.6:
            return "HIGH"
        if score >= 0.35:
            return "MEDIUM"
        return "LOW"
