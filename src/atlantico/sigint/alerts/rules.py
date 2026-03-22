"""Regras de geração de alertas SIGINT — padrão idêntico ao geoint/alerts/rules.py."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class AlertRule:
    rule_id: str
    name: str
    severity_mapping: dict[str, str]
    title_template: str
    description_template: str

    def map_severity(self, event_severity: str) -> str:
        return self.severity_mapping.get(event_severity, event_severity)

    def format_title(self, **kwargs) -> str:
        try:
            return self.title_template.format(**kwargs)
        except KeyError:
            return self.title_template

    def format_description(self, **kwargs) -> str:
        try:
            return self.description_template.format(**kwargs)
        except KeyError:
            return self.description_template


_PASSTHROUGH = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO"}
_ESCALATE    = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL", "INFO": "LOW"}

RULE_CVE_CRITICAL = AlertRule(
    rule_id="sigint.cve.critical.v1",
    name="CVE Crítico com exploit ativo",
    severity_mapping=_PASSTHROUGH,
    title_template="CVE CRÍTICO detectado: {cve_id} (CVSS {cvss_score:.1f}) — {attack_vector}",
    description_template=(
        "Vulnerabilidade {cve_id} publicada em {reference_date}. "
        "CVSS: {cvss_score:.1f} ({cvss_vector}). "
        "Vetor de ataque: {attack_vector}. "
        "Técnicas MITRE: {mitre_techniques}. "
        "Produtos afetados: {affected_products}. "
        "Prioridade recomendada: {recommended_priority}."
    ),
)

RULE_CVE_EXPLOIT_ACTIVE = AlertRule(
    rule_id="sigint.cve.exploit_active.v1",
    name="CVE com IOC ativo — exploit em andamento",
    severity_mapping=_ESCALATE,
    title_template="EXPLOIT ATIVO: {cve_id} correlacionado com {ioc_count} IOC(s)",
    description_template=(
        "CVE {cve_id} (CVSS {cvss_score:.1f}) está sendo explorado ativamente: "
        "{ioc_count} IOC(s) correlacionados com esta vulnerabilidade foram detectados "
        "nos últimos {window_days} dias. "
        "IOCs: {ioc_sample}. "
        "Ação imediata requerida: isolamento e patch."
    ),
)

RULE_IOC_HIGH_CONFIDENCE = AlertRule(
    rule_id="sigint.ioc.high_confidence.v1",
    name="IOC malicioso de alta confiança detectado",
    severity_mapping=_PASSTHROUGH,
    title_template="IOC {ioc_type} malicioso: {ioc_value_short} (confiança: {confidence_pct}%)",
    description_template=(
        "Indicador de comprometimento detectado: [{ioc_type}] {ioc_value}. "
        "Fonte: {source_id}. Confiança: {confidence_pct}%. "
        "Ator ameaça: {threat_actor}. Família de malware: {malware_family}. "
        "Países-alvo: {geo_targets}. "
        "Ação: bloquear imediatamente em firewall e EDR."
    ),
)

RULE_DISINFO_CAMPAIGN = AlertRule(
    rule_id="sigint.narrative.disinfo_campaign.v1",
    name="Campanha de desinformação detectada",
    severity_mapping=_PASSTHROUGH,
    title_template="Campanha de desinformação: '{campaign_name}' — {item_count} artigos em {source_count} fonte(s)",
    description_template=(
        "Campanha narrativa detectada por clustering NLP: '{campaign_name}'. "
        "Tipo: {campaign_type}. Score de desinformação: {disinfo_score_pct}%. "
        "Score de amplificação: {amplification_score_pct}%. "
        "Fontes: {source_count}. Artigos: {item_count}. "
        "Narrativa central: {central_narrative}. "
        "Tópicos-chave: {key_topics}."
    ),
)

RULE_INCIDENT_CRITICAL = AlertRule(
    rule_id="sigint.incident.critical_simulation.v1",
    name="Incidente cibernético crítico — simulação de resposta gerada",
    severity_mapping=_PASSTHROUGH,
    title_template="Incidente {incident_type}: playbook de resposta gerado — {severity}",
    description_template=(
        "Simulação de incidente disparada por {triggered_by}. "
        "Tipo: {incident_type}. Severidade: {severity}. "
        "Sistemas afetados: {affected_systems}. "
        "Tempo de recuperação estimado: {recovery_time}. "
        "Relevância PQC: {pqc_relevance}. "
        "Contramedidas: {countermeasures_count} geradas. "
        "Playbook disponível: {playbook_steps} passos."
    ),
)

RULE_CROSS_MODULE_SIGINT_FININT = AlertRule(
    rule_id="sigint.cross_module.cyber_financial.v1",
    name="Correlação SIGINT+FININT: ataque cibernético com anomalia financeira simultânea",
    severity_mapping=_ESCALATE,
    title_template="CORRELAÇÃO CYBER-FINANCEIRA: {cve_id} + anomalia {finint_type} em {state}",
    description_template=(
        "Correlação detectada: vulnerabilidade {cve_id} explorada simultaneamente "
        "a anomalia financeira {finint_type} em {state}. "
        "Padrão consistente com ataque coordenado (sabotagem + fraude financeira). "
        "Score SIGINT: {sigint_score:.0%}. Score FININT: {finint_score:.0%}. "
        "Ação: acionar CISO + compliance."
    ),
)

ALERT_RULES: dict[str, AlertRule] = {
    "sigint.cve.critical":               RULE_CVE_CRITICAL,
    "sigint.cve.exploit_active":         RULE_CVE_EXPLOIT_ACTIVE,
    "sigint.ioc.high_confidence":        RULE_IOC_HIGH_CONFIDENCE,
    "sigint.narrative.disinfo_campaign": RULE_DISINFO_CAMPAIGN,
    "sigint.incident.critical":          RULE_INCIDENT_CRITICAL,
    "sigint.cross_module.cyber_financial": RULE_CROSS_MODULE_SIGINT_FININT,
}
