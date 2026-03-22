"""
IncidentSimulator — Simulação de resposta a incidentes cibernéticos.

Baseado em dados públicos de incidentes e no framework MITRE ATT&CK,
gera playbooks de resposta, estima impacto e propõe contramedidas automáticas.

Não requer acesso externo — opera inteiramente sobre os dados já coletados
pelos conectores SIGINT e analisados pelo ThreatAnalyzer.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class IncidentPhase(str, Enum):
    """Fases do ciclo de vida de um incidente (NIST SP 800-61)."""
    PREPARATION    = "preparation"
    IDENTIFICATION = "identification"
    CONTAINMENT    = "containment"
    ERADICATION    = "eradication"
    RECOVERY       = "recovery"
    LESSONS_LEARNED = "lessons_learned"


@dataclass
class PlaybookStep:
    """Passo de um playbook de resposta a incidentes."""
    step_number:   int
    phase:         IncidentPhase
    action:        str
    responsible:   str           # "SOC" | "CISO" | "IR_TEAM" | "SYS_ADMIN" | "LEGAL"
    priority:      str           # "IMMEDIATE" | "HIGH" | "MEDIUM" | "LOW"
    estimated_time: str          # ex: "15min", "2h", "24h"
    tools:         list[str]     # ferramentas a usar
    success_criteria: str


@dataclass
class IncidentSimulationResult:
    """Resultado completo de uma simulação de incidente."""
    simulation_id:     str
    incident_type:     str
    triggered_by:      str                  # cve_id ou threat_id
    severity:          str
    estimated_impact:  dict[str, str]       # area → impacto estimado
    affected_systems:  list[str]
    attack_chain:      list[str]            # técnicas MITRE em ordem prováve
    playbook:          list[PlaybookStep]
    countermeasures:   list[str]
    recovery_time_estimate: str
    pqc_relevance:     str | None           # relevância para criptografia PQC
    generated_at:      datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ─── Dados estáticos: MITRE ATT&CK → Tácticas e contramedidas ──────────────────

_MITRE_TACTICS: dict[str, str] = {
    "T1059": "Execution", "T1078": "Initial Access / Persistence",
    "T1190": "Initial Access", "T1203": "Execution",
    "T1068": "Privilege Escalation", "T1499": "Impact",
    "T1600": "Defense Evasion", "T1083": "Discovery",
    "T1090": "Command and Control", "T1566": "Initial Access (Phishing)",
    "T1486": "Impact (Ransomware)", "T1071": "Command and Control",
    "T1055": "Defense Evasion (Injection)", "T1021": "Lateral Movement",
    "T1040": "Credential Access (Sniffing)",
}

_TECHNIQUE_COUNTERMEASURES: dict[str, list[str]] = {
    "T1059": [
        "Implementar Application Allowlisting",
        "Configurar PowerShell Constrained Language Mode",
        "Monitorar execução de scripts via SIEM (Splunk/Elastic)",
    ],
    "T1078": [
        "Ativar MFA em todas as contas privilegiadas",
        "Implementar PAM (Privileged Access Management)",
        "Auditar logins anômalos (horário/geo incomum)",
    ],
    "T1190": [
        "Aplicar patch do fornecedor imediatamente",
        "Configurar WAF com regras atualizadas",
        "Isolar serviço afetado até aplicação do patch",
    ],
    "T1068": [
        "Aplicar princípio de menor privilégio",
        "Revisar configurações SUID/SGID (Linux)",
        "Monitorar escalação de privilégios via auditd",
    ],
    "T1499": [
        "Ativar proteção DDoS (Cloudflare/Akamai)",
        "Configurar rate limiting na camada de aplicação",
        "Ativar modo de contingência para serviços críticos",
    ],
    "T1600": [
        "Migrar para suítes PQC (Kyber768+X25519, Dilithium3+Ed25519)",
        "Auditar configurações TLS (desabilitar TLS 1.0/1.1)",
        "Implementar certificate pinning em aplicações críticas",
    ],
    "T1486": [  # Ransomware
        "Isolar sistemas afetados da rede imediatamente",
        "Ativar backups offline e verificar integridade",
        "Notificar CERT.br e autoridades competentes",
        "NÃO pagar resgate sem consultar especialistas e autoridades",
    ],
    "T1566": [  # Phishing
        "Bloquear domínios de phishing detectados (IOC)",
        "Treinar usuários sobre reconhecimento de phishing",
        "Ativar DMARC/DKIM/SPF anti-spoofing",
    ],
}

_INCIDENT_TYPE_SYSTEMS: dict[str, list[str]] = {
    "ransomware":    ["file_servers", "databases", "backup_systems", "email"],
    "apt":           ["email", "vpn", "workstations", "internal_apps", "databases"],
    "data_breach":   ["databases", "file_servers", "cloud_storage", "email"],
    "ddos":          ["web_servers", "dns", "load_balancers", "cdn"],
    "phishing":      ["email", "workstations", "identity_provider"],
    "supply_chain":  ["ci_cd", "package_registry", "dev_workstations", "prod_servers"],
    "crypto_attack": ["hsm", "key_management", "tls_termination", "certificate_store"],
    "default":       ["workstations", "servers", "network_devices"],
}


class IncidentSimulator:
    """
    Simula resposta a incidentes cibernéticos a partir de dados SIGINT.

    Uso:
        simulator = IncidentSimulator()
        result = simulator.simulate(threat_payload, mitre_techniques)
        playbook = result.playbook
    """

    def simulate(
        self,
        threat_payload: dict,
        mitre_techniques: list[str],
        contextual_score: float = 0.5,
    ) -> IncidentSimulationResult:
        """
        Gera simulação de incidente baseada na ameaça analisada.

        Args:
            threat_payload:   Payload bruto da SigintObservation/ThreatAnalysisResult
            mitre_techniques: Lista de técnicas MITRE ATT&CK
            contextual_score: Score contextual do ThreatAnalyzer [0,1]
        """
        cve_id       = threat_payload.get("cve_id") or threat_payload.get("external_id", "unknown")
        description  = threat_payload.get("description", "").lower()
        cvss_score   = float(threat_payload.get("cvss_score") or 0.0)

        # Inferir tipo de incidente
        incident_type = self._infer_incident_type(description, mitre_techniques)
        severity      = self._score_to_severity(contextual_score, cvss_score)

        # Sistemas afetados
        affected_systems = _INCIDENT_TYPE_SYSTEMS.get(
            incident_type, _INCIDENT_TYPE_SYSTEMS["default"]
        )

        # Cadeia de ataque (kill chain baseado em técnicas)
        attack_chain = self._build_attack_chain(mitre_techniques)

        # Impacto estimado
        estimated_impact = self._estimate_impact(incident_type, severity, affected_systems)

        # Playbook de resposta
        playbook = self._generate_playbook(incident_type, mitre_techniques, severity)

        # Contramedidas específicas
        countermeasures = self._compile_countermeasures(mitre_techniques)

        # Tempo de recuperação estimado
        recovery_time = self._estimate_recovery_time(incident_type, severity)

        # Relevância PQC
        pqc_relevance = self._assess_pqc_relevance(description, mitre_techniques)

        return IncidentSimulationResult(
            simulation_id=str(uuid.uuid4()),
            incident_type=incident_type,
            triggered_by=cve_id,
            severity=severity,
            estimated_impact=estimated_impact,
            affected_systems=affected_systems,
            attack_chain=attack_chain,
            playbook=playbook,
            countermeasures=countermeasures,
            recovery_time_estimate=recovery_time,
            pqc_relevance=pqc_relevance,
        )

    def simulate_ransomware_scenario(
        self,
        organization_name: str = "Organização-Alvo",
        entry_vector: str = "phishing",
    ) -> IncidentSimulationResult:
        """
        Cenário pré-configurado: ataque de ransomware (mais comum no BR).
        Útil para exercícios de tabletop e treinamentos.
        """
        payload = {
            "cve_id": "RANSOMWARE-SCENARIO",
            "description": f"ransomware attack via {entry_vector} against {organization_name}",
            "cvss_score": 9.1,
        }
        techniques = ["T1566", "T1059", "T1078", "T1486", "T1083"]
        return self.simulate(payload, techniques, contextual_score=0.9)

    def simulate_apt_scenario(
        self,
        target_sector: str = "governo",
    ) -> IncidentSimulationResult:
        """Cenário pré-configurado: APT espionagem (relevante para Atlântico)."""
        payload = {
            "cve_id": "APT-SCENARIO",
            "description": f"advanced persistent threat targeting {target_sector} sector",
            "cvss_score": 8.5,
        }
        techniques = ["T1190", "T1078", "T1055", "T1021", "T1040", "T1071"]
        return self.simulate(payload, techniques, contextual_score=0.85)

    # ── Helpers ──────────────────────────────────────────────────────────────────

    def _infer_incident_type(self, description: str, techniques: list[str]) -> str:
        if "T1486" in techniques or "ransomware" in description:
            return "ransomware"
        if "T1600" in techniques or "cryptograph" in description or "pqc" in description:
            return "crypto_attack"
        if "T1499" in techniques or "denial of service" in description:
            return "ddos"
        if "T1566" in techniques or "phishing" in description:
            return "phishing"
        if "supply chain" in description or "ci/cd" in description:
            return "supply_chain"
        if "apt" in description or "espion" in description or "T1021" in techniques:
            return "apt"
        if "breach" in description or "leak" in description or "vazamento" in description:
            return "data_breach"
        return "default"

    def _build_attack_chain(self, techniques: list[str]) -> list[str]:
        order = ["T1566", "T1190", "T1078", "T1059", "T1203", "T1068",
                 "T1055", "T1040", "T1021", "T1083", "T1071", "T1486",
                 "T1499", "T1600"]
        ordered = [t for t in order if t in techniques]
        remaining = [t for t in techniques if t not in ordered]
        chain = ordered + remaining
        return [
            f"{t} — {_MITRE_TACTICS.get(t, 'Unknown Tactic')}" for t in chain[:8]
        ]

    def _estimate_impact(
        self, incident_type: str, severity: str, systems: list[str]
    ) -> dict[str, str]:
        sev_multiplier = {
            "CRITICAL": "Alto", "HIGH": "Moderado-Alto",
            "MEDIUM": "Moderado", "LOW": "Baixo",
        }.get(severity, "Indefinido")

        impact = {
            "confidentiality": sev_multiplier,
            "integrity":       sev_multiplier if incident_type not in ("ddos",) else "Baixo",
            "availability":    "Alto" if incident_type in ("ransomware", "ddos") else sev_multiplier,
            "financial":       "Alto" if severity in ("CRITICAL", "HIGH") else "Moderado",
            "reputational":    "Alto" if incident_type in ("data_breach", "ransomware") else "Moderado",
        }
        if "databases" in systems:
            impact["data_exposure"] = "Alto risco de vazamento de dados sensíveis"
        return impact

    def _generate_playbook(
        self, incident_type: str, techniques: list[str], severity: str
    ) -> list[PlaybookStep]:
        steps: list[PlaybookStep] = []
        n = 1

        # 1. Identificação imediata
        steps.append(PlaybookStep(
            step_number=n, phase=IncidentPhase.IDENTIFICATION,
            action=f"Confirmar e caracterizar o incidente ({incident_type}). Documentar hora, sistemas afetados e vetor inicial.",
            responsible="SOC", priority="IMMEDIATE", estimated_time="15min",
            tools=["SIEM", "EDR", "NetFlow"],
            success_criteria="Incidente confirmado e classificado com severidade definida.",
        ))
        n += 1

        # 2. Notificação
        steps.append(PlaybookStep(
            step_number=n, phase=IncidentPhase.IDENTIFICATION,
            action="Notificar CISO, liderança técnica e, se necessário, DPO (LGPD) e CERT.br.",
            responsible="SOC", priority="IMMEDIATE" if severity == "CRITICAL" else "HIGH",
            estimated_time="30min",
            tools=["Email", "Slack-seguro", "Telefone"],
            success_criteria="Stakeholders notificados; canal de comunicação de crise ativo.",
        ))
        n += 1

        # 3. Contenção
        if incident_type in ("ransomware", "apt", "data_breach"):
            steps.append(PlaybookStep(
                step_number=n, phase=IncidentPhase.CONTAINMENT,
                action="Isolar sistemas afetados da rede (VLAN quarantine ou desconexão física). Preservar evidências forenses.",
                responsible="SYS_ADMIN", priority="IMMEDIATE",
                estimated_time="1h",
                tools=["Firewall", "NAC", "VLAN management"],
                success_criteria="Sistemas isolados; propagação lateral bloqueada.",
            ))
            n += 1

        # 4. Coleta de evidências
        steps.append(PlaybookStep(
            step_number=n, phase=IncidentPhase.CONTAINMENT,
            action="Coletar logs, dumps de memória e artefatos forenses. NÃO reiniciar sistemas antes da coleta.",
            responsible="IR_TEAM", priority="HIGH",
            estimated_time="2h",
            tools=["Volatility", "Autopsy", "Wireshark", "auditd"],
            success_criteria="Evidências coletadas e preservadas em local seguro (chain of custody).",
        ))
        n += 1

        # 5. IOC Blocking
        steps.append(PlaybookStep(
            step_number=n, phase=IncidentPhase.CONTAINMENT,
            action="Bloquear IOCs identificados (IPs, domínios, hashes) em firewall, DNS e EDR.",
            responsible="SOC", priority="HIGH",
            estimated_time="1h",
            tools=["Firewall", "DNS sinkhole", "EDR blocklist"],
            success_criteria="IOCs bloqueados; tráfego C2 interrompido.",
        ))
        n += 1

        # 6. Erradicação
        steps.append(PlaybookStep(
            step_number=n, phase=IncidentPhase.ERADICATION,
            action="Remover malware/backdoors. Aplicar patches para CVEs explorados. Revogar credenciais comprometidas.",
            responsible="IR_TEAM", priority="HIGH",
            estimated_time="4-8h",
            tools=["EDR", "patch management", "IAM"],
            success_criteria="Todos os artefatos maliciosos removidos; credenciais rotacionadas.",
        ))
        n += 1

        # 7. Recuperação
        steps.append(PlaybookStep(
            step_number=n, phase=IncidentPhase.RECOVERY,
            action="Restaurar sistemas a partir de backups limpos. Validar integridade antes de reconectar à rede.",
            responsible="SYS_ADMIN", priority="HIGH",
            estimated_time="4-24h",
            tools=["Backup system", "Integrity checker", "AV scanner"],
            success_criteria="Sistemas restaurados e validados; serviços operacionais.",
        ))
        n += 1

        # 8. Lições aprendidas
        steps.append(PlaybookStep(
            step_number=n, phase=IncidentPhase.LESSONS_LEARNED,
            action="Conduzir post-mortem 72h após contenção. Documentar timeline, causas-raiz e melhorias.",
            responsible="CISO", priority="MEDIUM",
            estimated_time="1-3 dias",
            tools=["Jira", "Confluence", "relatório CERT.br"],
            success_criteria="Relatório de incidente entregue; plano de melhoria aprovado.",
        ))

        return steps

    def _compile_countermeasures(self, techniques: list[str]) -> list[str]:
        measures: list[str] = []
        seen: set[str] = set()
        for tech in techniques:
            for measure in _TECHNIQUE_COUNTERMEASURES.get(tech, []):
                if measure not in seen:
                    measures.append(measure)
                    seen.add(measure)
        if not measures:
            measures = [
                "Monitorar logs do sistema com SIEM",
                "Aplicar patches de segurança pendentes",
                "Revisar regras de firewall e ACLs",
            ]
        return measures[:10]

    def _estimate_recovery_time(self, incident_type: str, severity: str) -> str:
        rto_map = {
            ("ransomware", "CRITICAL"): "3-7 dias",
            ("ransomware", "HIGH"):     "1-3 dias",
            ("apt",        "CRITICAL"): "7-30 dias (investigação forense)",
            ("apt",        "HIGH"):     "3-7 dias",
            ("data_breach","CRITICAL"): "7-14 dias",
            ("ddos",       "CRITICAL"): "2-8 horas",
            ("ddos",       "HIGH"):     "1-4 horas",
            ("phishing",   "HIGH"):     "4-8 horas",
            ("crypto_attack","CRITICAL"): "14-60 dias (migração PQC)",
        }
        return rto_map.get((incident_type, severity), "1-5 dias úteis")

    def _assess_pqc_relevance(self, description: str, techniques: list[str]) -> str | None:
        desc_lower = description.lower()
        if "T1600" in techniques:
            return (
                "ALTO: Esta ameaça ataca criptografia diretamente. "
                "Migração urgente para Kyber768+X25519 e Dilithium3+Ed25519 via Projeto Atlântico."
            )
        if any(k in desc_lower for k in ["cryptograph", "tls", "ssl", "rsa", "ecc", "quantum"]):
            return (
                "MÉDIO: Risco de colheita de dados cifrados ('harvest now, decrypt later'). "
                "Planejar migração PQC em 6-12 meses."
            )
        return None

    def _score_to_severity(self, score: float, cvss: float) -> str:
        combined = max(score, cvss / 10.0)
        if combined >= 0.9:
            return "CRITICAL"
        if combined >= 0.7:
            return "HIGH"
        if combined >= 0.4:
            return "MEDIUM"
        return "LOW"
