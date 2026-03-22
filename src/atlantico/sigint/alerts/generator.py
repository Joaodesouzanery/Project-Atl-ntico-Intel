"""SigintAlertGenerator — gera alertas Dilithium-assinados via AlertRepository."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from atlantico.sigint.alerts.rules import ALERT_RULES, AlertRule
from atlantico.sigint.processing.threat_analyzer import ThreatAnalysisResult
from atlantico.sigint.processing.narrative_analyzer import ClusterResult
from atlantico.sigint.processing.incident_simulator import IncidentSimulationResult

logger = logging.getLogger(__name__)


class SigintAlertGenerator:
    """
    Gera alertas SIGINT e os persiste via AlertRepository (assinatura PQC Dilithium3+Ed25519).

    Injeção de dependências:
        alert_repo:    AlertRepository (src/atlantico/storage/repositories/alert_repo.py)
        audit_log:     AuditLogRepository
    """

    def __init__(self, alert_repo, audit_log) -> None:
        self._alert_repo = alert_repo
        self._audit_log  = audit_log

    async def generate_cve_alert(
        self,
        analysis: ThreatAnalysisResult,
        source_record_ids: list[str],
    ):
        """Alerta para CVE crítico."""
        if analysis.contextual_score < 0.6:
            return None

        rule_key = (
            "sigint.cve.exploit_active" if analysis.exploit_active
            else "sigint.cve.critical"
        )
        rule = ALERT_RULES[rule_key]
        severity = rule.map_severity(analysis.severity)

        title = rule.format_title(
            cve_id=analysis.cve_id or analysis.external_id,
            cvss_score=analysis.base_cvss,
            attack_vector=analysis.attack_vector,
            ioc_count=len(analysis.ioc_correlation),
        )
        description = rule.format_description(
            cve_id=analysis.cve_id or analysis.external_id,
            cvss_score=analysis.base_cvss,
            cvss_vector="N/A",
            attack_vector=analysis.attack_vector,
            mitre_techniques=", ".join(analysis.mitre_techniques[:5]),
            affected_products=", ".join(analysis.critical_products[:3]) or "N/A",
            recommended_priority=analysis.recommended_priority,
            ioc_count=len(analysis.ioc_correlation),
            ioc_sample=", ".join(analysis.ioc_correlation[:3]),
            window_days=7,
            reference_date=datetime.now(timezone.utc).date().isoformat(),
        )

        alert = await self._alert_repo.create(
            alert_id=f"sigint-cve-{uuid.uuid4().hex[:8]}",
            rule_id=rule.rule_id,
            severity=severity,
            title=title,
            description=description,
            source_record_ids=source_record_ids,
            metadata={
                "contextual_score": analysis.contextual_score,
                "exploit_active": analysis.exploit_active,
                "mitre_techniques": analysis.mitre_techniques,
            },
        )
        await self._audit_log.append(
            event_type="sigint.alert.cve_generated",
            entity_id=alert.id if alert else "unknown",
            details={"rule_id": rule.rule_id, "cve_id": analysis.cve_id},
        )
        return alert

    async def generate_disinfo_alert(
        self,
        cluster: ClusterResult,
        campaign_id: str,
        source_record_ids: list[str],
    ):
        """Alerta para campanha de desinformação detectada."""
        if cluster.disinfo_score < 0.4:
            return None

        rule = ALERT_RULES["sigint.narrative.disinfo_campaign"]
        severity = (
            "CRITICAL" if cluster.disinfo_score >= 0.8 else
            "HIGH"     if cluster.disinfo_score >= 0.6 else "MEDIUM"
        )

        title = rule.format_title(
            campaign_name=cluster.central_text[:60],
            item_count=len(cluster.item_ids),
            source_count=cluster.source_count,
        )
        description = rule.format_description(
            campaign_name=cluster.central_text[:100],
            campaign_type="influence_op" if cluster.is_amplification else "disinfo",
            disinfo_score_pct=int(cluster.disinfo_score * 100),
            amplification_score_pct=80 if cluster.is_amplification else 30,
            source_count=cluster.source_count,
            item_count=len(cluster.item_ids),
            central_narrative=cluster.central_text[:200],
            key_topics=", ".join(cluster.key_topics[:5]),
        )

        alert = await self._alert_repo.create(
            alert_id=f"sigint-disinfo-{uuid.uuid4().hex[:8]}",
            rule_id=rule.rule_id,
            severity=severity,
            title=title,
            description=description,
            source_record_ids=source_record_ids,
            metadata={
                "cluster_id": cluster.cluster_id,
                "disinfo_score": cluster.disinfo_score,
                "is_amplification": cluster.is_amplification,
            },
        )
        await self._audit_log.append(
            event_type="sigint.alert.disinfo_generated",
            entity_id=campaign_id,
            details={"cluster_id": cluster.cluster_id, "score": cluster.disinfo_score},
        )
        return alert

    async def generate_incident_alert(
        self,
        simulation: IncidentSimulationResult,
        source_record_ids: list[str],
    ):
        """Alerta para incidente crítico com playbook de resposta gerado."""
        if simulation.severity not in ("CRITICAL", "HIGH"):
            return None

        rule = ALERT_RULES["sigint.incident.critical"]

        title = rule.format_title(
            incident_type=simulation.incident_type,
            severity=simulation.severity,
        )
        description = rule.format_description(
            triggered_by=simulation.triggered_by,
            incident_type=simulation.incident_type,
            severity=simulation.severity,
            affected_systems=", ".join(simulation.affected_systems[:4]),
            recovery_time=simulation.recovery_time_estimate,
            pqc_relevance=simulation.pqc_relevance or "Nenhuma",
            countermeasures_count=len(simulation.countermeasures),
            playbook_steps=len(simulation.playbook),
        )

        alert = await self._alert_repo.create(
            alert_id=f"sigint-incident-{simulation.simulation_id[:8]}",
            rule_id=rule.rule_id,
            severity=simulation.severity,
            title=title,
            description=description,
            source_record_ids=source_record_ids,
            metadata={
                "simulation_id": simulation.simulation_id,
                "incident_type": simulation.incident_type,
                "attack_chain": simulation.attack_chain,
                "countermeasures": simulation.countermeasures,
            },
        )
        await self._audit_log.append(
            event_type="sigint.alert.incident_generated",
            entity_id=simulation.simulation_id,
            details={"incident_type": simulation.incident_type, "severity": simulation.severity},
        )
        return alert

    async def generate_ioc_alert(
        self,
        ioc_type: str,
        ioc_value: str,
        confidence: float,
        severity: str,
        threat_actor: str,
        malware_family: str,
        geo_targets: list[str],
        source_id: str,
        source_record_ids: list[str],
    ):
        """Alerta para IOC malicioso de alta confiança."""
        if confidence < 0.7:
            return None

        rule = ALERT_RULES["sigint.ioc.high_confidence"]
        title = rule.format_title(
            ioc_type=ioc_type,
            ioc_value_short=ioc_value[:40],
            confidence_pct=int(confidence * 100),
        )
        description = rule.format_description(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            source_id=source_id,
            confidence_pct=int(confidence * 100),
            threat_actor=threat_actor or "Desconhecido",
            malware_family=malware_family or "N/A",
            geo_targets=", ".join(geo_targets[:5]) or "GLOBAL",
        )

        return await self._alert_repo.create(
            alert_id=f"sigint-ioc-{uuid.uuid4().hex[:8]}",
            rule_id=rule.rule_id,
            severity=severity,
            title=title,
            description=description,
            source_record_ids=source_record_ids,
            metadata={"ioc_type": ioc_type, "confidence": confidence},
        )
