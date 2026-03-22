"""
InfrastructureProcessor — análise de proximidade e risco para infraestrutura crítica.

Calcula risco composto de eventos geoespaciais (desmatamento, incêndio, anomalia hídrica)
próximos a ativos de infraestrutura crítica.
"""

from __future__ import annotations

import logging
import uuid

from atlantico.geoint.models.infrastructure import InfrastructureAsset

logger = logging.getLogger(__name__)

# Pesos de severity para cálculo de risco composto
_SEVERITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH": 3.0,
    "MEDIUM": 2.0,
    "LOW": 1.0,
}

# Pesos de criticidade de ativo de infraestrutura
_CRITICALITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH": 3.0,
    "MEDIUM": 2.0,
    "LOW": 1.0,
}


class InfrastructureProcessor:
    """
    Algoritmos de análise de proximidade e risco para infraestrutura crítica.

    Stateless — recebe objetos de domínio, não acessa banco de dados.
    A lógica de busca geoespacial fica nos repositórios (ST_DWithin).
    """

    def compute_risk_score(
        self,
        event_severity: str,
        asset_criticality: str,
        distance_km: float,
    ) -> float:
        """
        Calcula score de risco composto para um par (evento, ativo).

        Fórmula: (severity_weight × criticality_weight) / (1 + distance_km)

        Args:
            event_severity:    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            asset_criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            distance_km:       Distância entre evento e ativo em km

        Returns:
            Score de risco [0.0, 16.0] — maior = mais crítico.
            Score 16.0 é CRITICAL × CRITICAL à distância 0.
        """
        sev_weight = _SEVERITY_WEIGHTS.get(event_severity, 1.0)
        crit_weight = _CRITICALITY_WEIGHTS.get(asset_criticality, 1.0)

        if distance_km < 0:
            distance_km = 0.0

        return (sev_weight * crit_weight) / (1.0 + distance_km)

    def prioritize_events_by_risk(
        self,
        event_asset_pairs: list[tuple[str, str, str, float]],
    ) -> list[dict]:
        """
        Ordena pares (evento, ativo) por risk_score decrescente.

        Args:
            event_asset_pairs: Lista de (event_id, event_severity, asset_criticality, distance_km)

        Returns:
            Lista ordenada de dicts com event_id, risk_score, severity, criticality, distance_km
        """
        results = []
        for event_id, event_severity, asset_criticality, distance_km in event_asset_pairs:
            score = self.compute_risk_score(event_severity, asset_criticality, distance_km)
            results.append({
                "event_id": event_id,
                "risk_score": score,
                "event_severity": event_severity,
                "asset_criticality": asset_criticality,
                "distance_km": distance_km,
            })

        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    def should_escalate_alert_severity(
        self,
        base_severity: str,
        nearby_assets: list[InfrastructureAsset],
    ) -> str:
        """
        Escalona severity de alerta quando há ativos críticos próximos.

        Regra: Se há ativo CRITICAL ou HIGH próximo, severity é escalada um nível.

        Args:
            base_severity: Severity base do evento
            nearby_assets: Ativos de infraestrutura próximos

        Returns:
            Severity possivelmente escalada.
        """
        if not nearby_assets:
            return base_severity

        max_criticality = max(
            _CRITICALITY_WEIGHTS.get(a.criticality, 1.0)
            for a in nearby_assets
        )

        _escalation_map = {
            "LOW": "MEDIUM",
            "MEDIUM": "HIGH",
            "HIGH": "CRITICAL",
            "CRITICAL": "CRITICAL",
        }

        if max_criticality >= _CRITICALITY_WEIGHTS["HIGH"]:
            return _escalation_map.get(base_severity, base_severity)

        return base_severity

    def classify_infrastructure_threat(
        self,
        risk_score: float,
    ) -> str:
        """
        Classifica nível de ameaça à infraestrutura pelo risk_score.

        Returns:
            "NEGLIGIBLE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        """
        if risk_score >= 8.0:
            return "CRITICAL"
        if risk_score >= 4.0:
            return "HIGH"
        if risk_score >= 2.0:
            return "MEDIUM"
        if risk_score >= 0.5:
            return "LOW"
        return "NEGLIGIBLE"
