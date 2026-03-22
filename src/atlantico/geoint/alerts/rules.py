"""
Regras de geração de alertas GEOINT.

Define AlertRule dataclasses com templates de título e descrição,
e o mapa ALERT_RULES com as regras de negócio do sistema.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlertRule:
    """
    Regra de alerta GEOINT.

    rule_id:           Identificador único e versionado da regra
    name:              Nome legível da regra
    severity_mapping:  Mapeia severity do evento → severity do alerta
                       Permite escalação (ex: LOW evento → MEDIUM alerta)
    title_template:    Template Python .format() para título do alerta
    description_template: Template Python .format() para descrição
    """

    rule_id: str
    name: str
    severity_mapping: dict[str, str]
    title_template: str
    description_template: str

    def map_severity(self, event_severity: str) -> str:
        """Retorna severity do alerta para um dado severity de evento."""
        return self.severity_mapping.get(event_severity, event_severity)

    def format_title(self, **kwargs) -> str:
        """Formata o título do alerta com os valores fornecidos."""
        try:
            return self.title_template.format(**kwargs)
        except KeyError:
            return self.title_template

    def format_description(self, **kwargs) -> str:
        """Formata a descrição do alerta com os valores fornecidos."""
        try:
            return self.description_template.format(**kwargs)
        except KeyError:
            return self.description_template


# ─── Regras de Desmatamento ────────────────────────────────────────────────────

_DEFORESTATION_SEVERITY_MAP = {
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}

RULE_DEFORESTATION_THRESHOLD = AlertRule(
    rule_id="geoint.deforestation.threshold.v1",
    name="Desmatamento acima do limiar mínimo",
    severity_mapping=_DEFORESTATION_SEVERITY_MAP,
    title_template="Desmatamento detectado: {area_ha:.1f} ha em {state} ({biome})",
    description_template=(
        "Evento de desmatamento detectado em {municipality}/{state}. "
        "Área: {area_ha:.1f} ha. Bioma: {biome}. "
        "Fonte: {source_type} (adquirido em {acquired_at}). "
        "Classificação INPE: {classname}. "
        "Tendência histórica: {trend_description}."
    ),
)

RULE_DEFORESTATION_NEAR_INFRASTRUCTURE = AlertRule(
    rule_id="geoint.deforestation.near_infrastructure.v1",
    name="Desmatamento próximo a infraestrutura crítica",
    severity_mapping={
        "LOW": "MEDIUM",
        "MEDIUM": "HIGH",
        "HIGH": "CRITICAL",
        "CRITICAL": "CRITICAL",
    },
    title_template="Desmatamento {area_ha:.1f} ha a {distance_km:.1f} km de {asset_name}",
    description_template=(
        "Evento de desmatamento em {municipality}/{state} detectado a "
        "{distance_km:.1f} km de {asset_name} ({asset_type}). "
        "Criticidade do ativo: {asset_criticality}. "
        "Área: {area_ha:.1f} ha no bioma {biome}."
    ),
)


# ─── Regras de Incêndio ────────────────────────────────────────────────────────

_FIRE_SEVERITY_MAP = {
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}

RULE_FIRE_CLUSTER_LARGE = AlertRule(
    rule_id="geoint.fire.cluster_large.v1",
    name="Cluster de incêndio de grande porte",
    severity_mapping=_FIRE_SEVERITY_MAP,
    title_template="Cluster de {hotspot_count} focos em {state} — FRP total: {total_frp_mw:.0f} MW",
    description_template=(
        "Cluster DBSCAN de {hotspot_count} focos de incêndio detectado em {state}/{biome}. "
        "FRP total: {total_frp_mw:.0f} MW (máx: {max_frp_mw:.0f} MW, médio: {mean_frp_mw:.1f} MW). "
        "Período de atividade: {min_acquired_at} a {max_acquired_at}."
    ),
)

RULE_FIRE_NEAR_INFRASTRUCTURE = AlertRule(
    rule_id="geoint.fire.near_infrastructure.v1",
    name="Incêndio próximo a infraestrutura crítica",
    severity_mapping={
        "LOW": "MEDIUM",
        "MEDIUM": "HIGH",
        "HIGH": "CRITICAL",
        "CRITICAL": "CRITICAL",
    },
    title_template="Focos de incêndio a {distance_km:.1f} km de {asset_type} em {state}",
    description_template=(
        "Cluster de {hotspot_count} focos de calor detectado a {distance_km:.1f} km de {asset_name}. "
        "Criticidade do ativo: {asset_criticality}. "
        "FRP total do cluster: {total_frp_mw:.0f} MW. "
        "Estado: {state}, Bioma: {biome}."
    ),
)


# ─── Regras de Recursos Hídricos ──────────────────────────────────────────────

RULE_WATER_ANOMALY = AlertRule(
    rule_id="geoint.water.anomaly.v1",
    name="Anomalia hídrica detectada",
    severity_mapping={
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    },
    title_template="Anomalia hídrica {anomaly_type} — Estação {station_name} ({station_code})",
    description_template=(
        "Estação {station_code} ({station_name}) detectou anomalia {anomaly_type}. "
        "Valor observado: {value:.2f} {unit}. "
        "Z-score: {z_score:.2f} σ (threshold: {threshold:.1f} σ). "
        "Referência histórica: {historical_mean:.2f} ± {historical_stddev:.2f} {unit}."
    ),
)

RULE_WATER_RAPID_CHANGE = AlertRule(
    rule_id="geoint.water.rapid_change.v1",
    name="Variação rápida de nível hídrico",
    severity_mapping={
        "MEDIUM": "HIGH",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    },
    title_template="Variação rápida em {station_name}: {change_pct:.1f}%/h",
    description_template=(
        "Estação {station_code} ({station_name}) apresentou variação rápida de "
        "{measurement_type}: {change_pct:.1f}% por hora nos últimos {window_hours}h. "
        "Pode indicar cheia relâmpago ou ruptura de barragem."
    ),
)


# ─── Mapa de Regras ────────────────────────────────────────────────────────────

ALERT_RULES: dict[str, AlertRule] = {
    "geoint.deforestation.threshold": RULE_DEFORESTATION_THRESHOLD,
    "geoint.deforestation.near_infrastructure": RULE_DEFORESTATION_NEAR_INFRASTRUCTURE,
    "geoint.fire.cluster_large": RULE_FIRE_CLUSTER_LARGE,
    "geoint.fire.near_infrastructure": RULE_FIRE_NEAR_INFRASTRUCTURE,
    "geoint.water.anomaly": RULE_WATER_ANOMALY,
    "geoint.water.rapid_change": RULE_WATER_RAPID_CHANGE,
}
