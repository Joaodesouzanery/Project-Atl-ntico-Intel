"""
Regras de geração de alertas FININT.

Define AlertRule dataclasses com templates de título e descrição,
e o mapa FININT_ALERT_RULES com as regras de negócio FININT.

Reutiliza o mesmo padrão de AlertRule de geoint/alerts/rules.py.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlertRule:
    """
    Regra de alerta FININT.

    rule_id:              Identificador único e versionado da regra
    name:                 Nome legível da regra
    severity_mapping:     Mapeia severity do sinal → severity do alerta
    title_template:       Template Python .format() para título do alerta
    description_template: Template Python .format() para descrição
    """

    rule_id: str
    name: str
    severity_mapping: dict[str, str]
    title_template: str
    description_template: str

    def map_severity(self, signal_severity: str) -> str:
        """Retorna severity do alerta para um dado severity de sinal."""
        return self.severity_mapping.get(signal_severity, signal_severity)

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


# ─── Regra: Anomalia em Indicador de Mercado ──────────────────────────────────

RULE_MARKET_ANOMALY = AlertRule(
    rule_id="finint.market.anomaly.v1",
    name="Anomalia em indicador de mercado",
    severity_mapping={
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    },
    title_template="Anomalia {anomaly_type} detectada: {series_name} (z={z_score:.2f}σ)",
    description_template=(
        "Série temporal '{series_name}' (código {series_code}) apresentou "
        "anomalia do tipo {anomaly_type} em {reference_date}. "
        "Valor observado: {value:.4f} {unit}. "
        "Z-score: {z_score:.2f}σ (threshold: {threshold:.1f}σ). "
        "Fonte: {source_id}."
    ),
)

# ─── Regra: Anomalia em Contratos Públicos ────────────────────────────────────

RULE_CONTRACT_ANOMALY = AlertRule(
    rule_id="finint.contract.anomaly.v1",
    name="Anomalia em contratos públicos",
    severity_mapping={
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    },
    title_template="Contratos anômalos em {state}: volume {total_value:,.0f} BRL ({anomaly_type})",
    description_template=(
        "Anomalia detectada em contratos públicos no estado {state}. "
        "Volume total: R$ {total_value:,.2f}. "
        "Tipo: {anomaly_type}. "
        "Fornecedores únicos: {unique_suppliers}. "
        "Período: {period}."
    ),
)

# ─── Regra: Spike em Exportação de Mineral Estratégico ───────────────────────

RULE_TRADE_MINERAL_SPIKE = AlertRule(
    rule_id="finint.trade.mineral_spike.v1",
    name="Spike em exportação de mineral estratégico",
    severity_mapping={
        "MEDIUM": "HIGH",    # Exportação mineral com anomalia → escalação
        "HIGH": "CRITICAL",
        "CRITICAL": "CRITICAL",
    },
    title_template="Spike de exportação {ncm_desc} ({ncm_code}) em {state}: US$ {value_usd:,.0f}",
    description_template=(
        "Exportação de {ncm_desc} (NCM {ncm_code}) em {state} atingiu US$ {value_usd:,.2f} "
        "em {reference_date} — {z_score:.1f}σ acima da média histórica "
        "(média: US$ {historical_mean:,.2f}, desvio: US$ {historical_stddev:,.2f}). "
        "Score de risco GEOINT: {geo_correlation_score:.2f}."
    ),
)

# ─── Regra: Hub de Rede Financeira Suspeita ───────────────────────────────────

RULE_NETWORK_HUB = AlertRule(
    rule_id="finint.network.hub_detected.v1",
    name="Hub de rede financeira suspeita detectado",
    severity_mapping={
        "MEDIUM": "HIGH",
        "HIGH": "CRITICAL",
        "CRITICAL": "CRITICAL",
    },
    title_template="Hub financeiro suspeito: {entity_id[:8]}... (PageRank={pagerank:.4f})",
    description_template=(
        "Entidade {entity_id} identificada como hub de rede financeira suspeita. "
        "PageRank: {pagerank:.6f}. "
        "Betweenness: {betweenness:.6f}. "
        "Grau de saída: {out_degree}, Grau de entrada: {in_degree}. "
        "Comunidade com {community_size} entidades."
    ),
)

# ─── Regra: Sinal Cruzado GEOINT + FININT (Garimpo) ─────────────────────────

RULE_CROSS_MODULE_GARIMPO = AlertRule(
    rule_id="finint.cross_module.garimpo_signal.v1",
    name="Sinal cruzado GEOINT+FININT: padrão de garimpo ilegal",
    severity_mapping={
        "HIGH": "CRITICAL",     # Sempre CRITICAL — correlação cross-module
        "CRITICAL": "CRITICAL",
        "MEDIUM": "HIGH",
    },
    title_template="[GARIMPO] Correlação desflorestamento + exportação ouro em {state}",
    description_template=(
        "Correlação detectada em {state}: "
        "desmatamento de {deforestation_ha:.1f} ha "
        "({deforestation_period}) coincide com spike de exportação de "
        "{ncm_desc} (NCM {ncm_code}): US$ {export_value_usd:,.2f} "
        "({z_score:.1f}σ acima da média). "
        "Score de correlação GEOINT: {geo_correlation_score:.2f}. "
        "Alerta prioritário — notificar IBAMA/PRF/PGR."
    ),
)


# ─── Mapa de Regras FININT ─────────────────────────────────────────────────────

FININT_ALERT_RULES: dict[str, AlertRule] = {
    "finint.market.anomaly": RULE_MARKET_ANOMALY,
    "finint.contract.anomaly": RULE_CONTRACT_ANOMALY,
    "finint.trade.mineral_spike": RULE_TRADE_MINERAL_SPIKE,
    "finint.network.hub_detected": RULE_NETWORK_HUB,
    "finint.cross_module.garimpo_signal": RULE_CROSS_MODULE_GARIMPO,
}
