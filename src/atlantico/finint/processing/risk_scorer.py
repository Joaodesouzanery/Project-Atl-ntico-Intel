"""
RiskScorer — Cálculo de score de risco FININT com correlação GEOINT.

Fórmula de risco:
  score = 0.4 * anomaly_score + 0.3 * centrality_score + 0.3 * geo_correlation_score

Correlação GEOINT: municípios com desmatamento recente em alta ou muitos focos de
incêndio recebem geo_correlation_score > 0, amplificando o risco de atividades
financeiras suspeitas na região.

Não importa oqs — sem crypto direto neste módulo.
"""

from __future__ import annotations

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Pesos do score composto
_W_ANOMALY = 0.4
_W_CENTRALITY = 0.3
_W_GEO = 0.3


class RiskScorer:
    """
    Calcula scores de risco compostos para entidades e fluxos FININT.

    Pode correlacionar com dados GEOINT via repositórios injetados.
    """

    def compute_entity_risk(
        self,
        anomaly_score: float,
        centrality_score: float,
        geo_correlation_score: float,
    ) -> float:
        """
        Calcula score de risco composto para uma entidade.

        Args:
            anomaly_score:         Score de anomalia financeira [0, 1]
            centrality_score:      PageRank normalizado [0, 1]
            geo_correlation_score: Correlação com eventos GEOINT [0, 1]

        Returns:
            Score [0, 1] — quanto maior, maior o risco.
        """
        # Normaliza PageRank para [0, 1] — PageRank típico é muito pequeno
        centrality_normalized = min(centrality_score * 100.0, 1.0)

        score = (
            _W_ANOMALY * _clamp(anomaly_score)
            + _W_CENTRALITY * _clamp(centrality_normalized)
            + _W_GEO * _clamp(geo_correlation_score)
        )
        return _clamp(score)

    def correlate_with_geoint(
        self,
        municipality_code: str,
        since: datetime,
        until: datetime,
        deforestation_ha: float = 0.0,
        hotspot_count: int = 0,
    ) -> dict:
        """
        Calcula score de correlação com dados GEOINT.

        Em produção, estes valores são buscados dos repositórios GEOINT.
        Para uso em testes unitários, aceita valores pré-calculados.

        Args:
            municipality_code: Código IBGE 7 dígitos
            since / until:     Janela temporal
            deforestation_ha:  Área total desmatada no município no período
            hotspot_count:     Número de focos de calor no município no período

        Returns:
            dict com deforestation_ha, hotspot_count, correlation_score [0, 1]
        """
        # Score de correlação: função de desmatamento + focos
        # Desmatamento: 0-10 ha → 0.1, 10-100 ha → 0.3, 100-500 ha → 0.6, >500 ha → 1.0
        if deforestation_ha > 500:
            defor_score = 1.0
        elif deforestation_ha > 100:
            defor_score = 0.6
        elif deforestation_ha > 10:
            defor_score = 0.3
        elif deforestation_ha > 0:
            defor_score = 0.1
        else:
            defor_score = 0.0

        # Focos: 0-5 → 0.1, 5-20 → 0.3, >20 → 0.5 (cap)
        if hotspot_count > 20:
            fire_score = 0.5
        elif hotspot_count > 5:
            fire_score = 0.3
        elif hotspot_count > 0:
            fire_score = 0.1
        else:
            fire_score = 0.0

        # Combinação linear (cap em 1.0)
        correlation_score = _clamp(defor_score * 0.7 + fire_score * 0.3)

        return {
            "municipality_code": municipality_code,
            "deforestation_ha": deforestation_ha,
            "hotspot_count": hotspot_count,
            "correlation_score": correlation_score,
        }

    def score_trade_flow(
        self,
        ncm_code: str,
        export_value_usd: float,
        historical_mean_usd: float,
        historical_stddev_usd: float,
        geo_correlation_score: float = 0.0,
        multiplier: float = 3.0,
    ) -> float:
        """
        Calcula score de risco para fluxo de comércio exterior.

        Exportação de ouro (7108) com alto geo_correlation → score máximo.
        """
        # NCMs mais sensíveis (ouro, pedras preciosas)
        HIGH_RISK_NCMS = {"7108", "7101", "7102"}
        ncm_multiplier = 1.5 if ncm_code in HIGH_RISK_NCMS else 1.0

        # Spike score
        if historical_stddev_usd <= 0:
            spike_score = 0.0
        else:
            z = (export_value_usd - historical_mean_usd) / historical_stddev_usd
            spike_score = _clamp(max(z - multiplier, 0) / multiplier)

        # Score composto: spike + correlação GEOINT
        base_score = _clamp(
            spike_score * 0.6 + _clamp(geo_correlation_score) * 0.4
        )
        return _clamp(base_score * ncm_multiplier)

    def classify_risk_level(self, score: float) -> str:
        """Classifica score [0,1] em nível de risco legível."""
        if score >= 0.8:
            return "CRITICAL"
        if score >= 0.6:
            return "HIGH"
        if score >= 0.4:
            return "MEDIUM"
        return "LOW"

    def determine_flags(
        self,
        score: float,
        anomaly_types: list[str],
        geo_correlation_score: float,
    ) -> list[str]:
        """Determina flags de risco para uma entidade com base nos sinais."""
        flags: list[str] = []
        if geo_correlation_score > 0.5:
            flags.append("garimpo_ilegal")
        if "supplier_concentration" in anomaly_types:
            flags.append("conta_laranja")
        if "spike_up" in anomaly_types and score > 0.7:
            flags.append("lavagem_dinheiro")
        if "isolation_forest" in anomaly_types:
            flags.append("comportamento_atipico")
        return flags


def _clamp(value: float) -> float:
    """Garante que o valor está em [0, 1]."""
    return max(0.0, min(1.0, float(value)))
