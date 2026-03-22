"""
SigintObservation — DTO compartilhado entre conectores e pipeline de ingestão SIGINT.

Objeto puro Python (sem SQLAlchemy, sem crypto) que normaliza observações
de sinais de inteligência de fontes heterogêneas para uma interface unificada.

Tipos de observação:
    cyber_threat      — Vulnerabilidade CVE, exploit ativo, campanha de malware
    threat_indicator  — IOC: IP, domínio, hash, URL maliciosa
    news_item         — Artigo de notícia, post de blog de segurança, relatório
    tech_trend        — Avanço tecnológico (PQC, IA ofensiva, novo protocolo)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SigintObservation:
    """
    Observação SIGINT bruta retornada por um conector.

    Campos:
        source_id:          Identificador canônico da fonte, ex: "nvd.cve.v2"
        external_id:        ID único do registro na fonte (para deduplication)
        observation_type:   Tipo semântico:
                            "cyber_threat" | "threat_indicator" |
                            "news_item" | "tech_trend"
        reference_date:     Data de publicação/detecção (timezone-aware UTC)
        payload:            Dict com todos os campos brutos da fonte
        data_classification: "PUBLIC" (padrão para dados abertos)
        severity:           Severidade estimada na ingestão:
                            "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
        source_type:        Tipo da fonte: "cve_feed" | "cert_advisory" |
                            "threat_intel" | "news_rss" | "ioc_feed"
        language:           Idioma do conteúdo (ISO 639-1, ex: "pt", "en")
        tags:               Lista de tags para classificação e busca
        geo_relevance:      Países/regiões relevantes para o sinal
                            ex: ["BR", "US", "LATAM"]
    """

    source_id: str
    external_id: str
    observation_type: str
    reference_date: datetime
    payload: dict[str, Any] = field(default_factory=dict)
    data_classification: str = "PUBLIC"
    severity: str = "INFO"
    source_type: str = "unknown"
    language: str = "en"
    tags: list[str] = field(default_factory=list)
    geo_relevance: list[str] = field(default_factory=list)

    _VALID_TYPES = frozenset(
        {"cyber_threat", "threat_indicator", "news_item", "tech_trend"}
    )
    _VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

    def __post_init__(self) -> None:
        if self.reference_date.tzinfo is None:
            raise ValueError(
                f"SigintObservation.reference_date deve ser timezone-aware. "
                f"Recebido: {self.reference_date!r} (sem tzinfo)."
            )
        if self.observation_type not in self._VALID_TYPES:
            raise ValueError(
                f"observation_type inválido: {self.observation_type!r}. "
                f"Valores válidos: {sorted(self._VALID_TYPES)}"
            )
        if self.severity not in self._VALID_SEVERITIES:
            raise ValueError(
                f"severity inválida: {self.severity!r}. "
                f"Valores válidos: {sorted(self._VALID_SEVERITIES)}"
            )
