"""EventoRegulatorio — ponto pivô temporal (crise, apagão, recall, surto)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from ._common import require_classification, require_confidence, require_tz

TIPOS_VALIDOS = frozenset(
    {"crise", "apagao", "recall", "acidente", "surto", "incidente_ambiental",
     "falha_servico", "evento_climatico", "ciberataque"}
)
SEVERIDADES = frozenset({"BAIXA", "MEDIA", "ALTA", "CRITICA"})


@dataclass
class EventoRegulatorio:
    """
    Evento externo que pivota a atuação regulatória (crise, acidente, recall).

    Identificador canônico: UUID local + ``data_evento``.
    """

    tipo: str
    titulo: str
    data_evento: datetime
    setor_afetado: str
    descricao: str
    id_evento: str = field(default_factory=lambda: str(uuid.uuid4()))
    severidade: str = "MEDIA"
    regulados_envolvidos: list[str] = field(default_factory=list)
    indicador_impactado_codigos: list[str] = field(default_factory=list)
    geo_uf: list[str] = field(default_factory=list)
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.tipo not in TIPOS_VALIDOS:
            raise ValueError(
                f"tipo inválido: {self.tipo!r}. Válidos: {sorted(TIPOS_VALIDOS)}"
            )
        if self.severidade not in SEVERIDADES:
            raise ValueError(
                f"severidade inválida: {self.severidade!r}. Válidas: {sorted(SEVERIDADES)}"
            )
        require_tz(self.data_evento, "data_evento")
        for uf in self.geo_uf:
            if len(uf) != 2:
                raise ValueError(f"UF inválida: {uf!r}")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        return f"{self.tipo.title()}: {self.titulo} ({self.data_evento.date().isoformat()})"
