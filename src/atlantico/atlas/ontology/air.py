"""AIR — Análise de Impacto Regulatório (Decreto 10.411/2020)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from ._common import require_classification, require_confidence, require_tz


@dataclass
class AIR:
    """
    Análise de Impacto Regulatório.

    Identificador canônico: ``id_air`` (UUID4 local).
    """

    orgao: str
    problema: str
    alternativas: list[str]
    data_inicio: datetime
    id_air: str = field(default_factory=lambda: str(uuid.uuid4()))
    alternativa_recomendada_idx: int | None = None
    custo_beneficio_resumo: str = ""
    indicadores_monitorados: list[str] = field(default_factory=list)
    norma_resultante_urn: str | None = None
    consulta_publica_id: str | None = None
    relatorio_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.alternativas:
            raise ValueError("AIR exige pelo menos uma alternativa (Decreto 10.411).")
        if self.alternativa_recomendada_idx is not None and not (
            0 <= self.alternativa_recomendada_idx < len(self.alternativas)
        ):
            raise ValueError(
                f"alternativa_recomendada_idx fora de range: {self.alternativa_recomendada_idx}"
            )
        require_tz(self.data_inicio, "data_inicio")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        return f"AIR {self.orgao} [{self.id_air[:8]}]"
