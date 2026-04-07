"""AcaoJudicial — ação judicial correlata a ato regulatório (DataJud CNJ)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import (
    require_classification,
    require_confidence,
    require_tz,
    validate_numero_cnj,
)

STATUS_VALIDOS = frozenset(
    {"distribuida", "em_tramitacao", "julgada", "transitada", "arquivada"}
)


@dataclass
class AcaoJudicial:
    """
    Ação judicial relacionada a ato regulatório.

    Identificador canônico: ``numero_cnj`` (Resolução CNJ 65/2008, 20 dígitos).
    """

    numero_cnj: str
    tribunal: str
    classe: str
    data_distribuicao: datetime
    partes_polo_ativo: list[str] = field(default_factory=list)
    partes_polo_passivo: list[str] = field(default_factory=list)
    status: str = "em_tramitacao"
    decisao_liminar: str | None = None
    decisao_merito: str | None = None
    norma_questionada_urn: str | None = None
    deliberacao_questionada_id: str | None = None
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.numero_cnj = validate_numero_cnj(self.numero_cnj)
        if self.status not in STATUS_VALIDOS:
            raise ValueError(
                f"status inválido: {self.status!r}. Válidos: {sorted(STATUS_VALIDOS)}"
            )
        require_tz(self.data_distribuicao, "data_distribuicao")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        return f"{self.classe} {self.numero_cnj} ({self.tribunal})"
