"""AutoInfracao — auto de infração / sanção administrativa."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from ._common import (
    require_classification,
    require_confidence,
    require_tz,
)

FASES_RECURSAIS = frozenset(
    {"lavrado", "defesa", "primeira_instancia", "recurso", "transitado", "executado"}
)
STATUS_PAGAMENTO = frozenset({"pendente", "parcelado", "pago", "inscrito_dau", "cancelado"})


@dataclass
class AutoInfracao:
    """
    Auto de infração lavrado por agência reguladora.

    Identificador canônico: ``numero_auto``.
    """

    numero_auto: str
    orgao: str
    regulado_id: str
    data_lavratura: datetime
    fundamento_norma_urn: str
    descricao: str
    valor_multa: Decimal
    fase_recursal: str = "lavrado"
    status_pagamento: str = "pendente"
    processo_sei: str | None = None
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.fase_recursal not in FASES_RECURSAIS:
            raise ValueError(
                f"fase_recursal inválida: {self.fase_recursal!r}. "
                f"Válidas: {sorted(FASES_RECURSAIS)}"
            )
        if self.status_pagamento not in STATUS_PAGAMENTO:
            raise ValueError(
                f"status_pagamento inválido: {self.status_pagamento!r}. "
                f"Válidos: {sorted(STATUS_PAGAMENTO)}"
            )
        if self.valor_multa < 0:
            raise ValueError(f"valor_multa não pode ser negativo: {self.valor_multa}")
        require_tz(self.data_lavratura, "data_lavratura")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        return f"Auto {self.orgao} nº {self.numero_auto}"
