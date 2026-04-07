"""IndicadorMercado — KPI/série temporal regulatória."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from ._common import require_classification, require_confidence, require_tz


@dataclass
class IndicadorMercado:
    """
    Ponto de uma série temporal de indicador regulatório
    (tarifa, qualidade de serviço, KPI setorial).

    Identificador canônico: ``(setor, codigo, periodo)``.
    """

    setor: str
    codigo: str
    periodo: datetime
    valor: Decimal
    unidade: str
    orgao_publicador: str
    descricao: str = ""
    fonte_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        require_tz(self.periodo, "periodo")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        return f"{self.codigo} [{self.setor}] @ {self.periodo.date().isoformat()}"
