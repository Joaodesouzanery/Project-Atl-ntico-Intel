"""ConsultaPublica — consulta pública / audiência pública regulatória."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import require_classification, require_confidence, require_tz


@dataclass
class ConsultaPublica:
    """
    Consulta pública ou audiência pública aberta por agência reguladora.

    Identificador canônico: ``(orgao, numero, ano)``.
    """

    orgao: str
    numero: int
    ano: int
    objeto: str
    data_abertura: datetime
    data_encerramento: datetime
    contribuicoes_recebidas: int = 0
    sumario_url: str | None = None
    norma_resultante_urn: str | None = None
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.numero <= 0:
            raise ValueError(f"numero deve ser > 0, recebido: {self.numero}")
        if self.ano < 1500 or self.ano > 9999:
            raise ValueError(f"ano fora de range: {self.ano}")
        if self.contribuicoes_recebidas < 0:
            raise ValueError(
                f"contribuicoes_recebidas não pode ser negativo: {self.contribuicoes_recebidas}"
            )
        require_tz(self.data_abertura, "data_abertura")
        require_tz(self.data_encerramento, "data_encerramento")
        if self.data_encerramento < self.data_abertura:
            raise ValueError("data_encerramento não pode ser anterior a data_abertura")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        return f"Consulta Pública {self.orgao} nº {self.numero}/{self.ano}"
