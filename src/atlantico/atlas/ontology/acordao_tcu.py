"""AcordaoTCU — acórdão do Tribunal de Contas da União."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import (
    compute_sha3_256,
    require_classification,
    require_confidence,
    require_tz,
)


@dataclass
class AcordaoTCU:
    """
    Acórdão do TCU (ou da CGU como variante interna).

    Identificador canônico: ``(numero, ano, colegiado)``.
    """

    numero: int
    ano: int
    colegiado: str  # "plenario" | "primeira_camara" | "segunda_camara"
    data_sessao: datetime
    relator: str
    area_tematica: str
    ementa: str
    recomendacoes: list[str] = field(default_factory=list)
    prazo_cumprimento_dias: int | None = None
    orgao_jurisdicionado: str | None = None
    text_hash_sha3_256: str | None = None
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
        if self.colegiado not in {"plenario", "primeira_camara", "segunda_camara"}:
            raise ValueError(f"colegiado inválido: {self.colegiado!r}")
        if self.prazo_cumprimento_dias is not None and self.prazo_cumprimento_dias < 0:
            raise ValueError("prazo_cumprimento_dias não pode ser negativo")
        require_tz(self.data_sessao, "data_sessao")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    def compute_text_hash(self, text: str) -> str:
        self.text_hash_sha3_256 = compute_sha3_256(text)
        return self.text_hash_sha3_256

    @property
    def identificador_humano(self) -> str:
        return f"Acórdão TCU {self.numero}/{self.ano} ({self.colegiado})"
