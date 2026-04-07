"""Deliberacao — decisão de colegiado regulatório."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import (
    compute_sha3_256,
    require_classification,
    require_confidence,
    require_tz,
)

DISPOSITIVOS_VALIDOS = frozenset(
    {"deferido", "indeferido", "parcialmente_deferido", "diligencia", "arquivado"}
)


@dataclass
class Voto:
    """Voto individual de um diretor numa deliberação."""

    diretor_id: str
    sentido: str  # "favoravel" | "contrario" | "abstencao" | "impedido"
    fundamento_resumo: str = ""

    def __post_init__(self) -> None:
        validos = {"favoravel", "contrario", "abstencao", "impedido"}
        if self.sentido not in validos:
            raise ValueError(
                f"sentido inválido: {self.sentido!r}. Válidos: {sorted(validos)}"
            )


@dataclass
class Deliberacao:
    """
    Decisão colegiada de uma agência reguladora.

    Identificador canônico: ``(orgao, colegiado, numero, ano)``.
    """

    orgao: str
    colegiado: str
    numero: int
    ano: int
    data_sessao: datetime
    relator_id: str
    dispositivo: str
    ementa: str
    processo_sei: str | None = None
    votos: list[Voto] = field(default_factory=list)
    fundamento: str = ""
    norma_citada_urns: list[str] = field(default_factory=list)
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
        if self.dispositivo not in DISPOSITIVOS_VALIDOS:
            raise ValueError(
                f"dispositivo inválido: {self.dispositivo!r}. "
                f"Válidos: {sorted(DISPOSITIVOS_VALIDOS)}"
            )
        require_tz(self.data_sessao, "data_sessao")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    def compute_text_hash(self, text: str) -> str:
        self.text_hash_sha3_256 = compute_sha3_256(text)
        return self.text_hash_sha3_256

    @property
    def identificador_humano(self) -> str:
        return f"{self.colegiado} {self.orgao} nº {self.numero}/{self.ano}"
