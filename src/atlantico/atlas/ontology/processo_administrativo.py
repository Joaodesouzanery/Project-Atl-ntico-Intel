"""ProcessoAdministrativo — processo SEI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import (
    require_classification,
    require_confidence,
    require_tz,
    validate_numero_sei,
)

FASES_VALIDAS = frozenset(
    {
        "autuacao",
        "instrucao",
        "manifestacao",
        "decisao",
        "recurso",
        "execucao",
        "arquivado",
    }
)


@dataclass
class ProcessoAdministrativo:
    """
    Processo administrativo no SEI (Sistema Eletrônico de Informações).

    Identificador canônico: ``numero_sei`` (formato NNNNN.NNNNNN/AAAA-DD).
    """

    numero_sei: str
    orgao: str
    assunto: str
    data_autuacao: datetime
    fase: str = "autuacao"
    partes: list[str] = field(default_factory=list)
    prazo_legal: datetime | None = None
    data_conclusao: datetime | None = None
    norma_relacionada_urn: str | None = None
    source_url: str | None = None
    source_id: str | None = None
    text_hash_sha3_256: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.numero_sei = validate_numero_sei(self.numero_sei)
        if self.fase not in FASES_VALIDAS:
            raise ValueError(
                f"fase inválida: {self.fase!r}. Válidas: {sorted(FASES_VALIDAS)}"
            )
        require_tz(self.data_autuacao, "data_autuacao")
        if self.prazo_legal is not None:
            require_tz(self.prazo_legal, "prazo_legal")
        if self.data_conclusao is not None:
            require_tz(self.data_conclusao, "data_conclusao")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def is_ativa(self) -> bool:
        return self.fase != "arquivado" and self.data_conclusao is None

    @property
    def identificador_humano(self) -> str:
        return f"Processo SEI {self.numero_sei} ({self.orgao})"
