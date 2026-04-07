"""Norma — ato normativo (lei, decreto, resolução, portaria, instrução normativa)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import (
    compute_sha3_256,
    require_classification,
    require_confidence,
    require_tz,
    validate_urn_lex,
)

NORMA_TIPOS_VALIDOS = frozenset(
    {
        "lei",
        "lei_complementar",
        "decreto",
        "decreto_legislativo",
        "medida_provisoria",
        "resolucao",
        "portaria",
        "instrucao_normativa",
        "deliberacao",
        "circular",
        "edital",
        "ato_normativo",
    }
)


@dataclass
class Norma:
    """
    Ato normativo brasileiro — entidade central da ontologia Atlas.

    Identificador canônico: ``urn_lex`` (LexML).
    """

    tipo: str
    numero: int
    ano: int
    orgao: str
    ementa: str
    data_publicacao_dou: datetime
    urn_lex: str | None = None
    vigencia_inicio: datetime | None = None
    vigencia_fim: datetime | None = None
    revogada_por_urn: str | None = None
    air_vinculada_id: str | None = None
    texto_canonico_url: str | None = None
    dou_url: str | None = None
    text_hash_sha3_256: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    source_id: str | None = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.tipo not in NORMA_TIPOS_VALIDOS:
            raise ValueError(
                f"tipo de norma inválido: {self.tipo!r}. "
                f"Valores válidos: {sorted(NORMA_TIPOS_VALIDOS)}"
            )
        if self.numero <= 0:
            raise ValueError(f"numero deve ser > 0, recebido: {self.numero}")
        if self.ano < 1500 or self.ano > 9999:
            raise ValueError(f"ano fora de range válido: {self.ano}")
        require_tz(self.data_publicacao_dou, "data_publicacao_dou")
        if self.vigencia_inicio is not None:
            require_tz(self.vigencia_inicio, "vigencia_inicio")
        if self.vigencia_fim is not None:
            require_tz(self.vigencia_fim, "vigencia_fim")
        if self.urn_lex is not None:
            validate_urn_lex(self.urn_lex)
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    def compute_text_hash(self, text: str) -> str:
        self.text_hash_sha3_256 = compute_sha3_256(text)
        return self.text_hash_sha3_256

    @property
    def is_vigente(self) -> bool:
        return self.revogada_por_urn is None and self.vigencia_fim is None

    @property
    def identificador_humano(self) -> str:
        tipo_legivel = self.tipo.replace("_", " ").title()
        return f"{tipo_legivel} {self.orgao} nº {self.numero}/{self.ano}"
