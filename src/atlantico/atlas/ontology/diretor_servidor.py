"""DiretorServidor — pessoa física vinculada a uma agência (LGPD-by-design)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ._common import (
    hash_cpf,
    require_classification,
    require_confidence,
    require_tz,
)

PAPEIS_VALIDOS = frozenset(
    {"diretor", "diretor_presidente", "servidor", "procurador", "ouvidor", "auditor"}
)


@dataclass
class DiretorServidor:
    """
    Diretor ou servidor de agência reguladora.

    Identificador canônico: ``cpf_hash`` (SHA3-256). **CPF cru NUNCA é
    armazenado** — princípio LGPD-by-design (memory item 5).

    Use o classmethod ``from_cpf()`` para construir a partir do CPF cru.
    """

    cpf_hash: str
    nome_publico: str
    orgao: str
    papel: str
    inicio_mandato: datetime
    fim_mandato: datetime | None = None
    indicacao_origem: str | None = None  # Casa Civil, Senado, etc.
    declaracoes_conflito: list[str] = field(default_factory=list)
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.papel not in PAPEIS_VALIDOS:
            raise ValueError(
                f"papel inválido: {self.papel!r}. Válidos: {sorted(PAPEIS_VALIDOS)}"
            )
        if len(self.cpf_hash) != 64:
            raise ValueError(
                f"cpf_hash deve ser SHA3-256 hex (64 chars). Recebido len={len(self.cpf_hash)}"
            )
        require_tz(self.inicio_mandato, "inicio_mandato")
        if self.fim_mandato is not None:
            require_tz(self.fim_mandato, "fim_mandato")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @classmethod
    def from_cpf(
        cls,
        cpf: str,
        nome_publico: str,
        orgao: str,
        papel: str,
        inicio_mandato: datetime,
        **kwargs: object,
    ) -> "DiretorServidor":
        """Construtor que aceita CPF cru, hasheia imediatamente e descarta."""
        return cls(
            cpf_hash=hash_cpf(cpf),
            nome_publico=nome_publico,
            orgao=orgao,
            papel=papel,
            inicio_mandato=inicio_mandato,
            **kwargs,  # type: ignore[arg-type]
        )

    @property
    def is_em_mandato(self) -> bool:
        return self.fim_mandato is None

    @property
    def identificador_humano(self) -> str:
        return f"{self.nome_publico} ({self.papel} {self.orgao})"
