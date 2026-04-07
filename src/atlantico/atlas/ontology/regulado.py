"""Regulado — empresa ou pessoa física sujeita a regulação."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._common import (
    normalize_cnpj,
    require_classification,
    require_confidence,
)

TIERS_RISCO = frozenset({"BAIXO", "MEDIO", "ALTO", "CRITICO"})


@dataclass
class Regulado:
    """
    Entidade regulada (concessionária, autorizada, permissionária etc.).

    Identificador canônico: ``cnpj`` (14 dígitos) ou ``cpf_hash`` para PF.
    Pelo menos um dos dois deve estar presente.
    """

    razao_social: str
    setor: str
    cnpj: str | None = None
    cpf_hash: str | None = None
    nome_fantasia: str | None = None
    grupo_economico: str | None = None
    contratos_ativos: list[str] = field(default_factory=list)
    historico_sancoes_ids: list[str] = field(default_factory=list)
    tier_risco: str = "MEDIO"
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.cnpj is None and self.cpf_hash is None:
            raise ValueError("Regulado exige cnpj OU cpf_hash (pelo menos um).")
        if self.cnpj is not None:
            self.cnpj = normalize_cnpj(self.cnpj)
        if self.cpf_hash is not None and len(self.cpf_hash) != 64:
            raise ValueError(
                f"cpf_hash deve ser SHA3-256 hex (64 chars). Recebido len={len(self.cpf_hash)}"
            )
        if self.tier_risco not in TIERS_RISCO:
            raise ValueError(
                f"tier_risco inválido: {self.tier_risco!r}. Válidos: {sorted(TIERS_RISCO)}"
            )
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        ident = self.cnpj or f"PF[{(self.cpf_hash or '')[:8]}...]"
        return f"{self.razao_social} ({ident})"
