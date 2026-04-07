"""StakeholderPolitico — parlamentar, ministério, frente parlamentar."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._common import require_classification, require_confidence

TIPOS_VALIDOS = frozenset(
    {"deputado", "senador", "ministerio", "frente_parlamentar", "comissao", "lobby"}
)


@dataclass
class StakeholderPolitico:
    """
    Ator político relevante para o ambiente regulatório.

    Identificador canônico: ``id_externo`` (ID na fonte: Câmara/Senado).
    """

    id_externo: str
    nome: str
    tipo: str
    fonte: str  # "camara" | "senado" | "casa_civil" | etc.
    sigla_partido: str | None = None
    uf: str | None = None
    posicoes_registradas: list[str] = field(default_factory=list)
    setores_interesse: list[str] = field(default_factory=list)
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.tipo not in TIPOS_VALIDOS:
            raise ValueError(
                f"tipo inválido: {self.tipo!r}. Válidos: {sorted(TIPOS_VALIDOS)}"
            )
        if self.uf is not None and len(self.uf) != 2:
            raise ValueError(f"uf deve ter 2 caracteres, recebido: {self.uf!r}")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def identificador_humano(self) -> str:
        suffix = f" ({self.sigla_partido}/{self.uf})" if self.sigla_partido and self.uf else ""
        return f"{self.nome}{suffix}"
