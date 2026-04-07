"""ContratoConcessao — contrato de concessão, permissão ou outorga."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from ._common import (
    require_classification,
    require_confidence,
    require_tz,
)

MODALIDADES = frozenset(
    {"concessao_comum", "concessao_patrocinada", "concessao_administrativa",
     "permissao", "autorizacao", "outorga", "ppp"}
)


@dataclass
class ContratoConcessao:
    """
    Contrato de concessão / outorga regulado por uma agência.

    Identificador canônico: ``(orgao, numero_contrato)``.
    """

    numero_contrato: str
    orgao: str
    modalidade: str
    objeto: str
    regulado_id: str  # CNPJ ou referência interna do Regulado
    data_assinatura: datetime
    prazo_anos: int
    valor_total: Decimal | None = None
    contraprestacao: Decimal | None = None
    cronograma_marcos: list[str] = field(default_factory=list)
    garantias: list[str] = field(default_factory=list)
    data_termino_prevista: datetime | None = None
    rescisao_motivo: str | None = None
    source_url: str | None = None
    source_id: str | None = None
    confidence: float = 1.0
    data_classification: str = "PUBLIC"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.modalidade not in MODALIDADES:
            raise ValueError(
                f"modalidade inválida: {self.modalidade!r}. "
                f"Válidas: {sorted(MODALIDADES)}"
            )
        if self.prazo_anos <= 0:
            raise ValueError(f"prazo_anos deve ser > 0, recebido: {self.prazo_anos}")
        require_tz(self.data_assinatura, "data_assinatura")
        if self.data_termino_prevista is not None:
            require_tz(self.data_termino_prevista, "data_termino_prevista")
        require_confidence(self.confidence)
        require_classification(self.data_classification)

    @property
    def is_vigente(self) -> bool:
        return self.rescisao_motivo is None

    @property
    def identificador_humano(self) -> str:
        return f"Contrato {self.orgao} nº {self.numero_contrato}"
