"""
FinintObservation — DTO compartilhado entre conectores e pipeline de ingestão FININT.

Objeto puro Python (sem SQLAlchemy, sem crypto) que normaliza observações
financeiras de fontes heterogêneas para uma interface unificada.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class FinintObservation:
    """
    Observação financeira bruta retornada por um conector FININT.

    Campos:
        source_id:          Identificador canônico da fonte, ex: "bcb.sgs.v1"
        external_id:        ID único do registro na fonte (para deduplication)
        observation_type:   Tipo semântico da observação:
                            "market_indicator" | "public_contract" | "trade_flow"
                            | "financial_flow"
        reference_date:     Data/período de referência do dado (timezone-aware UTC)
        payload:            Dict com todos os campos brutos da fonte
        data_classification: Classificação — "PUBLIC" (padrão para dados abertos)
        municipality_code:  Código IBGE do município (7 dígitos), se disponível
        state_code:         UF (2 letras), se disponível
        geo_point_wkt:      POINT WKT do município/estado, se disponível
    """

    source_id: str
    external_id: str
    observation_type: str
    reference_date: datetime
    payload: dict[str, Any] = field(default_factory=dict)
    data_classification: str = "PUBLIC"
    municipality_code: str | None = None
    state_code: str | None = None
    geo_point_wkt: str | None = None

    def __post_init__(self) -> None:
        if self.reference_date.tzinfo is None:
            msg = (
                f"FinintObservation.reference_date deve ser timezone-aware. "
                f"Recebido: {self.reference_date!r} (sem tzinfo)."
            )
            raise ValueError(msg)
