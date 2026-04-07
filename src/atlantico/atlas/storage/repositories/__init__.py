"""Repositórios async dos 5 objetos core do Atlas."""

from .contrato_repo import ContratoConcessaoRepository
from .deliberacao_repo import DeliberacaoRepository
from .norma_repo import NormaRepository
from .processo_repo import ProcessoAdministrativoRepository
from .regulado_repo import ReguladoRepository

__all__ = [
    "ContratoConcessaoRepository",
    "DeliberacaoRepository",
    "NormaRepository",
    "ProcessoAdministrativoRepository",
    "ReguladoRepository",
]
