"""Modelos SQLAlchemy do Atlas (5 objetos core do Sprint 4)."""

from .contrato_concessao import ContratoConcessaoModel
from .deliberacao import DeliberacaoModel
from .norma import NormaModel
from .processo_administrativo import ProcessoAdministrativoModel
from .regulado import ReguladoModel

__all__ = [
    "ContratoConcessaoModel",
    "DeliberacaoModel",
    "NormaModel",
    "ProcessoAdministrativoModel",
    "ReguladoModel",
]
