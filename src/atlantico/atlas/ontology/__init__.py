"""
Ontologia Atlântico Atlas — 15 objetos primários da inteligência regulatória.

Inspirada em Palantir Gotham, adaptada para o setor regulatório brasileiro
(memory: project_atlas_pivot.md).

Princípios:
    - Default público (LAI by design)
    - Provenance/chain-of-custody mandatório (text_hash_sha3_256)
    - LGPD-by-design (CPF apenas como hash)
    - Datetimes timezone-aware obrigatórios
    - Zero imports de outros módulos do projeto (vertical paralela)
"""

from .acao_judicial import AcaoJudicial
from .acordao_tcu import AcordaoTCU
from .air import AIR
from .auto_infracao import AutoInfracao
from .consulta_publica import ConsultaPublica
from .contrato_concessao import ContratoConcessao
from .deliberacao import Deliberacao, Voto
from .diretor_servidor import DiretorServidor
from .documento_bruto import DocumentoBruto
from .evento_regulatorio import EventoRegulatorio
from .indicador_mercado import IndicadorMercado
from .norma import Norma
from .processo_administrativo import ProcessoAdministrativo
from .regulado import Regulado
from .stakeholder_politico import StakeholderPolitico

__all__ = [
    "AIR",
    "AcaoJudicial",
    "AcordaoTCU",
    "AutoInfracao",
    "ConsultaPublica",
    "ContratoConcessao",
    "Deliberacao",
    "DiretorServidor",
    "DocumentoBruto",
    "EventoRegulatorio",
    "IndicadorMercado",
    "Norma",
    "ProcessoAdministrativo",
    "Regulado",
    "StakeholderPolitico",
    "Voto",
]
