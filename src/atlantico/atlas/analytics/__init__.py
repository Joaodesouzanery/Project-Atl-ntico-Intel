"""
Camada analítica do Atlântico Atlas.

Stdlib-only — nenhuma dependência de scipy/sklearn/numpy. As funções
operam sobre listas de ``Deliberacao`` (dataclass da ontologia) e
retornam dataclasses puras com os resultados. Tudo testável sem DB.

Módulos:
    jurimetria: análise estatística do comportamento decisório
                de colegiados regulatórios (Módulo 2 do conceito).
"""

from .jurimetria import (
    AlignmentMatrix,
    ColegiadoProfile,
    DirectorProfile,
    PredictionResult,
    TemporalInflection,
    compute_alignment_matrix,
    compute_colegiado_profile,
    compute_director_profile,
    detect_temporal_inflection,
    predict_deferment,
)

__all__ = [
    "AlignmentMatrix",
    "ColegiadoProfile",
    "DirectorProfile",
    "PredictionResult",
    "TemporalInflection",
    "compute_alignment_matrix",
    "compute_colegiado_profile",
    "compute_director_profile",
    "detect_temporal_inflection",
    "predict_deferment",
]
