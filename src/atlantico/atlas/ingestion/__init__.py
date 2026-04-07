"""Pipeline de ingestão Atlas: AtlasObservation → Norma → repository."""

from .normalizer import IngestionResult, observation_to_norma
from .pipeline import AtlasIngestionPipeline, IngestionStats

__all__ = [
    "AtlasIngestionPipeline",
    "IngestionResult",
    "IngestionStats",
    "observation_to_norma",
]
