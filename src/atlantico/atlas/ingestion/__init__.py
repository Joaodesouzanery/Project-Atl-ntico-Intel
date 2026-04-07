"""Pipeline de ingestão Atlas: AtlasObservation → Norma → repository."""

from .normalizer import IngestionResult, observation_to_norma

# Pipeline depende de sqlalchemy/asyncpg — só importa se disponível
# (atlas_demo Lambda não tem essas deps).
try:
    from .pipeline import AtlasIngestionPipeline, IngestionStats
except ImportError:  # pragma: no cover
    AtlasIngestionPipeline = None  # type: ignore
    IngestionStats = None  # type: ignore

__all__ = [
    "AtlasIngestionPipeline",
    "IngestionResult",
    "IngestionStats",
    "observation_to_norma",
]
