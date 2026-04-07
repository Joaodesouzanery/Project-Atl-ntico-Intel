"""Conectores de ingestão da plataforma Atlântico Atlas."""

from .base import (
    AtlasConnector,
    AtlasConnectorError,
    AtlasConnectorAuthError,
    AtlasConnectorParseError,
    AtlasConnectorRateLimitError,
    retry_with_backoff,
)
from .dou import DOUConnector
from .lexml import LexMLConnector

__all__ = [
    "AtlasConnector",
    "AtlasConnectorError",
    "AtlasConnectorAuthError",
    "AtlasConnectorParseError",
    "AtlasConnectorRateLimitError",
    "DOUConnector",
    "LexMLConnector",
    "retry_with_backoff",
]
