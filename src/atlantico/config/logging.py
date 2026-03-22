"""
Configuração de logging estruturado via structlog.

Todos os logs são emitidos em formato JSON para facilitar ingestão
em sistemas de observabilidade (Elasticsearch, Loki, etc.).
Informações sensíveis nunca devem aparecer em logs — use key_id, não chaves.
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(log_level: str = "INFO") -> None:
    """Configura structlog para logging JSON estruturado."""
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if sys.stderr.isatty():
        # Desenvolvimento: output legível por humanos
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(),
        ]
    else:
        # Produção/CI: JSON para ingestão por sistemas de log
        processors = [
            *shared_processors,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configurar também o logging padrão do Python para capturar libs externas
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.getLevelName(log_level),
    )
