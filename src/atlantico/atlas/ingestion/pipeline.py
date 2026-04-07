"""
AtlasIngestionPipeline — orquestra conector → normalizador → repositório.

Padrão idêntico ao pipeline SIGINT/FININT: o pipeline é dono do ciclo
async (context manager do conector + sessão do repositório), mas
**não** tem regra de negócio. Toda inteligência fica no normalizador
e nos validadores da ontologia.

Idempotência: garantida pelo ``NormaRepository.store()`` (ON CONFLICT
DO NOTHING na chave natural ``(orgao,tipo,numero,ano)``). Reexecutar o
pipeline com o mesmo ``since`` não duplica registros.

Entity resolution DOU↔LexML: como o store usa a chave natural e
não a URN, uma observação do DOU (sem URN) e a observação LexML
correspondente (com URN) **convergem na mesma linha** se forem do
mesmo (orgao,tipo,numero,ano). Esta é a primeira manifestação real
do entity resolution Gotham-style descrito na seção 1.5.2 do conceito.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from atlantico.atlas.connectors.base import AtlasConnector
from atlantico.atlas.ingestion.normalizer import (
    IngestionResult,
    observation_to_norma,
)
from atlantico.atlas.storage.repositories import NormaRepository

logger = logging.getLogger(__name__)


@dataclass
class IngestionStats:
    """Estatísticas de uma execução do pipeline."""

    fetched: int = 0
    converted: int = 0
    stored: int = 0
    skipped: int = 0
    errors: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    error_messages: list[str] = field(default_factory=list)

    def record_skip(self, reason: str) -> None:
        self.skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def record_error(self, msg: str) -> None:
        self.errors += 1
        self.error_messages.append(msg[:200])


class AtlasIngestionPipeline:
    """
    Orquestra um conector Atlas com o NormaRepository.

    Uso típico::

        async with DOUConnector() as connector:
            pipeline = AtlasIngestionPipeline(connector, NormaRepository(session))
            stats = await pipeline.run(since=since, limit=200)
        await session.commit()

    O pipeline NÃO chama ``session.commit()`` — o caller decide quando.
    """

    def __init__(
        self,
        connector: AtlasConnector,
        norma_repo: NormaRepository,
    ) -> None:
        self._connector = connector
        self._norma_repo = norma_repo

    async def run(
        self,
        since: datetime,
        limit: int = 100,
    ) -> IngestionStats:
        stats = IngestionStats()
        try:
            observations = await self._connector.fetch(since=since, limit=limit)
        except Exception as exc:
            stats.record_error(f"connector.fetch falhou: {exc}")
            return stats

        stats.fetched = len(observations)

        for obs in observations:
            try:
                result: IngestionResult = observation_to_norma(obs)
            except Exception as exc:
                stats.record_error(f"normalize {obs.external_id}: {exc}")
                continue

            if result.norma is None:
                stats.record_skip(result.reason or "desconhecido")
                continue

            stats.converted += 1
            try:
                await self._norma_repo.store(result.norma)
                stats.stored += 1
            except Exception as exc:
                stats.record_error(f"store {result.norma.identificador_humano}: {exc}")

        logger.info(
            "Atlas pipeline run: fetched=%d converted=%d stored=%d skipped=%d errors=%d",
            stats.fetched, stats.converted, stats.stored, stats.skipped, stats.errors,
        )
        return stats
