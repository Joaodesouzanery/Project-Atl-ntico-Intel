"""
Normalizador AtlasObservation → ontologia.

Converte observações brutas vindas dos conectores (DOU, LexML) em
``Norma`` quando possível. É um best-effort: extrai número e ano do
título por regex; se a observação já vem com ``urn_lex`` (caso LexML),
usa-a diretamente.

Quando uma observação não pode ser convertida em Norma — por exemplo,
um aviso administrativo do DOU sem padrão normativo — o normalizador
retorna ``IngestionResult(norma=None, reason=...)`` para que o pipeline
possa contabilizar como skip sem lançar exceção.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from atlantico.atlas.observations import AtlasObservation
from atlantico.atlas.ontology import Norma
from atlantico.atlas.ontology._common import compute_sha3_256

# Captura "nº 1.234" / "nº 14500" / "no 12" — separador opcional, milhar opcional
_NUM_RE = re.compile(
    r"n[º°o]\s*\.?\s*(\d{1,3}(?:[.,]\d{3})*|\d+)",
    re.IGNORECASE,
)
# Captura "de 2026" ou "/2026"
_ANO_RE = re.compile(r"\b(\d{4})\b")


@dataclass
class IngestionResult:
    """
    Resultado de uma tentativa de normalização.

    ``norma`` é None quando a observação não pôde ser convertida — a razão
    fica em ``reason`` (informativa, não erro).
    """

    norma: Norma | None
    reason: str | None = None


def _parse_numero(title: str) -> int | None:
    match = _NUM_RE.search(title)
    if not match:
        return None
    raw = match.group(1).replace(".", "").replace(",", "")
    try:
        return int(raw)
    except ValueError:
        return None


def _parse_ano(title: str, fallback: datetime) -> int:
    """Extrai ano do título; se ausente, usa o ano do reference_date."""
    matches = _ANO_RE.findall(title)
    for m in matches:
        year = int(m)
        if 1900 <= year <= 2100:
            return year
    return fallback.year


def observation_to_norma(obs: AtlasObservation) -> IngestionResult:
    """Tenta converter uma AtlasObservation em Norma.

    Regras:
        - obs.observation_type deve ser "norma"
        - obs.norma_tipo deve estar setado (DOU/LexML inferem por regex)
        - obs.orgao_publicador é obrigatório (entity-resolution natural key)
        - número precisa ser extraível do título via regex
        - ano: extraído do título ou fallback no ano do reference_date
    """
    if obs.observation_type != "norma":
        return IngestionResult(None, f"observation_type={obs.observation_type!r} (não-norma)")
    if not obs.norma_tipo:
        return IngestionResult(None, "norma_tipo ausente")
    if not obs.orgao_publicador:
        return IngestionResult(None, "orgao_publicador ausente")

    title = (
        obs.payload.get("title")
        or obs.payload.get("titulo")
        or ""
    )
    numero = _parse_numero(title)
    if numero is None:
        return IngestionResult(None, f"número não extraível do título: {title!r}")

    ano = _parse_ano(title, obs.reference_date)
    ementa = title or "(sem ementa)"

    text_hash = obs.text_hash_sha3_256 or compute_sha3_256(title) if title else None

    norma = Norma(
        tipo=obs.norma_tipo,
        numero=numero,
        ano=ano,
        orgao=obs.orgao_publicador,
        ementa=ementa,
        data_publicacao_dou=obs.reference_date,
        urn_lex=obs.urn_lex,  # LexML traz, DOU não — entity-resolution depois
        text_hash_sha3_256=text_hash,
        source_id=obs.source_id,
        data_classification=obs.data_classification,
        tags=list(obs.tags),
    )
    return IngestionResult(norma=norma)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
