"""
Conector Atlas: Diário Oficial da União (Imprensa Nacional).

Endpoint público "leiturajornal" da Imprensa Nacional retorna o índice
diário das publicações por seção (DO1, DO2, DO3, DO1 Extra). Não exige
autenticação.

URL base: https://www.in.gov.br/leiturajornal
Padrão de query: ?data=DD-MM-YYYY&secao=do1

A resposta é HTML que embute um JSON ``jsonArray`` (lista de matérias).
Para robustez, este conector também aceita uma resposta JSON direta caso
a API evolua.

SOURCE_ID: br.gov.in.dou.v1
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from atlantico.atlas.connectors.base import (
    AtlasConnector,
    AtlasConnectorError,
    AtlasConnectorParseError,
    retry_with_backoff,
)
from atlantico.atlas.observations import AtlasObservation

logger = logging.getLogger(__name__)

# Seções válidas da Imprensa Nacional
SECOES_DOU = frozenset({"do1", "do2", "do3", "do1e", "do2e", "do3e"})

# Heurística simples: mapeia título da matéria para tipo normativo Atlas
_TIPO_REGEX: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\blei\s+complementar\b", re.I), "lei_complementar"),
    (re.compile(r"\blei\s+n[º°]", re.I), "lei"),
    (re.compile(r"\bmedida\s+provis[óo]ria\b", re.I), "medida_provisoria"),
    (re.compile(r"\bdecreto\s+legislativo\b", re.I), "decreto_legislativo"),
    (re.compile(r"\bdecreto\b", re.I), "decreto"),
    (re.compile(r"\bresolu[çc][ãa]o\b", re.I), "resolucao"),
    (re.compile(r"\binstru[çc][ãa]o\s+normativa\b", re.I), "instrucao_normativa"),
    (re.compile(r"\bportaria\b", re.I), "portaria"),
    (re.compile(r"\bdelibera[çc][ãa]o\b", re.I), "deliberacao"),
    (re.compile(r"\bcircular\b", re.I), "circular"),
    (re.compile(r"\bedital\b", re.I), "edital"),
]

# Embed JSON pattern dentro da página leiturajornal
_EMBEDDED_JSON_RE = re.compile(
    r'jsonArray\s*[:=]\s*(\[.*?\])\s*[,;}]', re.DOTALL
)


class DOUConnector(AtlasConnector):
    """
    Conector do Diário Oficial da União (Imprensa Nacional).

    Não exige API key. Retorna observações do tipo ``norma`` (quando o
    título identifica um ato normativo) ou ``documento_bruto`` (caso
    contrário) para cada matéria publicada.
    """

    SOURCE_ID = "br.gov.in.dou.v1"

    def __init__(
        self,
        base_url: str = "https://www.in.gov.br/leiturajornal",
        secoes: tuple[str, ...] = ("do1",),
    ) -> None:
        super().__init__()
        for s in secoes:
            if s not in SECOES_DOU:
                raise ValueError(
                    f"Seção DOU inválida: {s!r}. Válidas: {sorted(SECOES_DOU)}"
                )
        self._base_url = base_url
        self._secoes = secoes

    # ─── API pública ──────────────────────────────────────────────────────────

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        limit: int = 100,
    ) -> list[AtlasObservation]:
        if since.tzinfo is None:
            raise ValueError("'since' deve ser timezone-aware (UTC)")

        observations: list[AtlasObservation] = []
        today = datetime.now(timezone.utc).date()
        current = since.date()

        while current <= today and len(observations) < limit:
            for secao in self._secoes:
                if len(observations) >= limit:
                    break
                items = await self._fetch_day(current, secao)
                for raw in items:
                    if len(observations) >= limit:
                        break
                    obs = self._build_observation(raw, secao, current)
                    if obs is not None:
                        observations.append(obs)
            current = current + timedelta(days=1)

        return observations

    async def health_check(self) -> bool:
        try:
            response = await self.client.get(
                self._base_url,
                params={"data": datetime.now(timezone.utc).strftime("%d-%m-%Y"), "secao": "do1"},
            )
            return response.status_code == 200
        except Exception as exc:  # pragma: no cover - defensivo
            logger.warning("DOU health_check falhou: %s", exc)
            return False

    # ─── Internos ─────────────────────────────────────────────────────────────

    async def _fetch_day(self, day, secao: str) -> list[dict[str, Any]]:
        params = {"data": day.strftime("%d-%m-%Y"), "secao": secao}
        try:
            response = await self.client.get(self._base_url, params=params)
        except httpx.HTTPError as exc:
            raise AtlasConnectorError(f"Falha de rede no DOU: {exc}") from exc

        self._check_rate_limit(response)
        self._check_auth(response)
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            raise AtlasConnectorError(
                f"DOU retornou HTTP {response.status_code} para {params}"
            )

        return self._parse_response(response)

    def _parse_response(self, response: httpx.Response) -> list[dict[str, Any]]:
        """
        Tenta parsear como JSON direto; se falhar, extrai o ``jsonArray``
        embutido no HTML da página leiturajornal.
        """
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                raise AtlasConnectorParseError(f"JSON inválido do DOU: {exc}") from exc
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "jsonArray" in data:
                return list(data["jsonArray"])
            raise AtlasConnectorParseError(
                f"Formato JSON inesperado do DOU: {type(data).__name__}"
            )

        # HTML — extrai o jsonArray embutido
        match = _EMBEDDED_JSON_RE.search(response.text)
        if not match:
            return []
        try:
            return list(json.loads(match.group(1)))
        except json.JSONDecodeError as exc:
            raise AtlasConnectorParseError(
                f"jsonArray embutido inválido: {exc}"
            ) from exc

    def _build_observation(
        self,
        raw: dict[str, Any],
        secao: str,
        publication_day,
    ) -> AtlasObservation | None:
        """Converte uma matéria do DOU em AtlasObservation."""
        external_id = (
            raw.get("id")
            or raw.get("urlTitle")
            or raw.get("url")
            or raw.get("titulo")
        )
        if not external_id:
            return None

        title = (raw.get("title") or raw.get("titulo") or "").strip()
        norma_tipo = self._infer_norma_tipo(title)
        observation_type = "norma" if norma_tipo else "documento_bruto"

        ref_date = datetime.combine(
            publication_day, datetime.min.time(), tzinfo=timezone.utc
        )

        obs = AtlasObservation(
            source_id=self.SOURCE_ID,
            external_id=str(external_id),
            observation_type=observation_type,
            reference_date=ref_date,
            payload=dict(raw),
            data_classification=self.DEFAULT_CLASSIFICATION,
            orgao_publicador=raw.get("orgao") or raw.get("artClass"),
            norma_tipo=norma_tipo,
            tags=[f"secao:{secao}"],
        )

        # Provenance: hash do título (texto bruto disponível na listagem)
        if title:
            obs.compute_text_hash(title)
        return obs

    @staticmethod
    def _infer_norma_tipo(title: str) -> str | None:
        if not title:
            return None
        for pattern, tipo in _TIPO_REGEX:
            if pattern.search(title):
                return tipo
        return None
