"""
Conector Atlas: LexML Brasil — OAI-PMH (Open Archives).

LexML é o repositório oficial brasileiro de metadados de atos normativos
mantido pelo Senado Federal em parceria com a Rede LexML. Expõe um
endpoint OAI-PMH 2.0 com metadataPrefix ``oai_dc`` (Dublin Core).

URL base: https://www.lexml.gov.br/oai_pmh
Verbo principal: ListRecords
Paginação: resumptionToken (até esgotar)

Cada registro contém ``<dc:identifier>`` com a URN LexML canônica
(``urn:lex:br:...``), que é o identificador soberano de normas brasileiras
e o ponto de junção com o conector DOU (que pode ter normas sem URN
ainda atribuída).

SOURCE_ID: br.gov.lexml.oai.v1
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import httpx

from atlantico.atlas.connectors.base import (
    AtlasConnector,
    AtlasConnectorError,
    AtlasConnectorParseError,
    retry_with_backoff,
)
from atlantico.atlas.observations import AtlasObservation

logger = logging.getLogger(__name__)


# Namespaces OAI-PMH 2.0 + Dublin Core
NS = {
    "oai": "http://www.openarchives.org/OAI/2.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "oai_dc": "http://www.openarchives.org/OAI/2.0/oai_dc/",
}

# Mapeamento de dc:type para tipo normativo Atlas
_DC_TYPE_TO_NORMA: dict[str, str] = {
    "lei": "lei",
    "lei complementar": "lei_complementar",
    "decreto": "decreto",
    "decreto legislativo": "decreto_legislativo",
    "medida provisoria": "medida_provisoria",
    "medida provisória": "medida_provisoria",
    "resolucao": "resolucao",
    "resolução": "resolucao",
    "portaria": "portaria",
    "instrucao normativa": "instrucao_normativa",
    "instrução normativa": "instrucao_normativa",
    "deliberacao": "deliberacao",
    "deliberação": "deliberacao",
    "circular": "circular",
    "edital": "edital",
}

_URN_RE = re.compile(r"urn:lex:br:[a-z0-9.\-]+:[a-z_]+:\d{4};\d+")


class LexMLConnector(AtlasConnector):
    """
    Conector OAI-PMH do LexML Brasil.

    Não exige API key. Usa o verbo ``ListRecords`` com ``metadataPrefix=oai_dc``
    e segue o ``resumptionToken`` até atingir ``limit`` registros ou esgotar
    a paginação.
    """

    SOURCE_ID = "br.gov.lexml.oai.v1"
    PAGE_SIZE_HINT = 100  # OAI-PMH é controlado pelo servidor; é só uma referência

    def __init__(
        self,
        base_url: str = "https://www.lexml.gov.br/oai_pmh",
        metadata_prefix: str = "oai_dc",
        oai_set: str | None = None,
    ) -> None:
        super().__init__()
        self._base_url = base_url
        self._metadata_prefix = metadata_prefix
        self._set = oai_set

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
        params: dict[str, str] = {
            "verb": "ListRecords",
            "metadataPrefix": self._metadata_prefix,
            "from": since.strftime("%Y-%m-%d"),
        }
        if self._set:
            params["set"] = self._set

        while len(observations) < limit:
            xml_text = await self._fetch_page(params)
            records, token = self._parse_list_records(xml_text)
            for raw in records:
                if len(observations) >= limit:
                    break
                obs = self._build_observation(raw)
                if obs is not None:
                    observations.append(obs)

            if not token or len(observations) >= limit:
                break
            # Quando há resumptionToken, OAI-PMH exige enviar APENAS verb + token
            params = {"verb": "ListRecords", "resumptionToken": token}

        return observations

    async def health_check(self) -> bool:
        try:
            response = await self.client.get(
                self._base_url, params={"verb": "Identify"}
            )
            return response.status_code == 200 and "<Identify>" in response.text
        except Exception as exc:  # pragma: no cover - defensivo
            logger.warning("LexML health_check falhou: %s", exc)
            return False

    # ─── Internos ─────────────────────────────────────────────────────────────

    async def _fetch_page(self, params: dict[str, str]) -> str:
        try:
            response = await self.client.get(self._base_url, params=params)
        except httpx.HTTPError as exc:
            raise AtlasConnectorError(f"Falha de rede no LexML: {exc}") from exc

        self._check_rate_limit(response)
        self._check_auth(response)
        if response.status_code != 200:
            raise AtlasConnectorError(
                f"LexML retornou HTTP {response.status_code}"
            )
        return response.text

    def _parse_list_records(
        self, xml_text: str
    ) -> tuple[list[dict[str, object]], str | None]:
        """
        Retorna ``(records, resumption_token)``.

        Cada record é um dict com chaves: identifier (header OAI),
        datestamp, urn, titulo, data, tipo (dc:type bruto), creator.
        """
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise AtlasConnectorParseError(f"XML inválido do LexML: {exc}") from exc

        # Erros OAI-PMH (ex: noRecordsMatch) — não é falha, retorna vazio
        error = root.find("oai:error", NS)
        if error is not None:
            code = error.get("code", "unknown")
            if code == "noRecordsMatch":
                return [], None
            raise AtlasConnectorError(f"LexML OAI-PMH error: {code} {error.text!r}")

        list_records = root.find("oai:ListRecords", NS)
        if list_records is None:
            return [], None

        records: list[dict[str, object]] = []
        for rec in list_records.findall("oai:record", NS):
            header = rec.find("oai:header", NS)
            if header is not None and header.get("status") == "deleted":
                continue
            parsed = self._parse_record(rec)
            if parsed is not None:
                records.append(parsed)

        token_el = list_records.find("oai:resumptionToken", NS)
        token = token_el.text.strip() if token_el is not None and token_el.text else None
        return records, token

    def _parse_record(self, rec: ET.Element) -> dict[str, object] | None:
        header = rec.find("oai:header", NS)
        identifier_el = header.find("oai:identifier", NS) if header is not None else None
        datestamp_el = header.find("oai:datestamp", NS) if header is not None else None

        metadata = rec.find("oai:metadata", NS)
        if metadata is None:
            return None
        dc = metadata.find("oai_dc:dc", NS)
        if dc is None:
            return None

        def _all(tag: str) -> list[str]:
            return [
                (el.text or "").strip()
                for el in dc.findall(f"dc:{tag}", NS)
                if el.text
            ]

        identifiers = _all("identifier")
        titles = _all("title")
        dates = _all("date")
        types = _all("type")
        creators = _all("creator")

        urn = next((i for i in identifiers if _URN_RE.match(i)), None)
        external_id = (
            (header.find("oai:identifier", NS).text or "").strip()
            if identifier_el is not None and identifier_el.text
            else (urn or (identifiers[0] if identifiers else None))
        )
        if not external_id:
            return None

        return {
            "external_id": external_id,
            "urn_lex": urn,
            "datestamp": datestamp_el.text.strip()
            if datestamp_el is not None and datestamp_el.text
            else None,
            "titulo": titles[0] if titles else "",
            "data": dates[0] if dates else None,
            "tipo": types[0] if types else None,
            "orgao": creators[0] if creators else None,
            "all_identifiers": identifiers,
        }

    def _build_observation(self, raw: dict[str, object]) -> AtlasObservation | None:
        external_id = raw.get("external_id")
        if not external_id:
            return None

        norma_tipo = self._infer_norma_tipo(raw.get("tipo"))
        observation_type = "norma" if norma_tipo or raw.get("urn_lex") else "documento_bruto"

        ref_date = self._parse_date(raw.get("datestamp") or raw.get("data"))

        urn_lex_raw = raw.get("urn_lex")
        urn_lex: str | None = urn_lex_raw if isinstance(urn_lex_raw, str) else None

        obs = AtlasObservation(
            source_id=self.SOURCE_ID,
            external_id=str(external_id),
            observation_type=observation_type,
            reference_date=ref_date,
            payload=dict(raw),
            data_classification=self.DEFAULT_CLASSIFICATION,
            orgao_publicador=raw.get("orgao") if isinstance(raw.get("orgao"), str) else None,
            norma_tipo=norma_tipo,
            urn_lex=urn_lex,
            tags=["fonte:lexml"],
        )

        titulo = raw.get("titulo")
        if isinstance(titulo, str) and titulo:
            obs.compute_text_hash(titulo)
        return obs

    @staticmethod
    def _infer_norma_tipo(dc_type: object) -> str | None:
        if not isinstance(dc_type, str) or not dc_type:
            return None
        key = dc_type.strip().lower()
        if key in _DC_TYPE_TO_NORMA:
            return _DC_TYPE_TO_NORMA[key]
        # Tenta substring (ex: "Lei Federal nº ..." → "lei")
        for token, tipo in _DC_TYPE_TO_NORMA.items():
            if token in key:
                return tipo
        return None

    @staticmethod
    def _parse_date(value: object) -> datetime:
        """Converte data ISO/OAI em datetime UTC; fallback = agora."""
        if isinstance(value, str) and value:
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y"):
                try:
                    dt = datetime.strptime(value, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return datetime.now(timezone.utc)
