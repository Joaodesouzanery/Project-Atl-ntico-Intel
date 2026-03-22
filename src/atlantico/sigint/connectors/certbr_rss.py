"""
Conector SIGINT: CERT.br RSS Feeds

Monitora alertas e avisos de segurança publicados pelo CERT.br
(Centro de Estudos, Resposta e Tratamento de Incidentes de Segurança no Brasil).

Feeds disponíveis:
  - Alertas:  https://www.cert.br/rss/alertas.rdf
  - Avisos:   https://www.cert.br/rss/avisos.rdf
  - Notícias: https://www.cert.br/rss/noticias.rdf

Autenticação: Pública (sem necessidade de API key)
SOURCE_ID: certbr.rss.v1
"""

from __future__ import annotations

import hashlib
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from atlantico.sigint.connectors.base import (
    ConnectorError,
    ConnectorParseError,
    SigintConnector,
    retry_with_backoff,
)
from atlantico.sigint.observations import SigintObservation

logger = logging.getLogger(__name__)

_CERT_FEEDS = {
    "alertas": "https://www.cert.br/rss/alertas.rdf",
    "avisos":  "https://www.cert.br/rss/avisos.rdf",
    "noticias": "https://www.cert.br/rss/noticias.rdf",
}

# Regex para extrair CVE IDs de texto livre
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Palavras-chave de alta severidade (PT-BR)
_HIGH_SEVERITY_KEYWORDS = [
    "crítico", "crítica", "emergência", "urgente", "ransomware",
    "zero-day", "0-day", "exploit", "comprometimento", "vazamento",
    "ataque direcionado", "apt", "incidente grave",
]
_MEDIUM_SEVERITY_KEYWORDS = [
    "alerta", "vulnerabilidade", "patch", "atualização", "falha",
    "brecha", "backdoor", "phishing", "malware",
]


class CertBrRssConnector(SigintConnector):
    """
    Busca alertas de segurança do CERT.br via RSS/RDF.

    Parseia XML RDF/RSS sem dependências externas, usando stdlib.
    Detecta CVEs mencionados nos textos e infere severidade por keywords.
    """

    SOURCE_ID = "certbr.rss.v1"

    def __init__(
        self,
        feeds: list[str] | None = None,
        base_urls: dict[str, str] | None = None,
    ) -> None:
        super().__init__()
        self._feeds = feeds or list(_CERT_FEEDS.keys())
        self._base_urls = base_urls or _CERT_FEEDS.copy()

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        limit: int = 100,
    ) -> list[SigintObservation]:
        """
        Busca alertas/avisos do CERT.br publicados desde `since`.

        Processa todos os feeds configurados e retorna observações únicas
        (por hash do link/título).
        """
        observations: list[SigintObservation] = []
        seen_ids: set[str] = set()

        for feed_name in self._feeds:
            url = self._base_urls.get(feed_name)
            if not url:
                continue
            try:
                feed_obs = await self._fetch_feed(feed_name, url, since)
                for obs in feed_obs:
                    if obs.external_id not in seen_ids:
                        seen_ids.add(obs.external_id)
                        observations.append(obs)
            except ConnectorError:
                raise
            except Exception as exc:
                logger.warning("Erro ao buscar feed CERT.br '%s': %s", feed_name, exc)

        observations.sort(key=lambda o: o.reference_date, reverse=True)
        result = observations[:limit]

        logger.info(
            "CERT.br: %d alertas carregados desde %s",
            len(result), since.date(),
        )
        return result

    async def _fetch_feed(
        self,
        feed_name: str,
        url: str,
        since: datetime,
    ) -> list[SigintObservation]:
        try:
            response = await self.client.get(url)
            self._check_rate_limit(response)
            response.raise_for_status()
        except Exception as exc:
            if isinstance(exc, ConnectorError):
                raise
            raise ConnectorError(
                f"Falha ao buscar feed CERT.br '{feed_name}': {exc}"
            ) from exc

        try:
            return self._parse_rdf(feed_name, response.text, since)
        except Exception as exc:
            raise ConnectorParseError(
                f"Erro ao parsear RDF do CERT.br '{feed_name}': {exc}"
            ) from exc

    def _parse_rdf(
        self, feed_name: str, xml_text: str, since: datetime
    ) -> list[SigintObservation]:
        # Remove XML declaration (must be stripped before wrapping in <root>)
        xml_clean = re.sub(r"<\?xml[^?]*\?>", "", xml_text)
        # Remove namespaces para simplificar parsing
        xml_clean = re.sub(r' xmlns[^"]*"[^"]*"', "", xml_clean)
        xml_clean = re.sub(r"</?rdf:[^>]*>", "", xml_clean)

        try:
            root = ET.fromstring(xml_clean)
        except ET.ParseError:
            # Tenta com texto bruto
            root = ET.fromstring(f"<root>{xml_clean}</root>")

        observations: list[SigintObservation] = []

        for item in root.iter("item"):
            obs = self._parse_item(feed_name, item, since)
            if obs:
                observations.append(obs)

        return observations

    def _parse_item(
        self, feed_name: str, item: ET.Element, since: datetime
    ) -> SigintObservation | None:
        def text(tag: str) -> str:
            el = item.find(tag)
            return (el.text or "").strip() if el is not None else ""

        title       = text("title")
        link        = text("link")
        description = text("description")
        pub_date_str = text("pubDate") or text("date")

        if not title or not link:
            return None

        # Parse data de publicação
        try:
            if pub_date_str:
                pub_date = parsedate_to_datetime(pub_date_str)
                if pub_date.tzinfo is None:
                    pub_date = pub_date.replace(tzinfo=timezone.utc)
                pub_date = pub_date.astimezone(timezone.utc)
            else:
                pub_date = datetime.now(timezone.utc)
        except Exception:
            pub_date = datetime.now(timezone.utc)

        # Filtrar por data
        if pub_date < since:
            return None

        # Extrair CVEs do texto
        full_text = f"{title} {description}"
        cve_ids = list(set(_CVE_PATTERN.findall(full_text)))

        # Inferir severidade
        severity = self._infer_severity(full_text)

        # Tags
        tags = [feed_name]
        if cve_ids:
            tags.extend(cve_ids)
        if "ransomware" in full_text.lower():
            tags.append("ransomware")
        if "phishing" in full_text.lower():
            tags.append("phishing")

        # External ID determinístico
        external_id = hashlib.sha256(link.encode()).hexdigest()[:20]

        return SigintObservation(
            source_id=self.SOURCE_ID,
            external_id=f"certbr-{feed_name}-{external_id}",
            observation_type="cyber_threat",
            reference_date=pub_date,
            severity=severity,
            source_type="cert_advisory",
            language="pt",
            tags=tags,
            geo_relevance=["BR"],
            payload={
                "title": title,
                "link": link,
                "description": description[:2000],
                "feed": feed_name,
                "cve_ids": cve_ids,
                "pub_date": pub_date_str,
            },
        )

    def _infer_severity(self, text: str) -> str:
        text_lower = text.lower()
        if any(kw in text_lower for kw in _HIGH_SEVERITY_KEYWORDS):
            return "HIGH"
        if any(kw in text_lower for kw in _MEDIUM_SEVERITY_KEYWORDS):
            return "MEDIUM"
        return "INFO"

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get(_CERT_FEEDS["alertas"])
            return resp.status_code == 200
        except Exception:
            return False
