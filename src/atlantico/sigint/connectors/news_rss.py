"""
Conector SIGINT: News RSS / Atom Feeds

Monitora feeds RSS/Atom de fontes de segurança, notícias geopolíticas
e análise de desinformação. Parseia XML sem dependências externas.

Feeds padrão monitorados:
  - Krebs on Security (segurança geral)
  - Bleeping Computer (malware/incidentes)
  - The Hacker News (vulnerabilidades/exploits)
  - CISA Alerts (US-CERT alertas operacionais)
  - Agência Brasil (notícias nacionais em PT-BR)
  - Aos Fatos / Lupa (checagem de fatos BR)

SOURCE_ID: news.rss.v1
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

# Feeds padrão: nome → (url, categoria, language, geo)
DEFAULT_FEEDS: dict[str, tuple[str, str, str, list[str]]] = {
    "krebs_security": (
        "https://krebsonsecurity.com/feed/",
        "security_news", "en", ["GLOBAL"],
    ),
    "bleeping_computer": (
        "https://www.bleepingcomputer.com/feed/",
        "security_news", "en", ["GLOBAL"],
    ),
    "the_hacker_news": (
        "https://feeds.feedburner.com/TheHackersNews",
        "security_news", "en", ["GLOBAL"],
    ),
    "cisa_alerts": (
        "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "cert_advisory", "en", ["US", "GLOBAL"],
    ),
    "agencia_brasil": (
        "https://agenciabrasil.ebc.com.br/rss/politica/feed.xml",
        "news", "pt", ["BR"],
    ),
}

# Keywords que indicam conteúdo relevante para SIGINT
_CYBER_KEYWORDS = {
    "en": [
        "ransomware", "malware", "exploit", "vulnerability", "breach",
        "zero-day", "phishing", "apt", "attack", "hacker", "cyber",
        "backdoor", "botnet", "spyware", "trojan", "data leak",
    ],
    "pt": [
        "ataque", "invasão", "vazamento", "ransomware", "vírus",
        "fraude", "golpe", "phishing", "desinformação", "fake news",
        "espionagem", "hacker", "vulnerabilidade", "cibersegurança",
    ],
}

# Keywords de desinformação/narrativa
_DISINFO_KEYWORDS = {
    "en": [
        "disinformation", "fake news", "propaganda", "manipulation",
        "deepfake", "influence operation", "narrative", "bot network",
        "coordinated inauthentic", "astroturfing",
    ],
    "pt": [
        "desinformação", "fake news", "propaganda", "manipulação",
        "deepfake", "operação de influência", "narrativa falsa",
        "robôs", "bot", "notícia falsa", "boato",
    ],
}

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NewsRssConnector(SigintConnector):
    """
    Monitora feeds RSS/Atom de segurança e notícias para SIGINT.

    Classifica automaticamente artigos como cyber_threat ou news_item,
    detecta menções a CVEs, e sinaliza possível conteúdo de desinformação.
    """

    SOURCE_ID = "news.rss.v1"

    def __init__(
        self,
        feeds: dict[str, tuple[str, str, str, list[str]]] | None = None,
        custom_feeds: dict[str, tuple[str, str, str, list[str]]] | None = None,
    ) -> None:
        super().__init__()
        self._feeds = feeds or DEFAULT_FEEDS.copy()
        if custom_feeds:
            self._feeds.update(custom_feeds)

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        limit: int = 200,
    ) -> list[SigintObservation]:
        """
        Busca artigos de todos os feeds RSS configurados desde `since`.

        Returns:
            Lista de SigintObservation com observation_type="news_item" ou
            "cyber_threat" dependendo do conteúdo.
        """
        observations: list[SigintObservation] = []
        seen_ids: set[str] = set()

        for feed_name, (url, category, lang, geo) in self._feeds.items():
            try:
                feed_obs = await self._fetch_feed(feed_name, url, category, lang, geo, since)
                for obs in feed_obs:
                    if obs.external_id not in seen_ids:
                        seen_ids.add(obs.external_id)
                        observations.append(obs)
            except ConnectorError:
                raise
            except Exception as exc:
                logger.warning("Feed RSS '%s' falhou: %s", feed_name, exc)

        observations.sort(key=lambda o: o.reference_date, reverse=True)
        result = observations[:limit]

        logger.info(
            "News RSS: %d artigos carregados de %d feeds desde %s",
            len(result), len(self._feeds), since.date(),
        )
        return result

    async def _fetch_feed(
        self,
        feed_name: str,
        url: str,
        category: str,
        lang: str,
        geo: list[str],
        since: datetime,
    ) -> list[SigintObservation]:
        try:
            resp = await self.client.get(url)
            self._check_rate_limit(resp)
            resp.raise_for_status()
        except Exception as exc:
            if isinstance(exc, ConnectorError):
                raise
            raise ConnectorError(f"Falha ao buscar feed '{feed_name}': {exc}") from exc

        try:
            return self._parse_feed_xml(
                feed_name, resp.text, category, lang, geo, since
            )
        except Exception as exc:
            raise ConnectorParseError(
                f"Erro ao parsear feed '{feed_name}': {exc}"
            ) from exc

    def _parse_feed_xml(
        self,
        feed_name: str,
        xml_text: str,
        category: str,
        lang: str,
        geo: list[str],
        since: datetime,
    ) -> list[SigintObservation]:
        # Limpar namespaces para simplicidade
        xml_clean = re.sub(r' xmlns(?::\w+)?="[^"]*"', "", xml_text)
        xml_clean = re.sub(r"<\?[^>]+\?>", "", xml_clean)

        try:
            root = ET.fromstring(xml_clean)
        except ET.ParseError:
            logger.warning("XML inválido no feed '%s'", feed_name)
            return []

        observations: list[SigintObservation] = []

        # Suporta RSS (item) e Atom (entry)
        items = root.findall(".//item") or root.findall(".//entry")

        for item in items:
            obs = self._parse_item(item, feed_name, category, lang, geo, since)
            if obs:
                observations.append(obs)

        return observations

    def _parse_item(
        self,
        item: ET.Element,
        feed_name: str,
        category: str,
        lang: str,
        geo: list[str],
        since: datetime,
    ) -> SigintObservation | None:
        def text(tag: str) -> str:
            el = item.find(tag)
            return (el.text or "").strip() if el is not None else ""

        title       = text("title")
        link        = text("link") or text("id")
        description = text("description") or text("summary") or text("content")
        pub_date_str = text("pubDate") or text("published") or text("updated")

        if not title:
            return None

        # Parse data
        try:
            if pub_date_str:
                try:
                    pub_date = parsedate_to_datetime(pub_date_str)
                except Exception:
                    pub_date = datetime.fromisoformat(
                        pub_date_str.replace("Z", "+00:00")
                    )
                if pub_date.tzinfo is None:
                    pub_date = pub_date.replace(tzinfo=timezone.utc)
                pub_date = pub_date.astimezone(timezone.utc)
            else:
                pub_date = datetime.now(timezone.utc)
        except Exception:
            pub_date = datetime.now(timezone.utc)

        if pub_date < since:
            return None

        full_text = f"{title} {description}"

        # Classificar tipo de observação
        obs_type, severity, tags = self._classify_content(full_text, lang, category)

        # CVEs mencionados
        cve_ids = list(set(_CVE_PATTERN.findall(full_text)))
        if cve_ids:
            tags.extend(cve_ids)
            obs_type = "cyber_threat"

        tags.append(feed_name)
        tags.append(category)

        # Detectar possível desinformação
        is_disinfo = self._detect_disinfo_signals(full_text, lang)
        if is_disinfo:
            tags.append("disinfo_signal")

        # External ID
        id_source = link or f"{feed_name}-{title}"
        external_id = hashlib.sha256(id_source.encode()).hexdigest()[:20]

        return SigintObservation(
            source_id=self.SOURCE_ID,
            external_id=f"news-{feed_name}-{external_id}",
            observation_type=obs_type,
            reference_date=pub_date,
            severity=severity,
            source_type=category,
            language=lang,
            tags=list(set(tags)),
            geo_relevance=geo,
            payload={
                "title": title,
                "link": link,
                "description": description[:2000],
                "feed": feed_name,
                "cve_ids": cve_ids,
                "is_disinfo_signal": is_disinfo,
                "pub_date": pub_date_str,
            },
        )

    def _classify_content(
        self, text: str, lang: str, category: str
    ) -> tuple[str, str, list[str]]:
        text_lower = text.lower()
        tags: list[str] = []

        cyber_kws = _CYBER_KEYWORDS.get(lang, _CYBER_KEYWORDS["en"])
        matched = [kw for kw in cyber_kws if kw in text_lower]

        if category == "cert_advisory" or len(matched) >= 3:
            obs_type = "cyber_threat"
            severity = "HIGH" if len(matched) >= 5 else "MEDIUM"
        elif len(matched) >= 1:
            obs_type = "cyber_threat"
            severity = "LOW"
        else:
            obs_type = "news_item"
            severity = "INFO"

        tags.extend(matched[:5])
        return obs_type, severity, tags

    def _detect_disinfo_signals(self, text: str, lang: str) -> bool:
        text_lower = text.lower()
        disinfo_kws = _DISINFO_KEYWORDS.get(lang, _DISINFO_KEYWORDS["en"])
        matches = sum(1 for kw in disinfo_kws if kw in text_lower)
        return matches >= 2

    async def health_check(self) -> bool:
        for _, (url, *_) in self._feeds.items():
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200:
                    return True
            except Exception:
                continue
        return False
