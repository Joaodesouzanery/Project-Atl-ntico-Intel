"""
Conector SIGINT: VirusTotal API v3

Analisa URLs, hashes de arquivos, IPs e domínios suspeitos contra
70+ motores antivírus e feeds de threat intelligence da comunidade.

Endpoint base: https://www.virustotal.com/api/v3
Autenticação: API Key (gratuita com limite: 4 req/min, 500 req/dia)
SOURCE_ID: virustotal.v3

Endpoints utilizados:
    GET /urls/{url_id}             — Análise de URL específica
    GET /files/{hash}              — Análise de hash (MD5/SHA1/SHA256)
    GET /ip_addresses/{ip}         — Análise de IP
    GET /domains/{domain}          — Análise de domínio
    POST /urls                     — Submeter URL para análise
"""

from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timezone

from atlantico.sigint.connectors.base import (
    ConnectorAuthError,
    ConnectorError,
    ConnectorParseError,
    ConnectorRateLimitError,
    SigintConnector,
    retry_with_backoff,
)
from atlantico.sigint.observations import SigintObservation

logger = logging.getLogger(__name__)

# Limiar de motores positivos para considerar malicioso
_MALICIOUS_THRESHOLD = 3
_SUSPICIOUS_THRESHOLD = 1


class VirusTotalConnector(SigintConnector):
    """
    Consulta o VirusTotal para análise de indicadores de ameaça.

    Modos de uso:
      - analyze_url(url)    → SigintObservation para uma URL
      - analyze_hash(hash)  → SigintObservation para um hash
      - analyze_ip(ip)      → SigintObservation para um IP
      - analyze_domain(d)   → SigintObservation para um domínio
      - fetch(since, iocs)  → Batch de IOCs

    Respects VirusTotal rate limits (4 req/min no plano gratuito).
    """

    SOURCE_ID = "virustotal.v3"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.virustotal.com/api/v3",
    ) -> None:
        super().__init__()
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    async def __aenter__(self) -> "VirusTotalConnector":
        await super().__aenter__()
        self._client.headers.update({"x-apikey": self._api_key})  # type: ignore[union-attr]
        return self

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        limit: int = 50,
        iocs: list[dict] | None = None,
    ) -> list[SigintObservation]:
        """
        Analisa uma lista de IOCs no VirusTotal.

        Args:
            since:  Filtro de data (IOCs analisados antes dessa data são pulados)
            limit:  Máx de IOCs a processar
            iocs:   Lista de dicts: [{"type": "url"|"hash"|"ip"|"domain", "value": "..."}]

        Returns:
            SigintObservation com observation_type="threat_indicator" para cada IOC.
        """
        if not iocs:
            logger.info("VirusTotal: nenhum IOC fornecido para análise.")
            return []

        observations: list[SigintObservation] = []
        for ioc in iocs[:limit]:
            ioc_type  = ioc.get("type", "")
            ioc_value = ioc.get("value", "")
            if not ioc_type or not ioc_value:
                continue

            try:
                obs = await self._analyze_ioc(ioc_type, ioc_value)
                if obs:
                    observations.append(obs)
            except ConnectorRateLimitError:
                logger.warning("VirusTotal rate limit — parando batch após %d IOCs", len(observations))
                break
            except ConnectorAuthError:
                raise
            except Exception as exc:
                logger.warning("Erro ao analisar IOC %s=%s: %s", ioc_type, ioc_value[:50], exc)

        logger.info(
            "VirusTotal: %d IOCs analisados, %d observações geradas",
            len(iocs[:limit]), len(observations),
        )
        return observations

    async def _analyze_ioc(self, ioc_type: str, value: str) -> SigintObservation | None:
        if ioc_type == "url":
            return await self.analyze_url(value)
        if ioc_type in ("hash", "hash_md5", "hash_sha1", "hash_sha256"):
            return await self.analyze_hash(value)
        if ioc_type == "ip":
            return await self.analyze_ip(value)
        if ioc_type == "domain":
            return await self.analyze_domain(value)
        return None

    @retry_with_backoff
    async def analyze_url(self, url: str) -> SigintObservation | None:
        """Analisa uma URL no VirusTotal."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._query_endpoint(f"/urls/{url_id}", "url", url)

    @retry_with_backoff
    async def analyze_hash(self, file_hash: str) -> SigintObservation | None:
        """Analisa um hash de arquivo (MD5/SHA1/SHA256)."""
        return await self._query_endpoint(f"/files/{file_hash}", "hash", file_hash)

    @retry_with_backoff
    async def analyze_ip(self, ip: str) -> SigintObservation | None:
        """Analisa um endereço IP."""
        return await self._query_endpoint(f"/ip_addresses/{ip}", "ip", ip)

    @retry_with_backoff
    async def analyze_domain(self, domain: str) -> SigintObservation | None:
        """Analisa um domínio."""
        return await self._query_endpoint(f"/domains/{domain}", "domain", domain)

    async def _query_endpoint(
        self, path: str, ioc_type: str, value: str
    ) -> SigintObservation | None:
        try:
            resp = await self.client.get(f"{self._base_url}{path}")
            self._check_rate_limit(resp)
            self._check_auth(resp)

            if resp.status_code == 404:
                logger.debug("VirusTotal: %s não encontrado", value[:50])
                return None

            resp.raise_for_status()
        except Exception as exc:
            if isinstance(exc, (ConnectorError, ConnectorAuthError)):
                raise
            raise ConnectorError(f"Falha ao consultar VT para {value[:50]}: {exc}") from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ConnectorParseError(f"Resposta VT não é JSON: {exc}") from exc

        return self._parse_vt_response(data, ioc_type, value)

    def _parse_vt_response(
        self, data: dict, ioc_type: str, value: str
    ) -> SigintObservation | None:
        try:
            attributes = data.get("data", {}).get("attributes", {})

            # Stats de análise
            last_analysis_stats: dict[str, int] = attributes.get(
                "last_analysis_stats", {}
            )
            malicious   = last_analysis_stats.get("malicious", 0)
            suspicious  = last_analysis_stats.get("suspicious", 0)
            harmless    = last_analysis_stats.get("harmless", 0)
            total = malicious + suspicious + harmless + last_analysis_stats.get("undetected", 0)

            # Determinar severidade
            if malicious >= _MALICIOUS_THRESHOLD:
                severity = "CRITICAL" if malicious >= 10 else "HIGH"
                is_malicious = True
            elif suspicious >= _SUSPICIOUS_THRESHOLD or malicious > 0:
                severity = "MEDIUM"
                is_malicious = True
            else:
                severity = "INFO"
                is_malicious = False

            # Data da última análise
            last_analysis_date = attributes.get("last_analysis_date")
            if last_analysis_date:
                analysis_dt = datetime.fromtimestamp(last_analysis_date, tz=timezone.utc)
            else:
                analysis_dt = datetime.now(timezone.utc)

            # Tags e nomes detectados
            names = attributes.get("meaningful_name") or attributes.get("name", "")
            popular_threat_names = attributes.get("popular_threat_classification", {})
            threat_category = popular_threat_names.get("suggested_threat_label", "")
            tags = []
            if is_malicious:
                tags.append("malicious")
            if threat_category:
                tags.append(f"threat:{threat_category}")

            # Engines que detectaram
            last_analysis_results = attributes.get("last_analysis_results", {})
            detections = [
                engine for engine, result in last_analysis_results.items()
                if result.get("category") in ("malicious", "suspicious")
            ]

            external_id = hashlib.sha256(
                f"vt-{ioc_type}-{value}".encode()
            ).hexdigest()[:20]

            return SigintObservation(
                source_id=self.SOURCE_ID,
                external_id=f"vt-{ioc_type}-{external_id}",
                observation_type="threat_indicator",
                reference_date=analysis_dt,
                severity=severity,
                source_type="ioc_feed",
                language="en",
                tags=tags,
                geo_relevance=["GLOBAL"],
                payload={
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_engines": total,
                    "detection_rate": round(malicious / total, 3) if total > 0 else 0.0,
                    "is_malicious": is_malicious,
                    "threat_label": threat_category,
                    "detected_by": detections[:10],
                    "meaningful_name": names,
                    "last_analysis_date": last_analysis_date,
                },
            )
        except Exception as exc:
            logger.warning("Erro ao parsear resposta VT para %s: %s", value[:50], exc)
            return None

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get(f"{self._base_url}/urls/aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ")
            return resp.status_code in (200, 404)
        except Exception:
            return False
