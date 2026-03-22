"""
Conector SIGINT: NIST NVD CVE API v2.0

Busca vulnerabilidades CVE publicadas/modificadas desde uma data, filtrando
por severidade mínima e palavras-chave de produtos relevantes.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Autenticação: API Key opcional (sem key: 5 req/30s; com key: 50 req/30s)
SOURCE_ID: nvd.cve.v2
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from atlantico.sigint.connectors.base import (
    ConnectorError,
    ConnectorParseError,
    SigintConnector,
    retry_with_backoff,
)
from atlantico.sigint.observations import SigintObservation

logger = logging.getLogger(__name__)

# NCMs de interesse do Projeto Atlântico para correlação
_KEYWORDS_OF_INTEREST = [
    "mining", "scada", "ics", "satellite", "gps", "gnss",
    "cryptography", "kyber", "dilithium", "post-quantum",
    "brazil", "governo", "government", "infrastructure",
]

# Técnicas MITRE ATT&CK mapeadas por palavras-chave no CVE
_MITRE_KEYWORD_MAP: dict[str, str] = {
    "remote code execution": "T1059",
    "sql injection": "T1190",
    "cross-site scripting": "T1059.007",
    "privilege escalation": "T1068",
    "buffer overflow": "T1203",
    "deserialization": "T1059",
    "authentication bypass": "T1078",
    "path traversal": "T1083",
    "ssrf": "T1090",
    "xxe": "T1190",
    "command injection": "T1059",
    "cryptographic weakness": "T1600",
    "weak encryption": "T1600",
    "denial of service": "T1499",
    "use after free": "T1203",
    "memory corruption": "T1203",
}


class NvdCveConnector(SigintConnector):
    """
    Busca CVEs na API NVD do NIST.

    Retorna vulnerabilidades com CVSS ≥ min_cvss_score publicadas ou
    modificadas desde `since`. Mapeia automaticamente técnicas MITRE ATT&CK
    com base na descrição do CVE.
    """

    SOURCE_ID = "nvd.cve.v2"

    def __init__(
        self,
        api_key: str | None = None,
        min_cvss_score: float = 7.0,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
    ) -> None:
        super().__init__()
        self._api_key = api_key
        self._min_cvss = min_cvss_score
        self._base_url = base_url

    async def __aenter__(self) -> "NvdCveConnector":
        await super().__aenter__()
        if self._api_key:
            self._client.headers.update({"apiKey": self._api_key})  # type: ignore[union-attr]
        return self

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        limit: int = 100,
    ) -> list[SigintObservation]:
        """
        Busca CVEs publicadas/modificadas desde `since`.

        Args:
            since: Data de início (timezone-aware UTC)
            limit: Máx CVEs a retornar

        Returns:
            Lista de SigintObservation com observation_type="cyber_threat"
        """
        pub_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": min(limit, 2000),
            "startIndex": 0,
        }
        if self._min_cvss >= 0:
            params["cvssV3Severity"] = self._cvss_threshold_to_param()

        try:
            response = await self.client.get(self._base_url, params=params)
            self._check_rate_limit(response)
            self._check_auth(response)
            response.raise_for_status()
        except Exception as exc:
            if isinstance(exc, (ConnectorError,)):
                raise
            raise ConnectorError(f"Falha ao buscar CVEs do NVD: {exc}") from exc

        try:
            data = response.json()
        except Exception as exc:
            raise ConnectorParseError(f"Resposta NVD não é JSON válido: {exc}") from exc

        observations: list[SigintObservation] = []
        for item in data.get("vulnerabilities", []):
            obs = self._parse_cve(item)
            if obs:
                observations.append(obs)

        logger.info(
            "NVD CVE: %d vulnerabilidades carregadas (CVSS ≥ %.1f) desde %s",
            len(observations), self._min_cvss, since.date(),
        )
        return observations

    def _cvss_threshold_to_param(self) -> str:
        if self._min_cvss >= 9.0:
            return "CRITICAL"
        if self._min_cvss >= 7.0:
            return "HIGH"
        if self._min_cvss >= 4.0:
            return "MEDIUM"
        return "LOW"

    def _parse_cve(self, item: dict) -> SigintObservation | None:
        try:
            cve = item.get("cve", {})
            cve_id: str = cve.get("id", "")
            if not cve_id:
                return None

            # Data de publicação
            pub_date_str = cve.get("published", "")
            try:
                pub_date = datetime.fromisoformat(
                    pub_date_str.replace("Z", "+00:00")
                )
                if pub_date.tzinfo is None:
                    pub_date = pub_date.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                pub_date = datetime.now(timezone.utc)

            # Descrição em inglês (fallback para pt)
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                next((d["value"] for d in descriptions), "Sem descrição"),
            )

            # CVSS v3.1 score
            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                if metrics.get("cvssMetricV31")
                else metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                if metrics.get("cvssMetricV30")
                else {}
            )
            cvss_score: float = float(cvss_data.get("baseScore", 0.0))
            cvss_vector: str = cvss_data.get("vectorString", "")
            attack_vector: str = cvss_data.get("attackVector", "UNKNOWN")

            # Filtro de severidade mínima
            if cvss_score < self._min_cvss:
                return None

            severity = self._cvss_to_severity(cvss_score)

            # CWEs
            weaknesses = cve.get("weaknesses", [])
            cwes = [
                d["value"]
                for w in weaknesses
                for d in w.get("description", [])
                if d.get("lang") == "en"
            ]

            # Produtos afetados (CPE)
            configs = cve.get("configurations", [])
            affected_products: list[str] = []
            for config in configs:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            affected_products.append(cpe_match.get("criteria", ""))

            # Referências
            references = [
                ref.get("url", "") for ref in cve.get("references", [])
            ]

            # MITRE ATT&CK mapping via keywords
            mitre_techniques = self._map_mitre_techniques(description)

            # Tags de relevância
            tags = self._extract_tags(description, cwes)

            # Geo relevance: CVEs em infraestrutura brasileira
            geo_relevance = self._infer_geo_relevance(description, affected_products)

            # external_id deterministico
            external_id = hashlib.sha256(cve_id.encode()).hexdigest()[:16]

            return SigintObservation(
                source_id=self.SOURCE_ID,
                external_id=f"{cve_id}-{external_id}",
                observation_type="cyber_threat",
                reference_date=pub_date,
                severity=severity,
                source_type="cve_feed",
                language="en",
                tags=tags,
                geo_relevance=geo_relevance,
                payload={
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "attack_vector": attack_vector,
                    "cwes": cwes,
                    "affected_products": affected_products[:20],
                    "references": references[:10],
                    "mitre_techniques": mitre_techniques,
                    "modified": cve.get("lastModified", ""),
                },
            )
        except Exception as exc:
            logger.warning("Erro ao parsear CVE: %s — %s", item.get("cve", {}).get("id"), exc)
            return None

    def _map_mitre_techniques(self, description: str) -> list[str]:
        desc_lower = description.lower()
        techniques = [
            technique
            for keyword, technique in _MITRE_KEYWORD_MAP.items()
            if keyword in desc_lower
        ]
        return list(set(techniques))

    def _extract_tags(self, description: str, cwes: list[str]) -> list[str]:
        tags: list[str] = list(cwes)
        desc_lower = description.lower()
        if any(k in desc_lower for k in ["remote", "network", "internet"]):
            tags.append("remote_exploitable")
        if "no authentication" in desc_lower or "unauthenticated" in desc_lower:
            tags.append("no_auth_required")
        if any(k in desc_lower for k in _KEYWORDS_OF_INTEREST):
            tags.append("atlantico_relevante")
        return tags

    def _infer_geo_relevance(
        self, description: str, products: list[str]
    ) -> list[str]:
        relevance = ["GLOBAL"]
        desc_lower = description.lower()
        combined = desc_lower + " ".join(products).lower()
        if any(k in combined for k in ["brazil", "brasil", "governo", "petrobras"]):
            relevance.append("BR")
        if any(k in combined for k in ["latin", "latam", "south america"]):
            relevance.append("LATAM")
        return relevance

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get(
                self._base_url,
                params={"resultsPerPage": 1, "startIndex": 0},
            )
            return resp.status_code == 200
        except Exception:
            return False
