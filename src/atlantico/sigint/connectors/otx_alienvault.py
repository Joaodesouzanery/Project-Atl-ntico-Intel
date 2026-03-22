"""
Conector SIGINT: AlienVault OTX (Open Threat Exchange)

Plataforma colaborativa open source de threat intelligence.
Fornece IOCs (Indicators of Compromise) como IPs maliciosos,
domínios, hashes de malware e URLs suspeitas.

Endpoint base: https://otx.alienvault.com/api/v1
Autenticação:  API Key (gratuita — cadastro em otx.alienvault.com)
SOURCE_ID:     otx.alienvault.v1

Endpoints utilizados:
    GET /pulses/subscribed         — Pulses (feeds) dos quais o usuário está inscrito
    GET /pulses/{pulse_id}/indicators — IOCs de um pulse específico
    GET /indicators/export         — Export massivo de IOCs (requer auth)
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from atlantico.sigint.connectors.base import (
    ConnectorAuthError,
    ConnectorError,
    ConnectorParseError,
    SigintConnector,
    retry_with_backoff,
)
from atlantico.sigint.observations import SigintObservation

logger = logging.getLogger(__name__)

# Mapeamento: tipo OTX → tipo IOC canônico
_IOC_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "email": "email",
    "YARA": "yara_rule",
    "CVE": "cve",
    "CIDR": "cidr",
}

# Categorias OTX de alta relevância para o Projeto Atlântico
_HIGH_RELEVANCE_TAGS = {
    "ransomware", "apt", "espionage", "critical infrastructure",
    "supply chain", "government", "banking", "brazil", "latam",
}


class OtxAlienVaultConnector(SigintConnector):
    """
    Busca IOCs e threat intelligence da plataforma OTX AlienVault.

    Cada "pulse" do OTX corresponde a uma campanha/ameaça identificada
    pela comunidade. Cada pulse contém N indicadores (IOCs).
    """

    SOURCE_ID = "otx.alienvault.v1"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://otx.alienvault.com/api/v1",
        max_pulses: int = 20,
    ) -> None:
        super().__init__()
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._max_pulses = max_pulses

    async def __aenter__(self) -> "OtxAlienVaultConnector":
        await super().__aenter__()
        self._client.headers.update({"X-OTX-API-KEY": self._api_key})  # type: ignore[union-attr]
        return self

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        limit: int = 200,
    ) -> list[SigintObservation]:
        """
        Busca pulses e seus IOCs publicados/modificados desde `since`.

        Returns:
            SigintObservation com observation_type="threat_indicator" por IOC,
            e observation_type="cyber_threat" por pulse (campanha).
        """
        modified_since = since.strftime("%Y-%m-%dT%H:%M:%S")

        try:
            resp = await self.client.get(
                f"{self._base_url}/pulses/subscribed",
                params={"modified_since": modified_since, "limit": self._max_pulses},
            )
            self._check_rate_limit(resp)
            self._check_auth(resp)
            resp.raise_for_status()
        except Exception as exc:
            if isinstance(exc, (ConnectorError, ConnectorAuthError)):
                raise
            raise ConnectorError(f"Falha ao buscar pulses OTX: {exc}") from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ConnectorParseError(f"Resposta OTX não é JSON: {exc}") from exc

        observations: list[SigintObservation] = []
        for pulse in data.get("results", []):
            # Observação do pulse (campanha/ameaça)
            pulse_obs = self._parse_pulse(pulse)
            if pulse_obs:
                observations.append(pulse_obs)

            # Observações dos IOCs do pulse
            for ioc in pulse.get("indicators", [])[:50]:  # máx 50 IOCs por pulse
                ioc_obs = self._parse_indicator(pulse, ioc)
                if ioc_obs:
                    observations.append(ioc_obs)

        result = observations[:limit]
        logger.info(
            "OTX AlienVault: %d observações carregadas desde %s",
            len(result), since.date(),
        )
        return result

    def _parse_pulse(self, pulse: dict) -> SigintObservation | None:
        try:
            pulse_id    = pulse.get("id", "")
            name        = pulse.get("name", "")
            description = pulse.get("description", "")
            created_str = pulse.get("created", "")
            tags        = pulse.get("tags", [])
            tlp         = pulse.get("tlp", "white")
            industries  = pulse.get("industries", [])
            targeted    = pulse.get("targeted_countries", [])
            adversary   = pulse.get("adversary", "")
            malware_families = pulse.get("malware_families", [])

            if not pulse_id:
                return None

            try:
                created = datetime.fromisoformat(
                    created_str.replace("Z", "+00:00")
                )
            except Exception:
                created = datetime.now(timezone.utc)

            # Inferir severidade pelo TLP e tags
            severity = self._infer_pulse_severity(tags, tlp)

            # Tags consolidadas
            all_tags = list(tags) + industries
            if adversary:
                all_tags.append(f"apt:{adversary}")
            for mf in malware_families:
                all_tags.append(f"malware:{mf.get('display_name', '')}")

            geo_relevance = targeted if targeted else ["GLOBAL"]

            external_id = hashlib.sha256(pulse_id.encode()).hexdigest()[:20]

            return SigintObservation(
                source_id=self.SOURCE_ID,
                external_id=f"otx-pulse-{external_id}",
                observation_type="cyber_threat",
                reference_date=created,
                severity=severity,
                source_type="threat_intel",
                language="en",
                tags=all_tags,
                geo_relevance=geo_relevance,
                payload={
                    "pulse_id": pulse_id,
                    "name": name,
                    "description": description[:1000],
                    "tlp": tlp,
                    "adversary": adversary,
                    "malware_families": [mf.get("display_name") for mf in malware_families],
                    "indicator_count": pulse.get("indicator_count", 0),
                    "industries": industries,
                    "targeted_countries": targeted,
                    "references": pulse.get("references", [])[:10],
                },
            )
        except Exception as exc:
            logger.warning("Erro ao parsear pulse OTX %s: %s", pulse.get("id"), exc)
            return None

    def _parse_indicator(self, pulse: dict, indicator: dict) -> SigintObservation | None:
        try:
            ioc_type_raw = indicator.get("type", "")
            ioc_type     = _IOC_TYPE_MAP.get(ioc_type_raw, ioc_type_raw)
            ioc_value    = indicator.get("indicator", "")
            description  = indicator.get("description", "")
            created_str  = indicator.get("created", "")
            is_active    = indicator.get("is_active", 1)

            if not ioc_value or not is_active:
                return None

            try:
                created = datetime.fromisoformat(
                    created_str.replace("Z", "+00:00")
                )
            except Exception:
                created = datetime.now(timezone.utc)

            # Severity herdada do pulse
            severity = self._infer_pulse_severity(
                pulse.get("tags", []), pulse.get("tlp", "white")
            )

            external_id = hashlib.sha256(
                f"{pulse.get('id')}-{ioc_value}".encode()
            ).hexdigest()[:20]

            return SigintObservation(
                source_id=self.SOURCE_ID,
                external_id=f"otx-ioc-{external_id}",
                observation_type="threat_indicator",
                reference_date=created,
                severity=severity,
                source_type="ioc_feed",
                language="en",
                tags=[ioc_type, f"pulse:{pulse.get('id', '')}"],
                geo_relevance=pulse.get("targeted_countries", ["GLOBAL"]) or ["GLOBAL"],
                payload={
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "description": description,
                    "pulse_id": pulse.get("id", ""),
                    "pulse_name": pulse.get("name", ""),
                    "adversary": pulse.get("adversary", ""),
                    "confidence": self._tlp_to_confidence(pulse.get("tlp", "white")),
                },
            )
        except Exception as exc:
            logger.debug("Erro ao parsear IOC OTX: %s", exc)
            return None

    def _infer_pulse_severity(self, tags: list[str], tlp: str) -> str:
        tags_lower = {t.lower() for t in tags}
        if tags_lower & _HIGH_RELEVANCE_TAGS or tlp in ("red", "amber"):
            return "HIGH"
        if tlp == "green":
            return "MEDIUM"
        return "INFO"

    def _tlp_to_confidence(self, tlp: str) -> float:
        return {"white": 0.5, "green": 0.7, "amber": 0.85, "red": 0.95}.get(tlp, 0.5)

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get(f"{self._base_url}/user/me")
            return resp.status_code == 200
        except Exception:
            return False
