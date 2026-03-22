"""
Conector INPE BDQueimadas — API REST de focos de calor.

BDQueimadas fornece dados de focos de calor detectados por satélites,
incluindo FRP (Fire Radiative Power), temperatura de brilho e risco de fogo.

API: REST JSON com autenticação Bearer (INPE_API_KEY).
URL: https://queimadas.dgi.inpe.br/api
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from atlantico.config.settings import get_settings
from atlantico.geoint.connectors.base import (
    ConnectorAuthError,
    ConnectorError,
    ConnectorParseError,
    GeointConnector,
    retry_with_backoff,
)
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)


class INPEBDQueimadasConnector(GeointConnector):
    """Conector INPE BDQueimadas (focos de calor / queimadas)."""

    SOURCE_ID = "inpe.bdqueimadas.v1"
    DEFAULT_CLASSIFICATION = "PUBLIC"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        bbox: tuple[float, float, float, float],
    ) -> list[GeointObservation]:
        """
        Busca focos de calor desde `since` dentro de `bbox`.

        Endpoint: GET /focos com parâmetros de data e bbox.
        """
        settings = get_settings()
        min_lon, min_lat, max_lon, max_lat = bbox
        now = datetime.now(tz=timezone.utc)

        headers: dict[str, str] = {}
        if settings.inpe_api_key:
            headers["Authorization"] = f"Bearer {settings.inpe_api_key}"

        params = {
            "startDate": since.strftime("%Y-%m-%d %H:%M"),
            "endDate": now.strftime("%Y-%m-%d %H:%M"),
            "latMin": min_lat,
            "latMax": max_lat,
            "longMin": min_lon,
            "longMax": max_lon,
            "outputFormat": "json",
        }

        try:
            resp = await self.client.get(
                f"{settings.inpe_bdqueimadas_url}/focos",
                params=params,
                headers=headers,
            )
        except Exception as exc:
            raise ConnectorError(f"BDQueimadas: falha de rede: {exc}") from exc

        if resp.status_code == 401:
            raise ConnectorAuthError(
                "BDQueimadas: autenticação falhou. Verifique ATLANTICO_INPE_API_KEY."
            )
        if resp.status_code != 200:
            raise ConnectorError(
                f"BDQueimadas: resposta inesperada HTTP {resp.status_code}"
            )

        try:
            data = resp.json()
        except Exception as exc:
            raise ConnectorParseError(
                f"BDQueimadas: JSON inválido: {exc}"
            ) from exc

        # A API pode retornar lista direta ou dict com "features"
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = data.get("features") or data.get("data") or data.get("focos") or []
        else:
            records = []

        observations = []
        for rec in records:
            obs = self._parse_record(rec)
            if obs is not None:
                observations.append(obs)

        logger.info(
            "BDQueimadas: %d focos desde %s (bbox=%s)",
            len(observations),
            since.isoformat(),
            bbox,
        )
        return observations

    def _parse_record(self, rec: dict) -> GeointObservation | None:
        try:
            lat = float(rec.get("latitude") or rec.get("lat") or 0)
            lon = float(rec.get("longitude") or rec.get("lon") or 0)
        except (TypeError, ValueError):
            return None

        if lat == 0 and lon == 0:
            return None

        # Timestamp de aquisição
        datahora = rec.get("datahora") or rec.get("data_hora_gmt") or rec.get("data")
        try:
            if datahora and "T" in str(datahora):
                acquired_at = datetime.fromisoformat(str(datahora)).replace(
                    tzinfo=timezone.utc
                )
            elif datahora:
                acquired_at = datetime.strptime(
                    str(datahora)[:16], "%Y-%m-%d %H:%M"
                ).replace(tzinfo=timezone.utc)
            else:
                acquired_at = datetime.now(tz=timezone.utc)
        except Exception:
            acquired_at = datetime.now(tz=timezone.utc)

        # External ID determinístico
        rec_id = rec.get("id") or rec.get("id_foco") or rec.get("uuid")
        if rec_id:
            external_id = f"bdqueimadas-{rec_id}"
        else:
            ts = acquired_at.strftime("%Y%m%d%H%M")
            external_id = f"bdqueimadas-{ts}-{lat:.4f}-{lon:.4f}"

        geometry_wkt = f"POINT({lon} {lat})"
        bbox_wkt = self._point_to_bbox_wkt(lon, lat)

        payload = {
            "latitude": lat,
            "longitude": lon,
            "datahora": str(datahora or ""),
            "municipio": rec.get("municipio") or rec.get("municipio_id"),
            "estado": rec.get("estado"),
            "pais": rec.get("pais", "Brasil"),
            "bioma": rec.get("bioma"),
            "satelite": rec.get("satelite") or rec.get("satellite"),
            "numero_dias_sem_chuva": rec.get("numero_dias_sem_chuva"),
            "precipitacao": rec.get("precipitacao"),
            "risco_fogo": rec.get("risco_fogo"),
            "frp": rec.get("frp"),
            "brightness": rec.get("brightness") or rec.get("brilho"),
            "confidence": rec.get("confidence") or rec.get("confianca"),
        }

        return GeointObservation(
            source_id=self.SOURCE_ID,
            external_id=external_id,
            observation_type="fire_hotspot",
            acquired_at=acquired_at,
            geometry_wkt=geometry_wkt,
            payload=payload,
            data_classification=self.DEFAULT_CLASSIFICATION,
            bbox_wkt=bbox_wkt,
        )

    async def health_check(self) -> bool:
        try:
            settings = get_settings()
            resp = await self.client.get(
                settings.inpe_bdqueimadas_url,
                timeout=10.0,
            )
            return resp.status_code in (200, 404)  # 404 no root ainda é up
        except Exception:
            return False
