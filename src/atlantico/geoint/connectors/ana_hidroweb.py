"""
Conector ANA HidroWeb — API REST de dados hidrológicos.

HidroWeb fornece leituras de estações fluviométricas e pluviométricas
do Sistema Nacional de Informações sobre Recursos Hídricos (SNIRH).

API: REST JSON — acesso público, sem autenticação.
URL: https://www.snirh.gov.br/hidroweb/rest/api

Dados fornecidos:
- Nível d'água (cota) em cm
- Vazão em m³/s
- Precipitação em mm
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from atlantico.config.settings import get_settings
from atlantico.geoint.connectors.base import (
    ConnectorError,
    ConnectorParseError,
    GeointConnector,
    retry_with_backoff,
)
from atlantico.geoint.observations import GeointObservation

logger = logging.getLogger(__name__)

# Estações estratégicas monitoradas (expandível via BD de InfrastructureAsset)
# Formato: (codigo_estacao, nome, lat, lon, bacia)
_STRATEGIC_STATIONS = [
    # Bacia do Rio Paraná / Itaipu
    ("65290000", "Foz do Iguaçu", -25.5574, -54.5910, "Paraná"),
    # Rio Xingu / Belo Monte
    ("40100000", "Altamira", -3.2033, -52.2111, "Xingu"),
    # Rio Madeira / Santo Antônio e Jirau
    ("15900000", "Porto Velho", -8.7608, -63.9025, "Madeira"),
    # Rio Negro / Manaus
    ("14100000", "Manaus", -3.1190, -60.0217, "Negro"),
    # Rio São Francisco
    ("46998000", "Sobradinho", -9.4242, -40.8308, "São Francisco"),
    # Rio Tocantins / Serra da Mesa e Tucuruí
    ("49910000", "Cana Brava", -13.9517, -48.3483, "Tocantins"),
]


class ANAHidroWebConnector(GeointConnector):
    """Conector ANA HidroWeb (estações fluviométricas e pluviométricas)."""

    SOURCE_ID = "ana.hidroweb.v1"
    DEFAULT_CLASSIFICATION = "PUBLIC"

    @retry_with_backoff
    async def fetch(
        self,
        since: datetime,
        bbox: tuple[float, float, float, float],
    ) -> list[GeointObservation]:
        """
        Busca leituras de estações HidroWeb dentro de `bbox` desde `since`.

        Estratégia:
        1. Busca estações dentro da bbox
        2. Para estações estratégicas conhecidas, busca leituras direto
        3. Para bbox nova, busca lista de estações via API
        """
        min_lon, min_lat, max_lon, max_lat = bbox
        observations: list[GeointObservation] = []

        # Filtra estações estratégicas dentro da bbox
        stations_in_bbox = [
            s for s in _STRATEGIC_STATIONS
            if min_lat <= s[2] <= max_lat and min_lon <= s[3] <= max_lon
        ]

        if not stations_in_bbox:
            # Tenta buscar via API (se não há estações estratégicas na bbox)
            stations_in_bbox = await self._fetch_stations_in_bbox(bbox)

        since_date = since.strftime("%Y-%m-%d")
        now_date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

        for station in stations_in_bbox:
            station_code = station[0] if isinstance(station, tuple) else station.get("codigo")
            station_name = station[1] if isinstance(station, tuple) else station.get("nome", "")
            lat = station[2] if isinstance(station, tuple) else float(station.get("latitude", 0))
            lon = station[3] if isinstance(station, tuple) else float(station.get("longitude", 0))

            readings = await self._fetch_readings(
                station_code=station_code,
                station_name=station_name,
                lat=lat,
                lon=lon,
                since_date=since_date,
                until_date=now_date,
            )
            observations.extend(readings)

        logger.info(
            "HidroWeb: %d leituras de %d estações desde %s",
            len(observations),
            len(stations_in_bbox),
            since_date,
        )
        return observations

    async def _fetch_stations_in_bbox(
        self,
        bbox: tuple[float, float, float, float],
    ) -> list[dict]:
        """Busca lista de estações dentro da bbox via API HidroWeb."""
        settings = get_settings()
        min_lon, min_lat, max_lon, max_lat = bbox

        try:
            resp = await self.client.get(
                f"{settings.ana_hidroweb_url}/estacao/list",
                params={
                    "latMin": min_lat,
                    "latMax": max_lat,
                    "lonMin": min_lon,
                    "lonMax": max_lon,
                    "tpEst": 1,  # Tipo 1 = fluviométrica
                    "statusEstacao": 2,  # Ativas
                },
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            return data if isinstance(data, list) else data.get("items", [])
        except Exception:
            return []

    async def _fetch_readings(
        self,
        station_code: str,
        station_name: str,
        lat: float,
        lon: float,
        since_date: str,
        until_date: str,
    ) -> list[GeointObservation]:
        """Busca leituras de telemetria para uma estação."""
        settings = get_settings()

        try:
            resp = await self.client.get(
                f"{settings.ana_hidroweb_url}/observation/telemetry",
                params={
                    "codEstacao": station_code,
                    "dataInicio": since_date,
                    "dataFim": until_date,
                },
            )
        except Exception as exc:
            raise ConnectorError(
                f"HidroWeb: falha ao buscar estação {station_code}: {exc}"
            ) from exc

        if resp.status_code != 200:
            logger.debug(
                "HidroWeb: estação %s retornou HTTP %d", station_code, resp.status_code
            )
            return []

        try:
            data = resp.json()
        except Exception as exc:
            raise ConnectorParseError(
                f"HidroWeb: JSON inválido para estação {station_code}: {exc}"
            ) from exc

        readings = data if isinstance(data, list) else data.get("items", [])
        observations = []

        for reading in readings:
            obs = self._parse_reading(reading, station_code, station_name, lat, lon)
            if obs is not None:
                observations.append(obs)

        return observations

    def _parse_reading(
        self,
        reading: dict,
        station_code: str,
        station_name: str,
        lat: float,
        lon: float,
    ) -> GeointObservation | None:
        data_str = reading.get("data") or reading.get("dataHora") or reading.get("date")
        if not data_str:
            return None

        try:
            acquired_at = datetime.fromisoformat(
                str(data_str).replace("Z", "+00:00")
            )
            if acquired_at.tzinfo is None:
                acquired_at = acquired_at.replace(tzinfo=timezone.utc)
        except Exception:
            return None

        # Determina tipo de medição e valor
        cota = reading.get("cota") or reading.get("nivel")
        vazao = reading.get("vazao") or reading.get("discharge")
        chuva = reading.get("chuva") or reading.get("rainfall")

        # Prioridade: nivel > vazao > chuva
        if cota is not None:
            measurement_type = "nivel"
            value = float(cota)
            unit = "cm"
        elif vazao is not None:
            measurement_type = "vazao"
            value = float(vazao)
            unit = "m3/s"
        elif chuva is not None:
            measurement_type = "chuva"
            value = float(chuva)
            unit = "mm"
        else:
            return None

        # Qualidade do dado (1=bruto, 2=consistido)
        data_quality = int(reading.get("nivelConsistencia") or 1)

        ts = acquired_at.strftime("%Y%m%d%H%M")
        external_id = f"hidroweb-{station_code}-{measurement_type}-{ts}"
        geometry_wkt = f"POINT({lon} {lat})"
        bbox_wkt = self._point_to_bbox_wkt(lon, lat)

        payload = {
            "station_code": station_code,
            "station_name": station_name,
            "latitude": lat,
            "longitude": lon,
            "measurement_type": measurement_type,
            "value": value,
            "unit": unit,
            "data_quality": data_quality,
            "cota": cota,
            "vazao": vazao,
            "chuva": chuva,
            "data": str(data_str),
        }

        return GeointObservation(
            source_id=self.SOURCE_ID,
            external_id=external_id,
            observation_type="water_gauge",
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
                settings.ana_hidroweb_url,
                timeout=10.0,
            )
            return resp.status_code in (200, 404)
        except Exception:
            return False
