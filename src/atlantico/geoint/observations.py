"""
GeointObservation — DTO compartilhado entre conectores e pipeline de ingestão.

Objeto puro Python (sem SQLAlchemy, sem crypto) que normaliza observações
geoespaciais de fontes heterogêneas para uma interface unificada.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class GeointObservation:
    """
    Observação geoespacial bruta retornada por um conector GEOINT.

    Campos:
        source_id:          Identificador canônico da fonte, ex: "inpe.deter.v1"
        external_id:        ID único do registro na fonte (para deduplication)
        observation_type:   Tipo semântico da observação:
                            "deforestation" | "fire_hotspot" | "water_gauge"
                            | "satellite_imagery" | "infrastructure"
        acquired_at:        Datetime UTC de aquisição (timezone-aware obrigatório)
        geometry_wkt:       Geometria em WKT, EPSG:4326, sem prefixo SRID
                            Ex: "POLYGON((-60 -10, -59 -10, ...))"
                                "POINT(-60.5 -12.3)"
        payload:            Dict com todos os campos brutos da fonte
        data_classification: Classificação padrão — "PUBLIC" | "RESTRICTED" | "CONFIDENTIAL"
        bbox_wkt:           Bounding box da geometria em WKT POLYGON.
                            Obrigatório para geometrias POINT (SourceRecord.geo_bounds é POLYGON).
                            O conector deve gerar um buffer mínimo de 0.001 grau ao redor do ponto.
    """

    source_id: str
    external_id: str
    observation_type: str
    acquired_at: datetime
    geometry_wkt: str
    payload: dict[str, Any]
    data_classification: str = "PUBLIC"
    bbox_wkt: str | None = None

    def __post_init__(self) -> None:
        if self.acquired_at.tzinfo is None:
            msg = (
                f"GeointObservation.acquired_at deve ser timezone-aware. "
                f"Recebido: {self.acquired_at!r} (sem tzinfo)."
            )
            raise ValueError(msg)

    @property
    def geo_bounds_wkt(self) -> str:
        """
        Retorna bbox_wkt se definido, caso contrário tenta usar geometry_wkt diretamente.
        SourceRecord.geo_bounds requer um POLYGON — conectores com geometria POINT
        DEVEM fornecer bbox_wkt com um buffer mínimo.
        """
        if self.bbox_wkt is not None:
            return self.bbox_wkt
        return self.geometry_wkt
