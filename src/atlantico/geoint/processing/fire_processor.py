"""
FireProcessor — clustering DBSCAN e análise de intensidade de focos de calor.

Algoritmos:
- DBSCAN com métrica haversine (sklearn) para agrupamento geoespacial
- FRP intensity statistics (numpy)
- Severity classification por tamanho do cluster e FRP total
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import numpy as np
from shapely.geometry import MultiPoint, Point

from atlantico.geoint.models.fire import FireCluster, FireHotspot

logger = logging.getLogger(__name__)

# Raio da Terra em km para conversão de distância DBSCAN → radianos
_EARTH_RADIUS_KM = 6371.0


class FireProcessor:
    """
    Algoritmos de clustering e análise para focos de calor.

    Stateless — não acessa banco de dados.
    """

    # Limiares de severity por hotspot_count
    SEVERITY_COUNT_THRESHOLDS = {
        "CRITICAL": 50,
        "HIGH": 15,
        "MEDIUM": 5,
    }
    # FRP total mínimo para elevar a CRITICAL independente do count
    FRP_CRITICAL_MW = 1000.0

    def cluster_hotspots(
        self,
        hotspots: list[FireHotspot],
        eps_km: float,
        min_samples: int,
        cluster_run_id: str | None = None,
    ) -> list[FireCluster]:
        """
        Aplica DBSCAN haversine para agrupar focos de calor em clusters.

        Args:
            hotspots:       Lista de FireHotspot com coordenadas WGS-84
            eps_km:         Raio de vizinhança em km (convertido para radianos)
            min_samples:    Mínimo de pontos para formar um cluster
            cluster_run_id: UUID do run (gerado se None)

        Returns:
            Lista de FireCluster (não persistidos — caller persiste).
            Focos de ruído (label=-1) são excluídos.
        """
        if not hotspots:
            return []

        if cluster_run_id is None:
            cluster_run_id = str(uuid.uuid4())

        try:
            from sklearn.cluster import DBSCAN
        except ImportError:
            logger.error(
                "scikit-learn não instalado. Instale: pip install scikit-learn>=1.5.0"
            )
            return []

        # Extrai coordenadas como array numpy em radianos (haversine requer radianos)
        coords = np.array([
            [self._get_lat(h), self._get_lon(h)]
            for h in hotspots
        ], dtype=float)
        coords_rad = np.radians(coords)

        # eps em radianos: eps_km / R_terra
        eps_rad = eps_km / _EARTH_RADIUS_KM

        db = DBSCAN(
            eps=eps_rad,
            min_samples=min_samples,
            metric="haversine",
            algorithm="ball_tree",
        ).fit(coords_rad)

        labels = db.labels_
        unique_labels = set(labels) - {-1}  # Exclui ruído

        clusters: list[FireCluster] = []
        for label in unique_labels:
            mask = labels == label
            cluster_hotspots = [h for h, m in zip(hotspots, mask) if m]
            cluster = self._build_cluster(
                hotspots=cluster_hotspots,
                cluster_run_id=cluster_run_id,
            )
            clusters.append(cluster)

        logger.info(
            "DBSCAN: %d focos → %d clusters (eps=%.1f km, min_samples=%d)",
            len(hotspots),
            len(clusters),
            eps_km,
            min_samples,
        )
        return clusters

    def _build_cluster(
        self,
        hotspots: list[FireHotspot],
        cluster_run_id: str,
    ) -> FireCluster:
        """Constrói um FireCluster a partir de um grupo de hotspots."""
        lats = [self._get_lat(h) for h in hotspots]
        lons = [self._get_lon(h) for h in hotspots]

        # Geometrias via shapely
        points = MultiPoint([Point(lon, lat) for lon, lat in zip(lons, lats)])
        centroid = points.centroid
        convex_hull = points.convex_hull

        centroid_wkt = f"SRID=4326;POINT({centroid.x} {centroid.y})"
        hull_wkt = f"SRID=4326;{convex_hull.wkt}" if convex_hull.geom_type != "Point" else None

        # FRP statistics
        frp_values = np.array(
            [float(h.frp) for h in hotspots if h.frp is not None],
            dtype=float,
        )
        total_frp = float(np.sum(frp_values)) if len(frp_values) > 0 else None
        max_frp = float(np.max(frp_values)) if len(frp_values) > 0 else None
        mean_frp = float(np.mean(frp_values)) if len(frp_values) > 0 else None

        # Temporalidade
        times = [h.acquired_at for h in hotspots if h.acquired_at]
        min_time = min(times) if times else datetime.now(tz=timezone.utc)
        max_time = max(times) if times else datetime.now(tz=timezone.utc)

        # Moda de biome e state
        biome = self._mode_value([h.biome for h in hotspots if h.biome])
        state = self._mode_value([h.state for h in hotspots if h.state])

        # Severity
        severity = self.classify_cluster_severity(
            hotspot_count=len(hotspots),
            total_frp_mw=total_frp,
        )

        cluster = FireCluster(
            cluster_run_id=cluster_run_id,
            hotspot_count=len(hotspots),
            centroid_geom=centroid_wkt,
            convex_hull=hull_wkt,
            total_frp_mw=total_frp,
            max_frp_mw=max_frp,
            mean_frp_mw=mean_frp,
            min_acquired_at=min_time,
            max_acquired_at=max_time,
            biome=biome,
            state=state,
            severity=severity,
            near_infrastructure=False,
            infra_asset_ids=[],
            analysis_status="pending",
        )
        return cluster

    def classify_cluster_severity(
        self,
        hotspot_count: int,
        total_frp_mw: float | None,
    ) -> str:
        """
        Classifica severidade do cluster.

        CRITICAL se hotspot_count >= 50 OU total_frp_mw >= 1000 MW.
        """
        if (
            hotspot_count >= self.SEVERITY_COUNT_THRESHOLDS["CRITICAL"]
            or (total_frp_mw is not None and total_frp_mw >= self.FRP_CRITICAL_MW)
        ):
            return "CRITICAL"
        if hotspot_count >= self.SEVERITY_COUNT_THRESHOLDS["HIGH"]:
            return "HIGH"
        if hotspot_count >= self.SEVERITY_COUNT_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        return "LOW"

    def compute_frp_intensity(
        self,
        hotspots: list[FireHotspot],
    ) -> dict:
        """
        Estatísticas de FRP para um conjunto de focos.

        Returns:
            Dict com mean, std, p95, sum, classification
            classification: "low" | "moderate" | "high" | "extreme"
        """
        frp_values = np.array(
            [float(h.frp) for h in hotspots if h.frp is not None],
            dtype=float,
        )

        if len(frp_values) == 0:
            return {
                "mean": None,
                "std": None,
                "p95": None,
                "sum": None,
                "count_with_frp": 0,
                "classification": "unknown",
            }

        mean = float(np.mean(frp_values))
        std = float(np.std(frp_values))
        p95 = float(np.percentile(frp_values, 95))
        total = float(np.sum(frp_values))

        # Classificação por FRP médio em MW
        if mean >= 500:
            classification = "extreme"
        elif mean >= 100:
            classification = "high"
        elif mean >= 20:
            classification = "moderate"
        else:
            classification = "low"

        return {
            "mean": mean,
            "std": std,
            "p95": p95,
            "sum": total,
            "count_with_frp": len(frp_values),
            "classification": classification,
        }

    def detect_frp_growth(
        self,
        hotspots: list[FireHotspot],
    ) -> float | None:
        """
        Detecta crescimento temporal de FRP usando numpy.gradient.

        Retorna a taxa de crescimento de FRP por hora (MW/h).
        None se dados insuficientes.
        """
        # Filtra hotspots com FRP e acquired_at válidos
        data = [
            (h.acquired_at, float(h.frp))
            for h in hotspots
            if h.frp is not None and h.acquired_at is not None
        ]

        if len(data) < 3:
            return None

        data.sort(key=lambda x: x[0])
        times_h = np.array([
            (t - data[0][0]).total_seconds() / 3600.0
            for t, _ in data
        ], dtype=float)
        frp_values = np.array([v for _, v in data], dtype=float)

        gradient = np.gradient(frp_values, times_h)
        # Retorna gradiente médio (tendência geral)
        return float(np.mean(gradient))

    @staticmethod
    def _get_lat(hotspot: FireHotspot) -> float:
        """Extrai latitude do hotspot (da geometria WKT ou do objeto)."""
        # O campo geom é uma string WKT "SRID=4326;POINT(lon lat)" ou objeto
        if hotspot.geom is not None:
            geom_str = str(hotspot.geom)
            if "POINT" in geom_str:
                import re
                match = re.search(r"POINT\s*\(\s*([-\d.]+)\s+([-\d.]+)\s*\)", geom_str)
                if match:
                    return float(match.group(2))  # lat é o segundo valor
        return 0.0

    @staticmethod
    def _get_lon(hotspot: FireHotspot) -> float:
        """Extrai longitude do hotspot."""
        if hotspot.geom is not None:
            geom_str = str(hotspot.geom)
            if "POINT" in geom_str:
                import re
                match = re.search(r"POINT\s*\(\s*([-\d.]+)\s+([-\d.]+)\s*\)", geom_str)
                if match:
                    return float(match.group(1))  # lon é o primeiro valor
        return 0.0

    @staticmethod
    def _mode_value(values: list[str]) -> str | None:
        """Retorna o valor mais frequente em uma lista."""
        if not values:
            return None
        from collections import Counter
        return Counter(values).most_common(1)[0][0]
