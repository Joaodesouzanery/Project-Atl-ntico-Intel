"""
WaterProcessor — detecção de anomalias em observações hídricas.

Algoritmos:
- Z-score vs. histórico (PostgreSQL AVG + STDDEV via WaterRepository)
- Detecção de variação rápida (numpy.gradient)
- Classificação: drought | flood | extreme_precipitation | rapid_change
"""

from __future__ import annotations

import logging

import numpy as np

from atlantico.geoint.models.water import WaterObservation

logger = logging.getLogger(__name__)


class WaterProcessor:
    """
    Algoritmos de detecção de anomalias hídricas.

    Stateless — recebe observações e estatísticas históricas,
    retorna resultados calculados (caller persiste via WaterRepository).
    """

    def detect_anomaly(
        self,
        value: float,
        measurement_type: str,
        historical_mean: float,
        historical_stddev: float,
        stddev_threshold: float = 3.0,
    ) -> tuple[str | None, str | None, float]:
        """
        Detecta anomalia em um valor de observação por Z-score.

        Args:
            value:             Valor observado
            measurement_type:  "nivel" | "vazao" | "chuva"
            historical_mean:   Média histórica do mesmo período/estação
            historical_stddev: Desvio padrão histórico
            stddev_threshold:  Número de desvios-padrão para anomalia (padrão: 3σ)

        Returns:
            Tupla (anomaly_type, anomaly_severity, z_score)
            anomaly_type é None se dentro do threshold.

        Classificação de severity:
            [threshold, threshold+1) → MEDIUM
            [threshold+1, threshold+2) → HIGH
            >= threshold+2 → CRITICAL
        """
        if historical_stddev is None or historical_stddev <= 0:
            return None, None, 0.0

        z_score = (value - historical_mean) / historical_stddev

        if abs(z_score) < stddev_threshold:
            return None, None, z_score

        # Tipo de anomalia
        anomaly_type = self._classify_anomaly_type(z_score, measurement_type)
        anomaly_severity = self._classify_severity(abs(z_score), stddev_threshold)

        return anomaly_type, anomaly_severity, z_score

    def _classify_anomaly_type(
        self,
        z_score: float,
        measurement_type: str,
    ) -> str:
        """Classifica o tipo de anomalia com base no Z-score e tipo de medição."""
        if measurement_type in ("nivel", "vazao"):
            if z_score > 0:
                return "flood"
            return "drought"
        elif measurement_type == "chuva":
            if z_score > 0:
                return "extreme_precipitation"
            return "drought"
        return "anomaly"

    def _classify_severity(
        self,
        abs_z: float,
        threshold: float,
    ) -> str:
        """Classifica severidade pela distância do Z-score do threshold."""
        excess = abs_z - threshold
        if excess >= 2.0:
            return "CRITICAL"
        if excess >= 1.0:
            return "HIGH"
        return "MEDIUM"

    def detect_rapid_change(
        self,
        observations: list[WaterObservation],
        window_hours: int = 6,
        change_pct_threshold: float = 50.0,
    ) -> bool:
        """
        Detecta variação rápida de nível ou vazão em uma janela temporal.

        Usa numpy.gradient na série temporal de valores.
        Retorna True se a taxa máxima de variação excede change_pct_threshold%.

        Args:
            observations: Lista de WaterObservation ordenada por tempo
            window_hours: Janela de análise em horas
            change_pct_threshold: Variação percentual máxima tolerada por hora

        Returns:
            True se variação rápida detectada.
        """
        if len(observations) < 3:
            return False

        # Ordena por acquired_at
        sorted_obs = sorted(observations, key=lambda o: o.acquired_at)

        times_h = np.array([
            (o.acquired_at - sorted_obs[0].acquired_at).total_seconds() / 3600.0
            for o in sorted_obs
        ], dtype=float)
        values = np.array([float(o.value) for o in sorted_obs], dtype=float)

        if np.any(values == 0):
            return False  # Evita divisão por zero

        # Gradiente em unidades/hora
        gradient = np.gradient(values, times_h)

        # Variação percentual por hora em relação ao valor médio
        mean_val = np.mean(values)
        if mean_val == 0:
            return False

        max_pct_change = float(np.max(np.abs(gradient)) / mean_val * 100)
        return max_pct_change > change_pct_threshold

    def analyze_observation(
        self,
        obs: WaterObservation,
        historical_mean: float | None,
        historical_stddev: float | None,
        stddev_threshold: float = 3.0,
    ) -> dict:
        """
        Análise completa de uma observação hídrica.

        Returns:
            Dict com z_score, anomaly_type, anomaly_severity,
            historical_mean, historical_stddev, has_anomaly
        """
        if historical_mean is None or historical_stddev is None:
            return {
                "z_score": None,
                "anomaly_type": None,
                "anomaly_severity": None,
                "historical_mean": None,
                "historical_stddev": None,
                "has_anomaly": False,
            }

        anomaly_type, anomaly_severity, z_score = self.detect_anomaly(
            value=float(obs.value),
            measurement_type=obs.measurement_type,
            historical_mean=historical_mean,
            historical_stddev=historical_stddev,
            stddev_threshold=stddev_threshold,
        )

        return {
            "z_score": z_score,
            "anomaly_type": anomaly_type,
            "anomaly_severity": anomaly_severity,
            "historical_mean": historical_mean,
            "historical_stddev": historical_stddev,
            "has_anomaly": anomaly_type is not None,
        }
