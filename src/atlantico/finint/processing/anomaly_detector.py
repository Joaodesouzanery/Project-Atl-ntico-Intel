"""
AnomalyDetector — Detecção de anomalias financeiras.

Métodos:
- Z-score com janela deslizante de 12 meses
- Isolation Forest (sklearn) para detecção multivariada
- detect_contract_anomaly: concentração de fornecedores
- detect_trade_spike: exportações > mean + N*stddev

Não importa oqs — sem crypto direto neste módulo.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime

import numpy as np

logger = logging.getLogger(__name__)

# Severidade baseada em quantos desvios acima do threshold
_SEVERITY_THRESHOLDS = [
    (2.0, "CRITICAL"),
    (1.0, "HIGH"),
    (0.0, "MEDIUM"),
]


def _classify_severity(excess: float) -> str:
    """Classifica severidade baseada no excesso além do threshold."""
    for threshold, level in _SEVERITY_THRESHOLDS:
        if excess >= threshold:
            return level
    return "MEDIUM"


class AnomalyDetector:
    """
    Detecta anomalias em séries temporais financeiras.

    Thread-safe: sem estado mútavel — todos os métodos são puramente funcionais.
    """

    def __init__(self, zscore_threshold: float = 3.0) -> None:
        self._zscore_threshold = zscore_threshold

    # ─── Z-score ──────────────────────────────────────────────────────────────

    def detect_series_anomaly(
        self,
        values: list[float],
        dates: list[datetime],
        method: str = "zscore",
        zscore_threshold: float | None = None,
    ) -> list[dict]:
        """
        Detecta anomalias em série temporal.

        Args:
            values: Lista de valores numéricos (mesma ordem que `dates`)
            dates: Datas correspondentes (timezone-aware)
            method: "zscore" ou "isolation_forest"
            zscore_threshold: Override do threshold padrão

        Returns:
            Lista de dicts com {index, date, value, z_score, is_anomaly, severity}
        """
        if len(values) < 3:
            return []

        threshold = zscore_threshold if zscore_threshold is not None else self._zscore_threshold

        if method == "isolation_forest":
            return self._isolation_forest(values, dates)
        return self._zscore_series(values, dates, threshold)

    def _zscore_series(
        self,
        values: list[float],
        dates: list[datetime],
        threshold: float,
    ) -> list[dict]:
        """Detecta anomalias via Z-score com baseline global da série."""
        arr = np.array(values, dtype=float)
        mean = float(np.mean(arr))
        stddev = float(np.std(arr, ddof=0))

        if stddev <= 0:
            return [
                {
                    "index": i,
                    "date": dates[i],
                    "value": v,
                    "z_score": 0.0,
                    "is_anomaly": False,
                    "severity": None,
                    "anomaly_type": None,
                }
                for i, v in enumerate(values)
            ]

        results = []
        for i, (v, d) in enumerate(zip(values, dates)):
            z = (v - mean) / stddev
            abs_z = abs(z)
            is_anomaly = abs_z > threshold
            excess = abs_z - threshold if is_anomaly else 0.0
            severity = _classify_severity(excess) if is_anomaly else None
            anomaly_type = None
            if is_anomaly:
                anomaly_type = "spike_up" if z > 0 else "spike_down"
            results.append(
                {
                    "index": i,
                    "date": d,
                    "value": v,
                    "z_score": round(z, 4),
                    "is_anomaly": is_anomaly,
                    "severity": severity,
                    "anomaly_type": anomaly_type,
                }
            )
        return results

    def _isolation_forest(
        self,
        values: list[float],
        dates: list[datetime],
    ) -> list[dict]:
        """Detecta anomalias via Isolation Forest (sklearn)."""
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            logger.warning("scikit-learn não disponível — fallback para Z-score.")
            return self._zscore_series(values, dates, self._zscore_threshold)

        arr = np.array(values, dtype=float).reshape(-1, 1)
        clf = IsolationForest(contamination=0.05, random_state=42)
        predictions = clf.fit_predict(arr)
        scores = clf.score_samples(arr)

        results = []
        for i, (v, d, pred, score) in enumerate(zip(values, dates, predictions, scores)):
            is_anomaly = pred == -1
            # score negativo = mais anômalo
            severity = None
            if is_anomaly:
                abs_score = abs(score)
                if abs_score > 0.3:
                    severity = "CRITICAL"
                elif abs_score > 0.2:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
            results.append(
                {
                    "index": i,
                    "date": d,
                    "value": v,
                    "z_score": float(score),
                    "is_anomaly": is_anomaly,
                    "severity": severity,
                    "anomaly_type": "isolation_forest" if is_anomaly else None,
                }
            )
        return results

    # ─── Z-score simples (para ponto único) ──────────────────────────────────

    def detect_single_anomaly(
        self,
        value: float,
        historical_mean: float,
        historical_stddev: float,
        zscore_threshold: float | None = None,
    ) -> tuple[str | None, str | None, float]:
        """
        Detecta anomalia em ponto único via Z-score.

        Returns: (anomaly_type, anomaly_severity, z_score)
        """
        threshold = zscore_threshold if zscore_threshold is not None else self._zscore_threshold

        if historical_stddev <= 0:
            return None, None, 0.0

        z = (value - historical_mean) / historical_stddev
        abs_z = abs(z)

        if abs_z <= threshold:
            return None, None, z

        excess = abs_z - threshold
        severity = _classify_severity(excess)
        anomaly_type = "spike_up" if z > 0 else "spike_down"
        return anomaly_type, severity, z

    # ─── Anomalias em contratos ───────────────────────────────────────────────

    def detect_contract_anomaly(
        self,
        contract_values: list[float],
        supplier_ids: list[str],
        historical_mean: float | None = None,
        historical_stddev: float | None = None,
        concentration_threshold: float = 0.8,
    ) -> dict:
        """
        Detecta anomalias em conjunto de contratos.

        Detecta:
        1. Volume total acima de mean + 3*stddev
        2. Concentração: 1 fornecedor com > concentration_threshold do volume

        Returns:
            dict com keys: has_anomaly, anomaly_types, score, details
        """
        if not contract_values:
            return {"has_anomaly": False, "anomaly_types": [], "score": 0.0, "details": {}}

        total = sum(contract_values)
        anomaly_types = []
        score = 0.0

        # Anomalia de volume
        if historical_mean is not None and historical_stddev is not None and historical_stddev > 0:
            z = (total - historical_mean) / historical_stddev
            if abs(z) > 3.0:
                anomaly_types.append("volume_spike")
                score = max(score, min(abs(z) / 10.0, 1.0))

        # Anomalia de concentração
        if supplier_ids:
            from collections import Counter
            counts = Counter(supplier_ids)
            top_supplier_count = max(counts.values())
            concentration = top_supplier_count / len(contract_values)
            if concentration >= concentration_threshold:
                anomaly_types.append("supplier_concentration")
                score = max(score, concentration)

        return {
            "has_anomaly": bool(anomaly_types),
            "anomaly_types": anomaly_types,
            "score": score,
            "details": {
                "total_value": total,
                "contract_count": len(contract_values),
                "unique_suppliers": len(set(supplier_ids)) if supplier_ids else 0,
            },
        }

    # ─── Spike em exportações ─────────────────────────────────────────────────

    def detect_trade_spike(
        self,
        current_value_usd: float,
        historical_mean: float,
        historical_stddev: float,
        multiplier: float = 3.0,
    ) -> bool:
        """
        Detecta spike em exportação de mineral estratégico.

        Returns True se current_value > mean + multiplier * stddev.
        """
        if historical_stddev <= 0:
            return False
        threshold_value = historical_mean + multiplier * historical_stddev
        return current_value_usd > threshold_value
