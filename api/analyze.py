"""POST /api/analyze — AnomalyDetector (Z-score + Isolation Forest)."""
from http.server import BaseHTTPRequestHandler
import json
import numpy as np


def _classify_severity(excess: float) -> str:
    if excess >= 2.0:
        return "CRITICAL"
    if excess >= 1.0:
        return "HIGH"
    return "MEDIUM"


def _zscore(values: list, threshold: float = 3.0,
            historical_mean: float | None = None,
            historical_stddev: float | None = None) -> list:
    arr = np.array(values, dtype=float)
    mean = historical_mean if historical_mean is not None else float(arr.mean())
    std  = historical_stddev if historical_stddev is not None else float(arr.std())
    results = []
    for i, v in enumerate(values):
        z = 0.0 if std == 0 else (v - mean) / std
        is_anom = std > 0 and abs(z) > threshold
        excess = abs(z) - threshold if is_anom else 0.0
        results.append({
            "index": i,
            "value": round(float(v), 2),
            "z_score": round(z, 4),
            "is_anomaly": bool(is_anom),
            "severity": _classify_severity(excess) if is_anom else None,
            "anomaly_type": ("spike_up" if z > 0 else "spike_down") if is_anom else None,
        })
    return results


def _isolation_forest(values: list) -> list:
    from sklearn.ensemble import IsolationForest
    arr = np.array(values, dtype=float).reshape(-1, 1)
    clf = IsolationForest(contamination=0.05, random_state=42)
    preds = clf.fit_predict(arr)
    scores = clf.score_samples(arr)
    results = []
    for i, (v, pred, sc) in enumerate(zip(values, preds, scores)):
        is_anom = bool(pred == -1)
        abs_sc = abs(float(sc))
        sev = ("CRITICAL" if abs_sc > 0.3 else "HIGH" if abs_sc > 0.2 else "MEDIUM") if is_anom else None
        results.append({
            "index": i,
            "value": round(float(v), 2),
            "z_score": round(float(sc), 4),
            "is_anomaly": is_anom,
            "severity": sev,
            "anomaly_type": "isolation_forest" if is_anom else None,
        })
    return results


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            values = [float(x) for x in body.get("values", [])]
            method = body.get("method", "zscore")
            threshold = float(body.get("threshold", 3.0))

            if len(values) < 3:
                raise ValueError("Mínimo 3 valores necessários.")

            hist_mean = body.get("historical_mean")
            hist_std  = body.get("historical_stddev")
            if method == "isolation_forest":
                results = _isolation_forest(values)
            else:
                results = _zscore(values, threshold,
                                  historical_mean=hist_mean,
                                  historical_stddev=hist_std)
            anomalies = [r for r in results if r["is_anomaly"]]
            self._respond({"results": results, "anomaly_count": len(anomalies), "method": method})
        except Exception as exc:
            self._respond({"error": str(exc)}, 400)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _respond(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass
