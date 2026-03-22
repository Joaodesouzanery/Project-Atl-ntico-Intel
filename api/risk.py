"""POST /api/risk — RiskScorer (score composto + flags)."""
from http.server import BaseHTTPRequestHandler
import json

_W_ANOMALY = 0.4
_W_CENTRALITY = 0.3
_W_GEO = 0.3
_HIGH_RISK_NCMS = {"7108", "7101", "7102"}


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def _geo_score(deforestation_ha: float, hotspot_count: int) -> float:
    if deforestation_ha > 500:
        defor = 1.0
    elif deforestation_ha > 100:
        defor = 0.6
    elif deforestation_ha > 10:
        defor = 0.3
    elif deforestation_ha > 0:
        defor = 0.1
    else:
        defor = 0.0

    if hotspot_count > 20:
        fire = 0.5
    elif hotspot_count > 5:
        fire = 0.3
    elif hotspot_count > 0:
        fire = 0.1
    else:
        fire = 0.0

    return _clamp(defor * 0.7 + fire * 0.3)


def _compute(body: dict) -> dict:
    anomaly_score = _clamp(float(body.get("anomaly_score", 0.0)))
    centrality_score = _clamp(float(body.get("centrality_score", 0.0)) * 100.0)
    deforestation_ha = float(body.get("deforestation_ha", 0.0))
    hotspot_count = int(body.get("hotspot_count", 0))
    ncm_code = str(body.get("ncm_code", ""))
    anomaly_types = body.get("anomaly_types", [])

    geo = _geo_score(deforestation_ha, hotspot_count)
    score = _clamp(_W_ANOMALY * anomaly_score + _W_CENTRALITY * centrality_score + _W_GEO * geo)

    if score >= 0.8:
        level = "CRITICAL"
    elif score >= 0.6:
        level = "HIGH"
    elif score >= 0.4:
        level = "MEDIUM"
    else:
        level = "LOW"

    flags = []
    if geo > 0.5:
        flags.append("garimpo_ilegal")
    if "supplier_concentration" in anomaly_types:
        flags.append("conta_laranja")
    if "spike_up" in anomaly_types and score > 0.7:
        flags.append("lavagem_dinheiro")
    if "isolation_forest" in anomaly_types:
        flags.append("comportamento_atipico")
    if ncm_code in _HIGH_RISK_NCMS and score > 0.5:
        flags.append("exportacao_mineral_suspeita")

    ncm_multiplier = 1.5 if ncm_code in _HIGH_RISK_NCMS else 1.0

    return {
        "risk_score": round(score, 4),
        "risk_level": level,
        "flags": flags,
        "components": {
            "anomaly": round(anomaly_score, 4),
            "centrality_normalized": round(centrality_score, 4),
            "geo_correlation": round(geo, 4),
        },
        "geo_detail": {
            "deforestation_ha": deforestation_ha,
            "hotspot_count": hotspot_count,
            "correlation_score": round(geo, 4),
        },
        "ncm_multiplier": ncm_multiplier,
    }


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            self._respond(_compute(body))
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
