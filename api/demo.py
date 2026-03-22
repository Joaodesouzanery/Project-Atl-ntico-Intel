"""GET /api/demo — Cenário completo Operação Altamira Gold."""
from http.server import BaseHTTPRequestHandler
import json

# Série BCB SGS 13522 — Exportações de Ouro (US$ milhões, simulado)
# 24 meses: Jan/2023 → Dez/2024
_GOLD_EXPORTS = [
    120, 135, 128, 142, 118, 130,   # Jan–Jun 2023 (normal)
    125, 138, 132, 145, 122, 140,   # Jul–Dez 2023 (normal)
    130, 125, 135, 128, 142, 138,   # Jan–Jun 2024 (normal)
    145, 152,                        # Jul–Ago 2024 (início da escalada)
    890, 1240, 980, 820,             # Set–Dez 2024 ← SPIKE (6–9× a média)
]

_DEFORESTATION_HA = [
    38, 45, 52, 40, 35, 48,         # Jan–Jun 2023
    55, 42, 60, 38, 50, 45,         # Jul–Dez 2023
    40, 55, 48, 62, 38, 52,         # Jan–Jun 2024
    68, 75,                          # Jul–Ago 2024
    720, 890, 650, 580,              # Set–Dez 2024 ← CORRELAÇÃO COM OURO
]

_MONTHS = [
    "Jan/23", "Fev/23", "Mar/23", "Abr/23", "Mai/23", "Jun/23",
    "Jul/23", "Ago/23", "Set/23", "Out/23", "Nov/23", "Dez/23",
    "Jan/24", "Fev/24", "Mar/24", "Abr/24", "Mai/24", "Jun/24",
    "Jul/24", "Ago/24", "Set/24", "Out/24", "Nov/24", "Dez/24",
]

_NETWORK_EDGES = [
    {"from": "MINERADORA ALTAMIRA PA", "to": "OURO NEGRO AM ME",        "value": 2_500_000, "type": "fornecedor"},
    {"from": "MINERADORA ALTAMIRA PA", "to": "EXPORTADORA RORAIMA SA",  "value": 1_800_000, "type": "exportador"},
    {"from": "MINERADORA ALTAMIRA PA", "to": "CONSULTORIA FONSECA",     "value": 900_000,   "type": "fornecedor"},
    {"from": "MINERADORA ALTAMIRA PA", "to": "COOPERATIVA OURO VERDE",  "value": 650_000,   "type": "fornecedor"},
    {"from": "OURO NEGRO AM ME",       "to": "FUNDO AMAZÔNIA INVEST",   "value": 1_200_000, "type": "sócio"},
    {"from": "EXPORTADORA RORAIMA SA", "to": "FUNDO AMAZÔNIA INVEST",   "value": 800_000,   "type": "sócio"},
    {"from": "CONSULTORIA FONSECA",    "to": "OURO NEGRO AM ME",        "value": 500_000,   "type": "contratante"},
    {"from": "MUNICÍPIO ALTAMIRA",     "to": "CONSULTORIA FONSECA",     "value": 650_000,   "type": "contratante"},
    {"from": "COOPERATIVA OURO VERDE", "to": "MINERADORA ALTAMIRA PA",  "value": 300_000,   "type": "fornecedor"},
]

_ENTITY_TYPES = {
    "MINERADORA ALTAMIRA PA": "empresa",
    "OURO NEGRO AM ME":       "empresa",
    "EXPORTADORA RORAIMA SA": "empresa",
    "CONSULTORIA FONSECA":    "empresa",
    "COOPERATIVA OURO VERDE": "empresa",
    "FUNDO AMAZÔNIA INVEST":  "fundo",
    "MUNICÍPIO ALTAMIRA":     "municipio",
}

_DEMO = {
    "scenario": "Operação Altamira Gold",
    "state": "PA",
    "municipality": "Altamira",
    "municipality_code": "1500602",
    "ncm_code": "7108",
    "ncm_desc": "Ouro (incluindo ouro platinado)",
    "months": _MONTHS,
    "gold_exports_usd_m": _GOLD_EXPORTS,
    "deforestation_ha": _DEFORESTATION_HA,
    "network_edges": _NETWORK_EDGES,
    "entity_types": _ENTITY_TYPES,
    "baseline": {
        "mean": 133.4,
        "stddev": 8.2,
        "spike_months": ["Set/24", "Out/24", "Nov/24", "Dez/24"],
    },
    "risk": {
        "score": 0.93,
        "level": "CRITICAL",
        "flags": ["garimpo_ilegal", "lavagem_dinheiro", "exportacao_mineral_suspeita"],
        "geo_correlation": 0.91,
        "deforestation_ha_peak": 890,
        "hotspot_count_peak": 34,
    },
    "alert": {
        "alert_id": "finint-garimpo-PA-202409",
        "rule_id": "finint.cross_module.garimpo_signal.v1",
        "severity": "CRITICAL",
        "title": "[GARIMPO] Correlação desflorestamento + exportação ouro em PA",
        "description": (
            "Correlação detectada em PA: desmatamento de 890 ha (Set/24–Dez/24) "
            "coincide com spike de exportação de ouro (NCM 7108): US$ 1.24B "
            "(9.2σ acima da média). Score de correlação GEOINT: 0.91. "
            "Alerta prioritário — notificar IBAMA/PRF/PGR."
        ),
        "occurred_at": "2024-09-01T00:00:00Z",
        "signed": False,
        "note": "Assinatura Dilithium3+Ed25519 requer stack Railway completo.",
    },
}


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond(_DEMO)

    def _respond(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass
