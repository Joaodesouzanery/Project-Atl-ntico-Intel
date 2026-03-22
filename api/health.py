"""GET /api/health — liveness check do demo Vercel."""
from http.server import BaseHTTPRequestHandler
import json
import sys


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = {
            "status": "ok",
            "demo": True,
            "python": sys.version.split()[0],
            "modules": {
                "numpy": _try_import("numpy"),
                "sklearn": _try_import("sklearn"),
                "networkx": _try_import("networkx"),
            },
            "note": "PQC/PostGIS/Celery requerem Railway (stack completo).",
        }
        self._respond(payload)

    def _respond(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def _try_import(name: str) -> str:
    try:
        mod = __import__(name)
        return getattr(mod, "__version__", "ok")
    except ImportError:
        return "unavailable"
