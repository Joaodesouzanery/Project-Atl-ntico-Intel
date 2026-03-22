"""GET / — Serve o dashboard HTML via Python (evita problema de static files no Vercel)."""
from http.server import BaseHTTPRequestHandler
import os


def _load_html() -> bytes:
    """Lê o _dashboard.html empacotado junto com a função Lambda."""
    # _dashboard.html fica em api/ — mesmo diretório desta função
    # Vercel inclui todos os arquivos de api/ no bundle da Lambda
    candidates = [
        os.path.join(os.path.dirname(__file__), "_dashboard.html"),
        os.path.join(os.path.dirname(__file__), "..", "index.html"),
        os.path.join(os.path.dirname(__file__), "..", "public", "index.html"),
    ]
    for path in candidates:
        try:
            with open(os.path.normpath(path), "rb") as f:
                return f.read()
        except FileNotFoundError:
            continue
    # Fallback mínimo se o arquivo não for encontrado
    return b"<html><body><p>Dashboard: <a href='/api/demo'>Demo JSON</a> | <a href='/api/health'>Health</a></p></body></html>"


_HTML_CONTENT = _load_html()


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_HTML_CONTENT)))
        self.send_header("Cache-Control", "public, max-age=60")
        self.end_headers()
        self.wfile.write(_HTML_CONTENT)

    def log_message(self, *_):
        pass
