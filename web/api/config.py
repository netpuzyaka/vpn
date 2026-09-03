import base64
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        fmt = (qs.get("format") or ["txt"])[0].lower()
        protos = [p.lower() for p in qs.get("protocol") or qs.get("protocols") or []]

        if fmt in ("clash", "yaml", "yml"):
            path = DATA_DIR / "clash.yaml"
            ctype = "text/yaml; charset=utf-8"
            encode_b64 = False
        elif fmt in ("b64", "base64"):
            path = DATA_DIR / "unified_config.txt"
            ctype = "text/plain; charset=utf-8"
            encode_b64 = True
        else:
            path = DATA_DIR / "unified_config.txt"
            ctype = "text/plain; charset=utf-8"
            encode_b64 = False

        if not path.is_file():
            body = b"config not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        text = path.read_text(encoding="utf-8")
        if protos and not encode_b64:
            links = [l for l in text.splitlines() if l.lower().split("://", 1)[0] in protos]
            text = "\n".join(links)
        body = text.encode("utf-8")
        if encode_b64:
            body = base64.b64encode(body).rstrip(b"=")

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "public, max-age=600")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass
