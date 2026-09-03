import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = DATA_DIR / "stats.json"
        if not path.is_file():
            body = b'{"error": "stats not found"}'
            self.send_response(404)
        else:
            body = path.read_bytes()
            self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass
