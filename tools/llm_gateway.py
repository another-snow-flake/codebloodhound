"""Authenticated gateway in front of a local Ollama server.

Ollama has no authentication, so it must never be exposed directly. This gateway
listens on 127.0.0.1 only and forwards just two OpenAI-compatible calls to Ollama:
GET /v1/models and POST /v1/chat/completions. Every request needs
`Authorization: Bearer <token>`. Put a tunnel (for example cloudflared) in front of
the gateway, then point the remote backend at it:

    LOCAL_LLM_BASE_URL = https://<tunnel-host>/v1
    LOCAL_LLM_API_KEY  = <token>

Usage:
    python tools/llm_gateway.py --token-file <path> [--port 11500] [--ollama http://127.0.0.1:11434]

The token file is created with a random token if it does not exist. Keep it out of git.
"""

import argparse
import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


MAX_BODY = 1024 * 1024
MAX_CONCURRENT = 2  # one GPU: queueing more requests only makes every answer slower
ROUTES = {("GET", "/v1/models"), ("POST", "/v1/chat/completions")}


def load_token(path: Path) -> str:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    token = path.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise SystemExit(f"Token in {path} is too short; delete the file to generate a new one.")
    return token


def make_handler(token: str, ollama: str, timeout: float):
    slots = threading.BoundedSemaphore(MAX_CONCURRENT)
    opener = build_opener(ProxyHandler({}))  # never route local traffic through a system proxy
    expected = f"Bearer {token}".encode()

    class Gateway(BaseHTTPRequestHandler):
        server_version = "llm-gateway"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep request bodies and tokens out of logs
            print(f"{self.log_date_time_string()} {self.command} {self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}", flush=True)

        def reply(self, status: int, body: bytes, content_type: str = "application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def error(self, status: int, message: str):
            self.reply(status, json.dumps({"error": {"message": message}}).encode())

        def handle_call(self):
            path = self.path.split("?", 1)[0]
            if (self.command, path) not in ROUTES:
                return self.error(404, "Not found.")
            supplied = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, expected):
                return self.error(401, "Invalid or missing API key.")

            body = None
            if self.command == "POST":
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    return self.error(411, "Content-Length is required.")
                if not 0 < length <= MAX_BODY:
                    return self.error(413, "Request body is too large.")
                body = self.rfile.read(length)
                try:
                    payload = json.loads(body)
                except ValueError:
                    return self.error(400, "Request body must be JSON.")
                if not isinstance(payload, dict) or payload.get("stream"):
                    return self.error(400, "Only non-streaming chat requests are supported.")

            if not slots.acquire(timeout=timeout):
                return self.error(429, "The model is busy. Try again later.")
            try:
                request = Request(f"{ollama}{path}", data=body, method=self.command,
                                  headers={"Content-Type": "application/json"})
                with opener.open(request, timeout=timeout) as response:
                    self.reply(response.status, response.read())
            except HTTPError as error:
                self.reply(error.code, error.read() or b"{}")
            except (URLError, TimeoutError, OSError):
                self.error(502, "The local model server is not reachable.")
            finally:
                slots.release()

        do_GET = handle_call
        do_POST = handle_call

        def do_PUT(self):
            self.error(405, "Method not allowed.")

        do_DELETE = do_PATCH = do_HEAD = do_PUT

    return Gateway


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=11500)
    parser.add_argument("--ollama", default="http://127.0.0.1:11434")
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    token = load_token(args.token_file)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(token, args.ollama.rstrip("/"), args.timeout))
    print(f"LLM gateway on http://127.0.0.1:{args.port} -> {args.ollama} (token in {args.token_file})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
