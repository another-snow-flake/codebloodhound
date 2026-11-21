"""Serve the editor and the API from one origin, behind HTTP Basic auth.

For demos where teammates open the site through a public tunnel. The server listens on
127.0.0.1 only; put a tunnel in front of it. It serves files from frontend/ at / and
forwards /api/* to the FastAPI backend with the /api prefix removed. Because the page
and the API share an origin, the backend's CORS list does not need to change, and the
editor finds the API at <origin>/api by itself.

Usage:
    python tools/serve_site.py --password-file <path> [--port 8080] [--api http://127.0.0.1:8000]

The password file is created with a random password if it does not exist. The user name
is "team". Keep the file out of git.

For showing the project without typing the password, open <site>/?key=<invite>: the invite
key is written to site-invite.txt next to the password file. The visit gets a session cookie
for 30 days and is redirected to the clean address. The key is derived from the password, so
a new password revokes old invite links and cookies.
"""

import argparse
import base64
import hashlib
import hmac
import mimetypes
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs
from urllib.request import ProxyHandler, Request, build_opener


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
USER = "team"
MAX_BODY = 11 * 1024 * 1024  # the API accepts ZIP uploads up to 10 MiB plus multipart overhead
MAX_CONNECTIONS = 32
READ_TIMEOUT = 30
FORWARD_HEADERS = ("Content-Type", "Accept", "X-CodeBloodhound-Session")
COOKIE = "cbh_session"
COOKIE_AGE = 30 * 24 * 3600
BUSY_RESPONSE = b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def load_password(path: Path) -> str:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_urlsafe(18), encoding="utf-8")
    password = path.read_text(encoding="utf-8").strip()
    if len(password) < 16:
        raise SystemExit(f"Password in {path} is too short; delete the file to generate a new one.")
    return password


def derived(password: str, purpose: str) -> str:
    digest = hmac.new(password.encode(), purpose.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def invite_key(password: str) -> str:
    """The key for <site>/?key=...: lets a visitor in without typing the password."""
    return derived(password, "invite")[:24]


def make_handler(password: str, api: str, root: Path = FRONTEND, timeout: float = 300):
    expected = ("Basic " + base64.b64encode(f"{USER}:{password}".encode()).decode()).encode()
    invite = invite_key(password).encode()
    session = derived(password, "session").encode()
    opener = build_opener(ProxyHandler({}))
    root = root.resolve()

    class Site(BaseHTTPRequestHandler):
        server_version = "codebloodhound-site"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(READ_TIMEOUT)

        def log_message(self, fmt, *args):  # method, path and status only: no bodies, no credentials
            # behind localhost.run every peer is 127.0.0.1: the tunnel does not pass the visitor's address,
            # and a client-supplied X-Forwarded-For would only let visitors forge log entries
            print(f"{self.log_date_time_string()} {self.client_address[0]} {self.command} "
                  f"{self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}", flush=True)

        def send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def has_session(self) -> bool:
            try:
                morsel = SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
            except CookieError:
                return False
            return morsel is not None and hmac.compare_digest(morsel.value.encode(), session)

        def accept_invite(self) -> bool:
            """GET /...?key=<invite>: set the session cookie and redirect to the address without the key."""
            if self.command not in ("GET", "HEAD") or "?" not in self.path:
                return False
            path, query = self.path.split("?", 1)
            keys = parse_qs(query).get("key", [])
            if len(keys) != 1 or not hmac.compare_digest(keys[0].encode(), invite):
                return False
            self.send(303, b"", "text/plain; charset=utf-8", {
                "Location": path if path.startswith("/") and not path.startswith("//") else "/",
                "Set-Cookie": f"{COOKIE}={session.decode()}; Max-Age={COOKIE_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax",
            })
            return True

        def authorized(self) -> bool:
            if hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected):
                return True
            if self.has_session():
                return True
            if self.accept_invite():
                return False
            self.send(401, b"Authentication required.", "text/plain; charset=utf-8",
                      {"WWW-Authenticate": 'Basic realm="CodeBloodhound", charset="UTF-8"'})
            return False

        def read_body(self) -> bytes | None:
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                return b""
            try:
                length = int(length_header)
            except ValueError:
                return None
            if not 0 <= length <= MAX_BODY:
                return None
            deadline = time.monotonic() + READ_TIMEOUT
            chunks, remaining = [], length
            while remaining:
                if time.monotonic() > deadline:
                    return None
                chunk = self.rfile.read1(min(remaining, 65536))
                if not chunk:
                    return None
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)

        def handle_any(self):
            if not self.authorized():
                return
            path = self.path.split("?", 1)[0]
            if path == "/api" or path.startswith("/api/"):
                return self.forward()
            if self.command not in ("GET", "HEAD"):
                return self.send(405, b"Method not allowed.", "text/plain; charset=utf-8")
            return self.static(path)

        def static(self, path: str):
            relative = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (root / relative).resolve()
            if root not in target.parents or not target.is_file():
                return self.send(404, b"Not found.", "text/plain; charset=utf-8")
            content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
                content_type += "; charset=utf-8"
            self.send(200, target.read_bytes(), content_type)

        def forward(self):
            if self.command not in ("GET", "POST", "PUT"):
                return self.send(405, b'{"code":"method_not_allowed","message":"Method not allowed."}', "application/json")
            try:
                body = self.read_body() if self.command != "GET" else None
            except (TimeoutError, OSError):
                body = None
            if body is None and self.command != "GET":
                self.close_connection = True
                return self.send(408, b'{"code":"request_timeout","message":"The request was not received in time or is too large."}',
                                 "application/json")
            upstream_path = self.path[len("/api"):] or "/"
            headers = {key: value for key in FORWARD_HEADERS if (value := self.headers.get(key))}
            request = Request(api + upstream_path, data=body, method=self.command, headers=headers)
            try:
                with opener.open(request, timeout=timeout) as response:
                    self.send(response.status, response.read(), response.headers.get("Content-Type", "application/json"))
            except HTTPError as error:
                self.send(error.code, error.read(), error.headers.get("Content-Type", "application/json"))
            except (URLError, TimeoutError, OSError):
                self.send(502, b'{"code":"api_unreachable","message":"The backend is not running."}', "application/json")

        do_GET = do_POST = do_PUT = do_HEAD = handle_any

        def do_DELETE(self):
            if self.authorized():
                self.send(405, b"Method not allowed.", "text/plain; charset=utf-8")

        do_PATCH = do_OPTIONS = do_DELETE

    return Site


class LimitedServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, max_connections: int = MAX_CONNECTIONS):
        super().__init__(address, handler)
        self.connections = threading.BoundedSemaphore(max_connections)

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            try:
                request.sendall(BUSY_RESPONSE)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    password = load_password(args.password_file)
    args.password_file.with_name("site-invite.txt").write_text(invite_key(password), encoding="utf-8")
    server = LimitedServer(("127.0.0.1", args.port), make_handler(password, args.api.rstrip("/")))
    print(f"Site on http://127.0.0.1:{args.port} (user {USER}, password in {args.password_file}) -> API {args.api}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
