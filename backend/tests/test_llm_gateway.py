import importlib.util
import json
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

GATEWAY_PATH = Path(__file__).resolve().parents[2] / "tools" / "llm_gateway.py"
spec = importlib.util.spec_from_file_location("llm_gateway", GATEWAY_PATH)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)

TOKEN = "t" * 40
OPENER = build_opener(ProxyHandler({}))


class FakeOllama(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body: dict):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply({"data": [{"id": "qwen3:8b"}]} if self.path == "/v1/models" else {"models": ["leak"]})

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self.reply({"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]})

    do_DELETE = do_POST


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.original_timeout = gateway.READ_TIMEOUT
        gateway.READ_TIMEOUT = 1
        self.upstream = serve(HTTPServer(("127.0.0.1", 0), FakeOllama))
        handler = gateway.make_handler(TOKEN, f"http://127.0.0.1:{self.upstream.server_port}", timeout=5)
        self.server = serve(gateway.LimitedServer(("127.0.0.1", 0), handler, max_connections=2))
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        gateway.READ_TIMEOUT = self.original_timeout
        for server in (self.server, self.upstream):
            server.shutdown()
            server.server_close()

    def call(self, method, path, body=None, token=TOKEN):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        try:
            with OPENER.open(Request(self.base + path, data=data, method=method, headers=headers), timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, None

    def test_requires_the_token(self):
        self.assertEqual(self.call("GET", "/v1/models", token=None)[0], 401)
        self.assertEqual(self.call("GET", "/v1/models", token="x" * 40)[0], 401)
        self.assertEqual(self.call("GET", "/v1/models"), (200, {"data": [{"id": "qwen3:8b"}]}))

    def test_only_two_routes_are_forwarded(self):
        self.assertEqual(self.call("GET", "/api/tags")[0], 404)
        self.assertEqual(self.call("POST", "/api/pull", {"model": "x"})[0], 404)
        self.assertEqual(self.call("DELETE", "/api/delete", {"model": "x"})[0], 405)
        self.assertEqual(self.call("POST", "/v1/chat/completions", {"model": "qwen3:8b", "stream": True})[0], 400)
        self.assertEqual(self.call("POST", "/v1/chat/completions", {"model": "qwen3:8b"})[0], 200)

    def test_slow_body_is_dropped_and_gateway_keeps_serving(self):
        with socket.create_connection(("127.0.0.1", self.server.server_port)) as slow:
            slow.sendall(
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                + b"\r\nContent-Length: 100\r\n\r\n{\"model\""
            )
            slow.settimeout(5)
            started = time.monotonic()
            answer = slow.recv(200)
            self.assertLess(time.monotonic() - started, 4)
        self.assertIn(b" 408 ", answer)
        self.assertEqual(self.call("GET", "/v1/models")[0], 200)

    def test_connections_beyond_the_limit_are_refused(self):
        idle = [socket.create_connection(("127.0.0.1", self.server.server_port)) for _ in range(2)]
        try:
            time.sleep(0.2)
            with socket.create_connection(("127.0.0.1", self.server.server_port)) as extra:
                extra.settimeout(3)
                self.assertTrue(extra.recv(100).startswith(b"HTTP/1.0 503"))
        finally:
            for connection in idle:
                connection.close()
        time.sleep(1.5)  # idle connections time out and free their slots
        self.assertEqual(self.call("GET", "/v1/models")[0], 200)

    def test_token_file_is_created_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "token.txt"
            first = gateway.load_token(path)
            self.assertEqual(gateway.load_token(path), first)
            self.assertGreaterEqual(len(first), 32)


if __name__ == "__main__":
    unittest.main()
