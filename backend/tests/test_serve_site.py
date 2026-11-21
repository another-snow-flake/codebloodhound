import base64
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

SITE_PATH = Path(__file__).resolve().parents[2] / "tools" / "serve_site.py"
spec = importlib.util.spec_from_file_location("serve_site", SITE_PATH)
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)

PASSWORD = "p" * 20


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # the tests look at redirects themselves


OPENER = build_opener(ProxyHandler({}), NoRedirect())


class FakeApi(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        pass

    def answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        FakeApi.seen.append((self.command, self.path, dict(self.headers), body))
        data = json.dumps({"path": self.path, "body": body.decode()}).encode()
        self.send_response(201 if self.command == "POST" else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = answer


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class ServeSiteTest(unittest.TestCase):
    def setUp(self):
        FakeApi.seen = []
        self.folder = tempfile.TemporaryDirectory()
        root = Path(self.folder.name) / "frontend"
        root.mkdir()
        (root / "index.html").write_text("<h1>editor</h1>", encoding="utf-8")
        (Path(self.folder.name) / "secret.txt").write_text("do not serve", encoding="utf-8")
        self.api = serve(HTTPServer(("127.0.0.1", 0), FakeApi))
        handler = site.make_handler(PASSWORD, f"http://127.0.0.1:{self.api.server_port}", root=root)
        self.server = serve(site.LimitedServer(("127.0.0.1", 0), handler))
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        for server in (self.server, self.api):
            server.shutdown()
            server.server_close()
        self.folder.cleanup()

    def call(self, method, path, body=None, password=PASSWORD, headers=None):
        headers = dict(headers or {})
        if password:
            headers["Authorization"] = "Basic " + base64.b64encode(f"team:{password}".encode()).decode()
        try:
            with OPENER.open(Request(self.base + path, data=body, method=method, headers=headers), timeout=5) as response:
                return response.status, response.read(), response.headers
        except HTTPError as error:
            return error.code, error.read(), error.headers

    def test_everything_needs_the_password(self):
        for path in ("/", "/api/health"):
            status, _, headers = self.call("GET", path, password=None)
            self.assertEqual(status, 401)
            self.assertIn("Basic", headers["WWW-Authenticate"])
        self.assertEqual(self.call("GET", "/", password="wrong-password-123")[0], 401)
        self.assertEqual(FakeApi.seen, [])

    def test_invite_link_sets_a_cookie_instead_of_the_password(self):
        key = site.invite_key(PASSWORD)
        self.assertEqual(self.call("GET", "/?key=wrong", password=None)[0], 401)
        self.assertEqual(self.call("POST", f"/api/workflows?key={key}", b"{}", password=None)[0], 401)
        status, _, headers = self.call("GET", f"/?key={key}", password=None)
        self.assertEqual((status, headers["Location"]), (303, "/"))
        cookie = headers["Set-Cookie"]
        for flag in ("HttpOnly", "Secure", "SameSite=Lax", "Max-Age="):
            self.assertIn(flag, cookie)
        session = cookie.split(";")[0]
        self.assertNotIn(key, session)
        self.assertEqual(self.call("GET", "/", password=None, headers={"Cookie": session})[0], 200)
        self.assertEqual(self.call("POST", "/api/workflows", b"{}", password=None, headers={"Cookie": session})[0], 201)
        self.assertEqual(self.call("GET", "/", password=None, headers={"Cookie": session + "x"})[0], 401)
        self.assertEqual(self.call("GET", "/", password=None, headers={"Cookie": "cbh_session=\"bad"})[0], 401)
        # a protocol-relative path must not turn the redirect into an open redirect
        location = self.call("GET", f"//evil.example?key={key}", password=None)[2]["Location"]
        self.assertTrue(location.startswith("/") and not location.startswith("//"), location)
        # the key depends on the password: a new password revokes old links
        self.assertNotEqual(site.invite_key("q" * 20), key)

    def test_serves_the_editor_but_nothing_outside_frontend(self):
        status, body, headers = self.call("GET", "/")
        self.assertEqual((status, body), (200, b"<h1>editor</h1>"))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.call("GET", "/../secret.txt")[0], 404)
        self.assertEqual(self.call("GET", "/%2e%2e/secret.txt")[0], 404)
        self.assertEqual(self.call("POST", "/", b"x")[0], 405)

    def test_api_prefix_is_removed_and_only_safe_headers_pass(self):
        status, body, _ = self.call("POST", "/api/workflows?x=1", b'{"name":"W"}', headers={
            "Content-Type": "application/json", "Cookie": "session=1", "Origin": "https://evil.example"})
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"path": "/workflows?x=1", "body": '{"name":"W"}'})
        forwarded = FakeApi.seen[-1][2]
        self.assertNotIn("Cookie", forwarded)
        self.assertNotIn("Origin", forwarded)
        self.assertNotIn("Authorization", forwarded)

    def test_api_methods_are_limited(self):
        self.assertEqual(self.call("DELETE", "/api/workflows/1")[0], 405)
        self.assertEqual(self.call("GET", "/api/health")[0], 200)

    def test_backend_down_gives_502(self):
        self.api.shutdown()
        self.api.server_close()
        status, body, _ = self.call("GET", "/api/health")
        self.assertEqual((status, json.loads(body)["code"]), (502, "api_unreachable"))


if __name__ == "__main__":
    unittest.main()
