"""HTTP layer: CSRF, sessions, headers, routing, limits, and a real socket server."""
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse

from helpers import tmp_app, rm, ROOT
from warden.server import App, BoundedServer, make_handler

H = {"host": "localhost"}


def cookie_of(resp, name="wsid"):
    for c in resp.headers_all("Set-Cookie"):
        if c.startswith(name + "="):
            return c.split(";")[0].split("=", 1)[1]
    return None


class Client:
    """Tiny cookie-keeping client around App.handle."""

    def __init__(self, app, host="localhost"):
        self.app, self.cookies, self.host = app, {}, host

    def req(self, method, path, form=None, headers=None, body=None, ctype=None):
        h = {"host": self.host}
        if self.cookies:
            h["cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            ctype = "application/x-www-form-urlencoded"
        if ctype:
            h["content-type"] = ctype
        h.update(headers or {})
        r = self.app.handle(method, path, h, body or b"", "10.0.0.1")
        for c in r.headers_all("Set-Cookie"):
            k, v = c.split(";")[0].split("=", 1)
            if "Max-Age=0" in c:
                self.cookies.pop(k, None)
            else:
                self.cookies[k] = v
        return r

    def csrf(self, path="/login"):
        r = self.req("GET", path)
        return re.search(r'name="_csrf" value="([^"]+)"', r.body.decode()).group(1)


class GuestbookFlow(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        shutil.copytree(os.path.join(ROOT, "examples", "guestbook"), os.path.join(self.d, "app"))
        shutil.rmtree(os.path.join(self.d, "app", "data"), ignore_errors=True)
        self.app = App(os.path.join(self.d, "app"), {"log_file": os.path.join(self.d, "log.jsonl")})
        self.c = Client(self.app)

    def tearDown(self):
        rm(self.d)

    def register(self, email="a@example.com", pw="supersecret1"):
        tok = self.c.csrf("/register")
        return self.c.req("POST", "/register", {"email": email, "password": pw, "_csrf": tok})

    def test_full_flow_with_stored_xss_attempt(self):
        self.assertEqual(self.app.compile_errors, [])
        r = self.register()
        self.assertEqual(r.status, 302)
        self.assertEqual(r.header("Location"), "/")
        tok = self.c.csrf("/")
        r = self.c.req("POST", "/post", {"body": "<script>alert(document.cookie)</script>\nline2", "_csrf": tok})
        self.assertEqual(r.status, 302)
        page = self.c.req("GET", "/").body.decode()
        self.assertIn("&lt;script&gt;alert(document.cookie)&lt;/script&gt;<br>", page)
        self.assertNotIn("<script>alert", page)
        api = json.loads(self.c.req("GET", "/api/messages").body)
        self.assertEqual(api[0]["body"], "<script>alert(document.cookie)</script>\nline2")
        one = self.c.req("GET", "/api/messages/1")
        self.assertEqual(json.loads(one.body)["id"], 1)
        self.assertEqual(self.c.req("GET", "/api/messages/999").status, 404)
        self.assertEqual(self.c.req("GET", "/api/messages/abc").status, 404)

    def test_login_logout_and_session_fixation(self):
        self.register()
        self.c.req("GET", "/logout")
        self.assertNotIn("wsid", self.c.cookies)
        tok = self.c.csrf("/login")
        pre_login_sid = self.c.cookies["wsid"]
        r = self.c.req("POST", "/login", {"email": "a@example.com", "password": "wrong-password", "_csrf": tok})
        self.assertIn("Invalid email or password", r.body.decode())
        r = self.c.req("POST", "/login", {"email": "A@example.com ", "password": "supersecret1", "_csrf": tok})
        self.assertEqual(r.status, 302)
        self.assertNotEqual(self.c.cookies["wsid"], pre_login_sid, "session id must rotate on login")
        self.assertIsNone(self.app.sessions.get(pre_login_sid), "old session must be destroyed")
        self.assertIn("Signed in as", self.c.req("GET", "/").body.decode())

    def test_attacker_chosen_session_id_ignored(self):
        self.c.cookies["wsid"] = "A" * 43
        self.c.csrf("/login")
        self.assertNotEqual(self.c.cookies["wsid"], "A" * 43)

    def test_sqli_via_login_form(self):
        self.register()
        c2 = Client(self.app)
        tok = c2.csrf("/login")
        r = c2.req("POST", "/login", {"email": "' OR '1'='1' --", "password": "x", "_csrf": tok})
        self.assertIn("Invalid email or password", r.body.decode())

    def test_reflected_xss_and_open_redirect_in_search(self):
        r = self.c.req("GET", "/search?q=" + urllib.parse.quote('"><svg onload=alert(1)>') +
                       "&back=" + urllib.parse.quote("javascript:alert(1)"))
        body = r.body.decode()
        self.assertEqual(r.status, 200)
        self.assertNotIn("<svg", body)
        self.assertIn('href="#blocked-unsafe-url"', body)

    def test_route_param_xss(self):
        r = self.c.req("GET", "/hello/" + urllib.parse.quote("<img src=x onerror=alert(1)>"))
        self.assertEqual(r.body, b"<h1>Hello, &lt;img src=x onerror=alert(1)&gt;!</h1>")

    def test_post_requires_login(self):
        tok = self.c.csrf("/login")
        r = self.c.req("POST", "/post", {"body": "hi", "_csrf": tok})
        self.assertEqual((r.status, r.header("Location")), (302, "/login"))

    def test_php_style_urls_still_work(self):
        self.assertEqual(self.c.req("GET", "/login.php").status, 200)
        self.assertEqual(self.c.req("GET", "/search.wdn").status, 200)

    def test_security_log_written(self):
        self.c.req("POST", "/post", {"body": "x"})  # no CSRF token
        with open(os.path.join(self.d, "log.jsonl")) as f:
            log = [json.loads(l) for l in f]
        self.assertTrue(any(e.get("kind") == "csrf" for e in log))


class CSRF(unittest.TestCase):
    def setUp(self):
        self.d = tmp_app({"pages/index.wdn": "<?= csrf_field() ?>",
                          "pages/do.wdn": '<?wdn session_set("did", 1); echo "done";',
                          "warden.json": json.dumps({"csrf_exempt_paths": ["/webhook"]}),
                          "pages/webhook.wdn": "ok"})
        self.app = App(self.d)

    def tearDown(self):
        rm(self.d)

    def test_missing_token(self):
        self.assertEqual(Client(self.app).req("POST", "/do", {"x": "1"}).status, 403)

    def test_wrong_token(self):
        c = Client(self.app)
        c.csrf("/")
        self.assertEqual(c.req("POST", "/do", {"_csrf": "forged"}).status, 403)

    def test_token_from_other_session(self):
        a, b = Client(self.app), Client(self.app)
        tok_a = a.csrf("/")
        b.csrf("/")
        self.assertEqual(b.req("POST", "/do", {"_csrf": tok_a}).status, 403)

    def test_valid_token_form_and_header(self):
        c = Client(self.app)
        tok = c.csrf("/")
        self.assertEqual(c.req("POST", "/do", {"_csrf": tok}).status, 200)
        self.assertEqual(c.req("POST", "/do", {}, headers={"x-csrf-token": tok}).status, 200)

    def test_cross_origin_rejected_even_with_token(self):
        c = Client(self.app)
        tok = c.csrf("/")
        self.assertEqual(c.req("POST", "/do", {"_csrf": tok}, headers={"origin": "https://evil.com"}).status, 403)
        self.assertEqual(c.req("POST", "/do", {"_csrf": tok}, headers={"origin": "null"}).status, 403)
        self.assertEqual(c.req("POST", "/do", {"_csrf": tok}, headers={"origin": "http://localhost"}).status, 200)

    def test_cookieless_json_api_allowed(self):
        r = Client(self.app).req("POST", "/do", body=b'{"a":1}', ctype="application/json")
        self.assertEqual(r.status, 200)

    def test_json_with_cookie_needs_token(self):
        c = Client(self.app)
        c.csrf("/")
        self.assertEqual(c.req("POST", "/do", body=b'{"a":1}', ctype="application/json").status, 403)

    def test_exempt_path(self):
        self.assertEqual(Client(self.app).req("POST", "/webhook", {"x": "1"}).status, 200)

    def test_simple_cors_content_types(self):
        self.assertEqual(Client(self.app).req("POST", "/do", body=b"x", ctype="application/xml").status, 415)


class Headers(unittest.TestCase):
    def setUp(self):
        self.d = tmp_app({
            "pages/index.wdn": "hi",
            "pages/hdr.wdn": '<?wdn header("X-Test: " . $_GET["v"]); echo "ok";',
            "pages/redir.wdn": '<?wdn redirect($_GET["to"]);',
            "pages/cookie.wdn": '<?wdn setcookie("pref", $_GET["v"]); echo "ok";',
            "pages/sess.wdn": '<?wdn session_set("a", 1); echo "ok";',
            "pages/err.wdn": '<?wdn $x = undefined_function_xyz();',
            "pages/limit.wdn": '<?wdn while (true) {}',
            "pages/txt.wdn": '<?wdn header("Content-Type: text/plain"); echo $_GET["v"];',
            "pages/_private.wdn": "secret",
            "public/a.txt": "static", "public/.env": "SECRET=1",
        })
        self.app = App(self.d, {"max_steps": 50_000})

    def tearDown(self):
        rm(self.d)

    def get(self, path, headers=None, method="GET"):
        h = dict(H)
        h.update(headers or {})
        return self.app.handle(method, path, h, b"", "1.2.3.4")

    def test_default_security_headers(self):
        r = self.get("/")
        for name in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
                     "Cross-Origin-Opener-Policy", "Permissions-Policy"):
            self.assertIsNotNone(r.header(name), name)
        self.assertEqual(r.header("Cache-Control"), "no-store")
        self.assertIn("frame-ancestors 'none'", r.header("Content-Security-Policy"))
        self.assertIsNone(r.header("X-Powered-By"))

    def test_header_injection(self):
        r = self.get("/hdr?v=" + urllib.parse.quote("a\r\nSet-Cookie: admin=1"))
        self.assertEqual(r.status, 400)
        self.assertIsNone(r.header("Set-Cookie"))
        self.assertEqual(self.get("/hdr?v=fine").header("X-Test"), "fine")

    def test_open_redirect(self):
        for bad in ["https://evil.com", "//evil.com", "/\\evil.com", "javascript:alert(1)", "\\\\evil.com",
                    "http:evil.com"]:
            r = self.get("/redir?to=" + urllib.parse.quote(bad))
            self.assertEqual(r.status, 400, bad)
            self.assertIsNone(r.header("Location"))
        r = self.get("/redir?to=" + urllib.parse.quote("/dashboard?x=1"))
        self.assertEqual((r.status, r.header("Location")), (302, "/dashboard?x=1"))

    def test_cookie_injection(self):
        self.assertEqual(self.get("/cookie?v=" + urllib.parse.quote("x; Domain=evil.com")).status, 400)
        r = self.get("/cookie?v=abc")
        c = r.header("Set-Cookie")
        self.assertIn("HttpOnly", c)
        self.assertIn("SameSite=Lax", c)

    def test_session_cookie_flags(self):
        c = self.get("/sess").header("Set-Cookie")
        self.assertRegex(c, r"^wsid=[A-Za-z0-9_\-]{43}; Path=/; HttpOnly; SameSite=Lax$")
        secure = App(self.d, {"secure_cookies": True, "hsts": True})
        r = secure.handle("GET", "/sess", H, b"", "1.1.1.1")
        self.assertRegex(r.header("Set-Cookie"), r"^__Host-wsid=.*; Secure$")
        self.assertIn("max-age", r.header("Strict-Transport-Security"))

    def test_errors_do_not_leak(self):
        r = self.get("/err")
        self.assertEqual(r.status, 500)
        self.assertNotIn(b"undefined_function_xyz", r.body)
        self.assertNotIn(b"Traceback", r.body)
        self.assertIn(b"Request ID", r.body)

    def test_cpu_limit_returns_503(self):
        self.assertEqual(self.get("/limit").status, 503)

    def test_non_html_content_type_not_sniffable(self):
        r = self.get("/txt?v=" + urllib.parse.quote("<script>x</script>"))
        self.assertEqual(r.header("Content-Type"), "text/plain; charset=utf-8")
        self.assertEqual(r.header("X-Content-Type-Options"), "nosniff")

    def test_host_header_validation(self):
        self.assertEqual(self.get("/", {"host": "evil.com"}).status, 400)
        self.assertEqual(self.get("/", {"host": "localhost:8080"}).status, 200)
        self.assertEqual(self.app.handle("GET", "/", {}, b"", "1.1.1.1").status, 400)

    def test_path_traversal_and_private_files(self):
        for p in ["/../warden.json", "/%2e%2e/warden.json", "/public/../pages/index.wdn", "/a/%2e%2e/%2e%2e/etc/passwd",
                  "/%00", "/..%5c..%5cwarden.json", "/.env", "/_private", "/pages/_private.wdn", "/a.txt/..",
                  "/index.wdn%00.txt"]:
            r = self.get(p)
            self.assertIn(r.status, (400, 404), p)
            self.assertNotIn(b"SECRET", r.body)
            self.assertNotIn(b"secret", r.body)
        self.assertEqual(self.get("/a.txt").body, b"static")

    def test_methods(self):
        self.assertEqual(self.get("/", method="TRACE").status, 405)
        self.assertEqual(self.get("/", method="OPTIONS").status, 204)
        r = self.get("/", method="HEAD")
        self.assertEqual((r.status, r.body), (200, b""))

    def test_404(self):
        self.assertEqual(self.get("/nope").status, 404)

    def test_body_too_large(self):
        r = self.app.handle("POST", "/", dict(H, **{"content-type": "text/plain"}), b"x" * (2 * 1024 * 1024), "1.1.1.1")
        self.assertEqual(r.status, 413)

    def test_too_many_fields(self):
        body = "&".join("a%d=1" % i for i in range(1500)).encode()
        r = self.app.handle("POST", "/", dict(H, **{"content-type": "application/x-www-form-urlencoded"}), body, "1.1.1.1")
        self.assertEqual(r.status, 400)

    def test_rate_limit(self):
        app = App(self.d, {"rate_limit_per_minute": 5})
        codes = [app.handle("GET", "/", H, b"", "9.9.9.9").status for _ in range(8)]
        self.assertEqual(codes[:5], [200] * 5)
        self.assertEqual(codes[-1], 429)
        self.assertEqual(app.handle("GET", "/", H, b"", "8.8.8.8").status, 200)


class Routing(unittest.TestCase):
    def test_routes_and_json(self):
        d = tmp_app({"app.wdn": '''<?wdn
            route("GET", "/", function($req) { return "home"; });
            route("GET", "/u/{id:int}", function($req) { return ["id" => int($req["params"]["id"])]; });
            route("POST", "/api/items", function($req) { return ["got" => $req["json"]["name"]]; });
            route("GET", "/s/{slug:slug}", function($req) { return $req["params"]["slug"]; });
        '''})
        try:
            app = App(d)
            self.assertEqual(app.handle("GET", "/", H).body, b"home")
            self.assertEqual(json.loads(app.handle("GET", "/u/42", H).body), {"id": 42})
            self.assertEqual(app.handle("GET", "/u/42x", H).status, 404)
            self.assertEqual(app.handle("GET", "/s/ok-slug", H).body, b"ok-slug")
            self.assertEqual(app.handle("GET", "/s/no%20way", H).status, 404)
            r = app.handle("POST", "/api/items", dict(H, **{"content-type": "application/json"}), b'{"name":"<b>"}')
            self.assertEqual(r.body, b'{"got":"\\u003cb\\u003e"}')
            self.assertEqual(app.handle("POST", "/api/items", dict(H, **{"content-type": "application/json"}),
                                        b'{bad json').status, 400)
        finally:
            rm(d)

    def test_share_nothing_between_requests(self):
        d = tmp_app({"pages/count.wdn": '<?wdn $n = ($n ?? 0) + 1; echo $n;'})
        try:
            app = App(d)
            self.assertEqual([app.handle("GET", "/count", H).body for _ in range(3)], [b"1"] * 3)
        finally:
            rm(d)

    def test_syntax_error_reported_at_startup(self):
        d = tmp_app({"pages/bad.wdn": "<?wdn echo ;"})
        try:
            self.assertEqual(len(App(d).compile_errors), 1)
        finally:
            rm(d)


class RealSocketServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tmp_app({"pages/index.wdn": "<p>Hello <?= $_GET['n'] ?? 'x' ?></p>",
                         "warden.json": json.dumps({"request_timeout": 2, "workers": 4})})
        cls.app = App(cls.d)
        threading.stack_size(64 * 1024 * 1024)
        cls.srv = BoundedServer(("127.0.0.1", 0), make_handler(cls.app), 4)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        rm(cls.d)

    def raw(self, data, timeout=5):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        s.sendall(data)
        out = b""
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    break
                out += b
        except socket.timeout:
            pass
        s.close()
        return out

    def test_basic_get(self):
        r = self.raw(b"GET /?n=%3Cb%3E HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn(b"200 OK", r)
        self.assertIn(b"<p>Hello &lt;b&gt;</p>", r)
        self.assertNotIn(b"Server:", r)
        self.assertNotIn(b"Python", r)

    def test_request_smuggling_te(self):
        r = self.raw(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
        self.assertIn(b"501", r.split(b"\r\n")[0])

    def test_duplicate_content_length(self):
        r = self.raw(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 5\r\n\r\nxxxxx")
        self.assertIn(b"400", r.split(b"\r\n")[0])

    def test_missing_length_on_post(self):
        r = self.raw(b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn(b"411", r.split(b"\r\n")[0])

    def test_oversized_content_length(self):
        r = self.raw(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999999\r\n\r\n")
        self.assertIn(b"413", r.split(b"\r\n")[0])

    def test_slowloris_times_out(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall(b"GET / HTTP/1.1\r\nHost: local")
        t0 = time.time()
        try:
            data = s.recv(100)
        except socket.timeout:
            data = b"timeout"
        s.close()
        self.assertLess(time.time() - t0, 6, "server must drop slow clients")

    def test_bad_host(self):
        r = self.raw(b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n")
        self.assertIn(b"400", r.split(b"\r\n")[0])

    def test_header_flood(self):
        hdrs = b"".join(b"X-%d: a\r\n" % i for i in range(200))
        r = self.raw(b"GET / HTTP/1.1\r\nHost: localhost\r\n" + hdrs + b"\r\n")
        self.assertNotIn(b"200 OK", r)

    def test_concurrency_cap(self):
        socks = [socket.create_connection(("127.0.0.1", self.port)) for _ in range(6)]
        for s in socks:
            s.sendall(b"GET / HTTP/1.1\r\nHost: loc")  # hold workers
        time.sleep(0.3)
        r = self.raw(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        for s in socks:
            s.close()
        self.assertIn(b"503", r.split(b"\r\n")[0])
        time.sleep(2.5)  # let held workers time out before other tests


class WSGI(unittest.TestCase):
    def test_wsgi_adapter(self):
        import io
        from wsgiref.util import setup_testing_defaults
        d = tmp_app({"pages/index.wdn": "<p><?= $_GET['q'] ?? '' ?></p>"})
        try:
            app = App(d)
            env = {}
            setup_testing_defaults(env)
            env.update({"PATH_INFO": "/", "QUERY_STRING": "q=%3Ci%3E", "HTTP_HOST": "localhost",
                        "wsgi.input": io.BytesIO(b"")})
            got = {}

            def start(status, headers):
                got["status"], got["headers"] = status, headers
            body = b"".join(app(env, start))
            self.assertEqual(got["status"], "200 OK")
            self.assertEqual(body, b"<p>&lt;i&gt;</p>")
        finally:
            rm(d)


if __name__ == "__main__":
    unittest.main()
