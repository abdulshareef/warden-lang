"""Warden application runtime + hardened HTTP server + WSGI adapter."""

import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .context import Context, SessionStore, DEFAULT_CONFIG
from .errors import (WardenError, WardenSyntaxError, SecurityViolation,
                     LimitExceeded, ExitSignal)
from .htmlctx import render_html
from .interp import Interp, Limits, safe_join, parse_file
from .tstr import TStr
from .values import BArray, Func, from_py, to_py

ALLOWED_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
UNSAFE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,100}$")
STATIC_SEGMENT = re.compile(r"^[A-Za-z0-9_\-][A-Za-z0-9_\-.]{0,200}$")


class Response:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or []
        self.body = body

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def headers_all(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]


REASONS = {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently", 302: "Found",
           303: "See Other", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
           400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 411: "Length Required", 413: "Payload Too Large",
           414: "URI Too Long", 415: "Unsupported Media Type", 422: "Unprocessable Content",
           429: "Too Many Requests", 431: "Request Header Fields Too Large",
           500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable"}


class RateLimiter:
    def __init__(self, per_minute):
        self.cap = float(per_minute)
        self.rate = per_minute / 60.0
        self.b = {}
        self.lock = threading.Lock()

    def allow(self, key):
        if self.cap <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            if len(self.b) > 100_000:
                self.b = {k: v for k, v in self.b.items() if now - v[1] < 120}
            tokens, last = self.b.get(key, (self.cap, now))
            tokens = min(self.cap, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.b[key] = (tokens, now)
                return False
            self.b[key] = (tokens - 1, now)
            return True


def _parse_pairs(pairs, max_fields=1000):
    """PHP-style form parsing: a=1, a[]=1, a[k]=1 -> tainted BArray."""
    out = BArray()
    for i, (k, v) in enumerate(pairs):
        if i >= max_fields:
            raise SecurityViolation("too many input fields", "dos")
        tv = TStr.tainted(v)
        m = re.fullmatch(r"([^\[\]]{1,200})\[([^\[\]]{0,200})\]", k)
        if m:
            base = TStr.tainted(m.group(1))
            cur = out.get(base, None)
            if not isinstance(cur, BArray):
                cur = BArray()
                out.set(base, cur)
            if m.group(2) == "":
                cur.append(tv)
            else:
                cur.set(TStr.tainted(m.group(2)), tv)
        else:
            out.set(TStr.tainted(k), tv)
    return out


def _parse_cookies(header):
    out = {}
    for part in header.split(";")[:100]:
        if "=" in part:
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and k not in out and len(k) < 128 and len(v) < 4096:
                out[k] = v[1:-1] if len(v) > 1 and v[0] == v[-1] == '"' else v
    return out


class App:
    def __init__(self, app_root, config=None):
        self.root = os.path.realpath(app_root)
        cfg = dict(DEFAULT_CONFIG)
        cfg_path = os.path.join(self.root, "warden.json")
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                user = json.load(f)
            unknown = set(user) - set(DEFAULT_CONFIG)
            if unknown:
                raise ValueError("unknown config keys in warden.json: %s" % ", ".join(sorted(unknown)))
            cfg.update(user)
        if config:
            cfg.update(config)
        self.config = cfg
        self.sessions = SessionStore(cfg["session_idle_seconds"], cfg["session_max_seconds"], cfg["max_sessions"])
        self.limiter = RateLimiter(cfg["rate_limit_per_minute"])
        self.limits = Limits(max_steps=cfg["max_steps"], max_depth=cfg["max_depth"],
                             max_output=cfg["max_output"])
        self.log = logging.getLogger("warden.%s" % secrets.token_hex(6))
        self.log.propagate = False
        if not self.log.handlers:
            h = logging.FileHandler(cfg["log_file"]) if cfg["log_file"] else logging.StreamHandler(sys.stderr)
            h.setFormatter(logging.Formatter("%(message)s"))
            self.log.addHandler(h)
            self.log.setLevel(logging.INFO)
        self.app_file = os.path.join(self.root, "app.wdn")
        # compile everything once at startup so syntax errors fail fast
        self.compile_errors = self.precompile()

    # ---------------------------------------------------------------- logging
    def event(self, level, rid, **kw):
        rec = {"ts": round(time.time(), 3), "level": level, "rid": rid}
        rec.update(kw)
        self.log.info(json.dumps(rec, ensure_ascii=True, default=str))

    def precompile(self):
        errs = []
        for dirpath, _, files in os.walk(self.root):
            if os.sep + "." in dirpath:
                continue
            for fn in files:
                if fn.endswith(".wdn"):
                    try:
                        parse_file(os.path.join(dirpath, fn))
                    except WardenSyntaxError as e:
                        errs.append(str(e))
        return errs

    # ---------------------------------------------------------------- headers
    def security_headers(self, html_page):
        h = [("X-Content-Type-Options", "nosniff"),
             ("X-Frame-Options", "DENY"),
             ("Referrer-Policy", "strict-origin-when-cross-origin"),
             ("Cross-Origin-Opener-Policy", "same-origin"),
             ("Cross-Origin-Resource-Policy", "same-origin"),
             ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
             ("Content-Security-Policy", self.config["csp"])]
        if self.config["hsts"]:
            h.append(("Strict-Transport-Security", "max-age=63072000; includeSubDomains"))
        return h

    def simple(self, status, text, rid=None):
        body = ("<!doctype html><title>%d</title><h1>%d %s</h1>%s" % (
            status, status, REASONS.get(status, ""), "<p>Request ID: %s</p>" % rid if rid else "")).encode()
        hdrs = [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")]
        return Response(status, hdrs + self.security_headers(True), body)

    # ---------------------------------------------------------------- request
    def handle(self, method, target, headers, body=b"", ip="0.0.0.0"):
        rid = secrets.token_hex(8)
        t0 = time.monotonic()
        try:
            resp = self._handle(rid, method, target, headers, body, ip)
        except Exception as e:  # last-resort guard: never leak internals
            self.event("error", rid, msg="unhandled: %r" % e)
            resp = self.simple(500, "", rid)
        resp.headers.append(("X-Request-Id", rid))
        self.event("access", rid, ip=ip, method=method[:10], path=target[:300], status=resp.status,
                   ms=round((time.monotonic() - t0) * 1000, 1))
        if method == "HEAD":
            resp.body = b""
        return resp

    def _handle(self, rid, method, target, headers, body, ip):
        cfg = self.config
        headers = {k.lower(): v for k, v in headers.items()}
        if cfg["trust_proxy"] and headers.get("x-forwarded-for"):
            ip = headers["x-forwarded-for"].split(",")[0].strip()[:64]
        if method not in ALLOWED_METHODS:
            return self.simple(405, "")
        if not self.limiter.allow(ip):
            self.event("security", rid, kind="rate-limit", ip=ip)
            r = self.simple(429, "")
            r.headers.append(("Retry-After", "60"))
            return r
        host = headers.get("host", "").lower()
        hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        if hostname not in [h.lower() for h in cfg["allowed_hosts"]]:
            self.event("security", rid, kind="bad-host", host=host[:100])
            return self.simple(400, "")
        if len(target) > 2048:
            return self.simple(414, "")
        if not target.startswith("/"):
            return self.simple(400, "")
        raw_path, _, query = target.partition("?")
        path = urllib.parse.unquote(raw_path, errors="strict") if "%" in raw_path else raw_path
        if re.search(r"[\x00-\x1f\x7f\\]", path) or "/../" in path + "/" or "/./" in path + "/":
            self.event("security", rid, kind="path-traversal", path=raw_path[:200])
            return self.simple(400, "")
        if method == "OPTIONS":
            r = Response(204, [("Allow", ", ".join(ALLOWED_METHODS))] + self.security_headers(False))
            return r
        if len(body) > cfg["max_body"]:
            return self.simple(413, "")

        # ---- inputs (all tainted)
        try:
            get = _parse_pairs(urllib.parse.parse_qsl(query, keep_blank_values=True, max_num_fields=1000))
        except ValueError:
            return self.simple(400, "")
        cookies = _parse_cookies(headers.get("cookie", ""))
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()
        post, json_body = BArray(), None
        if body:
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                return self.simple(400, "")
            if ctype == "application/x-www-form-urlencoded":
                try:
                    post = _parse_pairs(urllib.parse.parse_qsl(text, keep_blank_values=True, max_num_fields=1000))
                except ValueError:
                    return self.simple(400, "")
            elif ctype == "application/json":
                try:
                    json_body = from_py(json.loads(text), tainted=True)
                except (ValueError, RecursionError, WardenError):
                    return self.simple(400, "")
            elif ctype.startswith("multipart/"):
                return self.simple(415, "")
            elif method in UNSAFE_METHODS and ctype not in ("text/plain", ""):
                return self.simple(415, "")

        # ---- CSRF (state-changing requests)
        if method in UNSAFE_METHODS and not any(path.startswith(p) for p in cfg["csrf_exempt_paths"]):
            origin = headers.get("origin")
            if origin and origin != "null":
                o = urllib.parse.urlsplit(origin)
                if (o.netloc or "").lower() != host:
                    self.event("security", rid, kind="csrf-origin", origin=origin[:200])
                    return self.simple(403, "")
            elif origin == "null":
                return self.simple(403, "")
            api_call = ctype == "application/json" and "cookie" not in headers
            if not api_call:
                sess = self.sessions.get(cookies.get("__Host-wsid" if cfg["secure_cookies"] else "wsid"))
                sent = headers.get("x-csrf-token")
                if sent is None:
                    tok = post.get(TStr("_csrf"), None)
                    sent = tok.s if isinstance(tok, TStr) else None
                if sess is None or not sent or not hmac.compare_digest(sent.encode(), sess.csrf.encode()):
                    self.event("security", rid, kind="csrf", path=path[:200])
                    return self.simple(403, "")

        # ---- static files
        if method in ("GET", "HEAD"):
            static = self.static_file(path)
            if static is not None:
                return static

        request = {"method": method, "path": path, "headers": headers, "cookies": cookies,
                   "ip": ip, "json": json_body, "rid": rid}
        ctx = Context(self.root, cfg, self.sessions, request)
        it = Interp(self.root, self.limits, ctx)
        sg = it.superglobals
        sg["_GET"] = get
        sg["_POST"] = post
        req_all = get.copy()
        for k, v in post.items():
            req_all.set(k, v)
        sg["_REQUEST"] = req_all
        sg["_COOKIE"] = BArray.from_pairs((TStr.tainted(k), TStr.tainted(v)) for k, v in cookies.items())
        sg["_SERVER"] = BArray.from_pairs([
            (TStr("REQUEST_METHOD"), TStr(method)),
            (TStr("REQUEST_URI"), TStr.tainted(target)),
            (TStr("SCRIPT_NAME"), TStr.tainted(path)),
            (TStr("QUERY_STRING"), TStr.tainted(query)),
            (TStr("REMOTE_ADDR"), TStr.tainted(ip)),
            (TStr("HTTP_HOST"), TStr.tainted(host)),
            (TStr("HTTP_USER_AGENT"), TStr.tainted(headers.get("user-agent", ""))),
            (TStr("HTTP_REFERER"), TStr.tainted(headers.get("referer", ""))),
            (TStr("HTTPS"), TStr("on" if cfg["secure_cookies"] else "")),
            (TStr("REQUEST_TIME"), int(time.time())),
        ])
        try:
            found = self.dispatch(it, ctx, method, path, get, post, json_body)
            if not found:
                ctx.close()
                return self.simple(404, "")
            return self.build_response(it, ctx)
        except SecurityViolation as e:
            self.event("security", rid, kind=e.kind, msg=e.msg, path=path[:200], ip=ip)
            return self.simple(400, "", rid)
        except LimitExceeded as e:
            self.event("limit", rid, msg=str(e), path=path[:200], ip=ip)
            return self.simple(503, "", rid)
        except (WardenError, WardenSyntaxError) as e:
            self.event("error", rid, msg=str(e), line=getattr(e, "line", 0), file=it.filename, path=path[:200])
            if cfg["debug"] and hostname in ("localhost", "127.0.0.1"):
                import html as _h
                r = self.simple(500, "", rid)
                r.body += ("<pre>%s:%s: %s</pre>" % (_h.escape(it.filename), getattr(e, "line", 0),
                                                    _h.escape(str(e)))).encode()
                return r
            return self.simple(500, "", rid)
        finally:
            ctx.close()

    def dispatch(self, it, ctx, method, path, get, post, json_body):
        if os.path.exists(self.app_file):
            it.run_file(self.app_file)
            it.out, it.out_len = [], 0  # bootstrap output is discarded
        for rmethod, rx, handler, _ in ctx.routes:
            m = rx.match(path)
            if m and (rmethod == method or rmethod == "ANY" or (rmethod == "GET" and method == "HEAD")):
                params = BArray.from_pairs((TStr(k), TStr.tainted(v)) for k, v in m.groupdict().items())
                req = BArray.from_pairs([
                    (TStr("method"), TStr(method)), (TStr("path"), TStr.tainted(path)),
                    (TStr("params"), params), (TStr("query"), get), (TStr("body"), post),
                    (TStr("json"), json_body)])
                try:
                    result = it.call_value(handler, [req] if isinstance(handler, Func) and handler.params else [], 0)
                except ExitSignal:
                    return True
                if isinstance(result, BArray):
                    from .stdlib import json_dumps_safe
                    ctx.raw_body = json_dumps_safe(to_py(result)).encode()
                    ctx.headers["content-type"] = ("Content-Type", "application/json; charset=utf-8")
                elif isinstance(result, (TStr, int, float)) and not isinstance(result, bool):
                    from .values import to_str
                    it.emit(to_str(result))
                return True
        page = self.page_file(path)
        if page is None:
            return False
        it.run_file(page)
        return True

    def page_file(self, path):
        pages = os.path.join(self.root, self.config["pages_dir"])
        p = path.strip("/")
        p = re.sub(r"\.(php|wdn)$", "", p)
        segs = [s for s in p.split("/") if s] if p else []
        if not all(SEGMENT.match(s) for s in segs):
            return None
        cands = [os.path.join(pages, *segs) + ".wdn"] if segs else []
        cands.append(os.path.join(pages, *(segs + ["index.wdn"])))
        root_real = os.path.realpath(pages)
        for c in cands:
            real = os.path.realpath(c)
            if real.startswith(root_real + os.sep) and os.path.isfile(real):
                return real
        return None

    def static_file(self, path):
        pub = os.path.join(self.root, self.config["public_dir"])
        segs = [s for s in path.split("/") if s]
        if not segs or not all(STATIC_SEGMENT.match(s) for s in segs):
            return None
        if segs[-1].endswith((".wdn", ".php")):
            return None
        try:
            full = safe_join(pub, "/".join(segs), must_exist=False)
        except SecurityViolation:
            return None
        if not os.path.isfile(full):
            return None
        size = os.path.getsize(full)
        if size > 50 * 1024 * 1024:
            return self.simple(413, "")
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json", "image/svg+xml"):
            ctype += "; charset=utf-8"
        with open(full, "rb") as f:
            data = f.read()
        hdrs = [("Content-Type", ctype), ("Cache-Control", "public, max-age=3600")]
        hdrs += self.security_headers(False)
        if ctype.startswith("image/svg"):
            hdrs.append(("Content-Disposition", "attachment"))
        return Response(200, hdrs, data)

    def build_response(self, it, ctx):
        hdrs = []
        ct = ctx.headers.get("content-type", ("Content-Type", "text/html; charset=utf-8"))[1]
        if ctx.raw_body is not None:
            body = ctx.raw_body
        else:
            out = it.output()
            low = ct.lower()
            if "html" in low or "xml" in low or "svg" in low:
                body = render_html(out).encode("utf-8")
            else:
                body = out.s.encode("utf-8")
        if "charset" not in ct.lower() and ct.lower().startswith("text/"):
            ct += "; charset=utf-8"
        hdrs.append(("Content-Type", ct))
        hdrs.append(("Cache-Control", ctx.headers.get("cache-control", ("", "no-store"))[1]))
        for low, (name, value) in ctx.headers.items():
            if low in ("content-type", "cache-control"):
                continue
            hdrs.append((name, value))
        own = {k.lower() for k, _ in hdrs}
        hdrs += [h for h in self.security_headers(True) if h[0].lower() not in own]
        sec = "; Secure" if self.config["secure_cookies"] else ""
        if ctx.session_destroyed and not ctx.session:
            hdrs.append(("Set-Cookie", "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax%s" % (ctx.cookie_name, sec)))
        elif ctx.session_cookie_needed and ctx.session:
            hdrs.append(("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Lax%s" % (ctx.cookie_name, ctx.session.sid, sec)))
        for c in ctx.cookies_out:
            hdrs.append(("Set-Cookie", c))
        for lvl, msg in ctx.log_events:
            self.event("app-" + lvl, ctx.request.get("rid"), msg=msg[:2000])
        return Response(ctx.status, hdrs, body)

    # ----------------------------------------------------------------- WSGI
    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        target = environ.get("RAW_URI") or (urllib.parse.quote(environ.get("PATH_INFO", "/")) +
                                            ("?" + environ["QUERY_STRING"] if environ.get("QUERY_STRING") else ""))
        headers = {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_")}
        if environ.get("CONTENT_TYPE"):
            headers["content-type"] = environ["CONTENT_TYPE"]
        try:
            n = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > self.config["max_body"]:
            r = self.simple(413, "")
        else:
            body = environ["wsgi.input"].read(n) if n else b""
            r = self.handle(method, target, headers, body, environ.get("REMOTE_ADDR", "0.0.0.0"))
        start_response("%d %s" % (r.status, REASONS.get(r.status, "")), r.headers)
        return [r.body]


# ------------------------------------------------------------------ server
def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Warden"
        sys_version = ""
        protocol_version = "HTTP/1.0"
        timeout = app.config["request_timeout"]

        def log_message(self, fmt, *args):
            pass

        def _go(self):
            if "transfer-encoding" in {k.lower() for k in self.headers.keys()}:
                return self._send(app.simple(501, ""))
            cl = self.headers.get("Content-Length")
            body = b""
            if cl is not None:
                if not cl.isdigit() or len(self.headers.get_all("Content-Length")) > 1:
                    return self._send(app.simple(400, ""))
                n = int(cl)
                if n > app.config["max_body"]:
                    return self._send(app.simple(413, ""))
                body = self.rfile.read(n)
                if len(body) != n:
                    return
            elif self.command in UNSAFE_METHODS:
                return self._send(app.simple(411, ""))
            hdrs = {}
            for k, v in self.headers.items():
                lk = k.lower()
                hdrs[lk] = v if lk not in hdrs else hdrs[lk] + ", " + v
            self._send(app.handle(self.command, self.path, hdrs, body, self.client_address[0]))

        def _send(self, r):
            self.send_response_only(r.status, REASONS.get(r.status, ""))
            for k, v in r.headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(r.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(r.body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _go

        def send_error(self, code, message=None, explain=None):
            try:
                self._send(app.simple(code if code in REASONS else 400, ""))
            except Exception:
                pass

    return Handler


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, addr, handler, workers):
        super().__init__(addr, handler)
        self.sem = threading.BoundedSemaphore(workers)

    def process_request(self, request, client_address):
        if not self.sem.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def handle_error(self, request, client_address):
        pass  # client disconnects/timeouts are normal; never print tracebacks

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.sem.release()


def serve(app_root, host="127.0.0.1", port=8080, config=None, ready=None):
    threading.stack_size(64 * 1024 * 1024)
    app = App(app_root, config)
    if app.compile_errors:
        for e in app.compile_errors:
            print(e, file=sys.stderr)
        raise SystemExit("refusing to start: fix syntax errors above")
    srv = BoundedServer((host, port), make_handler(app), app.config["workers"])
    if ready is not None:
        ready(srv)
    print("Warden serving %s on http://%s:%d" % (app.root, host, srv.server_address[1]), file=sys.stderr)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
    return srv
