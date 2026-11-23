"""Per-request execution context: request data, response, sessions, database."""

import os
import re
import secrets
import sqlite3
import threading
import time

from .errors import WardenError, SecurityViolation
from .tstr import TStr
from .values import BArray, copy_val

DEFAULT_CONFIG = {
    "allowed_hosts": ["localhost", "127.0.0.1", "[::1]"],
    "secure_cookies": False,          # set true behind HTTPS (production)
    "hsts": False,                    # set true behind HTTPS (production)
    "max_body": 1024 * 1024,
    "max_steps": 5_000_000,
    "max_depth": 64,
    "max_output": 16 * 1024 * 1024,
    "rate_limit_per_minute": 600,
    "workers": 32,
    "request_timeout": 10,
    "session_idle_seconds": 1800,
    "session_max_seconds": 43200,
    "max_sessions": 100_000,
    "database": "data/app.db",
    "data_dir": "data",
    "public_dir": "public",
    "pages_dir": "pages",
    "redirect_allowlist": [],
    "csrf_exempt_paths": [],
    "db_timeout_seconds": 5,          # abort any single request's SQL work after this long
    "trust_proxy": False,             # honour X-Forwarded-For / -Proto from a reverse proxy
    "csp": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "log_file": None,
    "debug": False,
}


# ------------------------------------------------------------------ sessions
class Session:
    __slots__ = ("sid", "data", "csrf", "created", "seen")

    def __init__(self, sid):
        self.sid = sid
        self.data = {}
        self.csrf = secrets.token_urlsafe(32)
        self.created = self.seen = time.time()


class SessionStore:
    """In-memory server-side session store (swap for Redis/DB for multi-node)."""

    def __init__(self, idle=1800, max_age=43200, max_sessions=100_000):
        self.idle = idle
        self.max_age = max_age
        self.max_sessions = max_sessions
        self.s = {}
        self.lock = threading.Lock()
        self.last_purge = time.time()

    def get(self, sid):
        if not sid or not re.fullmatch(r"[A-Za-z0-9_\-]{40,64}", sid):
            return None
        now = time.time()
        with self.lock:
            sess = self.s.get(sid)
            if sess is None:
                return None
            if now - sess.seen > self.idle or now - sess.created > self.max_age:
                del self.s[sid]
                return None
            sess.seen = now
            return sess

    def create(self):
        now = time.time()
        with self.lock:
            if now - self.last_purge > 60:
                self._purge(now)
            if len(self.s) >= self.max_sessions:
                oldest = min(self.s.values(), key=lambda x: x.seen)
                del self.s[oldest.sid]
            sid = secrets.token_urlsafe(32)   # 256 bits
            sess = Session(sid)
            self.s[sid] = sess
            return sess

    def regenerate(self, sess):
        new = self.create()
        new.data = sess.data
        self.destroy(sess)
        return new

    def destroy(self, sess):
        with self.lock:
            self.s.pop(sess.sid, None)

    def _purge(self, now):
        self.last_purge = now
        dead = [k for k, v in self.s.items()
                if now - v.seen > self.idle or now - v.created > self.max_age]
        for k in dead:
            del self.s[k]


# ------------------------------------------------------------------ database
def _authorizer(action, arg1, arg2, dbname, source):
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and arg2 and arg2.lower() in ("load_extension", "readfile", "writefile", "edit"):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


# ------------------------------------------------------------------ context
class Context:
    def __init__(self, app_root, config=None, sessions=None, request=None):
        self.app_root = os.path.realpath(app_root)
        self.config = dict(DEFAULT_CONFIG)
        if config:
            self.config.update(config)
        self.sessions = sessions or SessionStore(self.config["session_idle_seconds"],
                                                 self.config["session_max_seconds"],
                                                 self.config["max_sessions"])
        self.request = request or {}
        # response state
        self.status = 200
        self.headers = {}             # lower-name -> (Name, value)
        self.cookies_out = []
        self.raw_body = None          # bytes set by respond_json etc.
        self.redirect_to = None
        # session state
        self.session = None
        self.session_cookie_needed = False
        self.session_destroyed = False
        self._session_loaded = False
        # routing
        self.routes = []
        self._db = None
        self.log_events = []

    # -------------------------------------------------------------- session
    @property
    def cookie_name(self):
        return "__Host-wsid" if self.config["secure_cookies"] else "wsid"

    def load_session(self, create):
        if not self._session_loaded:
            self._session_loaded = True
            sid = self.request.get("cookies", {}).get(self.cookie_name)
            self.session = self.sessions.get(sid)
        if self.session is None and create:
            self.session = self.sessions.create()
            self.session_cookie_needed = True
            self.session_destroyed = False
        return self.session

    def session_get(self, key, default=None):
        s = self.load_session(False)
        if s is None:
            return default
        return copy_val(s.data.get(key, default))

    def session_set(self, key, value):
        s = self.load_session(True)
        if len(s.data) > 1000:
            raise WardenError("too many session keys")
        s.data[key] = copy_val(value)

    def session_delete(self, key):
        s = self.load_session(False)
        if s is not None:
            s.data.pop(key, None)

    def session_regenerate(self):
        s = self.load_session(True)
        self.session = self.sessions.regenerate(s)
        self.session_cookie_needed = True

    def session_destroy(self):
        s = self.load_session(False)
        if s is not None:
            self.sessions.destroy(s)
        self.session = None
        self.session_destroyed = True

    def csrf_token(self):
        return self.load_session(True).csrf

    # -------------------------------------------------------------- headers
    def set_header(self, name, value):
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}", name):
            raise SecurityViolation("invalid header name", "header-injection")
        if any(c in value for c in "\r\n\x00") or len(value) > 8192:
            raise SecurityViolation("header value contains CR/LF/NUL (header injection blocked)",
                                    "header-injection")
        low = name.lower()
        if low in ("set-cookie", "content-length", "transfer-encoding", "connection"):
            raise WardenError("header %s cannot be set directly" % name)
        if low == "location":
            self.redirect(value)
            return
        self.headers[low] = (name, value)

    def redirect(self, url, code=302):
        if not self.redirect_allowed(url):
            raise SecurityViolation("open redirect blocked: %r" % url[:100], "open-redirect")
        if code not in (301, 302, 303, 307, 308):
            raise WardenError("invalid redirect status")
        if any(c in url for c in "\r\n\x00"):
            raise SecurityViolation("header injection in redirect", "header-injection")
        self.status = code
        self.headers["location"] = ("Location", url)

    def redirect_allowed(self, url):
        u = url.strip()
        if u.startswith("/") and not u.startswith("//") and "\\" not in u:
            return True
        if re.match(r"^[A-Za-z0-9_\-./?=&%#]+$", u) and ":" not in u and not u.startswith("//"):
            return True  # relative like "login.wdn?x=1"
        for prefix in self.config.get("redirect_allowlist") or []:
            if u == prefix or u.startswith(prefix.rstrip("/") + "/"):
                return True
        return False

    def set_cookie(self, name, value, max_age=None, path="/", httponly=True, samesite="Lax"):
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", name):
            raise SecurityViolation("invalid cookie name", "header-injection")
        if name in ("wsid", "__Host-wsid"):
            raise WardenError("cookie name is reserved for sessions")
        if re.search(r"[\x00-\x1f\x7f;,\s\"\\]", value) or len(value) > 4000:
            raise SecurityViolation("invalid characters in cookie value (use urlencode)",
                                    "header-injection")
        if samesite not in ("Strict", "Lax"):
            samesite = "Lax"
        parts = ["%s=%s" % (name, value), "Path=%s" % ("/" if not re.fullmatch(r"/[A-Za-z0-9_\-/]*", path) else path),
                 "SameSite=%s" % samesite]
        if max_age is not None:
            parts.append("Max-Age=%d" % int(max_age))
        if httponly:
            parts.append("HttpOnly")
        if self.config["secure_cookies"]:
            parts.append("Secure")
        self.cookies_out.append("; ".join(parts))

    # ------------------------------------------------------------- database
    def db(self):
        if self._db is None:
            path = os.path.join(self.app_root, self.config["database"])
            real = os.path.realpath(path)
            if not real.startswith(self.app_root + os.sep):
                raise SecurityViolation("database path escapes app root", "path")
            os.makedirs(os.path.dirname(real), exist_ok=True)
            con = sqlite3.connect(real, timeout=5, isolation_level=None)
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA trusted_schema=OFF")
            try:
                con.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
            con.set_authorizer(_authorizer)
            deadline = time.monotonic() + float(self.config["db_timeout_seconds"])
            con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
            con.row_factory = sqlite3.Row
            self._db = con
        return self._db

    def close(self):
        if self._db is not None:
            try:
                self._db.close()
            except Exception:
                pass
            self._db = None

    # ----------------------------------------------------------------- data
    @property
    def data_dir(self):
        d = os.path.join(self.app_root, self.config["data_dir"])
        os.makedirs(d, exist_ok=True)
        return d

    def log(self, level, msg):
        self.log_events.append((level, msg))
