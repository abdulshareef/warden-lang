# Changelog

## 1.0.0 — 2026-11-23
First release.

**Language**
- Interpreter for a PHP-like syntax with templates, strict typing rules, copy-on-write arrays and hard resource limits.

**Security**
- Character-level taint tracking with three kinds: raw, escaped and sanitised.
- Context-aware HTML encoding.
- SQL guard that refuses user-controlled SQL text.
- Automatic CSRF checks.
- Hardened sessions.
- Sandboxed files.
- Default security headers.

**Server**
- Hardened built-in HTTP server and WSGI adapter.
- JSON security and access logging.

**Migration**
- `warden migrate` converts PHP, auto-parameterises SQL and writes a security report.

**Tests**
- 171 automated tests, all passing on Python 3.13.
