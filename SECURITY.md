# Security model

## What Warden prevents by construction
| Attack class | Mechanism |
|---|---|
| XSS (reflected and stored) | Every string carries character-level taint. HTML responses are encoded per context (text, quoted attribute, URL attribute). Responses that put untrusted data in `<script>`, `<style>`, event handlers, `style=`, unquoted attributes or tag names are refused. DB rows and files are tainted too. A strict CSP is sent by default. |
| SQL injection (first and second order) | `db_*` functions refuse SQL text that contains any untrusted character, even after transformations or `htmlspecialchars`. Values must be bound with `?` or `:name`. Only one statement runs per call. ATTACH and `load_extension` are denied. SQL time is budgeted. |
| Command injection, RCE | No `eval`, `exec`, `system`, backticks, `unserialize`, `extract`, `$$var`, or dynamic includes. Calling a function by a name taken from input is a security violation. |
| Path traversal, LFI/RFI | Includes must be literal paths inside the app root. File functions are sandboxed to `data/`, with symlink-escape checks. URLs are rejected (no SSRF). |
| CSRF | Automatic token and Origin checks on POST, PUT, PATCH and DELETE. `csrf_field()` for forms. Cookieless JSON APIs are exempt. |
| Session fixation and hijacking | 256-bit server-side session IDs. Unknown IDs are never adopted. `session_regenerate()` on login. Cookies are HttpOnly and SameSite=Lax, plus `Secure` and the `__Host-` prefix in production. |
| Header and cookie injection, open redirect | CR/LF/NUL are rejected. Redirects must be relative or allowlisted. |
| Type juggling | Strict `==`. No implicit string↔number conversion. Integer overflow is an error. |
| DoS | CPU-step, recursion, string, array, output, body, field-count and per-IP rate limits. Bounded worker pool. Slow-client timeouts. Transfer-Encoding is rejected to prevent request smuggling. |
| Information disclosure | Generic error pages with a request ID. Details go only to the JSON log. No version banner. |

## What it cannot guarantee
No language can be "free from all vulnerabilities". Warden removes the mechanical bug classes above. These remain your responsibility:
- **Business logic and authorization**, such as forgetting to check that user A may edit record B (IDOR).
- **Implicit flows.** Data deliberately converted through numbers (`chr(ord($x))`) loses taint.
- **Untrusted data in client-side JavaScript.** Warden protects server-rendered output only.
- **The platform.** Keep Python, the OS and the reverse proxy patched, and terminate TLS in front of Warden.
- **This implementation.** It is new and has not had an independent audit. Commission a code review and penetration test before handling sensitive production data.

Report vulnerabilities privately to the maintainers. Security fixes ship as patch releases (see the maintenance guide).

---
Warden is developed with the support of [TALFOR Cybersecurity & Digital Forensics](https://talfor.in).
