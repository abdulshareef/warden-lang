# Warden

**A small, PHP-like language for web back ends that blocks the most common web attacks by design.**

![tests](https://img.shields.io/badge/tests-171%20passing-brightgreen) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![dependencies](https://img.shields.io/badge/dependencies-none-lightgrey) ![license](https://img.shields.io/badge/license-MIT-green)

---

## Introduction

For twenty-five years the same handful of bugs has topped every web-security list: cross-site scripting, SQL injection, command injection, file inclusion, CSRF and session hijacking. None of them is exotic. Each one happens because the language lets untrusted text flow, unnoticed, into a place where it is treated as code: HTML, SQL, a shell, a file path or an HTTP header.

Mainstream back-end languages leave the defence to the developer. Escape this, parameterise that, remember the CSRF token, never forget `htmlspecialchars`. One missed call is a breach. Code review and scanners catch some of these misses, but not all.

**Warden takes the opposite approach. The runtime does the remembering.** Every character that arrives from a request, cookie, header, database row or file is *tainted*. Warden tracks that taint through every concatenation, substring and string function. At each dangerous sink, Warden either encodes the tainted characters for the exact context they land in or refuses to run the operation. It never just hopes the developer escaped the data.

The syntax is deliberately close to PHP: `$variables`, `function`, `foreach`, `<?wdn ?>` templates, `$_GET` and `$_POST`, and PHP function names. Existing PHP teams can read it on day one. A migration tool converts legacy procedural PHP automatically.

```php
<?wdn $q = $_GET["q"] ?? ""; ?>
<h1>Results for <?= $q ?></h1>                                  <!-- escaped automatically -->
<?wdn foreach (db_query("SELECT title, url FROM posts WHERE title LIKE ?", ["%" . $q . "%"]) as $p): ?>
  <a href="<?= $p['url'] ?>"><?= $p['title'] ?></a>             <!-- javascript: URLs neutralised -->
<?wdn endforeach; ?>
```

Warden refuses to run this, and logs a `sqli` security event:

```php
db_query("SELECT * FROM users WHERE id = " . $_GET["id"]);
```

---

## Why Warden is different from PHP (and other back-end stacks)

| | PHP / typical stack | Warden |
|---|---|---|
| **XSS** | `echo $_GET['x']` is vulnerable unless you remember `htmlspecialchars()`, and you must pick the right escaping for each context yourself | Output is encoded automatically for the exact HTML context (text, quoted attribute, URL). Unsafe contexts such as `<script>`, `on*=` and unquoted attributes are refused |
| **SQL injection** | String-built queries run happily. Escaping functions exist but are easy to misuse | SQL text containing *any* user-controlled character will not execute, even after `trim`, `sprintf` or `htmlspecialchars`. Parameters are the only way in |
| **Stored / second-order attacks** | Data read back from the database is trusted | Database rows and file contents are tainted too |
| **Command execution** | `eval`, `system`, `exec`, backticks, `unserialize` and `extract` are all available | These do not exist in the language |
| **File inclusion** | `include $_GET['page']` works (LFI/RFI) | Includes must be literal paths inside the app. File I/O is sandboxed to `data/`, and URLs are refused (no SSRF) |
| **Type juggling** | `"0e123" == "0e456"` is `true`; magic-hash login bypasses | `==` is strict and there is no implicit string↔number conversion. Integer overflow is an error, not a silent float |
| **CSRF** | A framework or developer task | Automatic token and Origin checks on every POST, PUT, PATCH and DELETE |
| **Sessions** | Fixation is possible and cookie flags are opt-in | 256-bit server-side IDs, never adopted from the client. HttpOnly and SameSite by default, plus `Secure` and `__Host-` in production |
| **Headers and redirects** | Header injection and open redirects are the developer's job | CR/LF injection is blocked. Redirects must be relative or allowlisted |
| **Security headers** | Configure them yourself | CSP, X-Frame-Options, nosniff, Referrer-Policy and Permissions-Policy by default |
| **DoS** | `max_execution_time`, plus whatever the web server provides | Per-request limits on CPU steps, recursion, memory and output. Per-IP rate limiting, bounded workers, slow-client timeouts and anti-request-smuggling |
| **Error leakage** | Stack traces and paths are often shown to users | Generic error page with a request ID. Details go only to a JSON log |
| **Dependencies** | PHP runtime, extensions, web server modules | Pure Python standard library, about 6,000 lines, nothing else required |

Warden fails closed. Security violations abort the request and are logged, and scripts cannot catch them with `try/catch` and carry on.

### The key idea: taint has a *kind*

Escaping for one context does not make data safe for another. Warden marks each tainted range as one of:

- **raw**: straight from the user
- **escaped**: passed through `htmlspecialchars()`
- **sanitised**: passed through `html_sanitize()`

Escaped and sanitised text may be printed as HTML. Everywhere else (SQL, headers, paths, redirects) it is still treated as untrusted. That closes the classic hole where `"WHERE id = " . htmlspecialchars($id)` is "escaped" yet still injectable.

---

## Features

- **PHP-familiar syntax.** Templates, alternative syntax (`if: … endif;`), closures, `try/catch/finally`, constants, and more than 150 built-ins with PHP names.
- **Pages and routes.** `pages/login.wdn` is served at `/login` (and at `/login.php`, so old URLs keep working). There is also `route("GET", "/api/users/{id:int}", fn)` for APIs, and arrays returned from a route are sent as JSON automatically.
- **Database.** SQLite with `db_query`, `db_one`, `db_value`, `db_exec` and `db_transaction`, all parameter-only.
- **Security primitives.** scrypt `password_hash()`/`password_verify()` (it also verifies migrated PHP bcrypt hashes), `hash_equals`, `random_token`, and an HTML sanitizer.
- **Share-nothing execution.** A fresh interpreter for each request, like PHP, so there is no state bleed between users.
- **Production ready to deploy.** Hardened built-in server, a WSGI adapter for gunicorn, and nginx, systemd (sandboxed) and Docker configs in `deploy/`.
- **PHP migration tool.** `warden migrate` converts procedural PHP, auto-parameterises SQL, removes dangerous calls and writes a security report.

---

## Quick start

```bash
git clone https://github.com/abdulshareef/warden-lang.git
cd warden-lang
python3 run_tests.py -q                # 171 tests, should end with FAILED: 0
pip install .                          # installs the `warden` command

warden new myapp
warden serve myapp                     # http://127.0.0.1:8080
warden serve examples/guestbook        # full demo: register, login, post, search, JSON API
```

| Command | Purpose |
|---|---|
| `warden serve <app> [--port --debug]` | Run an app with the hardened built-in server |
| `warden run file.wdn` | Run a script from the command line |
| `warden check <dirs>` | Syntax-check every `.wdn` file (for CI) |
| `warden migrate <php_dir> <out_dir>` | Convert a PHP project and produce `MIGRATION_REPORT.md` |
| `warden new <dir>` | Create an app skeleton |

### A login page in Warden

```php
<?wdn
$error = "";
if (request_method() === "POST") {
    $user = db_one("SELECT email, pw FROM users WHERE email = ?", [strtolower(trim($_POST["email"] ?? ""))]);
    if ($user !== null && password_verify($_POST["password"] ?? "", $user["pw"])) {
        session_regenerate();                 // prevents session fixation
        session_set("user", $user["email"]);
        redirect("/");
    }
    $error = "Invalid email or password";
}
?>
<form method="post">
  <?= csrf_field() ?>
  <?wdn if ($error !== ""): ?><p><?= $error ?></p><?wdn endif; ?>
  <input name="email" type="email"> <input name="password" type="password"> <button>Log in</button>
</form>
```

---

## Migrating from PHP

```bash
warden migrate legacy_php/ myapp/
warden check myapp/
```

The converter rewrites the common procedural PHP patterns:

| PHP | Warden |
|---|---|
| `mysqli_query($c, "… WHERE id = '$id'")` | `db_query("… WHERE id = ?", [$id])` |
| `while ($r = mysqli_fetch_assoc($res))` | `foreach ($res as $r)` |
| `$_SESSION['user'] = $u` | `session_set('user', $u)` |
| `header("Location: index.php")` | `redirect("index.php")` |
| `eval(…)`, `system(…)`, `unserialize(…)`, `include $page` | Removed, and fails closed if reached |

The tool also handles PDO `prepare`/`execute`, includes, sorting and more. Everything it cannot convert safely, such as classes, `switch`, references and `preg_*`, is listed in the report with line numbers. The bundled `examples/php_legacy` app is deliberately full of SQLi, XSS, RCE, LFI and MD5 passwords. It migrates with zero syntax errors, and the result blocks every one of those attacks.

---

## Tested

The suite has **171 automated tests**, all passing, run with `python3 run_tests.py`:

- **Language semantics:** 43 tests
- **Attack vectors:** 63 tests, covering XSS in every context plus a 3,000-case fuzz test, SQLi including second-order and laundering, type juggling, the sandbox, and resource bombs
- **HTTP and live server:** 46 tests, covering CSRF, session fixation, header injection, open redirect, traversal, request smuggling, slowloris, header floods and the concurrency cap
- **PHP migration:** 16 tests
- **CLI end to end:** 3 tests

---

## Honest limits

No language can make an application "free from all vulnerabilities". Warden removes the *mechanical* bug classes above. You still own the rest:

- **Business logic and authorization.** For example, whether user A may edit record B.
- **Client-side JavaScript.**
- **Platform patching and TLS.**

Version 1.0 also has these gaps:

- No file uploads, classes or regex (ReDoS risk).
- SQLite is the only database.
- Sessions are in-memory and per process.

Warden 1.0 is new and has not yet had an independent audit. Commission one before it handles sensitive production data. See [`SECURITY.md`](SECURITY.md) for the full threat model.

## Documentation

- [`docs/LANGUAGE_REFERENCE.md`](docs/LANGUAGE_REFERENCE.md): syntax, every built-in, configuration
- [`SECURITY.md`](SECURITY.md): what is prevented, how, and what is not
- [`deploy/`](deploy/): nginx, gunicorn, systemd and Docker configurations
- [`CHANGELOG.md`](CHANGELOG.md)

## Project layout

```
warden/      interpreter, taint tracking, HTML encoder, stdlib, server, migration tool, CLI
tests/       171 tests (language, security, HTTP, migration, CLI)
examples/    guestbook app + a deliberately vulnerable PHP app to migrate
deploy/      production configs
docs/        language reference
```

## License

MIT. See [`LICENSE`](LICENSE).

---

## Credits

Developed by **Dr. Abdul Shareef Pallivalappil** with the support of **[TALFOR Cybersecurity & Digital Forensics](https://talfor.in)**, Bengaluru.

TALFOR provides digital forensics, incident response, AI security and cybersecurity training. Visit **[talfor.in](https://talfor.in)**.
