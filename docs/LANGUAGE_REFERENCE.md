# Warden language reference (1.0)

## Files and templates
A `.wdn` file starts in template mode. Text is output as trusted markup until `<?wdn` (code) or `<?= expr ?>` (echo). `?>` returns to template mode and swallows one newline right after it, as PHP does.

| Location | Purpose |
|---|---|
| `app.wdn` | Runs at the start of every request. Use it for routes and shared includes. |
| `pages/x.wdn` | Served at `/x`, `/x.php` and `/x.wdn`. `pages/index.wdn` is served at `/`. Files starting with `_` are private partials. |
| `public/` | Static files. |
| `data/` | The SQLite database and sandboxed files. |
| `warden.json` | Configuration. |

## Syntax (PHP subset)
```php
$x = 1; $s = "Hi $name {$user['email']} $arr[key]"; $t = 'raw $not';
const MAX = 10;  define("MIN", 1);
function add($a, $b = 0) { return $a + $b; }        // type hints accepted and ignored
$f = function($x) use ($k) { return $x * $k; };     // closures capture by value
if (...) { } elseif (...) { } else { }    while (...) { }    for ($i = 0; $i < 3; $i++) { }
foreach ($arr as $k => $v) { }    break 2; continue;
try { throw "msg"; } catch (Exception $e) { echo $e; } finally { }
include "lib/x.wdn"; include_once "lib/x.wdn";      // literal paths only, relative to app root
<?wdn if ($a): ?> ... <?wdn elseif ($b): ?> ... <?wdn else: ?> ... <?wdn endif; ?>   // also endforeach/endwhile/endfor
```
Operators: `+ - * / %`, `.`, `== != === !== < > <= >=`, `&& || ! and or`, `?:`, `??`, `??=`, `= += -= *= /= .= %=`, `++ --`, and the casts `(int) (float) (string) (bool)`.

## Semantics that differ from PHP (on purpose)
- `==` is strict and identical to `===`. Values of different types are never equal: `"1" == 1` is false, and so is `"0e1" == "0e2"`.
- No implicit conversion. `"5" + 1` is an error, so use `int($x)`. `int("12abc")` is an error, while `intval()` and `(int)` keep PHP's lenient parsing.
- Integers are 64-bit, and overflow is an error.
- Truthiness: only `false`, `null`, `0`, `0.0`, `""` and `[]` are falsy, so `"0"` is truthy.
- Reading an undefined variable or array key is an error. Use `??`, `isset()` or `empty()`.
- Arrays are values (copy-on-write). There are no references (`&`).
- Concatenating or echoing `bool` or `array` is an error. `null` becomes `""`.
- User functions cannot shadow built-ins.

## Not supported (compile-time error with an explanation)
Classes and objects (`new`, `->`, `::`), references, `global`, `static`, `switch`, `match`, `do/while`, `list()`, variable variables, `eval`, backticks, `goto`, namespaces, `preg_*`, file uploads (planned for 1.1), and arbitrary filesystem or network access.

## Built-in functions
- **Strings:** strlen, strtolower/upper, ucfirst, lcfirst, ucwords, trim/ltrim/rtrim, substr, str_replace, str_contains, str_starts_with, str_ends_with, strpos/stripos/strrpos, strrev, str_repeat, str_pad, str_split, explode, implode/join, sprintf, number_format, nl2br, htmlspecialchars, html_entity_decode, strip_tags, html_sanitize, urlencode/rawurlencode/urldecode, http_build_query, base64_encode/decode, bin2hex/hex2bin, ord, chr.
- **Types:** int, float, str/strval, intval, floatval, boolval, gettype, is_int/float/string/bool/array/null/numeric/callable, ctype_digit/alpha/alnum/xdigit/lower/upper/space, validate_email, filter_var (VALIDATE_INT/FLOAT/EMAIL/URL/BOOLEAN).
- **Arrays:** count, array_keys, array_values, in_array, array_search, array_key_exists, array_merge, array_slice, array_reverse, array_map, array_filter, array_reduce, array_sum, array_unique, array_combine, array_flip, array_column, array_first, array_last, array_fill, range. Sorting returns a new array: `sorted($a, $desc)`, `ksorted`, `asorted`, `usorted($a, $cmp)`.
- **Math:** abs, floor, ceil, round, intdiv, sqrt, pow, max, min, random_int/rand/mt_rand (all CSPRNG).
- **JSON and time:** json_encode (output is safe to embed in HTML), json_decode (always associative), time, microtime, date/gmdate (UTC), mktime.
- **Security:** password_hash (scrypt), password_verify (scrypt, plus PHP bcrypt if the `bcrypt` package is installed), password_needs_rehash, hash (sha256/384/512, sha3, blake2, md5, sha1), hash_hmac, hash_equals, random_bytes, random_token, md5, sha1.
- **Web:** route(method, pattern, fn), header, http_response_code/status, redirect, setcookie, respond_json(data, status), request_method, request_path, request_header, request_json, request_ip, csrf_field, csrf_token.
- **Sessions:** session_get(k, default), session_set, session_has, session_delete, session_regenerate, session_destroy, and session_start (a no-op).
- **Database (SQLite):** db_query(sql, params) returns rows, db_one returns a row or null, db_value returns a scalar, db_exec returns `["changes", "last_id"]`, and db_transaction(fn) runs a transaction.
- **Files (sandboxed to `data/`):** file_read/file_get_contents, file_write/file_put_contents (with FILE_APPEND), file_exists.
- **Misc:** print_r, var_dump, call_user_func(_array), function_exists, define, defined, env (WARDEN_* and APP_* only), log_info/warn/error, exit/die.

## Routes
```php
route("GET", "/users/{id:int}", function($req) {     // types: int, slug, alpha, any
    $u = db_one("SELECT id, name FROM users WHERE id = ?", [int($req["params"]["id"])]);
    if ($u === null) { respond_json(["error" => "not found"], 404); }
    return $u;                                        // array -> JSON, string -> HTML
});
```
`$req` has the keys `method`, `path`, `params`, `query`, `body` and `json`.

## Untrusted data and taint
Every character from a request, cookie, header, database row or file is tainted. Taint survives all string operations.

| Sink | What happens to tainted data |
|---|---|
| HTML output | Encoded for its context, or the response is refused. |
| SQL text | Refused, so pass values as parameters. |
| Headers, cookies and redirects | Validated. |
| Include and file paths | Validated. |
| Dynamic calls and sprintf format strings | Refused. |

`int()` or `float()` produce clean numbers. `htmlspecialchars()` and `html_sanitize()` make data safe for HTML output only. It stays tainted for SQL, headers and paths.

## Configuration (`warden.json`)
| Key | Default | Notes |
|---|---|---|
| allowed_hosts | localhost, 127.0.0.1, [::1] | Host header allowlist |
| secure_cookies / hsts | false | Set both to `true` in production (HTTPS) |
| trust_proxy | false | Set to `true` behind nginx so X-Forwarded-For is used for IPs |
| max_body | 1048576 | Bytes |
| max_steps / max_depth / max_output | 5,000,000 / 64 / 16 MB | Per request |
| rate_limit_per_minute | 600 | Per IP; 0 disables |
| workers / request_timeout | 32 / 10 s | Built-in server only |
| session_idle_seconds / session_max_seconds | 1800 / 43200 | |
| database / data_dir / public_dir / pages_dir | data/app.db, data, public, pages | |
| db_timeout_seconds | 5 | SQL time budget per request |
| redirect_allowlist | [] | Absolute URL prefixes allowed in redirect() |
| csrf_exempt_paths | [] | e.g. `["/webhooks/"]` |
| csp | strict self-only | Content-Security-Policy |
| log_file / debug | stderr / false | debug shows details to localhost only |
