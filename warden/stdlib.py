"""Built-in function library (PHP-compatible names where it is safe to be).

Absent on purpose: eval, exec, system, shell_exec, passthru, popen, proc_open,
unserialize, extract, assert(string), preg_* (ReDoS), include of dynamic
paths, outbound network access, raw filesystem access outside data/.
"""

import base64
import datetime
import hashlib
import hmac
import html
import json
import math
import os
import re
import secrets
import sqlite3
import time
import urllib.parse

from .errors import WardenError, SecurityViolation, ExitSignal, LimitExceeded
from .tstr import TStr, join as tjoin
from .values import (BArray, Func, type_name, is_num, check_int, truthy, to_str,
                     equals, compare, to_py, from_py, fmt_float, INT_MAX, INT_MIN)
from . import htmlctx

try:  # optional: verify migrated PHP bcrypt hashes
    import bcrypt as _bcrypt
except Exception:  # pragma: no cover
    _bcrypt = None

BUILTINS = {}
CONSTANTS = {
    "PHP_EOL": TStr("\n"), "PHP_INT_MAX": INT_MAX, "PHP_INT_MIN": INT_MIN,
    "PASSWORD_DEFAULT": TStr("scrypt"), "PASSWORD_BCRYPT": TStr("scrypt"),
    "PASSWORD_ARGON2ID": TStr("scrypt"), "ENT_QUOTES": 3, "ENT_HTML5": 48,
    "JSON_PRETTY_PRINT": 128, "JSON_UNESCAPED_SLASHES": 64, "JSON_UNESCAPED_UNICODE": 256,
    "JSON_THROW_ON_ERROR": 4194304, "M_PI": math.pi, "M_E": math.e,
    "FILTER_VALIDATE_INT": 257, "FILTER_VALIDATE_FLOAT": 259, "FILTER_VALIDATE_EMAIL": 274,
    "FILTER_VALIDATE_URL": 273, "FILTER_VALIDATE_BOOLEAN": 258, "FILTER_DEFAULT": 516,
    "SORT_REGULAR": 0, "COUNT_NORMAL": 0, "WARDEN_VERSION": TStr("1.0.0"),
}


def builtin(*names):
    def deco(fn):
        for n in names:
            BUILTINS[n.lower()] = fn
        return fn
    return deco


# ------------------------------------------------------------ arg helpers
def nargs(args, lo, hi, name, line):
    if not lo <= len(args) <= hi:
        if lo == hi:
            raise WardenError("%s() expects %d argument(s), %d given" % (name, lo, len(args)), line)
        raise WardenError("%s() expects %d to %d arguments, %d given" % (name, lo, hi, len(args)), line)


def s_arg(v, name, line, i=1):
    if isinstance(v, TStr):
        return v
    if is_num(v) and not isinstance(v, bool):
        return to_str(v)
    if v is None:
        return TStr("")
    raise WardenError("%s(): argument %d must be a string, %s given" % (name, i, type_name(v)), line)


def i_arg(v, name, line, i=1):
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    raise WardenError("%s(): argument %d must be an int, %s given" % (name, i, type_name(v)), line)


def n_arg(v, name, line, i=1):
    if is_num(v):
        return v
    raise WardenError("%s(): argument %d must be a number, %s given" % (name, i, type_name(v)), line)


def a_arg(v, name, line, i=1):
    if isinstance(v, BArray):
        return v
    raise WardenError("%s(): argument %d must be an array, %s given" % (name, i, type_name(v)), line)


def ctx_of(it):
    if it.ctx is None:
        from .context import Context
        it.ctx = Context(it.app_root)
    return it.ctx


def P(s):
    return TStr(s, ())


# --------------------------------------------------------------- strings
@builtin("strlen", "mb_strlen")
def _strlen(it, a, line):
    nargs(a, 1, 2, "strlen", line)
    return len(s_arg(a[0], "strlen", line).s)


@builtin("strtolower", "mb_strtolower")
def _lower(it, a, line):
    nargs(a, 1, 1, "strtolower", line)
    return s_arg(a[0], "strtolower", line).map_same(str.lower)


@builtin("strtoupper", "mb_strtoupper")
def _upper(it, a, line):
    nargs(a, 1, 1, "strtoupper", line)
    return s_arg(a[0], "strtoupper", line).map_same(str.upper)


@builtin("ucfirst")
def _ucfirst(it, a, line):
    nargs(a, 1, 1, "ucfirst", line)
    s = s_arg(a[0], "ucfirst", line)
    return s.map_same(lambda x: x[:1].upper() + x[1:])


@builtin("lcfirst")
def _lcfirst(it, a, line):
    nargs(a, 1, 1, "lcfirst", line)
    return s_arg(a[0], "lcfirst", line).map_same(lambda x: x[:1].lower() + x[1:])


@builtin("ucwords")
def _ucwords(it, a, line):
    nargs(a, 1, 1, "ucwords", line)
    return s_arg(a[0], "ucwords", line).map_same(
        lambda x: re.sub(r"(^|\s)(\S)", lambda m: m.group(1) + m.group(2).upper(), x))


def _trim_impl(s, chars, left, right):
    st, en = 0, len(s.s)
    while left and st < en and s.s[st] in chars:
        st += 1
    while right and en > st and s.s[en - 1] in chars:
        en -= 1
    return s.slice(st, en)


_WS = " \t\n\r\0\x0b"


@builtin("trim")
def _trim(it, a, line):
    nargs(a, 1, 2, "trim", line)
    return _trim_impl(s_arg(a[0], "trim", line), s_arg(a[1], "trim", line).s if len(a) > 1 else _WS, True, True)


@builtin("ltrim")
def _ltrim(it, a, line):
    nargs(a, 1, 2, "ltrim", line)
    return _trim_impl(s_arg(a[0], "ltrim", line), s_arg(a[1], "ltrim", line).s if len(a) > 1 else _WS, True, False)


@builtin("rtrim", "chop")
def _rtrim(it, a, line):
    nargs(a, 1, 2, "rtrim", line)
    return _trim_impl(s_arg(a[0], "rtrim", line), s_arg(a[1], "rtrim", line).s if len(a) > 1 else _WS, False, True)


@builtin("substr", "mb_substr")
def _substr(it, a, line):
    nargs(a, 2, 3, "substr", line)
    s = s_arg(a[0], "substr", line)
    start = i_arg(a[1], "substr", line, 2)
    n = len(s.s)
    if start < 0:
        start = max(0, n + start)
    if start > n:
        return P("")
    if len(a) > 2 and a[2] is not None:
        ln = i_arg(a[2], "substr", line, 3)
        end = start + ln if ln >= 0 else n + ln
    else:
        end = n
    return s.slice(start, max(start, end))


def _replace_one(subject, search, repl):
    if not search.s:
        return subject
    pieces, pos = [], 0
    while True:
        j = subject.s.find(search.s, pos)
        if j < 0:
            break
        pieces.append(subject.slice(pos, j))
        pieces.append(repl)
        pos = j + len(search.s)
    pieces.append(subject.slice(pos, None))
    return tjoin(pieces)


@builtin("str_replace")
def _str_replace(it, a, line):
    nargs(a, 3, 3, "str_replace", line)
    search, repl, subject = a
    if isinstance(subject, BArray):
        out = BArray()
        for k, v in subject.items():
            out.set(k, _str_replace(it, [search, repl, v], line))
        return out
    subject = s_arg(subject, "str_replace", line, 3)
    if isinstance(search, BArray):
        reps = repl.values() if isinstance(repl, BArray) else None
        for i, sv in enumerate(search.values()):
            r = (reps[i] if i < len(reps) else P("")) if reps is not None else repl
            subject = _replace_one(subject, s_arg(sv, "str_replace", line), s_arg(r, "str_replace", line))
        return it.check_str(subject)
    return it.check_str(_replace_one(subject, s_arg(search, "str_replace", line), s_arg(repl, "str_replace", line, 2)))


@builtin("str_contains")
def _str_contains(it, a, line):
    nargs(a, 2, 2, "str_contains", line)
    return s_arg(a[1], "str_contains", line).s in s_arg(a[0], "str_contains", line).s


@builtin("str_starts_with")
def _ssw(it, a, line):
    nargs(a, 2, 2, "str_starts_with", line)
    return s_arg(a[0], "str_starts_with", line).s.startswith(s_arg(a[1], "str_starts_with", line).s)


@builtin("str_ends_with")
def _sew(it, a, line):
    nargs(a, 2, 2, "str_ends_with", line)
    return s_arg(a[0], "str_ends_with", line).s.endswith(s_arg(a[1], "str_ends_with", line).s)


@builtin("strpos", "mb_strpos")
def _strpos(it, a, line):
    nargs(a, 2, 3, "strpos", line)
    off = i_arg(a[2], "strpos", line, 3) if len(a) > 2 else 0
    j = s_arg(a[0], "strpos", line).s.find(s_arg(a[1], "strpos", line).s, off)
    return False if j < 0 else j


@builtin("stripos")
def _stripos(it, a, line):
    nargs(a, 2, 3, "stripos", line)
    off = i_arg(a[2], "stripos", line, 3) if len(a) > 2 else 0
    j = s_arg(a[0], "stripos", line).s.lower().find(s_arg(a[1], "stripos", line).s.lower(), off)
    return False if j < 0 else j


@builtin("strrpos")
def _strrpos(it, a, line):
    nargs(a, 2, 2, "strrpos", line)
    j = s_arg(a[0], "strrpos", line).s.rfind(s_arg(a[1], "strrpos", line).s)
    return False if j < 0 else j


@builtin("strrev")
def _strrev(it, a, line):
    nargs(a, 1, 1, "strrev", line)
    s = s_arg(a[0], "strrev", line)
    return s.derived(s.s[::-1])


@builtin("str_repeat")
def _str_repeat(it, a, line):
    nargs(a, 2, 2, "str_repeat", line)
    s = s_arg(a[0], "str_repeat", line)
    n = i_arg(a[1], "str_repeat", line, 2)
    if n < 0:
        raise WardenError("str_repeat(): count must be >= 0", line)
    if len(s.s) * n > it.lim.max_str:
        raise LimitExceeded("string size limit exceeded")
    return tjoin([s] * n)


@builtin("str_pad")
def _str_pad(it, a, line):
    nargs(a, 2, 4, "str_pad", line)
    s = s_arg(a[0], "str_pad", line)
    n = i_arg(a[1], "str_pad", line, 2)
    pad_t = s_arg(a[2], "str_pad", line, 3) if len(a) > 2 else P(" ")
    pad = pad_t.s
    typ = i_arg(a[3], "str_pad", line, 4) if len(a) > 3 else 1  # STR_PAD_RIGHT
    if n > it.lim.max_str:
        raise WardenError("str_pad(): length too large", line)
    if not pad or len(s.s) >= n:
        return s
    need = n - len(s.s)
    mk = pad_t.derived
    if typ == 0:
        return mk((pad * need)[:need]).concat(s)
    if typ == 2:
        left = need // 2
        return mk((pad * need)[:left]).concat(s).concat(mk((pad * need)[:need - left]))
    return s.concat(mk((pad * need)[:need]))


CONSTANTS.update({"STR_PAD_RIGHT": 1, "STR_PAD_LEFT": 0, "STR_PAD_BOTH": 2})


@builtin("explode")
def _explode(it, a, line):
    nargs(a, 2, 3, "explode", line)
    d = s_arg(a[0], "explode", line).s
    s = s_arg(a[1], "explode", line, 2)
    limit = i_arg(a[2], "explode", line, 3) if len(a) > 2 else None
    if not d:
        raise WardenError("explode(): empty delimiter", line)
    out, pos = [], 0
    while True:
        if limit is not None and limit > 0 and len(out) == limit - 1:
            break
        j = s.s.find(d, pos)
        if j < 0:
            break
        out.append(s.slice(pos, j))
        pos = j + len(d)
    out.append(s.slice(pos, None))
    if limit is not None and limit < 0:
        out = out[:limit]
    return it.check_arr(BArray.from_list(out))


@builtin("implode", "join")
def _implode(it, a, line):
    nargs(a, 1, 2, "implode", line)
    if len(a) == 1:
        glue, arr = P(""), a[0]
    elif isinstance(a[0], BArray):
        arr, glue = a[0], s_arg(a[1], "implode", line)
    else:
        glue, arr = s_arg(a[0], "implode", line), a[1]
    arr = a_arg(arr, "implode", line, 2)
    parts = []
    for i, v in enumerate(arr.values()):
        if i:
            parts.append(glue)
        if isinstance(v, (BArray, bool, Func)):
            raise WardenError("implode(): cannot join a %s" % type_name(v), line)
        parts.append(to_str(v))
    return it.check_str(tjoin(parts))


@builtin("str_split", "mb_str_split")
def _str_split(it, a, line):
    nargs(a, 1, 2, "str_split", line)
    s = s_arg(a[0], "str_split", line)
    n = i_arg(a[1], "str_split", line, 2) if len(a) > 1 else 1
    if n < 1:
        raise WardenError("str_split(): length must be >= 1", line)
    return it.check_arr(BArray.from_list([s.slice(i, i + n) for i in range(0, len(s.s), n)] or [P("")]))


@builtin("sprintf")
def _sprintf(it, a, line):
    if not a:
        raise WardenError("sprintf() expects at least 1 argument", line)
    fmt = s_arg(a[0], "sprintf", line)
    if fmt.is_tainted:
        raise SecurityViolation("format string must not come from user input", "format-string")
    args = list(a[1:])
    parts, i, ai = [], 0, 0
    f = fmt.s
    spec = re.compile(r"%(?:(\d+)\$)?([-+ 0]|'.)*(\d+)?(?:\.(\d+))?([bcdeEfFgGosuxX%])")
    while i < len(f):
        j = f.find("%", i)
        if j < 0:
            parts.append(P(f[i:]))
            break
        parts.append(P(f[i:j]))
        m = spec.match(f, j)
        if not m:
            raise WardenError("sprintf(): bad format at offset %d" % j, line)
        conv = m.group(5)
        if conv == "%":
            parts.append(P("%"))
            i = m.end()
            continue
        if m.group(1):
            idx = int(m.group(1)) - 1
        else:
            idx = ai
            ai += 1
        if idx >= len(args):
            raise WardenError("sprintf(): too few arguments", line)
        v = args[idx]
        width = int(m.group(3)) if m.group(3) else 0
        prec = int(m.group(4)) if m.group(4) is not None else None
        flags = m.group(0)[1:]
        left = "-" in flags.split(m.group(3) or "\0")[0] if m.group(3) else "-" in flags
        zero = flags.startswith("0") or "0" in (flags.split(m.group(3))[0] if m.group(3) else "")
        if conv == "s":
            sv = s_arg(v, "sprintf", line)
            if prec is not None:
                sv = sv.slice(0, prec)
            padn = max(0, width - len(sv.s))
            parts.append(sv.concat(P(" " * padn)) if left else P(" " * padn).concat(sv))
            i = m.end()
            continue
        if conv in "dux":
            iv = php_intval(v)
            txt = format(iv, "x" if conv == "x" else "d")
        elif conv == "X":
            txt = format(php_intval(v), "X")
        elif conv == "b":
            txt = format(php_intval(v), "b")
        elif conv == "o":
            txt = format(php_intval(v), "o")
        elif conv == "c":
            txt = chr(php_intval(v))
        else:
            fv = php_floatval(v)
            txt = format(fv, "." + str(6 if prec is None else prec) + ("f" if conv in "fF" else conv))
        if width and len(txt) < width:
            txt = txt.ljust(width) if left else (txt.rjust(width, "0") if zero else txt.rjust(width))
        parts.append(P(txt))
        i = m.end()
    return it.check_str(tjoin(parts))


@builtin("number_format")
def _number_format(it, a, line):
    nargs(a, 1, 4, "number_format", line)
    v = n_arg(a[0], "number_format", line)
    dec = i_arg(a[1], "number_format", line, 2) if len(a) > 1 else 0
    dp_t = s_arg(a[2], "number_format", line) if len(a) > 2 else P(".")
    ts_t = s_arg(a[3], "number_format", line) if len(a) > 3 else P(",")
    txt = format(round(v, dec), ",.%df" % max(0, dec))
    txt = txt.replace(",", "\0").replace(".", dp_t.s).replace("\0", ts_t.s)
    return TStr.tainted(txt) if (dp_t.is_tainted or ts_t.is_tainted) else P(txt)


@builtin("nl2br")
def _nl2br(it, a, line):
    nargs(a, 1, 1, "nl2br", line)
    s = s_arg(a[0], "nl2br", line)
    return _replace_one(s, P("\n"), P("<br>\n"))


@builtin("htmlspecialchars", "htmlentities", "e", "escape_html")
def _hsc(it, a, line):
    nargs(a, 1, 4, "htmlspecialchars", line)
    s = s_arg(a[0], "htmlspecialchars", line)
    out = htmlctx.escape_text(s.s)
    # escaped text is safe for HTML output only; it stays untrusted for SQL, headers, paths
    return TStr.tainted(out, "h") if s.is_tainted else P(out)


@builtin("html_entity_decode", "htmlspecialchars_decode")
def _hed(it, a, line):
    nargs(a, 1, 3, "html_entity_decode", line)
    s = s_arg(a[0], "html_entity_decode", line)
    return s.derived(html.unescape(s.s))


@builtin("strip_tags")
def _strip_tags(it, a, line):
    nargs(a, 1, 2, "strip_tags", line)
    s = s_arg(a[0], "strip_tags", line)
    return s.derived(re.sub(r"<[^>]*>?", "", s.s))


@builtin("html_sanitize")
def _html_sanitize(it, a, line):
    nargs(a, 1, 1, "html_sanitize", line)
    s = s_arg(a[0], "html_sanitize", line)
    out = htmlctx.sanitize_html(s.s)
    return TStr.tainted(out, "m") if s.is_tainted else P(out)


@builtin("urlencode")
def _urlencode(it, a, line):
    nargs(a, 1, 1, "urlencode", line)
    s = s_arg(a[0], "urlencode", line)
    return s.derived(urllib.parse.quote_plus(s.s, safe=""))


@builtin("rawurlencode")
def _rawurlencode(it, a, line):
    nargs(a, 1, 1, "rawurlencode", line)
    s = s_arg(a[0], "rawurlencode", line)
    return s.derived(urllib.parse.quote(s.s, safe="-_.~"))


@builtin("urldecode", "rawurldecode")
def _urldecode(it, a, line):
    nargs(a, 1, 1, "urldecode", line)
    s = s_arg(a[0], "urldecode", line)
    return s.derived(urllib.parse.unquote_plus(s.s))


@builtin("http_build_query")
def _hbq(it, a, line):
    nargs(a, 1, 1, "http_build_query", line)
    arr = a_arg(a[0], "http_build_query", line)
    tainted = any(isinstance(v, TStr) and v.is_tainted for v in arr.values()) or bool(arr.kt)
    q = urllib.parse.urlencode([(str(k), to_str(v).s) for k, v in arr.d.items()])
    return TStr.tainted(q) if tainted else P(q)


@builtin("base64_encode")
def _b64e(it, a, line):
    nargs(a, 1, 1, "base64_encode", line)
    s = s_arg(a[0], "base64_encode", line)
    return s.derived(base64.b64encode(s.s.encode("utf-8")).decode())


@builtin("base64_decode")
def _b64d(it, a, line):
    nargs(a, 1, 2, "base64_decode", line)
    s = s_arg(a[0], "base64_decode", line)
    try:
        raw = base64.b64decode(s.s, validate=False)
    except Exception:
        return False
    return s.derived(raw.decode("utf-8", "replace"))


@builtin("bin2hex")
def _bin2hex(it, a, line):
    nargs(a, 1, 1, "bin2hex", line)
    s = s_arg(a[0], "bin2hex", line)
    return s.derived(s.s.encode("latin-1", "replace").hex() if all(ord(c) < 256 for c in s.s)
                     else s.s.encode("utf-8").hex())


@builtin("hex2bin")
def _hex2bin(it, a, line):
    nargs(a, 1, 1, "hex2bin", line)
    s = s_arg(a[0], "hex2bin", line)
    try:
        return s.derived(bytes.fromhex(s.s).decode("latin-1"))
    except ValueError:
        return False


@builtin("ord")
def _ord(it, a, line):
    nargs(a, 1, 1, "ord", line)
    s = s_arg(a[0], "ord", line).s
    return ord(s[0]) if s else 0


@builtin("chr")
def _chr(it, a, line):
    nargs(a, 1, 1, "chr", line)
    return P(chr(i_arg(a[0], "chr", line) % 256))


def _hash_bytes(s):
    return s.s.encode("utf-8")


@builtin("md5")
def _md5(it, a, line):
    nargs(a, 1, 1, "md5", line)
    return P(hashlib.md5(_hash_bytes(s_arg(a[0], "md5", line)), usedforsecurity=False).hexdigest())


@builtin("sha1")
def _sha1(it, a, line):
    nargs(a, 1, 1, "sha1", line)
    return P(hashlib.sha1(_hash_bytes(s_arg(a[0], "sha1", line)), usedforsecurity=False).hexdigest())


_HASHES = {"sha256", "sha384", "sha512", "sha3-256", "sha3-512", "blake2b", "blake2s", "md5", "sha1"}


@builtin("hash")
def _hash(it, a, line):
    nargs(a, 2, 2, "hash", line)
    algo = s_arg(a[0], "hash", line).s.lower()
    if algo not in _HASHES:
        raise WardenError("hash(): unsupported algorithm %r" % algo, line)
    return P(hashlib.new(algo.replace("-", "_") if algo.startswith("sha3") else algo,
                         _hash_bytes(s_arg(a[1], "hash", line))).hexdigest())


@builtin("hash_hmac")
def _hash_hmac(it, a, line):
    nargs(a, 3, 3, "hash_hmac", line)
    algo = s_arg(a[0], "hash_hmac", line).s.lower()
    if algo not in ("sha256", "sha384", "sha512"):
        raise WardenError("hash_hmac(): use sha256/sha384/sha512", line)
    return P(hmac.new(_hash_bytes(s_arg(a[2], "hash_hmac", line)),
                      _hash_bytes(s_arg(a[1], "hash_hmac", line)), algo).hexdigest())


@builtin("hash_equals")
def _hash_equals(it, a, line):
    nargs(a, 2, 2, "hash_equals", line)
    return hmac.compare_digest(_hash_bytes(s_arg(a[0], "hash_equals", line)),
                               _hash_bytes(s_arg(a[1], "hash_equals", line)))


# ---------------------------------------------------------- type helpers
def php_intval(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return 0
        return check_int(int(v))
    if isinstance(v, TStr):
        m = re.match(r"\s*([+-]?\d+)", v.s)
        if not m:
            return 0
        n = int(m.group(1))
        return max(INT_MIN, min(INT_MAX, n))
    if v is None:
        return 0
    if isinstance(v, BArray):
        return 1 if len(v) else 0
    raise WardenError("cannot convert %s to int" % type_name(v))


def php_floatval(v):
    if isinstance(v, bool):
        return float(v)
    if is_num(v):
        return float(v)
    if isinstance(v, TStr):
        m = re.match(r"\s*([+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?)", v.s)
        return float(m.group(1)) if m else 0.0
    if v is None:
        return 0.0
    raise WardenError("cannot convert %s to float" % type_name(v))


_STRICT_INT = re.compile(r"^\s*[+-]?\d{1,19}\s*$")
_STRICT_FLOAT = re.compile(r"^\s*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d{1,3})?\s*$")


@builtin("int")
def _int(it, a, line):
    """Strict conversion: int("12abc") is an error, not 12."""
    nargs(a, 1, 2, "int", line)
    v = a[0]
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, float):
        return php_intval(v)
    if isinstance(v, TStr) and _STRICT_INT.match(v.s):
        n = int(v.s.strip())
        if INT_MIN <= n <= INT_MAX:
            return n
    if len(a) > 1:
        return a[1]
    raise WardenError("int(): %s is not a valid integer" % (repr(v.s[:30]) if isinstance(v, TStr) else type_name(v)), line)


@builtin("float")
def _float(it, a, line):
    nargs(a, 1, 2, "float", line)
    v = a[0]
    if is_num(v):
        return float(v)
    if isinstance(v, TStr) and _STRICT_FLOAT.match(v.s):
        return float(v.s.strip())
    if len(a) > 1:
        return a[1]
    raise WardenError("float(): not a valid number", line)


@builtin("intval")
def _intval(it, a, line):
    nargs(a, 1, 2, "intval", line)
    return php_intval(a[0])


@builtin("floatval", "doubleval")
def _floatval(it, a, line):
    nargs(a, 1, 1, "floatval", line)
    return php_floatval(a[0])


@builtin("str", "strval")
def _strval(it, a, line):
    nargs(a, 1, 1, "strval", line)
    v = a[0]
    if isinstance(v, bool):
        return P("1" if v else "")
    return to_str(v, line)


@builtin("boolval", "bool")
def _boolval(it, a, line):
    nargs(a, 1, 1, "boolval", line)
    return truthy(a[0])


for _n, _t in (("is_int", lambda v: isinstance(v, int) and not isinstance(v, bool)),
               ("is_integer", lambda v: isinstance(v, int) and not isinstance(v, bool)),
               ("is_float", lambda v: isinstance(v, float)),
               ("is_string", lambda v: isinstance(v, TStr)),
               ("is_bool", lambda v: isinstance(v, bool)),
               ("is_array", lambda v: isinstance(v, BArray)),
               ("is_null", lambda v: v is None),
               ("is_callable", lambda v: isinstance(v, Func)),
               ("is_numeric", lambda v: is_num(v) or (isinstance(v, TStr) and bool(_STRICT_FLOAT.match(v.s))))):
    def _mk(t, name):
        def f(it, a, line):
            nargs(a, 1, 1, name, line)
            return t(a[0])
        return f
    BUILTINS[_n] = _mk(_t, _n)


@builtin("gettype", "get_debug_type")
def _gettype(it, a, line):
    nargs(a, 1, 1, "gettype", line)
    return P(type_name(a[0]))


for _n, _rx in (("ctype_digit", r"\d+"), ("ctype_alpha", r"[A-Za-z]+"),
                ("ctype_alnum", r"[A-Za-z0-9]+"), ("ctype_xdigit", r"[0-9A-Fa-f]+"),
                ("ctype_lower", r"[a-z]+"), ("ctype_upper", r"[A-Z]+"), ("ctype_space", r"\s+")):
    def _mkc(rx, name):
        cre = re.compile(rx, re.ASCII)

        def f(it, a, line):
            nargs(a, 1, 1, name, line)
            return isinstance(a[0], TStr) and bool(cre.fullmatch(a[0].s))
        return f
    BUILTINS[_n] = _mkc(_rx, _n)

_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


@builtin("validate_email")
def _validate_email(it, a, line):
    nargs(a, 1, 1, "validate_email", line)
    return isinstance(a[0], TStr) and len(a[0].s) <= 254 and bool(_EMAIL.match(a[0].s))


@builtin("filter_var")
def _filter_var(it, a, line):
    nargs(a, 1, 3, "filter_var", line)
    v = a[0]
    f = a[1] if len(a) > 1 else 516
    s = to_str(v).s if not isinstance(v, (BArray, bool, Func)) else None
    if s is None:
        return False
    if f == 257:
        return int(s.strip()) if _STRICT_INT.match(s) and INT_MIN <= int(s.strip()) <= INT_MAX else False
    if f == 259:
        return float(s.strip()) if _STRICT_FLOAT.match(s) else False
    if f == 274:
        return v if len(s) <= 254 and _EMAIL.match(s) else False
    if f == 273:
        p = urllib.parse.urlsplit(s)
        return v if p.scheme in ("http", "https") and p.netloc and not re.search(r"[\s<>\"]", s) else False
    if f == 258:
        low = s.strip().lower()
        if low in ("1", "true", "on", "yes"):
            return True
        if low in ("0", "false", "off", "no", ""):
            return False
        return None
    return v


# ---------------------------------------------------------------- arrays
@builtin("count", "sizeof")
def _count(it, a, line):
    nargs(a, 1, 2, "count", line)
    v = a[0]
    if isinstance(v, BArray):
        return len(v)
    raise WardenError("count(): argument must be an array, %s given" % type_name(v), line)


@builtin("array_keys")
def _array_keys(it, a, line):
    nargs(a, 1, 1, "array_keys", line)
    arr = a_arg(a[0], "array_keys", line)
    return BArray.from_list([k for k, _ in arr.items()])


@builtin("array_values")
def _array_values(it, a, line):
    nargs(a, 1, 1, "array_values", line)
    return BArray.from_list(a_arg(a[0], "array_values", line).values())


@builtin("in_array")
def _in_array(it, a, line):
    nargs(a, 2, 3, "in_array", line)
    return any(equals(a[0], v) for v in a_arg(a[1], "in_array", line, 2).values())


@builtin("array_search")
def _array_search(it, a, line):
    nargs(a, 2, 3, "array_search", line)
    for k, v in a_arg(a[1], "array_search", line, 2).items():
        if equals(a[0], v):
            return k
    return False


@builtin("array_key_exists", "key_exists")
def _ake(it, a, line):
    nargs(a, 2, 2, "array_key_exists", line)
    return a_arg(a[1], "array_key_exists", line, 2).has(a[0])


@builtin("array_merge")
def _array_merge(it, a, line):
    out = BArray()
    for i, arr in enumerate(a):
        arr = a_arg(arr, "array_merge", line, i + 1)
        for k, v in arr.items():
            if isinstance(k, int):
                out.append(v)
            else:
                out.set(k, v)
    return it.check_arr(out)


@builtin("array_slice")
def _array_slice(it, a, line):
    nargs(a, 2, 4, "array_slice", line)
    arr = a_arg(a[0], "array_slice", line)
    items = arr.items()
    off = i_arg(a[1], "array_slice", line, 2)
    ln = a[2] if len(a) > 2 else None
    n = len(items)
    st = off if off >= 0 else max(0, n + off)
    if ln is None:
        en = n
    else:
        ln = i_arg(ln, "array_slice", line, 3)
        en = st + ln if ln >= 0 else n + ln
    out = BArray()
    for k, v in items[st:max(st, en)]:
        if isinstance(k, int):
            out.append(v)
        else:
            out.set(k, v)
    return out


@builtin("array_reverse")
def _array_reverse(it, a, line):
    nargs(a, 1, 2, "array_reverse", line)
    out = BArray()
    for k, v in reversed(a_arg(a[0], "array_reverse", line).items()):
        if isinstance(k, int):
            out.append(v)
        else:
            out.set(k, v)
    return out


@builtin("array_map")
def _array_map(it, a, line):
    nargs(a, 2, 2, "array_map", line)
    fn, arr = a[0], a_arg(a[1], "array_map", line, 2)
    out = BArray()
    for k, v in arr.items():
        out.set(k, it.call_value(fn, [v], line))
    return out


@builtin("array_filter")
def _array_filter(it, a, line):
    nargs(a, 1, 2, "array_filter", line)
    arr = a_arg(a[0], "array_filter", line)
    out = BArray()
    for k, v in arr.items():
        keep = truthy(it.call_value(a[1], [v], line)) if len(a) > 1 and a[1] is not None else truthy(v)
        if keep:
            out.set(k, v)
    return out


@builtin("array_reduce")
def _array_reduce(it, a, line):
    nargs(a, 2, 3, "array_reduce", line)
    acc = a[2] if len(a) > 2 else None
    for v in a_arg(a[0], "array_reduce", line).values():
        acc = it.call_value(a[1], [acc, v], line)
    return acc


@builtin("array_sum")
def _array_sum(it, a, line):
    nargs(a, 1, 1, "array_sum", line)
    total = 0
    for v in a_arg(a[0], "array_sum", line).values():
        total = check_int(total + n_arg(v, "array_sum", line), line)
    return total


@builtin("array_unique")
def _array_unique(it, a, line):
    nargs(a, 1, 2, "array_unique", line)
    out, seen = BArray(), []
    for k, v in a_arg(a[0], "array_unique", line).items():
        if not any(equals(v, s) for s in seen):
            seen.append(v)
            out.set(k, v)
    return out


@builtin("array_combine")
def _array_combine(it, a, line):
    nargs(a, 2, 2, "array_combine", line)
    ks, vs = a_arg(a[0], "array_combine", line).values(), a_arg(a[1], "array_combine", line, 2).values()
    if len(ks) != len(vs):
        raise WardenError("array_combine(): arrays must have equal length", line)
    return BArray.from_pairs(zip(ks, vs))


@builtin("array_flip")
def _array_flip(it, a, line):
    nargs(a, 1, 1, "array_flip", line)
    return BArray.from_pairs((v, k) for k, v in a_arg(a[0], "array_flip", line).items())


@builtin("array_column")
def _array_column(it, a, line):
    nargs(a, 2, 2, "array_column", line)
    out = BArray()
    for row in a_arg(a[0], "array_column", line).values():
        if isinstance(row, BArray) and row.has(a[1]):
            out.append(row.get(a[1]))
    return out


@builtin("array_first")
def _array_first(it, a, line):
    nargs(a, 1, 1, "array_first", line)
    v = a_arg(a[0], "array_first", line).values()
    return v[0] if v else None


@builtin("array_last")
def _array_last(it, a, line):
    nargs(a, 1, 1, "array_last", line)
    v = a_arg(a[0], "array_last", line).values()
    return v[-1] if v else None


@builtin("array_fill")
def _array_fill(it, a, line):
    nargs(a, 3, 3, "array_fill", line)
    st, n = i_arg(a[0], "array_fill", line), i_arg(a[1], "array_fill", line, 2)
    if n < 0 or n > it.lim.max_array:
        raise WardenError("array_fill(): bad count", line)
    return BArray.from_pairs((st + i, a[2]) for i in range(n))


@builtin("range")
def _range(it, a, line):
    nargs(a, 2, 3, "range", line)
    lo, hi = i_arg(a[0], "range", line), i_arg(a[1], "range", line, 2)
    step = abs(i_arg(a[2], "range", line, 3)) if len(a) > 2 else 1
    if step == 0:
        raise WardenError("range(): step cannot be 0", line)
    if abs(hi - lo) // step > it.lim.max_array:
        raise WardenError("range(): too many elements", line)
    seq = range(lo, hi + 1, step) if hi >= lo else range(lo, hi - 1, -step)
    return BArray.from_list(list(seq))


def _sort_key(v):
    if is_num(v):
        return (0, v, "")
    if isinstance(v, TStr):
        return (1, 0, v.s)
    if v is None:
        return (-1, 0, "")
    if isinstance(v, bool):
        return (0, int(v), "")
    return (2, len(v) if isinstance(v, BArray) else 0, "")


@builtin("sorted")
def _sorted(it, a, line):
    nargs(a, 1, 2, "sorted", line)
    vals = sorted(a_arg(a[0], "sorted", line).values(), key=_sort_key,
                  reverse=truthy(a[1]) if len(a) > 1 else False)
    return BArray.from_list(vals)


@builtin("ksorted")
def _ksorted(it, a, line):
    nargs(a, 1, 2, "ksorted", line)
    arr = a_arg(a[0], "ksorted", line)
    items = sorted(arr.items(), key=lambda kv: _sort_key(kv[0]), reverse=truthy(a[1]) if len(a) > 1 else False)
    return BArray.from_pairs(items)


@builtin("asorted")
def _asorted(it, a, line):
    nargs(a, 1, 2, "asorted", line)
    arr = a_arg(a[0], "asorted", line)
    items = sorted(arr.items(), key=lambda kv: _sort_key(kv[1]), reverse=truthy(a[1]) if len(a) > 1 else False)
    return BArray.from_pairs(items)


@builtin("usorted")
def _usorted(it, a, line):
    import functools
    nargs(a, 2, 2, "usorted", line)

    def cmp(x, y):
        r = it.call_value(a[1], [x, y], line)
        if not isinstance(r, int) or isinstance(r, bool):
            raise WardenError("usorted(): comparator must return an int", line)
        return r
    return BArray.from_list(sorted(a_arg(a[0], "usorted", line).values(), key=functools.cmp_to_key(cmp)))


# ----------------------------------------------------------------- math
@builtin("abs")
def _abs(it, a, line):
    nargs(a, 1, 1, "abs", line)
    return check_int(abs(n_arg(a[0], "abs", line)), line)


@builtin("floor")
def _floor(it, a, line):
    nargs(a, 1, 1, "floor", line)
    return float(math.floor(n_arg(a[0], "floor", line)))


@builtin("ceil")
def _ceil(it, a, line):
    nargs(a, 1, 1, "ceil", line)
    return float(math.ceil(n_arg(a[0], "ceil", line)))


@builtin("round")
def _round(it, a, line):
    nargs(a, 1, 2, "round", line)
    v = n_arg(a[0], "round", line)
    p = i_arg(a[1], "round", line, 2) if len(a) > 1 else 0
    m = 10 ** p
    r = math.floor(abs(v) * m + 0.5) / m  # PHP half-away-from-zero
    return float(math.copysign(r, v))


@builtin("intdiv")
def _intdiv(it, a, line):
    nargs(a, 2, 2, "intdiv", line)
    x, y = i_arg(a[0], "intdiv", line), i_arg(a[1], "intdiv", line, 2)
    if y == 0:
        raise WardenError("division by zero", line)
    q = abs(x) // abs(y)
    return check_int(q if (x >= 0) == (y >= 0) else -q, line)


@builtin("sqrt")
def _sqrt(it, a, line):
    nargs(a, 1, 1, "sqrt", line)
    v = n_arg(a[0], "sqrt", line)
    return math.sqrt(v) if v >= 0 else float("nan")


@builtin("pow")
def _pow(it, a, line):
    nargs(a, 2, 2, "pow", line)
    b, e = n_arg(a[0], "pow", line), n_arg(a[1], "pow", line, 2)
    if isinstance(b, int) and isinstance(e, int) and e >= 0:
        if e > 64 and abs(b) > 1:
            raise WardenError("integer overflow", line)
        return check_int(b ** e, line)
    try:
        return float(b) ** float(e)
    except (OverflowError, ZeroDivisionError):
        raise WardenError("pow(): result out of range", line)


@builtin("max")
def _max(it, a, line):
    vals = a[0].values() if len(a) == 1 and isinstance(a[0], BArray) else a
    if not vals:
        raise WardenError("max(): needs at least one value", line)
    best = vals[0]
    for v in vals[1:]:
        if compare(v, best, line) > 0:
            best = v
    return best


@builtin("min")
def _min(it, a, line):
    vals = a[0].values() if len(a) == 1 and isinstance(a[0], BArray) else a
    if not vals:
        raise WardenError("min(): needs at least one value", line)
    best = vals[0]
    for v in vals[1:]:
        if compare(v, best, line) < 0:
            best = v
    return best


@builtin("random_int", "rand", "mt_rand")
def _random_int(it, a, line):
    if not a:
        return secrets.randbelow(2 ** 31)
    nargs(a, 2, 2, "random_int", line)
    lo, hi = i_arg(a[0], "random_int", line), i_arg(a[1], "random_int", line, 2)
    if hi < lo:
        raise WardenError("random_int(): max < min", line)
    return lo + secrets.randbelow(hi - lo + 1)


@builtin("random_bytes")
def _random_bytes(it, a, line):
    nargs(a, 1, 1, "random_bytes", line)
    n = i_arg(a[0], "random_bytes", line)
    if not 1 <= n <= 1024:
        raise WardenError("random_bytes(): length must be 1..1024", line)
    return P(secrets.token_bytes(n).decode("latin-1"))


@builtin("random_token")
def _random_token(it, a, line):
    nargs(a, 0, 1, "random_token", line)
    n = i_arg(a[0], "random_token", line) if a else 32
    if not 8 <= n <= 256:
        raise WardenError("random_token(): bytes must be 8..256", line)
    return P(secrets.token_hex(n))


# ----------------------------------------------------------------- json
def _json_default(v):
    raise TypeError("not serialisable")


def json_dumps_safe(obj, pretty=False):
    txt = json.dumps(obj, ensure_ascii=False, indent=2 if pretty else None,
                     separators=None if pretty else (",", ":"), allow_nan=False)
    # safe to embed anywhere in HTML: no raw < > & ' and no U+2028/2029
    return (txt.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
               .replace("'", "\\u0027").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _has_taint(v, depth=0):
    if isinstance(v, TStr):
        return v.is_tainted
    if isinstance(v, BArray):
        return bool(v.kt) or any(_has_taint(x, depth + 1) for x in v.d.values())
    return False


@builtin("json_encode")
def _json_encode(it, a, line):
    nargs(a, 1, 3, "json_encode", line)
    flags = a[1] if len(a) > 1 and isinstance(a[1], int) else 0
    try:
        txt = json_dumps_safe(to_py(a[0]), pretty=bool(flags & 128))
    except (ValueError, TypeError) as e:
        raise WardenError("json_encode(): %s" % e, line)
    return TStr.tainted(txt) if _has_taint(a[0]) else P(txt)


@builtin("json_decode")
def _json_decode(it, a, line):
    nargs(a, 1, 4, "json_decode", line)
    s = s_arg(a[0], "json_decode", line)
    if len(s.s) > it.lim.max_str:
        raise WardenError("json_decode(): input too large", line)
    try:
        obj = json.loads(s.s, parse_constant=lambda c: None)
        return from_py(obj, tainted=s.is_tainted)
    except (ValueError, RecursionError):
        return None
    except WardenError:
        return None


# ----------------------------------------------------------------- time
@builtin("time")
def _time(it, a, line):
    nargs(a, 0, 0, "time", line)
    return int(time.time())


@builtin("microtime")
def _microtime(it, a, line):
    return time.time()


_DATE_MAP = {
    "d": "%d", "D": "%a", "j": None, "l": "%A", "N": None, "w": None, "z": None,
    "F": "%B", "m": "%m", "M": "%b", "n": None, "Y": "%Y", "y": "%y", "a": None,
    "A": "%p", "g": None, "G": None, "h": "%I", "H": "%H", "i": "%M", "s": "%S",
    "T": "UTC", "e": "UTC", "c": None, "U": None, "t": None,
}


@builtin("date", "gmdate")
def _date(it, a, line):
    nargs(a, 1, 2, "date", line)
    fmt_t = s_arg(a[0], "date", line)
    fmt = fmt_t.s
    ts = i_arg(a[1], "date", line, 2) if len(a) > 1 else int(time.time())
    try:
        d = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise WardenError("date(): timestamp out of range", line)
    out, esc = [], False
    for ch in fmt:
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == "j":
            out.append(str(d.day))
        elif ch == "n":
            out.append(str(d.month))
        elif ch == "N":
            out.append(str(d.isoweekday()))
        elif ch == "w":
            out.append(str(d.isoweekday() % 7))
        elif ch == "z":
            out.append(str(d.timetuple().tm_yday - 1))
        elif ch == "G":
            out.append(str(d.hour))
        elif ch == "g":
            out.append(str(d.hour % 12 or 12))
        elif ch == "a":
            out.append("am" if d.hour < 12 else "pm")
        elif ch == "c":
            out.append(d.isoformat())
        elif ch == "U":
            out.append(str(ts))
        elif ch == "t":
            import calendar
            out.append(str(calendar.monthrange(d.year, d.month)[1]))
        elif ch in _DATE_MAP:
            v = _DATE_MAP[ch]
            out.append(d.strftime(v) if v and v.startswith("%") else v)
        else:
            out.append(ch)
    return fmt_t.derived("".join(out))


@builtin("mktime")
def _mktime(it, a, line):
    nargs(a, 6, 6, "mktime", line)
    h, mi, s, mo, d, y = [i_arg(x, "mktime", line) for x in a]
    try:
        return int(datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        return False


# -------------------------------------------------------------- passwords
def _b64(b):
    return base64.b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


@builtin("password_hash")
def _password_hash(it, a, line):
    nargs(a, 1, 3, "password_hash", line)
    pw = s_arg(a[0], "password_hash", line).s.encode("utf-8")
    if len(pw) > 4096:
        raise WardenError("password too long", line)
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=64 * 1024 * 1024, dklen=32)
    return P("$scrypt$n=%d,r=%d,p=%d$%s$%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P, _b64(salt), _b64(dk)))


@builtin("password_verify")
def _password_verify(it, a, line):
    nargs(a, 2, 2, "password_verify", line)
    pw = s_arg(a[0], "password_verify", line).s.encode("utf-8")
    h = s_arg(a[1], "password_verify", line, 2).s
    if len(pw) > 4096:
        return False
    m = re.fullmatch(r"\$scrypt\$n=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)", h)
    if m:
        n, r, p = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if n > 2 ** 20 or r > 32 or p > 16:
            return False
        try:
            dk = hashlib.scrypt(pw, salt=_unb64(m.group(4)), n=n, r=r, p=p,
                                maxmem=256 * 1024 * 1024, dklen=32)
        except (ValueError, MemoryError):
            return False
        return hmac.compare_digest(dk, _unb64(m.group(5)))
    if h.startswith(("$2y$", "$2a$", "$2b$")) and _bcrypt is not None:
        try:
            return _bcrypt.checkpw(pw[:72], h.replace("$2y$", "$2b$", 1).encode())
        except ValueError:
            return False
    return False


@builtin("password_needs_rehash")
def _pnr(it, a, line):
    nargs(a, 1, 3, "password_needs_rehash", line)
    h = s_arg(a[0], "password_needs_rehash", line).s
    return not h.startswith("$scrypt$n=%d,r=%d,p=%d$" % (SCRYPT_N, SCRYPT_R, SCRYPT_P))


# ---------------------------------------------------------- misc / debug
def repr_val(v, depth=0):
    pad = "  " * depth
    if isinstance(v, BArray):
        if depth > 16:
            return P("[...]")
        parts = [P("[\n")]
        for k, x in v.items():
            parts += [P(pad + "  "), to_str(k) if isinstance(k, TStr) else P(str(k)), P(" => "),
                      repr_val(x, depth + 1), P("\n")]
        parts.append(P(pad + "]"))
        return tjoin(parts)
    if isinstance(v, TStr):
        return P('"').concat(v).concat(P('"'))
    if v is None:
        return P("null")
    if isinstance(v, bool):
        return P("true" if v else "false")
    if isinstance(v, float):
        return P(fmt_float(v))
    if isinstance(v, Func):
        return P("function %s()" % v.name)
    return P(str(v))


@builtin("print_r", "var_export")
def _print_r(it, a, line):
    nargs(a, 1, 2, "print_r", line)
    s = repr_val(a[0])
    if len(a) > 1 and truthy(a[1]):
        return s
    it.emit(s)
    return True


@builtin("var_dump")
def _var_dump(it, a, line):
    for v in a:
        it.emit(P(type_name(v) + " ").concat(repr_val(v)).concat(P("\n")))
    return None


@builtin("function_exists")
def _function_exists(it, a, line):
    nargs(a, 1, 1, "function_exists", line)
    n = s_arg(a[0], "function_exists", line).s.lower()
    return n in it.functions or n in it.builtins


@builtin("call_user_func")
def _cuf(it, a, line):
    if not a:
        raise WardenError("call_user_func() needs a callable", line)
    return it.call_value(a[0], list(a[1:]), line)


@builtin("call_user_func_array")
def _cufa(it, a, line):
    nargs(a, 2, 2, "call_user_func_array", line)
    return it.call_value(a[0], a_arg(a[1], "call_user_func_array", line, 2).values(), line)


@builtin("define")
def _define(it, a, line):
    nargs(a, 2, 3, "define", line)
    name = s_arg(a[0], "define", line)
    if name.is_tainted or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name.s):
        raise WardenError("define(): invalid constant name", line)
    if name.s in it.constants:
        raise WardenError("constant %s already defined" % name.s, line)
    it.constants[name.s] = a[1]
    return True


@builtin("defined")
def _defined(it, a, line):
    nargs(a, 1, 1, "defined", line)
    return s_arg(a[0], "defined", line).s in it.constants


@builtin("env", "getenv")
def _env(it, a, line):
    nargs(a, 1, 2, "env", line)
    name = s_arg(a[0], "env", line).s
    if not name.startswith("WARDEN_") and not name.startswith("APP_"):
        raise SecurityViolation("only WARDEN_* / APP_* environment variables are readable", "env")
    v = os.environ.get(name)
    if v is None:
        return a[1] if len(a) > 1 else None
    return P(v)


def _log(level):
    def f(it, a, line):
        nargs(a, 1, 1, "log", line)
        msg = s_arg(a[0], "log", line).s
        ctx_of(it).log(level, msg)
        return None
    return f


BUILTINS["log_info"] = _log("info")
BUILTINS["log_warn"] = _log("warn")
BUILTINS["log_error"] = _log("error")
BUILTINS["error_log"] = _log("error")


# ------------------------------------------------------------------ web
@builtin("header")
def _header(it, a, line):
    nargs(a, 1, 3, "header", line)
    h = s_arg(a[0], "header", line)
    if len(a) >= 2 and isinstance(a[1], TStr):
        name, value = h.s, a[1].s
    else:
        if ":" not in h.s:
            raise WardenError("header(): expected 'Name: value'", line)
        name, value = h.s.split(":", 1)
    ctx_of(it).set_header(name.strip(), value.strip())
    if len(a) == 3 and isinstance(a[2], int):
        _status(it, [a[2]], line)
    return None


@builtin("http_response_code", "status")
def _status(it, a, line):
    nargs(a, 0, 1, "http_response_code", line)
    c = ctx_of(it)
    if not a:
        return c.status
    code = i_arg(a[0], "http_response_code", line)
    if not 100 <= code <= 599:
        raise WardenError("invalid HTTP status", line)
    c.status = code
    return True


@builtin("redirect")
def _redirect(it, a, line):
    nargs(a, 1, 2, "redirect", line)
    code = i_arg(a[1], "redirect", line, 2) if len(a) > 1 else 302
    ctx_of(it).redirect(s_arg(a[0], "redirect", line).s, code)
    raise ExitSignal()


@builtin("setcookie", "set_cookie")
def _setcookie(it, a, line):
    nargs(a, 2, 3, "setcookie", line)
    name = s_arg(a[0], "setcookie", line).s
    value = s_arg(a[1], "setcookie", line, 2).s
    max_age, httponly, samesite, path = None, True, "Lax", "/"
    if len(a) > 2:
        o = a[2]
        if isinstance(o, int) and not isinstance(o, bool):
            max_age = max(0, o - int(time.time())) if o > 10 ** 9 else o
        elif isinstance(o, BArray):
            if o.has(P("expires")):
                exp = o.get(P("expires"))
                max_age = max(0, exp - int(time.time())) if isinstance(exp, int) and exp > 10 ** 9 else exp
            if o.has(P("max_age")):
                max_age = o.get(P("max_age"))
            if o.has(P("httponly")):
                httponly = truthy(o.get(P("httponly")))
            if o.has(P("samesite")):
                samesite = to_str(o.get(P("samesite"))).s.capitalize()
            if o.has(P("path")):
                path = to_str(o.get(P("path"))).s
    ctx_of(it).set_cookie(name, value, max_age, path, httponly, samesite)
    return True


@builtin("respond_json", "json_response")
def _respond_json(it, a, line):
    nargs(a, 1, 2, "respond_json", line)
    c = ctx_of(it)
    try:
        c.raw_body = json_dumps_safe(to_py(a[0])).encode("utf-8")
    except (ValueError, TypeError) as e:
        raise WardenError("respond_json(): %s" % e, line)
    c.headers["content-type"] = ("Content-Type", "application/json; charset=utf-8")
    if len(a) > 1:
        _status(it, [a[1]], line)
    raise ExitSignal()


@builtin("session_start")
def _session_start(it, a, line):
    return True  # sessions start automatically and lazily


@builtin("session_get")
def _session_get(it, a, line):
    nargs(a, 1, 2, "session_get", line)
    return ctx_of(it).session_get(s_arg(a[0], "session_get", line).s, a[1] if len(a) > 1 else None)


@builtin("session_set")
def _session_set(it, a, line):
    nargs(a, 2, 2, "session_set", line)
    if isinstance(a[1], Func):
        raise WardenError("cannot store a function in the session", line)
    ctx_of(it).session_set(s_arg(a[0], "session_set", line).s, a[1])
    return None


@builtin("session_has")
def _session_has(it, a, line):
    nargs(a, 1, 1, "session_has", line)
    return ctx_of(it).session_get(s_arg(a[0], "session_has", line).s) is not None


@builtin("session_delete", "session_unset_key")
def _session_delete(it, a, line):
    nargs(a, 1, 1, "session_delete", line)
    ctx_of(it).session_delete(s_arg(a[0], "session_delete", line).s)
    return None


@builtin("session_regenerate", "session_regenerate_id")
def _session_regen(it, a, line):
    ctx_of(it).session_regenerate()
    return True


@builtin("session_destroy")
def _session_destroy(it, a, line):
    ctx_of(it).session_destroy()
    return True


@builtin("csrf_token")
def _csrf_token(it, a, line):
    return P(ctx_of(it).csrf_token())


@builtin("csrf_field")
def _csrf_field(it, a, line):
    return P('<input type="hidden" name="_csrf" value="%s">' % ctx_of(it).csrf_token())


@builtin("route")
def _route(it, a, line):
    nargs(a, 3, 3, "route", line)
    method = s_arg(a[0], "route", line).s.upper()
    pattern = s_arg(a[1], "route", line, 2).s
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "ANY"):
        raise WardenError("route(): unsupported method %s" % method, line)
    handler = a[2]
    if not isinstance(handler, (Func, TStr)):
        raise WardenError("route(): handler must be a function", line)
    if not pattern.startswith("/"):
        raise WardenError("route(): pattern must start with /", line)
    rx = ["^"]
    for seg in pattern.strip("/").split("/") if pattern != "/" else []:
        m = re.fullmatch(r"\{([A-Za-z_]\w*)(?::(int|slug|alpha|any))?\}", seg)
        if m:
            kind = m.group(2) or "any"
            body = {"int": r"[0-9]{1,18}", "slug": r"[A-Za-z0-9_\-]{1,200}",
                    "alpha": r"[A-Za-z]{1,200}", "any": r"[^/]{1,500}"}[kind]
            rx.append("/(?P<%s>%s)" % (m.group(1), body))
        elif re.fullmatch(r"[A-Za-z0-9_\-.~]+", seg):
            rx.append("/" + re.escape(seg))
        else:
            raise WardenError("route(): invalid pattern segment %r" % seg, line)
    rx.append("/?$" if pattern != "/" else "/$")
    ctx_of(it).routes.append((method, re.compile("".join(rx)), handler, pattern))
    return None


@builtin("request_method")
def _request_method(it, a, line):
    return P(ctx_of(it).request.get("method", "GET"))


@builtin("request_path")
def _request_path(it, a, line):
    return TStr.tainted(ctx_of(it).request.get("path", "/"))


@builtin("request_header")
def _request_header(it, a, line):
    nargs(a, 1, 2, "request_header", line)
    hv = ctx_of(it).request.get("headers", {}).get(s_arg(a[0], "request_header", line).s.lower())
    if hv is None:
        return a[1] if len(a) > 1 else None
    return TStr.tainted(hv)


@builtin("request_json")
def _request_json(it, a, line):
    j = ctx_of(it).request.get("json")
    return j


@builtin("request_ip")
def _request_ip(it, a, line):
    return TStr.tainted(ctx_of(it).request.get("ip", ""))


# ------------------------------------------------------------- database
def _db_params(p, line):
    if p is None:
        return ()
    if not isinstance(p, BArray):
        raise WardenError("db: parameters must be an array", line)

    def conv(v):
        if isinstance(v, TStr):
            return v.s
        if isinstance(v, bool):
            return int(v)
        if v is None or is_num(v):
            return v
        raise WardenError("db: parameter of type %s not allowed" % type_name(v), line)
    if p.is_list():
        return tuple(conv(v) for v in p.values())
    return {str(k).lstrip(":"): conv(v) for k, v in p.d.items()}


def _db_sql(v, line):
    if not isinstance(v, TStr):
        raise WardenError("db: SQL must be a string", line)
    if v.is_tainted:
        raise SecurityViolation(
            "SQL injection blocked: the SQL text contains user-controlled data; "
            "use ? placeholders and pass values in the parameter array", "sqli")
    return v.s


def _db_run(it, a, line, name):
    nargs(a, 1, 2, name, line)
    sql = _db_sql(a[0], line)
    params = _db_params(a[1] if len(a) > 1 else None, line)
    con = ctx_of(it).db()
    try:
        return con.execute(sql, params)
    except sqlite3.Warning as e:
        raise WardenError("db: only one SQL statement per call is allowed", line)
    except sqlite3.DatabaseError as e:
        raise WardenError("db error: %s" % e, line)


def _row(r):
    a = BArray()
    for k in r.keys():
        a.set(TStr(k, ()), from_py(r[k], tainted=True))
    return a


@builtin("db_query")
def _db_query(it, a, line):
    cur = _db_run(it, a, line, "db_query")
    out = BArray()
    for r in cur:
        out.append(_row(r))
        if len(out) > it.lim.max_array:
            raise WardenError("db_query(): too many rows", line)
    return out


@builtin("db_one", "db_first")
def _db_one(it, a, line):
    cur = _db_run(it, a, line, "db_one")
    r = cur.fetchone()
    return _row(r) if r is not None else None


@builtin("db_value")
def _db_value(it, a, line):
    cur = _db_run(it, a, line, "db_value")
    r = cur.fetchone()
    return from_py(r[0], tainted=True) if r is not None else None


@builtin("db_exec")
def _db_exec(it, a, line):
    cur = _db_run(it, a, line, "db_exec")
    return BArray.from_pairs([(P("changes"), cur.rowcount), (P("last_id"), cur.lastrowid)])


@builtin("db_transaction")
def _db_transaction(it, a, line):
    nargs(a, 1, 1, "db_transaction", line)
    con = ctx_of(it).db()
    con.execute("BEGIN IMMEDIATE")
    try:
        r = it.call_value(a[0], [], line)
    except BaseException:
        con.execute("ROLLBACK")
        raise
    con.execute("COMMIT")
    return r


# ------------------------------------------------------------ sandboxed files
def _data_path(it, rel, line, must_exist=True):
    from .interp import safe_join
    if not isinstance(rel, TStr):
        raise WardenError("file path must be a string", line)
    if re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://", rel.s):
        raise SecurityViolation("URL access from file functions is blocked (SSRF protection)", "ssrf")
    return safe_join(ctx_of(it).data_dir, rel.s, must_exist)


@builtin("file_read", "file_get_contents")
def _file_read(it, a, line):
    nargs(a, 1, 1, "file_read", line)
    p = _data_path(it, a[0], line)
    if os.path.getsize(p) > it.lim.max_str:
        raise WardenError("file too large", line)
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return TStr.tainted(f.read())


@builtin("file_write", "file_put_contents")
def _file_write(it, a, line):
    nargs(a, 2, 3, "file_write", line)
    p = _data_path(it, a[0], line, must_exist=False)
    data = s_arg(a[1], "file_write", line, 2).s
    if os.path.basename(p).startswith("."):
        raise SecurityViolation("dotfiles cannot be written", "path")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    mode = "a" if len(a) > 2 and a[2] == 8 else "w"
    with open(p, mode, encoding="utf-8") as f:
        f.write(data)
    return len(data)


CONSTANTS["FILE_APPEND"] = 8


@builtin("file_exists")
def _file_exists(it, a, line):
    nargs(a, 1, 1, "file_exists", line)
    try:
        return os.path.exists(_data_path(it, a[0], line, must_exist=False))
    except SecurityViolation:
        return False


# ------------------------------------------------------------ migration shims
@builtin("warden_removed")
def _warden_removed(it, a, line):
    what = a[0].s if a and isinstance(a[0], TStr) else "call"
    raise SecurityViolation("removed dangerous PHP construct invoked: %s" % what, "removed-call")


@builtin("warden_noescape")
def _warden_noescape(it, a, line):
    """Replaces mysqli_real_escape_string(): escaping is meaningless in Warden;
    the value stays tainted so it can only reach SQL as a bound parameter."""
    nargs(a, 1, 1, "warden_noescape", line)
    return a[0]
