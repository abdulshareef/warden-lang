"""PHP -> Warden migration assistant.

Converts the common procedural PHP subset automatically, rewrites risky
idioms to their secure Warden equivalents, removes dangerous calls (fail
closed), auto-parameterises interpolated SQL, and writes a security report
listing every finding with line numbers.

It is an assistant, not a magic compiler: object-oriented code, references,
switch, preg_* and uploads are flagged for manual porting. Run
`warden check` on the output - anything not converted fails loudly.
"""

import json
import os
import re
import shutil

CRITICAL_FUNCS = ["eval", "system", "exec", "shell_exec", "passthru", "popen", "proc_open",
                  "pcntl_exec", "assert", "create_function", "unserialize", "extract",
                  "phpinfo", "dl", "putenv", "ini_set", "move_uploaded_file", "fsockopen",
                  "curl_exec", "curl_init", "mail", "parse_str", "highlight_file", "show_source"]


class Finding:
    def __init__(self, sev, line, rule, msg):
        self.sev, self.line, self.rule, self.msg = sev, line, rule, msg

    def as_dict(self):
        return {"severity": self.sev, "line": self.line, "rule": self.rule, "message": self.msg}


# ------------------------------------------------------------------ scanner
def scan(src):
    """Split PHP source into tokens: html, open, close, code, str, cmt."""
    toks, i, n = [], 0, len(src)
    while i < n:
        j = src.find("<?", i)
        if j < 0:
            toks.append(("html", src[i:]))
            break
        if j > i:
            toks.append(("html", src[i:j]))
        if src.startswith("<?php", j):
            toks.append(("open", "<?php"))
            i = j + 5
        elif src.startswith("<?=", j):
            toks.append(("open", "<?="))
            i = j + 3
        elif src.startswith("<?xml", j):
            toks.append(("html", "<?xml"))
            i = j + 5
            continue
        else:
            toks.append(("open", "<?"))
            i = j + 2
        # code until ?>
        buf = []
        while i < n:
            c = src[i]
            if src.startswith("?>", i):
                if buf:
                    toks.append(("code", "".join(buf)))
                    buf = []
                toks.append(("close", "?>"))
                i += 2
                break
            if c in "'\"":
                if buf:
                    toks.append(("code", "".join(buf)))
                    buf = []
                k = i + 1
                while k < n and src[k] != c:
                    k += 2 if src[k] == "\\" else 1
                toks.append(("str", src[i:k + 1]))
                i = k + 1
                continue
            if src.startswith("<<<", i):
                m = re.match(r"<<<\s*(['\"]?)([A-Za-z_]\w*)\1\r?\n", src[i:])
                if m:
                    tag = m.group(2)
                    end = re.compile(r"\r?\n[ \t]*%s\b" % tag).search(src, i + m.end() - 1)
                    if end:
                        body = src[i + m.end():end.start()]
                        nowdoc = m.group(1) == "'"
                        if buf:
                            toks.append(("code", "".join(buf)))
                            buf = []
                        if nowdoc:
                            toks.append(("str", "'" + body.replace("\\", "\\\\").replace("'", "\\'") + "'"))
                        else:
                            toks.append(("str", '"' + body.replace('"', '\\"') + '"'))
                        i = end.end()
                        continue
            if c == "#" or src.startswith("//", i):
                if buf:
                    toks.append(("code", "".join(buf)))
                    buf = []
                k = i
                while k < n and src[k] != "\n" and not src.startswith("?>", k):
                    k += 1
                toks.append(("cmt", src[i:k]))
                i = k
                continue
            if src.startswith("/*", i):
                if buf:
                    toks.append(("code", "".join(buf)))
                    buf = []
                k = src.find("*/", i + 2)
                k = n if k < 0 else k + 2
                toks.append(("cmt", src[i:k]))
                i = k
                continue
            buf.append(c)
            i += 1
        if buf:
            toks.append(("code", "".join(buf)))
    return toks


# ------------------------------------------------------------- conversion
class Converter:
    def __init__(self, filename, include_map=None, rel_dir=""):
        self.fn = filename
        self.findings = []
        self.include_map = include_map or {}
        self.rel_dir = rel_dir
        self.strings = []
        self.others = []

    def find(self, sev, line, rule, msg):
        self.findings.append(Finding(sev, line, rule, msg))

    # placeholders ---------------------------------------------------------
    def sp(self, s):
        self.strings.append(s)
        return "__WSTR%d__" % (len(self.strings) - 1)

    def op(self, s):
        self.others.append(s)
        return "__WOTH%d__" % (len(self.others) - 1)

    def strval(self, ph):
        m = re.fullmatch(r"__WSTR(\d+)__", ph.strip())
        return self.strings[int(m.group(1))] if m else None

    def unmask(self, text):
        for _ in range(3):
            text = re.sub(r"__WSTR(\d+)__", lambda m: self.strings[int(m.group(1))], text)
        return text

    def line_of(self, text, pos):
        return text.count("\n", 0, pos) + 1

    # main -------------------------------------------------------------------
    def convert(self, src):
        toks = scan(src)
        masked = []
        for kind, val in toks:
            if kind == "html":
                masked.append(self.op(val))
            elif kind == "open":
                masked.append("<?wdn " if val in ("<?php", "<?") else "<?=")
            elif kind == "close":
                masked.append("?>")
            elif kind == "str":
                masked.append(self.sp(self.fix_string(val, src)))
            elif kind == "cmt":
                masked.append(self.op(val))
            else:
                masked.append(val)
        code = "".join(masked)
        code = self.transform(code)
        # unmask (repeat: replacements may contain placeholders)
        for _ in range(3):
            code = re.sub(r"__WSTR(\d+)__", lambda m: self.strings[int(m.group(1))], code)
            code = re.sub(r"__WOTH(\d+)__", lambda m: self.others[int(m.group(1))], code)
        code = code.replace("<?wdn  ", "<?wdn ")
        return code

    def fix_string(self, s, src):
        if s.startswith('"'):
            body = s[1:-1]
            body = re.sub(r"\$\{(\w+)\}", r"{$\1}", body)
            if re.search(r"\$\w+->\w+", body):
                self.find("MANUAL", 0, "object-in-string", "object property in string %s needs manual port" % s[:60])

            def inner(m):
                return m.group(0).replace('\\"', "'").replace('"', "'")
            body = re.sub(r"\{\$[^{}]*\}", inner, body)
            return '"' + body + '"'
        return s

    def transform(self, code):
        F = self.find
        L = lambda pos: self.line_of(code, pos)

        # dangerous functions -> fail-closed
        for name in CRITICAL_FUNCS:
            for m in re.finditer(r"(?<![\w$>:])%s\s*\(" % name, code):
                F("CRITICAL", L(m.start()), "dangerous-call",
                  "%s() removed: it does not exist in Warden (call now fails closed)" % name)
            code = re.sub(r"(?<![\w$>:])%s\s*\(" % name,
                          lambda m: "warden_removed(%s, " % self.sp('"%s"' % name), code)
        code = re.sub(r"warden_removed\((__WSTR\d+__), \)", r"warden_removed(\1)", code)
        if "`" in code:
            F("CRITICAL", L(code.find("`")), "shell-backtick", "backtick shell execution removed")
            code = re.sub(r"`[^`]*`", lambda m: 'warden_removed(%s)' % self.sp('"shell"'), code)

        # includes
        def inc(m):
            kw, arg = m.group(1).lower(), m.group(2).strip()
            once = "_once" if kw.endswith("_once") else ""
            arg2 = re.sub(r"^(__DIR__|dirname\(__FILE__\))\s*\.\s*", "", arg)
            lit = self.strval(arg2)
            if lit is None or "$" in lit:
                F("CRITICAL", L(m.start()), "dynamic-include",
                  "dynamic include removed (local/remote file inclusion risk): %s" % self.unmask(arg)[:60])
                return "warden_removed(%s);" % self.sp('"dynamic include"')
            raw = lit[1:-1]
            base_rel = os.path.normpath(os.path.join(self.rel_dir, raw.lstrip("/"))).replace(os.sep, "/")
            target = self.include_map.get(base_rel)
            if target is None:
                target = "pages/" + re.sub(r"\.php$", ".wdn", base_rel)
            return "include%s %s;" % (once, self.sp('"%s"' % target))
        code = re.sub(r"\b(include_once|require_once|include|require)\b\s*\(?\s*([^;]+?)\s*\)?\s*;", inc, code)

        # sessions
        code = re.sub(r"\bsession_start\s*\(\s*\)\s*;", self.op("/* session_start(): automatic in Warden */"), code)
        code = re.sub(r"\bsession_unset\s*\(\s*\)\s*;", "session_destroy();", code)
        code = re.sub(r"\$_SESSION\s*=\s*(array\(\s*\)|\[\s*\])\s*;", "session_destroy();", code)
        code = re.sub(r"\bisset\s*\(\s*\$_SESSION\[\s*([^\]]+?)\s*\]\s*\)", r"session_has(\1)", code)
        code = re.sub(r"\bunset\s*\(\s*\$_SESSION\[\s*([^\]]+?)\s*\]\s*\)\s*;", r"session_delete(\1);", code)
        code = re.sub(r"\$_SESSION\[\s*([^\]]+?)\s*\]\s*=(?!=)\s*([^;]+);", r"session_set(\1, \2);", code)
        code = re.sub(r"\$_SESSION\[\s*([^\]]+?)\s*\]", r"session_get(\1)", code)
        if "$_SESSION" in code:
            F("MANUAL", L(code.find("$_SESSION")), "session", "remaining $_SESSION usage needs manual port")
        code = re.sub(r"\bsession_regenerate_id\s*\([^)]*\)", "session_regenerate()", code)

        # redirects
        def hdr(m):
            arg = m.group(1)
            first = re.match(r"\s*(__WSTR\d+__)", arg)
            if first:
                lit = self.strval(first.group(1))
                mm = re.match(r"""^(["'])\s*Location\s*:\s*""", lit, re.I)
                if mm:
                    newlit = lit[0] + lit[mm.end():]
                    rest = arg[first.end():]
                    expr = self.sp(newlit) + rest
                    expr = re.sub(r"^__WSTR(\d+)__\s*\.\s*", lambda x: "" if self.strings[int(x.group(1))] in ('""', "''") else x.group(0), expr)
                    return "redirect(%s)" % expr.strip()
            return m.group(0)
        code = re.sub(r"\bheader\s*\(((?:[^()]|\([^()]*\))*)\)", hdr, code)

        # mysqli / mysql
        if re.search(r"\b(mysqli?_connect|new\s+mysqli|new\s+PDO)\b", code):
            F("INFO", 0, "db-connect", "database connection removed: configure \"database\" in warden.json "
                                       "(built-in SQLite; see guide for other databases)")
        code = re.sub(r"\$\w+\s*=\s*(mysqli_connect|mysql_connect)\s*\([^;]*\)\s*(or\s+die\s*\([^;]*\))?\s*;",
                      self.op("/* db connection: configured in warden.json */"), code)
        code = re.sub(r"\$\w+\s*=\s*new\s+(mysqli|PDO)\s*\([^;]*\)\s*;", self.op("/* db connection: configured in warden.json */"), code)
        code = re.sub(r"\$\w+->setAttribute\([^;]*\);", "", code)
        code = re.sub(r"\bmysqli?_close\s*\([^)]*\)\s*;", "", code)
        code = re.sub(r"\bmysqli_select_db\s*\([^;]*\)\s*;", "", code)
        code = re.sub(r"\bmysqli_real_escape_string\s*\(\s*\$\w+\s*,\s*", "warden_noescape(", code)
        code = re.sub(r"\bmysql_real_escape_string\s*\(\s*", "warden_noescape(", code)
        code = re.sub(r"\bmysqli?_error\s*\([^)]*\)", self.sp('"Database error"'), code)
        code = re.sub(r"\bmysqli_num_rows\s*\(", "count(", code)
        code = re.sub(r"\bmysqli_insert_id\s*\([^)]*\)", "db_value(%s)" % self.sp('"SELECT last_insert_rowid()"'), code)
        code = re.sub(r"while\s*\(\s*\$(\w+)\s*=\s*mysqli?_fetch_(?:assoc|array|object)\s*\(\s*\$(\w+)\s*\)\s*\)",
                      r"foreach ($\2 as $\1)", code)
        code = re.sub(r"\bmysqli?_fetch_(?:assoc|array)\s*\(\s*\$(\w+)\s*\)", r"($\1[0] ?? null)", code)

        def q(m):
            sql_expr = m.group(1)
            return "db_query(%s)" % self.parameterize(sql_expr, L(m.start()))
        code = re.sub(r"\bmysqli_query\s*\(\s*\$\w+\s*,\s*((?:[^()]|\([^()]*\))*?)\s*\)", q, code)
        code = re.sub(r"\bmysql_query\s*\(\s*((?:[^()]|\([^()]*\))*?)\s*(?:,\s*\$\w+\s*)?\)", q, code)

        # PDO prepare/execute idiom
        def pdo(m):
            var, sql, args = m.group(1), m.group(2), m.group(3).strip() or "[]"
            return "$%s = db_query(%s, %s);" % (var, sql.strip(), args)
        code = re.sub(r"\$(\w+)\s*=\s*\$\w+->prepare\s*\(((?:[^()]|\([^()]*\))*)\)\s*;\s*\$\1->execute\s*\(((?:[^()]|\([^()]*\))*)\)\s*;",
                      pdo, code)
        code = re.sub(r"while\s*\(\s*\$(\w+)\s*=\s*\$(\w+)->fetch\s*\([^)]*\)\s*\)", r"foreach ($\2 as $\1)", code)
        code = re.sub(r"\$(\w+)->fetchAll\s*\([^)]*\)", r"$\1", code)
        code = re.sub(r"\$(\w+)->fetch\s*\([^)]*\)", r"($\1[0] ?? null)", code)
        code = re.sub(r"\$(\w+)->fetchColumn\s*\(\s*\)", r"(($\1[0] ?? [])[array_keys($\1[0] ?? [0])[0]] ?? null)", code)
        code = re.sub(r"\$(\w+)->rowCount\s*\(\s*\)", r"count($\1)", code)
        code = re.sub(r"\$\w+->lastInsertId\s*\(\s*\)", "db_value(%s)" % self.sp('"SELECT last_insert_rowid()"'), code)
        code = re.sub(r"\$\w+->query\s*\(", "db_query(", code)

        # sql built from variables in db_query(...) that we couldn't parameterise
        for m in re.finditer(r"db_query\(([^;]*)\)", code):
            first = m.group(1).split(", [")[0]
            parts = re.split(r"\s*\.\s*", first.strip())
            concat = len(parts) > 1 and any(not re.fullmatch(r"__WSTR\d+__", x) for x in parts)
            interp = any("$" in (self.strval(x) or "") and (self.strval(x) or "").startswith('"')
                         for x in re.findall(r"__WSTR\d+__", first))
            if concat or interp:
                F("HIGH", L(m.start()), "sql-concat",
                  "SQL built from variables: Warden will block it at runtime if any part is user input. "
                  "Rewrite with ? placeholders.")

        # arrays mutated by reference in PHP
        for php, wd in (("sort", "sorted($\\1)"), ("rsort", "sorted($\\1, true)"), ("ksort", "ksorted($\\1)"),
                        ("krsort", "ksorted($\\1, true)"), ("asort", "asorted($\\1)"), ("arsort", "asorted($\\1, true)")):
            code = re.sub(r"\b%s\s*\(\s*\$(\w+)\s*(?:,\s*\w+\s*)?\)\s*;" % php, r"$\1 = %s;" % wd, code)
        code = re.sub(r"\busort\s*\(\s*\$(\w+)\s*,\s*([^;]+)\)\s*;", r"$\1 = usorted($\1, \2);", code)
        code = re.sub(r"\barray_push\s*\(\s*\$(\w+)\s*,\s*([^;,]+)\)\s*;", r"$\1[] = \2;", code)
        for fn in ("array_pop", "array_shift", "array_unshift", "array_splice", "shuffle", "end", "reset", "next"):
            for m in re.finditer(r"\b%s\s*\(" % fn, code):
                F("MANUAL", L(m.start()), "by-reference", "%s() modifies arrays by reference; rewrite with array_slice()/array_last()" % fn)

        # misc rewrites
        code = re.sub(r"\$(\w+)->getMessage\s*\(\s*\)", r"$\1", code)
        code = re.sub(r"\$_SERVER\[\s*(__WSTR\d+__)\s*\]", lambda m: "$_SERVER[%s]" % (
            self.sp('"SCRIPT_NAME"') if self.strval(m.group(1))[1:-1] == "PHP_SELF" else m.group(1)), code)

        # findings without rewrite
        for m in re.finditer(r"\b(md5|sha1|crypt)\s*\(([^;]*?)\)", code, re.I):
            if re.search(r"pass|pwd", self.unmask(m.group(2)), re.I):
                F("HIGH", L(m.start()), "weak-password-hash",
                  "%s() used for passwords; use password_hash()/password_verify()" % m.group(1))
        for m in re.finditer(r"\bpreg_\w+\s*\(", code):
            F("MANUAL", L(m.start()), "regex", "preg_* is not available (ReDoS risk); use str_*/ctype_*/filter_var helpers")
        for m in re.finditer(r"\$_FILES", code):
            F("MANUAL", L(m.start()), "uploads", "file uploads are not supported in Warden 1.0")
        for m in re.finditer(r"->|::|\bnew\s+\w|\bclass\s+\w", code):
            F("MANUAL", L(m.start()), "oop", "object-oriented code must be ported to functions + arrays")
            break
        for m in re.finditer(r"\bswitch\s*\(", code):
            F("MANUAL", L(m.start()), "switch", "switch must be rewritten as if/elseif")
        for m in re.finditer(r"\bglobal\s+\$", code):
            F("MANUAL", L(m.start()), "global", "'global' is not supported; pass values as parameters")
        for m in re.finditer(r"function\s+\w*\s*\([^)]*&\s*\$", code):
            F("MANUAL", L(m.start()), "reference-param", "pass-by-reference parameters are not supported")
        for m in re.finditer(r"\$\$\w+", code):
            F("CRITICAL", L(m.start()), "variable-variables", "variable variables are not supported (mass-assignment risk)")
        for m in re.finditer(r"file_get_contents\s*\(\s*(__WSTR\d+__|\$)", code):
            lit = self.strval(m.group(1)) if m.group(1) != "$" else None
            if lit is None or re.match(r"""["']\w+://""", lit):
                F("HIGH", L(m.start()), "ssrf", "file_get_contents() with URL/variable path: remote access is blocked "
                                               "and local paths are sandboxed to data/")
        echoes = len(re.findall(r"(echo|<\?=)[^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)", code))
        if echoes:
            F("INFO", 0, "xss-fixed", "%d direct echo(s) of request data: now auto-escaped by context" % echoes)
        loose = len(re.findall(r"[^=!<>]==[^=]|!=[^=]", code))
        if loose:
            F("INFO", 0, "strict-compare", "%d loose comparison(s): Warden == is strict (no type juggling); "
                                           "review comparisons between numbers and strings" % loose)
        return code

    def parameterize(self, expr, line):
        """Turn "...'$x'..." or "..." . $x . "..." SQL into ("...?...", [$x])."""
        e = expr.strip()
        parts = re.split(r"\s*\.\s*", e)
        if not all(re.fullmatch(r"__WSTR\d+__|\$\w+(\[[^\]]+\])*|\(int\)\s*\$\w+(\[[^\]]+\])*|intval\(\$\w+(\[[^\]]+\])*\)", p) for p in parts):
            return expr
        sql, args, changed = [], [], False
        for p in parts:
            lit = self.strval(p)
            if lit is None:
                sql.append("\0?\0")
                args.append(p)
                changed = True
                continue
            body = lit[1:-1]
            if lit[0] == '"':
                def rep(m):
                    v = m.group(1) or m.group(2)
                    args.append(v)
                    return "\0?\0"
                nb = re.sub(r"\{(\$[^{}]+)\}|(\$\w+(?:\[[^\]]+\])?)", rep, body)
                if nb != body:
                    changed = True
                body = nb.replace('\\"', '"')
            else:
                body = body.replace("\\'", "'")
            sql.append(body)
        if not changed:
            return expr
        s = "".join(sql)
        s = re.sub(r"'\0\?\0'", "?", s)
        s = re.sub(r'"\0\?\0"', "?", s)
        s = s.replace("\0?\0", "?")
        fixed = []
        for a in args:
            a = re.sub(r"\[(\w+)\]", lambda m: "['%s']" % m.group(1), a) if "'" not in a and '"' not in a else a
            fixed.append(a)
        self.find("INFO", line, "sql-parameterized", "SQL with interpolated variables converted to a parameterized query")
        lit = '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'
        return "%s, [%s]" % (self.sp(lit), ", ".join(fixed))


# ------------------------------------------------------------------ tree
def migrate_source(src, filename="input.php", include_map=None, rel_dir=""):
    c = Converter(filename, include_map, rel_dir)
    out = c.convert(src)
    return out, c.findings


def _find_includes(src):
    return re.findall(r"\b(?:include|require)(?:_once)?\b\s*\(?\s*(?:__DIR__\s*\.\s*|dirname\(__FILE__\)\s*\.\s*)?['\"]([^'\"$]+\.php)['\"]", src)


def migrate_tree(src_dir, out_dir):
    src_dir = os.path.realpath(src_dir)
    os.makedirs(out_dir, exist_ok=True)
    php_files, others = [], []
    for d, dirs, files in os.walk(src_dir):
        dirs[:] = [x for x in dirs if not x.startswith(".") and x not in ("vendor", "node_modules")]
        for f in files:
            rel = os.path.relpath(os.path.join(d, f), src_dir).replace(os.sep, "/")
            (php_files if f.endswith(".php") else others).append(rel)
    # pass 1: which files are included by others -> private partials
    included = set()
    for rel in php_files:
        with open(os.path.join(src_dir, rel), encoding="utf-8", errors="replace") as fh:
            for inc in _find_includes(fh.read()):
                p = os.path.normpath(os.path.join(os.path.dirname(rel), inc.lstrip("/"))).replace(os.sep, "/")
                included.add(p)
    include_map = {}
    for rel in php_files:
        d, f = os.path.split(rel)
        stem = f[:-4]
        safe = re.sub(r"[^A-Za-z0-9_\-]", "_", stem)
        if rel in included:
            safe = "_" + safe.lstrip("_")
        elif not re.match(r"[A-Za-z0-9]", safe):
            safe = "p" + safe
        include_map[rel] = "pages/" + (d + "/" if d else "") + safe + ".wdn"
    report = {"files": {}, "critical": 0, "high": 0, "manual": 0}
    for rel in sorted(php_files):
        with open(os.path.join(src_dir, rel), encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        out, findings = migrate_source(src, rel, include_map, os.path.dirname(rel))
        dest = os.path.join(out_dir, include_map[rel])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(out)
        report["files"][rel] = {"output": include_map[rel], "findings": [x.as_dict() for x in findings]}
        report["critical"] += sum(1 for x in findings if x.sev == "CRITICAL")
        report["high"] += sum(1 for x in findings if x.sev == "HIGH")
        report["manual"] += sum(1 for x in findings if x.sev == "MANUAL")
    for rel in others:
        if rel.startswith(".") or rel.endswith((".sql", ".env", ".ini", ".htaccess", ".log", ".bak")):
            continue
        dest = os.path.join(out_dir, "public", rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(os.path.join(src_dir, rel), dest)
    cfg = os.path.join(out_dir, "warden.json")
    if not os.path.exists(cfg):
        with open(cfg, "w") as fh:
            json.dump({"allowed_hosts": ["localhost", "127.0.0.1"], "secure_cookies": False}, fh, indent=2)
    # syntax check the output
    from .parser import parse
    from .errors import WardenSyntaxError
    syntax = []
    for rel, info in report["files"].items():
        try:
            with open(os.path.join(out_dir, info["output"]), encoding="utf-8") as fh:
                parse(fh.read(), info["output"])
        except WardenSyntaxError as e:
            syntax.append(str(e))
    report["syntax_errors"] = syntax
    lines = ["# Warden migration report", "",
             "Source: `%s`  " % src_dir, "Output: `%s`" % os.path.realpath(out_dir), "",
             "| Files | Critical removed | High | Manual port | Syntax errors |", "|---|---|---|---|---|",
             "| %d | %d | %d | %d | %d |" % (len(php_files), report["critical"], report["high"],
                                          report["manual"], len(syntax)), ""]
    for rel, info in report["files"].items():
        lines.append("## %s → %s" % (rel, info["output"]))
        if not info["findings"]:
            lines.append("No findings.")
        for f in info["findings"]:
            lines.append("- **%s** (line %s, %s): %s" % (f["severity"], f["line"] or "-", f["rule"], f["message"]))
        lines.append("")
    if syntax:
        lines.append("## Files that still need manual edits to compile")
        lines += ["- `%s`" % s for s in syntax]
    with open(os.path.join(out_dir, "MIGRATION_REPORT.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "migration_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    report["summary"] = ("Migrated %d PHP file(s): %d critical call(s) removed, %d high-risk finding(s), "
                         "%d item(s) need manual porting, %d file(s) with syntax errors."
                         % (len(php_files), report["critical"], report["high"], report["manual"], len(syntax)))
    return report
