"""Lexer for Warden source files.

A .wdn file starts in template mode (like PHP): literal text is output as
trusted markup until an opening tag `<?wdn` (or `<?=` for an echo).
`?>` returns to template mode. A file may also be pure code if it starts
with `<?wdn` and never closes the tag.
"""

import re as _re

from .errors import WardenSyntaxError

KEYWORDS = {
    "function", "return", "if", "elseif", "else", "while", "for", "foreach",
    "as", "break", "continue", "echo", "print", "true", "false", "null", "try",
    "catch", "finally", "throw", "use", "include", "include_once", "require",
    "require_once", "const", "endif", "endwhile", "endfor", "endforeach",
    "isset", "empty", "exit", "die", "array", "unset", "and", "or",
}

# longest first
OPERATORS = [
    "===", "!==", "**=", "??=", "...",
    "==", "!=", "<>", "<=", ">=", "&&", "||", "??", "++", "--", "+=", "-=",
    "*=", "/=", ".=", "%=", "=>", "->", "::",
    "+", "-", "*", "/", "%", ".", "=", "<", ">", "!", "?", ":", ";", ",",
    "(", ")", "[", "]", "{", "}", "&", "|", "^", "~", "@", "\\", "`", "$",
]

MAX_SOURCE = 4 * 1024 * 1024


class Token:
    __slots__ = ("kind", "value", "line")

    def __init__(self, kind, value, line):
        self.kind = kind    # VAR IDENT KW NUM STR OP HTML ECHO_OPEN EOF
        self.value = value
        self.line = line

    def __repr__(self):
        return "Token(%s,%r,%d)" % (self.kind, self.value, self.line)


def _is_ident_start(c):
    return c.isalpha() or c == "_"


def _is_ident_char(c):
    return c.isalnum() or c == "_"


class Lexer:
    def __init__(self, src, filename="<input>", code_mode=False):
        if len(src) > MAX_SOURCE:
            raise WardenSyntaxError("source file too large", filename, 1)
        if "\x00" in src:
            raise WardenSyntaxError("NUL byte in source", filename, 1)
        self.src = src
        self.fn = filename
        self.i = 0
        self.line = 1
        self.toks = []
        self.code_mode = code_mode

    def err(self, msg):
        raise WardenSyntaxError(msg, self.fn, self.line)

    def add(self, kind, value):
        self.toks.append(Token(kind, value, self.line))

    def tokenize(self):
        if self.code_mode:
            self.lex_code(stop_at_close=False)
        else:
            self.lex_template()
        self.add("EOF", None)
        return self.toks

    # template mode ------------------------------------------------------
    def lex_template(self):
        src = self.src
        while self.i < len(src):
            j_wdn = src.find("<?wdn", self.i)
            j_eq = src.find("<?=", self.i)
            cands = [j for j in (j_wdn, j_eq) if j >= 0]
            if not cands:
                self._html(src[self.i:])
                self.i = len(src)
                break
            j = min(cands)
            if j > self.i:
                self._html(src[self.i:j])
            if j == j_eq:
                self.i = j + 3
                self.add("KW", "echo")
                self.lex_code(stop_at_close=True)
                self.add("OP", ";")
            else:
                self.i = j + 5
                if self.i < len(src) and not src[self.i].isspace():
                    self.err("expected whitespace after <?wdn")
                self.lex_code(stop_at_close=True)

    def _html(self, text):
        if text:
            self.add("HTML", text)
            self.line += text.count("\n")

    # code mode ----------------------------------------------------------
    def lex_code(self, stop_at_close):
        src = self.src
        n = len(src)
        while self.i < n:
            c = src[self.i]
            if c == "\n":
                self.line += 1
                self.i += 1
                continue
            if c in " \t\r\f\v":
                self.i += 1
                continue
            if src.startswith("?>", self.i):
                if not stop_at_close:
                    self.err("unexpected ?>")
                self.i += 2
                # PHP swallows a single newline directly after ?>
                if src.startswith("\r\n", self.i):
                    self.i += 2
                    self.line += 1
                elif src.startswith("\n", self.i):
                    self.i += 1
                    self.line += 1
                self.add("OP", ";")  # ?> implies statement end
                return
            if c == "#" or src.startswith("//", self.i):
                while self.i < n and src[self.i] != "\n":
                    if stop_at_close and src.startswith("?>", self.i):
                        break
                    self.i += 1
                continue
            if src.startswith("/*", self.i):
                end = src.find("*/", self.i + 2)
                if end < 0:
                    self.err("unterminated comment")
                self.line += src.count("\n", self.i, end)
                self.i = end + 2
                continue
            if c == "$" and self.i + 1 < n and _is_ident_start(src[self.i + 1]):
                j = self.i + 1
                while j < n and _is_ident_char(src[j]):
                    j += 1
                self.add("VAR", src[self.i + 1:j])
                self.i = j
                continue
            if _is_ident_start(c):
                j = self.i
                while j < n and _is_ident_char(src[j]):
                    j += 1
                word = src[self.i:j]
                low = word.lower()
                if low in KEYWORDS:
                    self.add("KW", low)
                else:
                    self.add("IDENT", word)
                self.i = j
                continue
            if c.isdigit():
                self.lex_number()
                continue
            if c == "'":
                self.lex_single()
                continue
            if c == '"':
                self.lex_double()
                continue
            for op in OPERATORS:
                if src.startswith(op, self.i):
                    if op in ("`",):
                        self.err("backtick shell execution is not supported")
                    self.add("OP", op)
                    self.i += len(op)
                    break
            else:
                self.err("unexpected character %r" % c)
        if stop_at_close:
            return  # file may end inside code block

    def lex_number(self):
        src, j = self.src, self.i
        n = len(src)
        if src.startswith(("0x", "0X"), j):
            j += 2
            while j < n and (src[j] in "0123456789abcdefABCDEF_"):
                j += 1
            txt = src[self.i:j].replace("_", "")
            self.add("NUM", int(txt, 16))
            self.i = j
            return
        while j < n and (src[j].isdigit() or src[j] == "_"):
            j += 1
        is_float = False
        if j < n - 1 and src[j] == "." and src[j + 1].isdigit():
            is_float = True
            j += 1
            while j < n and (src[j].isdigit() or src[j] == "_"):
                j += 1
        if j < n and src[j] in "eE":
            k = j + 1
            if k < n and src[k] in "+-":
                k += 1
            if k < n and src[k].isdigit():
                is_float = True
                j = k
                while j < n and src[j].isdigit():
                    j += 1
        txt = src[self.i:j].replace("_", "")
        self.add("NUM", float(txt) if is_float else int(txt))
        self.i = j

    def lex_single(self):
        src, j, n = self.src, self.i + 1, len(self.src)
        out = []
        while True:
            if j >= n:
                self.err("unterminated string")
            c = src[j]
            if c == "\\" and j + 1 < n and src[j + 1] in "'\\":
                out.append(src[j + 1])
                j += 2
                continue
            if c == "'":
                break
            if c == "\n":
                self.line += 1
            out.append(c)
            j += 1
        self.add("STR", [("lit", "".join(out))])
        self.i = j + 1

    ESC = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "$": "$",
           "0": "\0", "e": "\x1b", "v": "\v", "f": "\f"}

    def lex_double(self):
        src, j, n = self.src, self.i + 1, len(self.src)
        parts, buf = [], []
        start_line = self.line

        def flush():
            if buf:
                parts.append(("lit", "".join(buf)))
                buf.clear()

        while True:
            if j >= n:
                self.line = start_line
                self.err("unterminated string")
            c = src[j]
            if c == '"':
                break
            if c == "\\" and j + 1 < n:
                e = src[j + 1]
                if e in self.ESC:
                    buf.append(self.ESC[e])
                    j += 2
                    continue
                if e == "u" and j + 2 < n and src[j + 2] == "{":
                    k = src.find("}", j + 3)
                    if k < 0:
                        self.err("bad \\u{} escape")
                    try:
                        cp = int(src[j + 3:k], 16)
                        buf.append(chr(cp))
                    except (ValueError, OverflowError):
                        self.err("bad \\u{} escape")
                    j = k + 1
                    continue
                buf.append(c)
                j += 1
                continue
            if c == "$" and j + 1 < n and _is_ident_start(src[j + 1]):
                k = j + 1
                while k < n and _is_ident_char(src[k]):
                    k += 1
                expr = src[j:k]
                # PHP simple syntax: "$arr[key]", "$arr[0]", "$arr[$i]"
                if k < n and src[k] == "[":
                    e = src.find("]", k)
                    inner = src[k + 1:e] if e > 0 else ""
                    if _re.fullmatch(r"[A-Za-z_]\w*", inner):
                        expr += "['%s']" % inner
                        k = e + 1
                    elif _re.fullmatch(r"-?\d+|\$[A-Za-z_]\w*", inner):
                        expr += "[%s]" % inner
                        k = e + 1
                flush()
                parts.append(("expr", expr, self.line))
                j = k
                continue
            if c == "{" and j + 1 < n and src[j + 1] == "$":
                depth, k = 0, j
                while k < n:
                    if src[k] == "{":
                        depth += 1
                    elif src[k] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    elif src[k] == '"':
                        self.err("quotes inside {$...} interpolation are not supported; use single quotes")
                    k += 1
                if k >= n:
                    self.err("unterminated {$...} in string")
                flush()
                parts.append(("expr", src[j + 1:k], self.line))
                j = k + 1
                continue
            if c == "\n":
                self.line += 1
            buf.append(c)
            j += 1
        flush()
        if not parts:
            parts = [("lit", "")]
        self.add("STR", parts)
        self.i = j + 1
