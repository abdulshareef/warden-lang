"""Recursive-descent parser producing a tuple-based AST.

Node shape: (kind, line, *fields). See interp.py for semantics.
Dangerous or ambiguous PHP features are rejected at compile time with a
clear message instead of being half-supported.
"""

from .errors import WardenSyntaxError
from .lexer import Lexer

ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", ".=", "%=", "??="}
CASTS = {"int": "int", "integer": "int", "float": "float", "double": "float",
         "string": "string", "bool": "bool", "boolean": "bool"}

UNSUPPORTED = {
    "->": "objects/methods are not supported; use arrays and functions",
    "::": "classes/static calls are not supported; use arrays and functions",
    "&": "references (&) are not supported; Warden uses value semantics",
    "@": "the @ error-suppression operator is not supported",
    "`": "shell execution is not supported",
    "\\": "namespaces are not supported",
    "$": "variable variables ($$x) are not supported",
    "|": "bitwise operators are not supported",
    "^": "bitwise operators are not supported",
    "~": "bitwise operators are not supported",
}
UNSUPPORTED_IDENTS = {
    "class": "classes are not supported; use arrays and functions",
    "new": "objects are not supported; use arrays and functions",
    "eval": "eval() does not exist in Warden",
    "global": "'global' is not supported; pass values as parameters",
    "static": "'static' is not supported",
    "goto": "goto is not supported",
    "namespace": "namespaces are not supported",
    "interface": "interfaces are not supported",
    "trait": "traits are not supported",
    "switch": "switch is not supported; use if/elseif",
    "match": "match is not supported; use if/elseif",
    "do": "do/while is not supported; use while",
    "list": "list() destructuring is not supported",
    "extract": "extract() does not exist in Warden",
    "fn": "arrow functions are not supported; use function() use () {}",
}


class Parser:
    def __init__(self, src, filename="<input>", code_mode=False):
        self.fn = filename
        self.toks = Lexer(src, filename, code_mode).tokenize()
        self.p = 0

    # helpers --------------------------------------------------------------
    def peek(self, k=0):
        return self.toks[min(self.p + k, len(self.toks) - 1)]

    def next(self):
        t = self.toks[self.p]
        self.p += 1
        return t

    def err(self, msg, tok=None):
        tok = tok or self.peek()
        raise WardenSyntaxError(msg, self.fn, tok.line)

    def at(self, kind, value=None, k=0):
        t = self.peek(k)
        return t.kind == kind and (value is None or t.value == value)

    def at_op(self, v):
        return self.at("OP", v)

    def at_kw(self, v):
        return self.at("KW", v)

    def accept_op(self, v):
        if self.at_op(v):
            return self.next()
        return None

    def expect_op(self, v):
        if not self.at_op(v):
            t = self.peek()
            self.err("expected '%s' but found %s" % (v, self.describe(t)))
        return self.next()

    def expect_kw(self, v):
        if not self.at_kw(v):
            self.err("expected '%s' but found %s" % (v, self.describe(self.peek())))
        return self.next()

    @staticmethod
    def describe(t):
        if t.kind == "EOF":
            return "end of file"
        if t.kind == "HTML":
            return "template text"
        if t.kind == "STR":
            return "string"
        return repr(t.value if t.kind != "VAR" else "$" + t.value)

    def check_unsupported(self):
        t = self.peek()
        if t.kind == "OP" and t.value in UNSUPPORTED:
            self.err(UNSUPPORTED[t.value])
        if t.kind == "IDENT" and t.value.lower() in UNSUPPORTED_IDENTS:
            self.err(UNSUPPORTED_IDENTS[t.value.lower()])

    # program ---------------------------------------------------------------
    def parse_program(self):
        stmts = []
        while not self.at("EOF"):
            s = self.statement()
            if s is not None:
                stmts.append(s)
        return ("block", 1, stmts)

    def block_or_statement(self):
        if self.at_op("{"):
            return self.block()
        line = self.peek().line
        s = self.statement()
        return ("block", line, [s] if s else [])

    def block(self):
        line = self.expect_op("{").line
        stmts = []
        while not self.at_op("}"):
            if self.at("EOF"):
                self.err("unexpected end of file; missing '}'")
            s = self.statement()
            if s is not None:
                stmts.append(s)
        self.next()
        return ("block", line, stmts)

    def alt_block(self, *enders):
        """Statements until one of the given keywords (alternative syntax)."""
        line = self.peek().line
        stmts = []
        while not any(self.at_kw(e) for e in enders):
            if self.at("EOF"):
                self.err("unexpected end of file; expected %s" % " or ".join(enders))
            s = self.statement()
            if s is not None:
                stmts.append(s)
        return ("block", line, stmts)

    def end_stmt(self):
        if self.at_op(";"):
            self.next()
            return
        if self.at("EOF") or self.at("HTML"):
            return
        self.err("expected ';' but found %s" % self.describe(self.peek()))

    # statements -------------------------------------------------------------
    def statement(self):
        self.check_unsupported()
        t = self.peek()
        line = t.line
        if t.kind == "HTML":
            self.next()
            return ("html", line, t.value)
        if t.kind == "OP":
            if t.value == ";":
                self.next()
                return None
            if t.value == "{":
                return self.block()
        if t.kind == "KW":
            v = t.value
            if v in ("echo", "print"):
                self.next()
                exprs = [self.expr()]
                while self.accept_op(","):
                    exprs.append(self.expr())
                self.end_stmt()
                return ("echo", line, exprs)
            if v == "if":
                return self.if_stmt()
            if v == "while":
                return self.while_stmt()
            if v == "for":
                return self.for_stmt()
            if v == "foreach":
                return self.foreach_stmt()
            if v == "function" and self.peek(1).kind == "IDENT":
                return self.func_decl()
            if v == "return":
                self.next()
                e = None
                if not (self.at_op(";") or self.at("EOF") or self.at("HTML")):
                    e = self.expr()
                self.end_stmt()
                return ("return", line, e)
            if v in ("break", "continue"):
                self.next()
                lv = 1
                if self.at("NUM"):
                    lv = self.next().value
                    if not isinstance(lv, int) or lv < 1:
                        self.err("bad break/continue level")
                self.end_stmt()
                return (v, line, lv)
            if v == "try":
                return self.try_stmt()
            if v == "throw":
                self.next()
                e = self.expr()
                self.end_stmt()
                return ("throw", line, e)
            if v in ("include", "include_once", "require", "require_once"):
                self.next()
                paren = self.accept_op("(")
                if not self.at("STR"):
                    self.err("include path must be a string literal (dynamic includes are forbidden)")
                parts = self.next().value
                if len(parts) != 1 or parts[0][0] != "lit":
                    self.err("include path must be a constant string (no interpolation)")
                if paren:
                    self.expect_op(")")
                self.end_stmt()
                return ("include", line, parts[0][1], v.endswith("_once"))
            if v == "const":
                self.next()
                if not self.at("IDENT"):
                    self.err("expected constant name")
                name = self.next().value
                self.expect_op("=")
                e = self.expr()
                self.end_stmt()
                return ("const", line, name, e)
            if v == "unset":
                self.next()
                self.expect_op("(")
                targets = [self.expr()]
                while self.accept_op(","):
                    targets.append(self.expr())
                self.expect_op(")")
                for tg in targets:
                    if tg[0] not in ("var", "index"):
                        self.err("unset() needs a variable or array element")
                self.end_stmt()
                return ("unset", line, targets)
            if v in ("else", "elseif", "endif", "endwhile", "endfor", "endforeach", "catch", "finally"):
                self.err("unexpected '%s'" % v)
        e = self.expr()
        self.end_stmt()
        return ("expr", line, e)

    def if_stmt(self):
        line = self.next().line
        self.expect_op("(")
        cond = self.expr()
        self.expect_op(")")
        if self.accept_op(":"):  # alternative syntax
            branches = [(cond, self.alt_block("elseif", "else", "endif"))]
            other = None
            while True:
                if self.at_kw("elseif"):
                    self.next()
                    self.expect_op("(")
                    c = self.expr()
                    self.expect_op(")")
                    self.expect_op(":")
                    branches.append((c, self.alt_block("elseif", "else", "endif")))
                elif self.at_kw("else"):
                    self.next()
                    self.expect_op(":")
                    other = self.alt_block("endif")
                else:
                    self.expect_kw("endif")
                    self.end_stmt()
                    break
            return ("if", line, branches, other)
        branches = [(cond, self.block_or_statement())]
        other = None
        while True:
            if self.at_kw("elseif") or (self.at_kw("else") and self.at("KW", "if", 1)):
                if self.at_kw("else"):
                    self.next()
                self.next()
                self.expect_op("(")
                c = self.expr()
                self.expect_op(")")
                branches.append((c, self.block_or_statement()))
            elif self.at_kw("else"):
                self.next()
                other = self.block_or_statement()
                break
            else:
                break
        return ("if", line, branches, other)

    def while_stmt(self):
        line = self.next().line
        self.expect_op("(")
        cond = self.expr()
        self.expect_op(")")
        if self.accept_op(":"):
            body = self.alt_block("endwhile")
            self.next()
            self.end_stmt()
        else:
            body = self.block_or_statement()
        return ("while", line, cond, body)

    def for_stmt(self):
        line = self.next().line
        self.expect_op("(")
        init, step = [], []
        if not self.at_op(";"):
            init.append(self.expr())
            while self.accept_op(","):
                init.append(self.expr())
        self.expect_op(";")
        cond = None if self.at_op(";") else self.expr()
        self.expect_op(";")
        if not self.at_op(")"):
            step.append(self.expr())
            while self.accept_op(","):
                step.append(self.expr())
        self.expect_op(")")
        if self.accept_op(":"):
            body = self.alt_block("endfor")
            self.next()
            self.end_stmt()
        else:
            body = self.block_or_statement()
        return ("for", line, init, cond, step, body)

    def foreach_stmt(self):
        line = self.next().line
        self.expect_op("(")
        subject = self.expr()
        self.expect_kw("as")
        if self.at_op("&"):
            self.err("foreach by reference (&) is not supported")
        a = self.postfix_target()
        k, v = None, a
        if self.accept_op("=>"):
            if self.at_op("&"):
                self.err("foreach by reference (&) is not supported")
            k, v = a, self.postfix_target()
        self.expect_op(")")
        if self.accept_op(":"):
            body = self.alt_block("endforeach")
            self.next()
            self.end_stmt()
        else:
            body = self.block_or_statement()
        return ("foreach", line, subject, k, v, body)

    def postfix_target(self):
        e = self.postfix()
        if e[0] not in ("var", "index"):
            self.err("expected a variable")
        return e

    def params(self):
        self.expect_op("(")
        ps = []
        seen = set()
        while not self.at_op(")"):
            # optional PHP type hints are accepted and ignored
            if self.at("IDENT") or (self.at_op("?") and self.at("IDENT", None, 1)):
                if self.at_op("?"):
                    self.next()
                self.next()
            if self.at_op("&"):
                self.err("pass-by-reference parameters are not supported")
            if self.at_op("..."):
                self.err("variadic parameters are not supported")
            if not self.at("VAR"):
                self.err("expected parameter name")
            name = self.next().value
            if name in seen:
                self.err("duplicate parameter $%s" % name)
            seen.add(name)
            default = None
            if self.accept_op("="):
                default = self.expr()
            ps.append((name, default))
            if not self.accept_op(","):
                break
        self.expect_op(")")
        # optional return type hint
        if self.accept_op(":"):
            if self.at_op("?"):
                self.next()
            if self.at("IDENT") or self.at_kw("array") or self.at_kw("null"):
                self.next()
            else:
                self.err("expected return type")
        return ps

    def func_decl(self):
        line = self.next().line
        name = self.next().value
        ps = self.params()
        body = self.block()
        return ("func", line, name, ps, body)

    def try_stmt(self):
        line = self.next().line
        body = self.block()
        cvar, cblock, fblock = None, None, None
        if self.at_kw("catch"):
            self.next()
            self.expect_op("(")
            # optional exception class names: catch (Exception | Error $e)
            while self.at("IDENT"):
                self.next()
                if self.at_op("|"):
                    self.next()
            if self.at("VAR"):
                cvar = self.next().value
            self.expect_op(")")
            cblock = self.block()
        if self.at_kw("finally"):
            self.next()
            fblock = self.block()
        if cblock is None and fblock is None:
            self.err("try needs catch or finally")
        return ("try", line, body, cvar, cblock, fblock)

    # expressions ------------------------------------------------------------
    def expr(self):
        return self.low_or()

    def low_or(self):
        left = self.low_and()
        while self.at_kw("or"):
            line = self.next().line
            left = ("or", line, left, self.low_and())
        return left

    def low_and(self):
        left = self.assignment()
        while self.at_kw("and"):
            line = self.next().line
            left = ("and", line, left, self.assignment())
        return left

    def assignment(self):
        left = self.ternary()
        t = self.peek()
        if t.kind == "OP" and t.value in ASSIGN_OPS:
            if left[0] not in ("var", "index"):
                self.err("cannot assign to this expression")
            self.next()
            if self.at_op("&"):
                self.err("assignment by reference (=&) is not supported")
            right = self.assignment()
            return ("assign", t.line, left, t.value, right)
        return left

    def ternary(self):
        cond = self.coalesce()
        while self.at_op("?"):
            line = self.next().line
            if self.accept_op(":"):
                other = self.coalesce()
                cond = ("ternary", line, cond, None, other)
            else:
                a = self.assignment()
                self.expect_op(":")
                b = self.assignment()
                cond = ("ternary", line, cond, a, b)
        return cond

    def coalesce(self):
        left = self.oror()
        if self.at_op("??"):
            line = self.next().line
            return ("coalesce", line, left, self.coalesce())
        return left

    def oror(self):
        left = self.andand()
        while self.at_op("||"):
            line = self.next().line
            left = ("or", line, left, self.andand())
        return left

    def andand(self):
        left = self.equality()
        while self.at_op("&&"):
            line = self.next().line
            left = ("and", line, left, self.equality())
        return left

    def equality(self):
        left = self.comparison()
        while self.peek().kind == "OP" and self.peek().value in ("==", "!=", "===", "!==", "<>"):
            t = self.next()
            op = {"===": "==", "!==": "!=", "<>": "!="}.get(t.value, t.value)
            left = ("bin", t.line, op, left, self.comparison())
        return left

    def comparison(self):
        left = self.concat()
        while self.peek().kind == "OP" and self.peek().value in ("<", ">", "<=", ">="):
            t = self.next()
            left = ("bin", t.line, t.value, left, self.concat())
        return left

    def concat(self):
        left = self.additive()
        while self.at_op("."):
            t = self.next()
            left = ("bin", t.line, ".", left, self.additive())
        return left

    def additive(self):
        left = self.term()
        while self.peek().kind == "OP" and self.peek().value in ("+", "-"):
            t = self.next()
            left = ("bin", t.line, t.value, left, self.term())
        return left

    def term(self):
        left = self.unary()
        while self.peek().kind == "OP" and self.peek().value in ("*", "/", "%"):
            t = self.next()
            left = ("bin", t.line, t.value, left, self.unary())
        return left

    def unary(self):
        self.check_unsupported()
        t = self.peek()
        if t.kind == "OP":
            if t.value == "!":
                self.next()
                return ("not", t.line, self.unary())
            if t.value == "-":
                self.next()
                return ("neg", t.line, self.unary())
            if t.value == "+":
                self.next()
                return ("pos", t.line, self.unary())
            if t.value in ("++", "--"):
                self.next()
                target = self.unary()
                if target[0] not in ("var", "index"):
                    self.err("++/-- needs a variable")
                return ("incdec", t.line, target, t.value, True)
            if t.value == "(" and self.peek(1).kind in ("IDENT", "KW") and \
                    str(self.peek(1).value).lower() in CASTS and \
                    self.peek(2).kind == "OP" and self.peek(2).value == ")":
                self.next()
                kind = CASTS[str(self.next().value).lower()]
                self.next()
                return ("cast", t.line, kind, self.unary())
        return self.postfix()

    def postfix(self):
        e = self.primary()
        while True:
            self.check_unsupported()
            if self.at_op("["):
                line = self.next().line
                if self.accept_op("]"):
                    e = ("index", line, e, None)
                else:
                    idx = self.expr()
                    self.expect_op("]")
                    e = ("index", line, e, idx)
            elif self.at_op("("):
                line = self.peek().line
                args = self.args()
                e = ("callv", line, e, args)
            elif self.peek().kind == "OP" and self.peek().value in ("++", "--"):
                if e[0] not in ("var", "index"):
                    break
                t = self.next()
                e = ("incdec", t.line, e, t.value, False)
            else:
                break
        return e

    def args(self):
        self.expect_op("(")
        out = []
        while not self.at_op(")"):
            if self.at_op("&"):
                self.err("pass-by-reference is not supported")
            if self.at_op("..."):
                self.err("argument unpacking is not supported")
            out.append(self.expr())
            if not self.accept_op(","):
                break
        self.expect_op(")")
        return out

    def primary(self):
        self.check_unsupported()
        t = self.peek()
        line = t.line
        if t.kind == "VAR":
            self.next()
            if t.value == "this":
                self.err("$this is not supported (no objects)")
            return ("var", line, t.value)
        if t.kind == "NUM":
            self.next()
            return ("num", line, t.value)
        if t.kind == "STR":
            self.next()
            parts = []
            for p in t.value:
                if p[0] == "lit":
                    parts.append(("lit", p[1]))
                else:
                    sub = Parser("<?wdn " + p[1], self.fn)
                    for tok in sub.toks:
                        tok.line = p[2]
                    e = sub.expr()
                    if not sub.at("EOF"):
                        sub.err("bad interpolation expression")
                    parts.append(("expr", e))
            if len(parts) == 1 and parts[0][0] == "lit":
                return ("str", line, parts[0][1])
            return ("interp", line, parts)
        if t.kind == "KW":
            v = t.value
            if v == "true":
                self.next()
                return ("const_val", line, True)
            if v == "false":
                self.next()
                return ("const_val", line, False)
            if v == "null":
                self.next()
                return ("const_val", line, None)
            if v == "array":
                self.next()
                self.expect_op("(")
                return self.array_items(")", line)
            if v == "function":
                return self.closure()
            if v == "isset":
                self.next()
                args = self.args()
                if not args:
                    self.err("isset() needs arguments")
                return ("isset", line, args)
            if v == "empty":
                self.next()
                args = self.args()
                if len(args) != 1:
                    self.err("empty() takes exactly one argument")
                return ("empty", line, args[0])
            if v in ("exit", "die"):
                self.next()
                arg = None
                if self.at_op("("):
                    args = self.args()
                    if len(args) > 1:
                        self.err("exit() takes at most one argument")
                    arg = args[0] if args else None
                return ("exit", line, arg)
            self.err("unexpected keyword '%s'" % v)
        if t.kind == "OP":
            if t.value == "(":
                self.next()
                e = self.expr()
                self.expect_op(")")
                return e
            if t.value == "[":
                self.next()
                return self.array_items("]", line)
        if t.kind == "IDENT":
            self.next()
            if self.at_op("("):
                return ("call", line, t.value, self.args())
            return ("constref", line, t.value)
        self.err("unexpected %s" % self.describe(t))

    def array_items(self, closer, line):
        items = []
        while not self.at_op(closer):
            if self.at_op("..."):
                self.err("array spread is not supported; use array_merge()")
            v = self.expr()
            if self.accept_op("=>"):
                items.append((v, self.expr()))
            else:
                items.append((None, v))
            if not self.accept_op(","):
                break
        self.expect_op(closer)
        return ("array", line, items)

    def closure(self):
        line = self.next().line
        ps = self.params()
        uses = []
        if self.at_kw("use"):
            self.next()
            self.expect_op("(")
            while not self.at_op(")"):
                if self.at_op("&"):
                    self.err("use (&$x) by reference is not supported")
                if not self.at("VAR"):
                    self.err("expected variable in use()")
                uses.append(self.next().value)
                if not self.accept_op(","):
                    break
            self.expect_op(")")
        body = self.block()
        return ("closure", line, ps, uses, body)


def parse(src, filename="<input>", code_mode=False):
    return Parser(src, filename, code_mode).parse_program()
