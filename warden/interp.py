"""Tree-walking interpreter with hard resource limits."""

import os
import sys
import threading

from .errors import (WardenError, WardenSyntaxError, SecurityViolation,
                     LimitExceeded, ExitSignal)
from .parser import parse
from .tstr import TStr, join as tjoin
from .values import (BArray, Func, type_name, is_num, check_int, truthy,
                     to_str, equals, compare, copy_val)

sys.setrecursionlimit(max(sys.getrecursionlimit(), 8000))

SUPERGLOBALS = ("_GET", "_POST", "_COOKIE", "_SERVER", "_REQUEST", "_FILES", "_ENV")


class Limits:
    def __init__(self, max_steps=5_000_000, max_depth=64, max_str=8 * 1024 * 1024,
                 max_array=1_000_000, max_output=16 * 1024 * 1024):
        self.max_steps = max_steps
        self.max_depth = max_depth
        self.max_str = max_str
        self.max_array = max_array
        self.max_output = max_output


class UndefinedError(WardenError):
    pass


class BreakSig(Exception):
    def __init__(self, levels):
        self.levels = levels


class ContinueSig(Exception):
    def __init__(self, levels):
        self.levels = levels


class ReturnSig(Exception):
    def __init__(self, value):
        self.value = value


class ThrowSig(WardenError):
    pass


_parse_cache = {}
_parse_lock = threading.Lock()


def parse_file(path):
    st = os.stat(path)
    key = (path, st.st_mtime_ns, st.st_size)
    with _parse_lock:
        hit = _parse_cache.get(key)
    if hit is not None:
        return hit
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    try:
        tree = parse(src, os.path.basename(path))
    except RecursionError:
        raise WardenSyntaxError("code nested too deeply", os.path.basename(path), 0)
    with _parse_lock:
        if len(_parse_cache) > 2000:
            _parse_cache.clear()
        _parse_cache[key] = tree
    return tree


def safe_join(root, rel, must_exist=True):
    """Resolve rel inside root; refuse traversal, absolute paths and symlink escapes."""
    if not isinstance(rel, str) or not rel or "\x00" in rel:
        raise SecurityViolation("invalid path", "path")
    if rel.startswith(("/", "\\")) or (len(rel) > 1 and rel[1] == ":"):
        raise SecurityViolation("absolute paths are not allowed", "path")
    parts = rel.replace("\\", "/").split("/")
    if any(p in ("..", "") for p in parts):
        raise SecurityViolation("path traversal blocked: %r" % rel, "path")
    root_real = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root_real, *parts))
    if full != root_real and not full.startswith(root_real + os.sep):
        raise SecurityViolation("path escapes sandbox: %r" % rel, "path")
    if must_exist and not os.path.exists(full):
        raise WardenError("file not found: %s" % rel)
    return full


class Interp:
    def __init__(self, app_root=None, limits=None, ctx=None):
        from . import stdlib
        self.app_root = app_root or os.getcwd()
        self.lim = limits or Limits()
        self.ctx = ctx                      # web context (request/response/session/db) or None
        self.functions = {}                 # lower name -> Func
        self.constants = dict(stdlib.CONSTANTS)
        self.globals = {}
        self.superglobals = {n: BArray() for n in SUPERGLOBALS}
        self.out = []
        self.out_len = 0
        self.steps = 0
        self.depth = 0
        self.included = set()
        self.builtins = stdlib.BUILTINS
        self.filename = "<input>"
        self.E = {k[2:]: getattr(self, k) for k in dir(self) if k.startswith("e_")}
        self.S = {k[2:]: getattr(self, k) for k in dir(self) if k.startswith("s_")}

    # ------------------------------------------------------------------ api
    def run_source(self, src, filename="<input>", code_mode=False):
        try:
            tree = parse(src, filename, code_mode)
        except RecursionError:
            raise WardenSyntaxError("code nested too deeply", filename, 0)
        return self.run_tree(tree, filename)

    def run_file(self, path):
        return self.run_tree(parse_file(path), os.path.basename(path))

    def run_tree(self, tree, filename):
        self.filename = filename
        try:
            self.hoist(tree, filename)
            self.exec_block(tree, self.globals)
        except ExitSignal:
            pass
        except ReturnSig:
            pass
        except (BreakSig, ContinueSig):
            raise WardenError("break/continue outside of a loop")
        except RecursionError:
            raise LimitExceeded("maximum nesting depth exceeded")

    def output(self):
        return tjoin(self.out)

    # ------------------------------------------------------------- helpers
    def tick(self):
        self.steps += 1
        if self.steps > self.lim.max_steps:
            raise LimitExceeded("CPU step limit exceeded (%d)" % self.lim.max_steps)

    def emit(self, ts):
        self.out_len += len(ts.s)
        if self.out_len > self.lim.max_output:
            raise LimitExceeded("output size limit exceeded")
        self.out.append(ts)

    def check_str(self, ts):
        if len(ts.s) > self.lim.max_str:
            raise LimitExceeded("string size limit exceeded")
        return ts

    def check_arr(self, a):
        if len(a) > self.lim.max_array:
            raise LimitExceeded("array size limit exceeded")
        return a

    def hoist(self, block, filename):
        for st in block[2]:
            if st[0] == "func":
                self.declare(st, filename)

    def declare(self, st, filename):
        name = st[2]
        low = name.lower()
        if low in self.builtins:
            raise WardenError("cannot redefine built-in function %s()" % name, st[1])
        existing = self.functions.get(low)
        if existing is not None and existing.body is not st[4]:
            raise WardenError("function %s() already defined" % name, st[1])
        self.functions[low] = Func(name, st[3], st[4], None, filename)

    # ---------------------------------------------------------- statements
    def exec_block(self, block, scope):
        S = self.S
        for st in block[2]:
            self.tick()
            S[st[0]](st, scope)

    def s_block(self, st, scope):
        self.exec_block(st, scope)

    def s_html(self, st, scope):
        self.emit(TStr(st[2], ()))

    def s_echo(self, st, scope):
        for e in st[2]:
            v = self.eval(e, scope)
            if isinstance(v, (bool, BArray, Func)):
                raise WardenError("cannot echo a %s" % type_name(v), st[1])
            self.emit(to_str(v, st[1]))

    def s_expr(self, st, scope):
        self.eval(st[2], scope)

    def s_if(self, st, scope):
        for cond, body in st[2]:
            if truthy(self.eval(cond, scope)):
                self.exec_block(body, scope)
                return
        if st[3] is not None:
            self.exec_block(st[3], scope)

    def _loop_body(self, body, scope):
        """Run loop body; return 'break' / 'continue' / None, re-raising outer levels."""
        try:
            self.exec_block(body, scope)
        except BreakSig as b:
            if b.levels > 1:
                raise BreakSig(b.levels - 1)
            return "break"
        except ContinueSig as c:
            if c.levels > 1:
                raise ContinueSig(c.levels - 1)
        return None

    def s_while(self, st, scope):
        while truthy(self.eval(st[2], scope)):
            self.tick()
            if self._loop_body(st[3], scope) == "break":
                break

    def s_for(self, st, scope):
        for e in st[2]:
            self.eval(e, scope)
        while st[3] is None or truthy(self.eval(st[3], scope)):
            self.tick()
            if self._loop_body(st[5], scope) == "break":
                break
            for e in st[4]:
                self.eval(e, scope)

    def s_foreach(self, st, scope):
        subject = self.eval(st[2], scope)
        if subject is None:
            raise WardenError("foreach over null", st[1])
        if not isinstance(subject, BArray):
            raise WardenError("foreach needs an array, got %s" % type_name(subject), st[1])
        for k, v in subject.items():  # snapshot: mutation inside the loop is safe
            self.tick()
            if st[3] is not None:
                self.assign_to(st[3], k, scope)
            self.assign_to(st[4], v, scope)
            if self._loop_body(st[5], scope) == "break":
                break

    def s_func(self, st, scope):
        self.declare(st, self.filename)

    def s_return(self, st, scope):
        raise ReturnSig(None if st[2] is None else self.eval(st[2], scope))

    def s_break(self, st, scope):
        raise BreakSig(st[2])

    def s_continue(self, st, scope):
        raise ContinueSig(st[2])

    def s_throw(self, st, scope):
        v = self.eval(st[2], scope)
        msg = v.s if isinstance(v, TStr) else type_name(v)
        raise ThrowSig(msg, st[1], v)

    def s_try(self, st, scope):
        _, line, body, cvar, cblock, fblock = st
        try:
            try:
                self.exec_block(body, scope)
            except (WardenError,) as e:
                if cblock is None:
                    raise
                if isinstance(e, UndefinedError) or not isinstance(e, ThrowSig):
                    val = TStr(e.msg, ())
                else:
                    val = e.value
                if cvar:
                    scope[cvar] = val
                self.exec_block(cblock, scope)
        finally:
            if fblock is not None:
                self.exec_block(fblock, scope)

    def s_include(self, st, scope):
        rel = st[2]
        if not rel.endswith(".wdn"):
            raise SecurityViolation("only .wdn files can be included", "include")
        full = safe_join(self.app_root, rel)
        if st[3] and full in self.included:
            return
        self.included.add(full)
        if len(self.included) > 256:
            raise LimitExceeded("too many includes")
        tree = parse_file(full)
        prev = self.filename
        self.filename = os.path.basename(full)
        try:
            self.hoist(tree, self.filename)
            self.exec_block(tree, scope)
        finally:
            self.filename = prev

    def s_const(self, st, scope):
        name = st[2]
        if name in self.constants:
            raise WardenError("constant %s already defined" % name, st[1])
        v = self.eval(st[3], scope)
        if isinstance(v, Func):
            raise WardenError("constants cannot hold functions", st[1])
        self.constants[name] = v

    def s_unset(self, st, scope):
        for tg in st[2]:
            if tg[0] == "var":
                if tg[2] in SUPERGLOBALS:
                    raise WardenError("cannot unset superglobal", st[1])
                scope.pop(tg[2], None)
            else:
                if tg[3] is None:
                    raise WardenError("cannot unset []", st[1])
                try:
                    cont = self.container_for_write(tg[2], scope, st[1], create=False)
                except UndefinedError:
                    continue
                if cont is not None:
                    cont.delete(self.eval(tg[3], scope))

    # --------------------------------------------------------- expressions
    def eval(self, node, scope):
        self.tick()
        return self.E[node[0]](node, scope)

    def e_num(self, n, scope):
        return n[2]

    def e_str(self, n, scope):
        return TStr(n[2], ())

    def e_const_val(self, n, scope):
        return n[2]

    def e_interp(self, n, scope):
        parts = []
        for p in n[2]:
            if p[0] == "lit":
                parts.append(TStr(p[1], ()))
            else:
                v = self.eval(p[1], scope)
                if isinstance(v, (bool, BArray, Func)):
                    raise WardenError("cannot interpolate a %s" % type_name(v), n[1])
                parts.append(to_str(v, n[1]))
        return self.check_str(tjoin(parts))

    def e_var(self, n, scope):
        name = n[2]
        if name in SUPERGLOBALS:
            return self.superglobals[name]
        try:
            return scope[name]
        except KeyError:
            raise UndefinedError("undefined variable $%s" % name, n[1])

    def e_constref(self, n, scope):
        try:
            return self.constants[n[2]]
        except KeyError:
            up = n[2].upper()
            if up in ("TRUE", "FALSE", "NULL"):
                return {"TRUE": True, "FALSE": False, "NULL": None}[up]
            raise WardenError("undefined constant %s" % n[2], n[1])

    def e_index(self, n, scope):
        if n[3] is None:
            raise WardenError("cannot use [] for reading", n[1])
        base = self.eval(n[2], scope)
        key = self.eval(n[3], scope)
        if isinstance(base, BArray):
            try:
                return base.get(key)
            except KeyError:
                raise UndefinedError("undefined array key %s" % self.key_repr(key), n[1])
        if isinstance(base, TStr):
            if not isinstance(key, int) or isinstance(key, bool):
                raise WardenError("string offset must be an int", n[1])
            if key < 0:
                key += len(base.s)
            if not 0 <= key < len(base.s):
                raise UndefinedError("string offset %d out of range" % key, n[1])
            return base.slice(key, key + 1)
        if base is None:
            raise UndefinedError("cannot index null", n[1])
        raise WardenError("cannot index a %s" % type_name(base), n[1])

    @staticmethod
    def key_repr(k):
        if isinstance(k, TStr):
            s = k.s[:40].replace("\n", "\\n").replace("\r", "\\r")
            return '"%s"' % s
        return str(k)

    def e_array(self, n, scope):
        a = BArray()
        for k, v in n[2]:
            val = copy_val(self.eval(v, scope))
            if k is None:
                a.append(val)
            else:
                a.set(self.eval(k, scope), val)
        return self.check_arr(a)

    def e_closure(self, n, scope):
        captured = {}
        for name in n[3]:
            if name not in scope:
                raise UndefinedError("undefined variable $%s in use()" % name, n[1])
            captured[name] = copy_val(scope[name])
        return Func("{closure}", n[2], n[4], captured, self.filename)

    def e_not(self, n, scope):
        return not truthy(self.eval(n[2], scope))

    def e_neg(self, n, scope):
        v = self.eval(n[2], scope)
        if not is_num(v):
            raise WardenError("cannot negate %s" % type_name(v), n[1])
        return check_int(-v, n[1])

    def e_pos(self, n, scope):
        v = self.eval(n[2], scope)
        if not is_num(v):
            raise WardenError("unary + needs a number, got %s" % type_name(v), n[1])
        return v

    def e_cast(self, n, scope):
        from .stdlib import php_intval, php_floatval
        v = self.eval(n[3], scope)
        kind = n[2]
        if kind == "int":
            return php_intval(v)
        if kind == "float":
            return php_floatval(v)
        if kind == "bool":
            return truthy(v)
        if kind == "string":
            if isinstance(v, bool):
                return TStr("1" if v else "", ())
            return to_str(v, n[1])
        raise WardenError("bad cast", n[1])

    def e_and(self, n, scope):
        return truthy(self.eval(n[2], scope)) and truthy(self.eval(n[3], scope))

    def e_or(self, n, scope):
        return truthy(self.eval(n[2], scope)) or truthy(self.eval(n[3], scope))

    def quiet_eval(self, node, scope):
        """Evaluate, returning None if a variable/key is undefined (isset/??)."""
        try:
            return self.eval(node, scope)
        except UndefinedError:
            return None

    def e_coalesce(self, n, scope):
        v = self.quiet_eval(n[2], scope)
        return v if v is not None else self.eval(n[3], scope)

    def e_isset(self, n, scope):
        return all(self.quiet_eval(a, scope) is not None for a in n[2])

    def e_empty(self, n, scope):
        return not truthy(self.quiet_eval(n[2], scope))

    def e_ternary(self, n, scope):
        c = self.eval(n[2], scope)
        if truthy(c):
            return c if n[3] is None else self.eval(n[3], scope)
        return self.eval(n[4], scope)

    def e_exit(self, n, scope):
        if n[2] is not None:
            v = self.eval(n[2], scope)
            if isinstance(v, TStr):
                self.emit(v)
            elif isinstance(v, int) and not isinstance(v, bool):
                pass
            else:
                raise WardenError("exit() takes a string or int", n[1])
        raise ExitSignal()

    def e_bin(self, n, scope):
        op = n[2]
        a = self.eval(n[3], scope)
        b = self.eval(n[4], scope)
        return self.binop(op, a, b, n[1])

    def binop(self, op, a, b, line):
        if op == ".":
            for v in (a, b):
                if isinstance(v, (bool, BArray, Func)):
                    raise WardenError("cannot concatenate a %s" % type_name(v), line)
            return self.check_str(to_str(a, line).concat(to_str(b, line)))
        if op == "==":
            return equals(a, b)
        if op == "!=":
            return not equals(a, b)
        if op in ("<", ">", "<=", ">="):
            c = compare(a, b, line)
            return {"<": c < 0, ">": c > 0, "<=": c <= 0, ">=": c >= 0}[op]
        if op == "+" and isinstance(a, BArray) and isinstance(b, BArray):
            r = a.copy()
            for k, v in b.d.items():
                if k not in r.d:
                    r.set(b.key_value(k), v)
            return self.check_arr(r)
        if not (is_num(a) and is_num(b)):
            hint = ""
            if isinstance(a, TStr) or isinstance(b, TStr):
                hint = " (convert explicitly with int() or float())"
            raise WardenError("unsupported operand types: %s %s %s%s"
                              % (type_name(a), op, type_name(b), hint), line)
        if op == "+":
            r = a + b
        elif op == "-":
            r = a - b
        elif op == "*":
            r = a * b
        elif op == "/":
            if b == 0:
                raise WardenError("division by zero", line)
            if isinstance(a, int) and isinstance(b, int) and a % b == 0:
                r = a // b
            else:
                r = a / b
        elif op == "%":
            if not (isinstance(a, int) and isinstance(b, int)):
                raise WardenError("modulo needs integers", line)
            if b == 0:
                raise WardenError("modulo by zero", line)
            r = abs(a) % abs(b) * (1 if a >= 0 else -1)  # PHP sign semantics
        else:
            raise WardenError("unknown operator %s" % op, line)
        return check_int(r, line)

    # assignment ----------------------------------------------------------
    def e_assign(self, n, scope):
        _, line, target, op, rhs = n
        if op == "=":
            v = self.eval(rhs, scope)
        elif op == "??=":
            cur = self.quiet_eval(target, scope)
            if cur is not None:
                return cur
            v = self.eval(rhs, scope)
        else:
            cur = self.eval(target, scope)
            v = self.binop(op[:-1], cur, self.eval(rhs, scope), line)
        self.assign_to(target, v, scope)
        return v

    def e_incdec(self, n, scope):
        _, line, target, op, prefix = n
        cur = self.quiet_eval(target, scope) if target[0] == "var" else self.eval(target, scope)
        if cur is None:
            cur = 0
        if not isinstance(cur, int) or isinstance(cur, bool):
            raise WardenError("++/-- needs an int, got %s" % type_name(cur), line)
        new = check_int(cur + (1 if op == "++" else -1), line)
        self.assign_to(target, new, scope)
        return new if prefix else cur

    def assign_to(self, target, value, scope):
        value = copy_val(value)
        if target[0] == "var":
            name = target[2]
            if name in SUPERGLOBALS:
                raise WardenError("superglobals are read-only", target[1])
            if name == "this":
                raise WardenError("cannot assign $this", target[1])
            scope[name] = value
            return
        cont = self.container_for_write(target[2], scope, target[1])
        if target[3] is None:
            cont.append(value)
        else:
            cont.set(self.eval(target[3], scope), value)
        self.check_arr(cont)

    def container_for_write(self, node, scope, line, create=True):
        """Return an array that may be mutated in place for node[...] = v."""
        if node[0] == "var":
            name = node[2]
            if name in SUPERGLOBALS:
                raise WardenError("superglobals are read-only", line)
            cur = scope.get(name)
            if cur is None:
                if not create:
                    raise UndefinedError("undefined variable $%s" % name, line)
                cur = BArray()
                scope[name] = cur
            elif not isinstance(cur, BArray):
                raise WardenError("cannot use a %s as an array" % type_name(cur), line)
            elif cur.shared:
                cur = cur.copy()
                scope[name] = cur
            return cur
        if node[0] == "index":
            parent = self.container_for_write(node[2], scope, line, create)
            if node[3] is None:
                child = BArray()
                parent.append(child)
                return child
            key = self.eval(node[3], scope)
            child = parent.get(key, None)
            if child is None:
                if not create:
                    raise UndefinedError("undefined array key", line)
                child = BArray()
                parent.set(key, child)
            elif not isinstance(child, BArray):
                raise WardenError("cannot use a %s as an array" % type_name(child), line)
            elif child.shared:
                child = child.copy()
                parent.set(key, child)
            return child
        raise WardenError("invalid assignment target", line)

    # calls ----------------------------------------------------------------
    def e_call(self, n, scope):
        name = n[2]
        low = name.lower()
        args = [self.eval(a, scope) for a in n[3]]
        fn = self.functions.get(low)
        if fn is not None:
            return self.call_func(fn, args, n[1])
        bi = self.builtins.get(low)
        if bi is not None:
            return bi(self, args, n[1])
        raise WardenError("call to undefined function %s()" % name, n[1])

    def e_callv(self, n, scope):
        callee = self.eval(n[2], scope)
        args = [self.eval(a, scope) for a in n[3]]
        return self.call_value(callee, args, n[1])

    def call_value(self, callee, args, line):
        if isinstance(callee, Func):
            return self.call_func(callee, args, line)
        if isinstance(callee, TStr):
            if callee.is_tainted:
                raise SecurityViolation("calling a function by a name that came from user input is forbidden",
                                        "dynamic-call")
            low = callee.s.lower()
            fn = self.functions.get(low)
            if fn is not None:
                return self.call_func(fn, args, line)
            bi = self.builtins.get(low)
            if bi is not None and low not in ("call_user_func", "call_user_func_array"):
                return bi(self, args, line)
            raise WardenError("call to undefined function %s()" % callee.s, line)
        raise WardenError("value of type %s is not callable" % type_name(callee), line)

    def call_func(self, fn, args, line):
        if self.depth >= self.lim.max_depth:
            raise LimitExceeded("maximum function call depth (%d) exceeded" % self.lim.max_depth)
        params = fn.params
        if len(args) > len(params):
            raise WardenError("%s() expects at most %d arguments, %d given"
                              % (fn.name, len(params), len(args)), line)
        local = {}
        if fn.captured:
            for k, v in fn.captured.items():
                local[k] = copy_val(v)
        for i, (pname, default) in enumerate(params):
            if i < len(args):
                local[pname] = copy_val(args[i])
            elif default is not None:
                local[pname] = self.eval(default, local)
            else:
                raise WardenError("%s() missing argument $%s" % (fn.name, pname), line)
        self.depth += 1
        prev = self.filename
        self.filename = fn.filename
        try:
            self.exec_block(fn.body, local)
        except ReturnSig as r:
            return r.value
        except (BreakSig, ContinueSig):
            raise WardenError("break/continue outside of a loop", line)
        finally:
            self.depth -= 1
            self.filename = prev
        return None
