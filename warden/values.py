"""Runtime value types and conversions.

Warden values:  null(None) bool int float string(TStr) array(BArray) function(Func)

Rules that remove whole classes of PHP bugs:
  * No implicit type juggling: "abc" == 0 is false, "1e3" == "1000" is false,
    "5" + 1 is a type error (use int()).
  * Integers are 64-bit and overflow is an error, never silent wrap or float.
  * Arrays have value semantics (copy-on-write), like PHP, with no references.
  * "0" is truthy (only false, null, 0, 0.0, "" and [] are falsy).
"""

import math

from .errors import WardenError
from .tstr import TStr

INT_MIN = -(2 ** 63)
INT_MAX = 2 ** 63 - 1


class Func:
    __slots__ = ("name", "params", "body", "captured", "filename")

    def __init__(self, name, params, body, captured=None, filename="<input>"):
        self.name = name
        self.params = params
        self.body = body
        self.captured = captured
        self.filename = filename


class BArray:
    """Ordered map with PHP-style int/string keys and copy-on-write children."""
    __slots__ = ("d", "next", "kt", "shared")

    def __init__(self):
        self.d = {}
        self.next = 0
        self.kt = set()      # string keys whose text came from untrusted input
        self.shared = False  # True when another array also references this one

    @staticmethod
    def from_list(items):
        a = BArray()
        for v in items:
            a.append(v)
        return a

    @staticmethod
    def from_pairs(pairs):
        a = BArray()
        for k, v in pairs:
            a.set(k, v)
        return a

    def copy(self):
        c = BArray()
        c.d = dict(self.d)
        c.next = self.next
        c.kt = set(self.kt)
        for v in self.d.values():
            if isinstance(v, BArray):
                v.shared = True
        return c

    @staticmethod
    def norm_key(k):
        if isinstance(k, bool):
            raise WardenError("array key cannot be a boolean")
        if isinstance(k, int):
            return k, False
        if isinstance(k, TStr):
            s = k.s
            # PHP normalises canonical decimal strings to int keys
            if s and (s.isdigit() and (s == "0" or s[0] != "0")) and len(s) < 19:
                return int(s), False
            if s.startswith("-") and s[1:].isdigit() and s[1] != "0" and len(s) < 20:
                return int(s), False
            return s, k.is_tainted
        if k is None:
            return "", False
        raise WardenError("array key must be int or string, got %s" % type_name(k))

    def has(self, k):
        key, _ = self.norm_key(k)
        return key in self.d

    def get(self, k, default=KeyError):
        key, _ = self.norm_key(k)
        if key in self.d:
            return self.d[key]
        if default is KeyError:
            raise KeyError(key)
        return default

    def set(self, k, v):
        key, tainted = self.norm_key(k)
        self.d[key] = v
        if isinstance(key, str):
            if tainted:
                self.kt.add(key)
            else:
                self.kt.discard(key)
        elif key >= self.next:
            self.next = key + 1

    def append(self, v):
        if self.next > INT_MAX:
            raise WardenError("array index overflow")
        self.d[self.next] = v
        self.next += 1

    def delete(self, k):
        key, _ = self.norm_key(k)
        self.d.pop(key, None)
        self.kt.discard(key) if isinstance(key, str) else None

    def key_value(self, key):
        """Return a key as a Warden value (string keys keep their taint)."""
        if isinstance(key, int):
            return key
        return TStr.tainted(key) if key in self.kt else TStr.plain(key)

    def items(self):
        return [(self.key_value(k), v) for k, v in self.d.items()]

    def values(self):
        return list(self.d.values())

    def is_list(self):
        return all(k == i for i, k in enumerate(self.d))

    def __len__(self):
        return len(self.d)


def type_name(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, TStr):
        return "string"
    if isinstance(v, BArray):
        return "array"
    if isinstance(v, Func):
        return "function"
    return "unknown"


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def check_int(v, line=0):
    if isinstance(v, int) and not isinstance(v, bool) and not (INT_MIN <= v <= INT_MAX):
        raise WardenError("integer overflow", line)
    return v


def truthy(v):
    if v is None or v is False:
        return False
    if v is True:
        return True
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, TStr):
        return v.s != ""
    if isinstance(v, BArray):
        return len(v) > 0
    return True


def fmt_float(f):
    if math.isnan(f):
        return "NAN"
    if math.isinf(f):
        return "INF" if f > 0 else "-INF"
    if f.is_integer() and abs(f) < 1e15:
        return str(int(f))
    r = repr(f)
    return r


def to_str(v, line=0, what="value"):
    """Convert a value to TStr for output / concatenation."""
    if isinstance(v, TStr):
        return v
    if v is None:
        return TStr("", ())
    if isinstance(v, bool):
        raise WardenError("cannot use bool as string (use a ternary or json_encode)", line)
    if isinstance(v, int):
        return TStr(str(v), ())
    if isinstance(v, float):
        return TStr(fmt_float(v), ())
    raise WardenError("cannot convert %s to string" % type_name(v), line)


def equals(a, b):
    if a is None or b is None:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_num(a) and is_num(b):
        return a == b
    if isinstance(a, TStr) and isinstance(b, TStr):
        return a.s == b.s
    if isinstance(a, BArray) and isinstance(b, BArray):
        if len(a) != len(b) or set(a.d) != set(b.d):
            return False
        return all(equals(a.d[k], b.d[k]) for k in a.d)
    if isinstance(a, Func) and isinstance(b, Func):
        return a is b
    return False


def compare(a, b, line=0):
    if is_num(a) and is_num(b):
        return (a > b) - (a < b)
    if isinstance(a, TStr) and isinstance(b, TStr):
        return (a.s > b.s) - (a.s < b.s)
    raise WardenError("cannot compare %s with %s" % (type_name(a), type_name(b)), line)


def copy_val(v):
    if isinstance(v, BArray):
        return v.copy()
    return v


def to_py(v):
    """Strip taint & convert to plain Python (for JSON, DB params)."""
    if isinstance(v, TStr):
        return v.s
    if isinstance(v, BArray):
        if v.is_list():
            return [to_py(x) for x in v.d.values()]
        return {str(k): to_py(x) for k, x in v.d.items()}
    if isinstance(v, Func):
        raise WardenError("cannot convert a function to data")
    return v


def from_py(o, tainted=True, depth=0):
    """Convert plain Python data (JSON, DB rows) into Warden values."""
    if depth > 64:
        raise WardenError("data nested too deeply")
    if isinstance(o, str):
        return TStr.tainted(o) if tainted else TStr.plain(o)
    if isinstance(o, bool) or o is None:
        return o
    if isinstance(o, int):
        return check_int(o)
    if isinstance(o, float):
        return o
    if isinstance(o, (list, tuple)):
        return BArray.from_list([from_py(x, tainted, depth + 1) for x in o])
    if isinstance(o, dict):
        a = BArray()
        for k, x in o.items():
            a.set(TStr.tainted(str(k)) if tainted else TStr.plain(str(k)),
                  from_py(x, tainted, depth + 1))
        return a
    if isinstance(o, bytes):
        return TStr.tainted(o.decode("utf-8", "replace")) if tainted else TStr.plain(o.decode("utf-8", "replace"))
    raise WardenError("unsupported data type")
