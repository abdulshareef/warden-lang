"""Taint-tracked strings.

Every string in a Warden program is a TStr: the text plus the character
ranges that came from an untrusted source (request data, cookies, headers,
database rows, files). Taint survives concatenation, slicing, interpolation
and string functions, so the runtime always knows exactly which characters
of an HTML page, SQL statement, header or path were supplied by an attacker.

Each tainted range has a kind:
  'u'  raw untrusted text
  'h'  untrusted text that has been HTML-escaped (htmlspecialchars)
  'm'  untrusted markup that passed the HTML sanitizer (html_sanitize)

Kinds 'h' and 'm' are only "safe" for HTML output. For SQL, headers, paths,
redirects and dynamic calls every kind counts as untrusted, so escaping for
one context can never launder data into another.
"""

U, H, M = "u", "h", "m"


def _merge(ranges):
    out = []
    for a, b, k in sorted(r for r in ranges if r[1] > r[0]):
        if out and a <= out[-1][1] and out[-1][2] == k:
            if b > out[-1][1]:
                out[-1] = (out[-1][0], b, k)
        else:
            out.append((a, b, k))
    return tuple(out)


class TStr:
    __slots__ = ("s", "t")

    def __init__(self, s="", t=()):
        self.s = s
        self.t = t  # tuple of (start, end, kind), sorted, non-overlapping

    # constructors -----------------------------------------------------
    @staticmethod
    def plain(s):
        return TStr(s, ())

    @staticmethod
    def tainted(s, kind=U):
        return TStr(s, ((0, len(s), kind),) if s else ())

    # queries ----------------------------------------------------------
    @property
    def is_tainted(self):
        return bool(self.t)

    def segments(self):
        """Yield (text, kind_or_None) pieces in order."""
        pos = 0
        for a, b, k in self.t:
            if a > pos:
                yield self.s[pos:a], None
            yield self.s[a:b], k
            pos = b
        if pos < len(self.s):
            yield self.s[pos:], None

    # operations -------------------------------------------------------
    def concat(self, other):
        n = len(self.s)
        if not other.t:
            return TStr(self.s + other.s, self.t)
        return TStr(self.s + other.s,
                    _merge(self.t + tuple((a + n, b + n, k) for a, b, k in other.t)))

    def slice(self, i, j):
        i, j, _ = slice(i, j).indices(len(self.s))
        if j <= i:
            return TStr("", ())
        r = []
        for a, b, k in self.t:
            a2, b2 = max(a, i), min(b, j)
            if b2 > a2:
                r.append((a2 - i, b2 - i, k))
        return TStr(self.s[i:j], tuple(r))

    def map_same(self, fn):
        """Apply a char transform; keep ranges if length unchanged, else taint all."""
        ns = fn(self.s)
        if len(ns) == len(self.s):
            return TStr(ns, self.t)
        return TStr.tainted(ns) if self.t else TStr(ns, ())

    def derived(self, ns):
        """A new string computed from this one: wholly raw-untrusted if any input taint."""
        return TStr.tainted(ns) if self.t else TStr(ns, ())

    # python protocol --------------------------------------------------
    def __eq__(self, other):
        return isinstance(other, TStr) and self.s == other.s

    def __hash__(self):
        return hash(self.s)

    def __len__(self):
        return len(self.s)

    def __repr__(self):
        return "TStr(%r, %r)" % (self.s, self.t)

    def __str__(self):
        return self.s


def join(parts):
    texts, ranges, n = [], [], 0
    for p in parts:
        texts.append(p.s)
        ranges.extend((a + n, b + n, k) for a, b, k in p.t)
        n += len(p.s)
    return TStr("".join(texts), _merge(ranges))


def any_tainted(*vals):
    return any(isinstance(v, TStr) and v.t for v in vals)
