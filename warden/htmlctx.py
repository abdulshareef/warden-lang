"""Context-aware output encoding for HTML responses.

The whole response body is a TStr. Trusted (developer-written) characters
drive an HTML tokenizer state machine; every untrusted range is encoded for
the exact context it lands in - or the response is refused when no safe
encoding exists (script/style blocks, event-handler attributes, unquoted
attributes, tag/attribute names).
"""

import html
import re
from html.parser import HTMLParser

from .errors import SecurityViolation
from .tstr import TStr

URL_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "background",
             "poster", "cite", "data", "codebase", "longdesc", "manifest",
             "ping", "srcset", "icon", "lowsrc", "dynsrc", "archive", "profile"}
FORBIDDEN_ATTRS = {"style", "srcdoc"}
RAWTEXT = {"script", "style", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext"}
SAFE_SCHEMES = {"http", "https", "mailto", "tel"}

TEXT, TAG_OPEN, TAG_NAME, IN_TAG, ATTR_NAME, AFTER_ATTR, BEFORE_VAL, VAL_DQ, \
    VAL_SQ, VAL_UQ, COMMENT, RAW, END_TAG = range(13)

_ctrl = re.compile(r"[\x00-\x20\x7f]+")


def url_is_safe(value):
    v = _ctrl.sub("", html.unescape(value)).lower()
    if not v:
        return True
    m = re.match(r"^([a-z][a-z0-9+.\-]*):", v)
    if m is None:
        # relative URL; reject protocol-relative ("//evil") and backslash tricks
        return not v.startswith(("//", "\\\\", "/\\", "\\/"))
    return m.group(1) in SAFE_SCHEMES


def escape_text(s):
    return html.escape(s, quote=True).replace("`", "&#96;")


class _State:
    def __init__(self):
        self.st = TEXT
        self.tag = ""
        self.attr = ""
        self.val = ""        # trusted text so far in current attribute value
        self.val_tainted = False
        self.raw_tag = ""
        self.is_end = False


def render_html(body):
    """Encode untrusted ranges of a TStr according to their HTML context."""
    if not body.t:
        return body.s
    S = _State()
    out = []
    for text, kind in body.segments():
        if kind is None:
            _advance(S, text)
            out.append(text)
        elif kind == "m" and S.st == TEXT:
            # sanitizer output: balanced allow-listed markup, valid in text context only
            _advance(S, text)
            out.append(text)
        elif kind == "h":
            # already-escaped untrusted text: decode and re-encode for the real context
            out.append(_encode(S, html.unescape(text)))
        else:
            out.append(_encode(S, text))
    return "".join(out)


def _encode(S, text):
    st = S.st
    if st == TEXT:
        return escape_text(text)
    if st == COMMENT:
        return escape_text(text).replace("-", "&#45;")
    if st == RAW:
        raise SecurityViolation("untrusted data inside <%s> is not allowed; pass data via a "
                                "data-* attribute or a JSON endpoint" % S.raw_tag, "xss")
    if st in (VAL_DQ, VAL_SQ):
        a = S.attr
        if a.startswith("on"):
            raise SecurityViolation("untrusted data in event handler attribute %s" % a, "xss")
        if a in FORBIDDEN_ATTRS or (S.tag == "meta" and a == "content") or \
                (S.tag == "base" and a == "href"):
            raise SecurityViolation("untrusted data in %s attribute" % a, "xss")
        if a in URL_ATTRS or a.endswith("url"):
            prefix = S.val
            if not prefix.strip() and not S.val_tainted:
                # untrusted data controls the URL scheme
                if not url_is_safe(text):
                    S.val_tainted = True
                    return "#blocked-unsafe-url"
            elif not url_is_safe(prefix + "x"):
                raise SecurityViolation("untrusted data appended to an unsafe URL scheme", "xss")
        S.val_tainted = True
        return escape_text(text)
    if st in (BEFORE_VAL, VAL_UQ):
        raise SecurityViolation("untrusted data in unquoted attribute %r; quote the attribute" % S.attr, "xss")
    raise SecurityViolation("untrusted data in tag or attribute name position", "xss")


def _advance(S, text):
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        st = S.st
        if st == TEXT:
            j = text.find("<", i)
            if j < 0:
                return
            i = j + 1
            if text.startswith("!--", i):
                S.st = COMMENT
                i += 3
            elif i < n and text[i] == "/":
                S.st, S.is_end, S.tag = TAG_NAME, True, ""
                i += 1
            elif i < n and (text[i].isalpha()):
                S.st, S.is_end, S.tag = TAG_NAME, False, ""
            elif i >= n:
                S.st, S.is_end, S.tag = TAG_OPEN, False, ""
            continue
        if st == TAG_OPEN:
            if c == "/":
                S.st, S.is_end = TAG_NAME, True
                i += 1
            elif c.isalpha():
                S.st = TAG_NAME
            elif c == "!" and text.startswith("!--", i):
                S.st = COMMENT
                i += 3
            else:
                S.st = TEXT
            continue
        if st == COMMENT:
            j = text.find("-->", i)
            if j < 0:
                return
            S.st = TEXT
            i = j + 3
            continue
        if st == RAW:
            m = re.compile(r"</%s[\s/>]" % re.escape(S.raw_tag), re.I).search(text, i)
            if m is None:
                if re.search(r"</%s$" % re.escape(S.raw_tag), text[i:], re.I):
                    pass
                return
            i = m.start()
            S.st = TEXT
            continue
        if st == TAG_NAME:
            if c.isspace():
                S.st = IN_TAG
            elif c == ">":
                _close_tag(S)
            elif c == "/":
                S.st = IN_TAG
            else:
                S.tag += c.lower()
            i += 1
            continue
        if st == IN_TAG:
            if c == ">":
                _close_tag(S)
            elif c.isspace() or c == "/":
                pass
            else:
                S.st, S.attr = ATTR_NAME, c.lower()
            i += 1
            continue
        if st == ATTR_NAME:
            if c == "=":
                S.st = BEFORE_VAL
            elif c.isspace():
                S.st = AFTER_ATTR
            elif c == ">":
                _close_tag(S)
            elif c == "/":
                S.st = IN_TAG
            else:
                S.attr += c.lower()
            i += 1
            continue
        if st == AFTER_ATTR:
            if c == "=":
                S.st = BEFORE_VAL
            elif c == ">":
                _close_tag(S)
            elif not c.isspace():
                S.st, S.attr = ATTR_NAME, c.lower()
            i += 1
            continue
        if st == BEFORE_VAL:
            S.val, S.val_tainted = "", False
            if c == '"':
                S.st = VAL_DQ
            elif c == "'":
                S.st = VAL_SQ
            elif c == ">":
                _close_tag(S)
            elif not c.isspace():
                S.st = VAL_UQ
                S.val = c
            i += 1
            continue
        if st in (VAL_DQ, VAL_SQ):
            q = '"' if st == VAL_DQ else "'"
            j = text.find(q, i)
            if j < 0:
                S.val += text[i:]
                return
            S.val += text[i:j]
            S.st = IN_TAG
            i = j + 1
            continue
        if st == VAL_UQ:
            if c.isspace():
                S.st = IN_TAG
            elif c == ">":
                _close_tag(S)
            else:
                S.val += c
            i += 1
            continue
        i += 1


def _close_tag(S):
    if not S.is_end and S.tag in RAWTEXT:
        S.st, S.raw_tag = RAW, S.tag
    else:
        S.st = TEXT


# ---------------------------------------------------------------- sanitizer
ALLOWED_TAGS = {"b", "i", "em", "strong", "u", "p", "br", "ul", "ol", "li", "a",
                "blockquote", "code", "pre", "h1", "h2", "h3", "h4", "span", "hr"}
VOID = {"br", "hr"}
DROP_CONTENT = {"script", "style", "iframe", "object", "embed", "template", "svg", "math", "noscript"}


class _Sanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.stack = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in DROP_CONTENT:
            self.skip += 1
            return
        if self.skip or tag not in ALLOWED_TAGS:
            return
        parts = [tag]
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v is not None and url_is_safe(v):
                    parts.append('href="%s"' % escape_text(v))
            parts.append('rel="nofollow noopener noreferrer"')
        self.out.append("<%s>" % " ".join(parts))
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in self.stack and tag not in VOID and self.stack[-1] == tag:
            self.stack.pop()
            self.out.append("</%s>" % tag)

    def handle_endtag(self, tag):
        if tag in DROP_CONTENT:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in self.stack:
            return
        while self.stack:
            t = self.stack.pop()
            self.out.append("</%s>" % t)
            if t == tag:
                break

    def handle_data(self, data):
        if not self.skip:
            self.out.append(escape_text(data))


def sanitize_html(s):
    p = _Sanitizer()
    p.feed(s)
    p.close()
    while p.stack:
        p.out.append("</%s>" % p.stack.pop())
    return "".join(p.out)
