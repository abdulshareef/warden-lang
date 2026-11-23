"""Attack-vector tests for the runtime (no HTTP)."""
import os
import unittest

from helpers import run, tmp_app, rm, Limits
from warden.errors import WardenError, WardenSyntaxError, SecurityViolation, LimitExceeded
from warden.htmlctx import render_html, sanitize_html, url_is_safe
from warden.tstr import TStr, join
from warden.interp import Interp
from warden.context import Context

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "</textarea><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "`-alert(1)-`",
    "<a href=\"javascript:alert(1)\">x</a>",
    "\" autofocus onfocus=\"alert(1)",
    "' onmouseover='alert(1)",
    "<!--<script>-->",
    "&lt;script&gt;",
]


def T(s):
    return TStr.tainted(s)


def P(s):
    return TStr.plain(s)


def page(*parts):
    return render_html(join(parts))


class TaintTracking(unittest.TestCase):
    def test_concat_slice_preserve_taint(self):
        s = P("ab").concat(T("XY")).concat(P("cd"))
        self.assertEqual(s.t, ((2, 4, "u"),))
        self.assertEqual(s.slice(3, 5).t, ((0, 1, "u"),))
        self.assertEqual(s.slice(0, 2).t, ())

    def test_string_functions_preserve_taint(self):
        it = Interp()
        it.superglobals["_GET"].set(P("q"), T("<b>"))
        it.run_source('<?wdn echo strtoupper(trim(" " . $_GET["q"] . " ")), substr($_GET["q"], 1), '
                      'str_replace("x", $_GET["q"], "axa"), implode(",", explode("b", $_GET["q"])), '
                      'sprintf("[%s]", $_GET["q"]), "{$_GET[\'q\']}";')
        out = render_html(it.output())
        self.assertNotIn("<b>", out)
        self.assertNotIn("<B>", out)
        self.assertIn("&lt;B&gt;", out)


class XSS(unittest.TestCase):
    def test_text_context(self):
        for p in XSS_PAYLOADS:
            out = page(P("<div>"), T(p), P("</div>"))
            self.assertNotRegex(out, r"<(script|img|svg|iframe|a)\b", p)

    def test_double_and_single_quoted_attribute(self):
        for p in XSS_PAYLOADS:
            for q in ('"', "'"):
                out = page(P("<input value=%s" % q), T(p), P("%s>" % q))
                inner = out[len("<input value=") + 1:-2]
                self.assertNotIn(q, inner, p)
                self.assertNotIn("<", inner)

    def test_textarea_and_title(self):
        out = page(P("<textarea>"), T("</textarea><script>x</script>"), P("</textarea>"))
        self.assertEqual(out.count("<script"), 0)

    def test_url_scheme_blocked(self):
        for bad in ["javascript:alert(1)", " JaVaScRiPt:alert(1)", "java\tscript:alert(1)",
                    "data:text/html,<script>", "vbscript:x", "&#106;avascript:alert(1)", "//evil.com", "\\\\evil.com"]:
            out = page(P('<a href="'), T(bad), P('">x</a>'))
            self.assertIn("#blocked-unsafe-url", out, bad)
        for good in ["https://example.com/?a=1&b=2", "/path", "page?x=1", "mailto:a@b.c", "#top"]:
            out = page(P('<a href="'), T(good), P('">x</a>'))
            self.assertNotIn("blocked", out, good)

    def test_url_after_trusted_prefix_is_fine(self):
        out = page(P('<a href="/search?q='), T("javascript:alert(1)"), P('">x</a>'))
        self.assertNotIn("blocked", out)
        self.assertIn('/search?q=javascript:alert(1)', out)

    def test_trusted_javascript_prefix_with_untrusted_suffix_refused(self):
        with self.assertRaises(SecurityViolation):
            page(P('<a href="javascript:go(\''), T("x"), P('\')">x</a>'))

    def test_script_block_refused(self):
        with self.assertRaises(SecurityViolation):
            page(P("<script>var x = '"), T("';alert(1);//"), P("';</script>"))
        with self.assertRaises(SecurityViolation):
            page(P("<style>body{color:"), T("red}"), P("}</style>"))

    def test_after_script_block_ok(self):
        out = page(P("<script src=/a.js></script><p>"), T("<b>"), P("</p>"))
        self.assertIn("&lt;b&gt;", out)

    def test_event_handler_and_style_refused(self):
        for attr in ("onclick", "onmouseover", "style", "srcdoc"):
            with self.assertRaises(SecurityViolation):
                page(P('<div %s="' % attr), T("x"), P('">'))

    def test_unquoted_attribute_refused(self):
        with self.assertRaises(SecurityViolation):
            page(P("<input value="), T("x onfocus=alert(1)"), P(">"))

    def test_tag_and_attribute_name_positions_refused(self):
        with self.assertRaises(SecurityViolation):
            page(P("<"), T("script"), P(">"))
        with self.assertRaises(SecurityViolation):
            page(P("<div "), T("onclick"), P('="x">'))

    def test_comment_context(self):
        out = page(P("<!-- "), T("--><script>alert(1)</script>"), P(" -->"))
        self.assertNotIn("<script", out)

    def test_trusted_markup_untouched(self):
        self.assertEqual(page(P("<b>bold</b>")), "<b>bold</b>")

    def test_htmlspecialchars_no_double_escape(self):
        out = run('echo htmlspecialchars($_GET["q"]);', get={"q": "<b>&"})
        self.assertEqual(out, "&lt;b&gt;&amp;")

    def test_nl2br_keeps_br_trusted(self):
        out = run('echo nl2br($_GET["q"]);', get={"q": "a\n<i>"})
        self.assertEqual(out, "a<br>\n&lt;i&gt;")

    def test_superglobal_keys_tainted(self):
        out = run('foreach ($_GET as $k => $v) { echo $k; }', get={"<script>": "1"})
        self.assertEqual(out, "&lt;script&gt;")

    def test_sanitizer(self):
        dirty = ('<p onclick="x">Hi <b>there</b><script>alert(1)</script><a href="javascript:alert(1)">j</a>'
                 '<a href="https://ok.com">ok</a><img src=x onerror=alert(1)><svg><g onload=alert(1)></g></svg>'
                 '<style>*{}</style><iframe src=//evil></iframe>')
        clean = sanitize_html(dirty)
        for bad in ("onclick", "<script", "javascript:", "<img", "onerror", "<svg", "onload", "<style", "<iframe"):
            self.assertNotIn(bad, clean)
        self.assertIn('<a href="https://ok.com" rel="nofollow noopener noreferrer">ok</a>', clean)
        self.assertIn("<b>there</b>", clean)

    def test_taint_kinds_in_html(self):
        # escaped text is re-encoded for its real context, never double-escaped
        self.assertEqual(run('echo "<p title=\\"" . htmlspecialchars($_GET["q"]) . "\\">" . htmlspecialchars($_GET["q"]) . "</p>";',
                             get={"q": "\"<x>'"}), '<p title="&quot;&lt;x&gt;&#x27;">&quot;&lt;x&gt;&#x27;</p>')
        # sanitized markup renders as markup in text, but is escaped inside an attribute
        self.assertEqual(run('echo "<div>" . html_sanitize($_GET["q"]) . "</div>";', get={"q": "<b>hi</b><script>x</script>"}),
                         "<div><b>hi</b></div>")
        out = run('echo "<input value=\\"" . html_sanitize($_GET["q"]) . "\\">";', get={"q": "<b>hi</b>"})
        self.assertEqual(out, '<input value="&lt;b&gt;hi&lt;/b&gt;">')
        # escaping does not make data safe inside <script>
        with self.assertRaises(SecurityViolation):
            run('echo "<script>var a = \'" . htmlspecialchars($_GET["q"]) . "\';</script>";', get={"q": "x"})
        # escaped javascript: URL is still caught
        self.assertIn("#blocked", run('echo "<a href=\\"" . htmlspecialchars($_GET["q"]) . "\\">x</a>";',
                                      get={"q": "javascript:alert(1)"}))

    def test_date_format_laundering(self):
        out = run('echo date($_GET["f"], 0);', get={"f": "\\<\\s\\c\\r\\i\\p\\t\\>"})
        self.assertEqual(out, "&lt;script&gt;")

    def test_meta_refresh_and_base_refused(self):
        with self.assertRaises(SecurityViolation):
            page(P('<meta http-equiv="refresh" content="0;url='), T("https://evil.com"), P('">'))
        with self.assertRaises(SecurityViolation):
            page(P('<base href="'), T("https://evil.com/"), P('">'))

    def test_url_is_safe(self):
        self.assertFalse(url_is_safe("jav&#x09;ascript:alert(1)"))
        self.assertTrue(url_is_safe("https://a.b"))


class SQLInjection(unittest.TestCase):
    def setUp(self):
        self.d = tmp_app({})
        self.it = Interp(self.d, None, Context(self.d))
        self.it.run_source('<?wdn db_exec("CREATE TABLE u (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)");'
                           'db_exec("INSERT INTO u (name, secret) VALUES (?, ?)", ["alice", "s1"]);'
                           'db_exec("INSERT INTO u (name, secret) VALUES (?, ?)", ["bob", "s2"]);')

    def tearDown(self):
        self.it.ctx.close()
        rm(self.d)

    def go(self, src, q):
        self.it.out = []
        self.it.superglobals["_GET"].set(P("q"), T(q))
        self.it.run_source("<?wdn " + src)
        return self.it.output().s

    def test_concatenated_sql_blocked(self):
        for q in ["' OR '1'='1", "1; DROP TABLE u", "x"]:
            with self.assertRaises(SecurityViolation):
                self.go('db_query("SELECT * FROM u WHERE name = \'" . $_GET["q"] . "\'");', q)

    def test_interpolated_sql_blocked(self):
        with self.assertRaises(SecurityViolation):
            self.go('db_query("SELECT * FROM u WHERE name = \'{$_GET[\'q\']}\'");', "' OR 1=1 --")

    def test_taint_survives_transformations(self):
        for expr in ['strtolower($_GET["q"])', 'trim($_GET["q"])', 'substr($_GET["q"], 0)',
                     'implode(",", [$_GET["q"]])', 'sprintf("%s", $_GET["q"])', 'base64_decode(base64_encode($_GET["q"]))',
                     'warden_noescape($_GET["q"])', 'str_replace("\'", "\'\'", $_GET["q"])']:
            with self.assertRaises(SecurityViolation, msg=expr):
                self.go('db_query("SELECT * FROM u WHERE name = \'" . %s . "\'");' % expr, "' OR '1'='1")

    def test_html_escaping_does_not_launder_into_sql(self):
        # htmlspecialchars() makes data safe for HTML, not for SQL: "1 OR 1=1" has nothing to escape
        for expr in ['htmlspecialchars($_GET["q"])', 'html_sanitize($_GET["q"])', 'strip_tags($_GET["q"])',
                     'date($_GET["q"])', 'str_pad("1", 9, $_GET["q"])', 'number_format(1000, 0, ".", $_GET["q"])']:
            with self.assertRaises(SecurityViolation, msg=expr):
                self.go('db_query("SELECT * FROM u WHERE id = " . %s);' % expr, "1 OR 1=1")

    def test_parameterized_is_safe(self):
        out = self.go('echo count(db_query("SELECT * FROM u WHERE name = ?", [$_GET["q"]]));', "' OR '1'='1")
        self.assertEqual(out, "0")
        out = self.go('echo db_one("SELECT secret FROM u WHERE name = :n", ["n" => $_GET["q"]])["secret"];', "alice")
        self.assertEqual(out, "s1")

    def test_int_conversion_clears_taint(self):
        out = self.go('$id = int($_GET["q"]); echo count(db_query("SELECT * FROM u WHERE id = " . $id));', "1")
        self.assertEqual(out, "1")
        with self.assertRaises(WardenError):
            self.go('$id = int($_GET["q"]);', "1 OR 1=1")

    def test_stacked_queries_rejected(self):
        with self.assertRaises(WardenError):
            self.go('db_exec("SELECT 1; DROP TABLE u");', "")
        self.assertEqual(self.go('echo db_value("SELECT count(*) FROM u");', ""), "2")

    def test_attach_denied(self):
        with self.assertRaises(WardenError):
            self.go('db_exec("ATTACH DATABASE \'/tmp/x.db\' AS x");', "")

    def test_db_rows_are_tainted_stored_xss(self):
        self.go('db_exec("INSERT INTO u (name, secret) VALUES (?, ?)", [$_GET["q"], "s"]);', "<script>alert(1)</script>")
        self.it.out = []
        self.it.run_source('<?wdn foreach (db_query("SELECT name FROM u") as $r) { echo "<li>" . $r["name"] . "</li>"; }')
        out = render_html(self.it.output())
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)
        with self.assertRaises(SecurityViolation):  # second-order SQLi
            self.go('$n = db_value("SELECT name FROM u WHERE id = 3"); db_query("SELECT * FROM u WHERE name = \'" . $n . "\'");', "")


class TypeJuggling(unittest.TestCase):
    def test_no_loose_comparison_bugs(self):
        cases = ['"0e123" == "0e456"', '"abc" == 0', '"1" == 1', 'null == false', '"" == null', '[] == false',
                 '"1e3" == "1000"', '" 1" == "1"', '0 == "a"', '"0" == false']
        for c in cases:
            self.assertEqual(run("echo (%s) ? 'T' : 'F';" % c), "F", c)

    def test_magic_hash_auth_bypass(self):
        self.assertEqual(run('echo md5("240610708") == md5("QNKCDZO") ? "bypass" : "safe";'), "safe")

    def test_strict_arithmetic(self):
        for src in ['echo "5" + 1;', 'echo [] + 1;', 'echo null + 1;', 'echo true + 1;']:
            with self.assertRaises(WardenError):
                run(src)

    def test_integer_overflow_is_error(self):
        with self.assertRaises(WardenError):
            run("echo PHP_INT_MAX + 1;")
        with self.assertRaises(WardenError):
            run("echo PHP_INT_MAX * 2;")
        with self.assertRaises(WardenError):
            run("echo pow(2, 64);")

    def test_strict_int_parse(self):
        self.assertEqual(run('echo int("42");'), "42")
        for bad in ['"42abc"', '"0x1A"', '"1e3"', '""', '"9999999999999999999999"']:
            with self.assertRaises(WardenError, msg=bad):
                run("echo int(%s);" % bad)
        self.assertEqual(run('echo int("x", -1);'), "-1")

    def test_zero_string_truthy(self):
        self.assertEqual(run('echo "0" ? "T" : "F";'), "T")


class DangerousFeaturesAbsent(unittest.TestCase):
    def test_no_eval_exec(self):
        for f in ["eval", "system", "exec", "shell_exec", "passthru", "popen", "proc_open", "unserialize",
                  "extract", "assert", "create_function", "preg_replace", "mail", "curl_exec", "fsockopen",
                  "file", "fopen", "unlink", "include_path", "phpinfo"]:
            with self.assertRaises((WardenError, WardenSyntaxError), msg=f):
                run('%s("id");' % f)

    def test_backtick_rejected(self):
        with self.assertRaises(WardenSyntaxError):
            run("echo `id`;")

    def test_variable_variables_rejected(self):
        with self.assertRaises(WardenSyntaxError):
            run('$a = "b"; echo $$a;')

    def test_objects_and_references_rejected(self):
        for src in ['$o = new Foo();', '$a->b();', 'Foo::bar();', '$b = &$a;', 'function f(&$x) {}', 'global $x;',
                    'class A {}']:
            with self.assertRaises(WardenSyntaxError, msg=src):
                run(src)

    def test_dynamic_call_with_tainted_name_blocked(self):
        with self.assertRaises(SecurityViolation):
            run('$f = $_GET["f"]; $f("x");', get={"f": "strtoupper"})
        with self.assertRaises(SecurityViolation):
            run('call_user_func($_GET["f"], "x");', get={"f": "session_destroy"})
        self.assertEqual(run('$f = "strtoupper"; echo $f("x");'), "X")

    def test_format_string_from_user_blocked(self):
        with self.assertRaises(SecurityViolation):
            run('echo sprintf($_GET["f"], 1);', get={"f": "%s%s%s"})

    def test_env_restricted(self):
        with self.assertRaises(SecurityViolation):
            run('echo env("PATH");')


class IncludeAndFiles(unittest.TestCase):
    def setUp(self):
        self.d = tmp_app({"lib/a.wdn": '<?wdn function libf() { return "lib"; }',
                          "data/notes.txt": "hello", "secret.txt": "TOPSECRET"})

    def tearDown(self):
        rm(self.d)

    def test_include_ok(self):
        self.assertEqual(run('include "lib/a.wdn"; include_once "lib/a.wdn"; echo libf();', root=self.d), "lib")

    def test_dynamic_include_is_syntax_error(self):
        with self.assertRaises(WardenSyntaxError):
            run('include $_GET["p"];', root=self.d)
        with self.assertRaises(WardenSyntaxError):
            run('include "lib/" . "a.wdn";', root=self.d)

    def test_include_traversal(self):
        for p in ["../etc/passwd.wdn", "/etc/passwd.wdn", "lib/../../x.wdn", "secret.txt"]:
            with self.assertRaises(SecurityViolation, msg=p):
                run('include "%s";' % p, root=self.d)

    def test_symlink_escape(self):
        os.symlink("/etc", os.path.join(self.d, "lib", "etc"))
        with self.assertRaises(SecurityViolation):
            run('include "lib/etc/x.wdn";', root=self.d)

    def test_file_sandbox(self):
        it = Interp(self.d, None, Context(self.d))
        it.run_source('<?wdn echo file_read("notes.txt"); file_write("sub/out.txt", "x"); echo file_exists("sub/out.txt") ? "Y" : "N";')
        self.assertEqual(it.output().s, "helloY")
        for p in ["../secret.txt", "/etc/passwd", "sub/../../secret.txt", "http://169.254.169.254/latest/meta-data/",
                  "file:///etc/passwd", "php://filter/resource=x"]:
            with self.assertRaises(SecurityViolation, msg=p):
                Interp(self.d, None, Context(self.d)).run_source('<?wdn file_read("%s");' % p)

    def test_file_read_is_tainted(self):
        it = Interp(self.d, None, Context(self.d))
        it.run_source('<?wdn file_write("x.html", "<script>"); echo file_read("x.html");')
        self.assertEqual(render_html(it.output()), "&lt;script&gt;")


class ResourceLimits(unittest.TestCase):
    def test_infinite_loop(self):
        with self.assertRaises(LimitExceeded):
            run("while (true) { }", limits=Limits(max_steps=100_000))

    def test_deep_recursion(self):
        with self.assertRaises(LimitExceeded):
            run("function f($n) { return f($n + 1); } f(0);")

    def test_string_bomb(self):
        with self.assertRaises(LimitExceeded):
            run('$s = "x"; for ($i = 0; $i < 40; $i++) { $s = $s . $s; }', limits=Limits(max_str=1024 * 1024))
        with self.assertRaises(LimitExceeded):
            run('echo str_repeat("x", 100000000);')

    def test_array_bomb(self):
        with self.assertRaises(LimitExceeded):
            run("$a = []; while (true) { $a[] = 1; }", limits=Limits(max_array=10_000))

    def test_output_bomb(self):
        with self.assertRaises(LimitExceeded):
            run('while (true) { echo "xxxxxxxxxx"; }', limits=Limits(max_output=10_000))

    def test_parser_nesting_bomb(self):
        with self.assertRaises((WardenSyntaxError, LimitExceeded)):
            run("echo " + "(" * 5000 + "1" + ")" * 5000 + ";")

    def test_json_nesting_bomb(self):
        self.assertEqual(run('echo json_decode(str_repeat("[", 100000) . str_repeat("]", 100000)) === null ? "null" : "x";'), "null")

    def test_limits_not_catchable(self):
        with self.assertRaises(LimitExceeded):
            run("try { while (true) {} } catch ($e) { echo 'swallowed'; }", limits=Limits(max_steps=10_000))
        with self.assertRaises(SecurityViolation):
            run('try { db_query("SELECT " . $_GET["q"]); } catch ($e) { echo "swallowed"; }', get={"q": "1"})


class Passwords(unittest.TestCase):
    def test_hash_verify(self):
        out = run('$h = password_hash("correct horse"); echo password_verify("correct horse", $h) ? "Y" : "N", '
                  'password_verify("wrong", $h) ? "Y" : "N", str_starts_with($h, \'$scrypt$\') ? "S" : "-", '
                  'password_hash("a") === password_hash("a") ? "same" : "salted";')
        self.assertEqual(out, "YNSsalted")

    def test_malformed_hashes(self):
        for h in ["", "abc", "$scrypt$n=99999999,r=8,p=1$AAAA$AAAA", "$1$md5crypt$x"]:
            self.assertEqual(run('echo password_verify("x", "%s") ? "Y" : "N";' % h.replace("$", "\\$")), "N")

    def test_hash_equals_and_tokens(self):
        out = run('echo hash_equals("abc", "abc") ? 1 : 0, hash_equals("abc", "abd") ? 1 : 0, strlen(random_token(16)), '
                  'random_token() !== random_token() ? "u" : "d";')
        self.assertEqual(out, "1032u")


class XSSFuzz(unittest.TestCase):
    """Property test: random hostile input in every quoted context never creates markup."""

    def test_fuzz_contexts(self):
        import random
        from html.parser import HTMLParser
        rnd = random.Random(1337)
        alphabet = list("<>\"'`=/ &;#:\\\n\t()-!?[]{}") + ["script", "onerror", "javascript:", "&#x22;", "&quot;",
                                                         "-->", "<!--", "</", "svg", "img", "\x00", "\u2028", "data:"]
        templates = [
            ("<div>", "</div>"), ('<a title="', '">x</a>'), ("<a title='", "'>x</a>"),
            ('<a href="', '">x</a>'), ('<img src="', '">'), ("<textarea>", "</textarea>"),
            ("<!-- ", " -->"), ('<input value="', '" name="n">'),
        ]

        class Collect(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=True)
                self.tags, self.attrs = [], []

            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
                self.attrs += [k for k, _ in attrs]

        for i in range(3000):
            payload = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 25)))
            pre, post = rnd.choice(templates)
            out = page(P(pre), T(payload), P(post))
            base, got = Collect(), Collect()
            base.feed(pre + "SAFE" + post)
            got.feed(out)
            self.assertEqual(got.tags, base.tags, (pre, payload, out))
            self.assertEqual(got.attrs, base.attrs, (pre, payload, out))
            if "href" in pre or "src" in pre:
                v = out[len(pre):len(out) - len(post)]
                self.assertTrue(url_is_safe(v) or v == "#blocked-unsafe-url", (payload, v))


if __name__ == "__main__":
    unittest.main()
