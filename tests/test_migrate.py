"""PHP -> Warden migration assistant."""
import json
import os
import sqlite3
import tempfile
import unittest
import urllib.parse

from helpers import ROOT, rm, run
from warden.migrate import migrate_source, migrate_tree
from warden.parser import parse
from warden.server import App

H = {"host": "localhost"}


def conv(src):
    out, findings = migrate_source(src, "t.php")
    return out, [(f.sev, f.rule) for f in findings]


class SourceConversion(unittest.TestCase):
    def test_tags_and_basic_code_compile(self):
        out, _ = conv('<?php $a = array(1, 2); foreach ($a as $k => $v) { echo "$k:$v "; } ?><b><?= count($a) ?></b>')
        self.assertTrue(out.startswith("<?wdn "))
        parse(out)
        self.assertEqual(run(out, code=False), "0:1 1:2 <b>2</b>")

    def test_interpolated_sql_parameterized(self):
        out, f = conv('<?php $r = mysqli_query($conn, "SELECT * FROM t WHERE a = \'$x\' AND b = {$y[\'k\']}");')
        self.assertIn('db_query("SELECT * FROM t WHERE a = ? AND b = ?", [$x, $y[\'k\']])', out)
        self.assertIn(("INFO", "sql-parameterized"), f)

    def test_concatenated_sql_parameterized(self):
        out, _ = conv('<?php $r = mysqli_query($c, "SELECT * FROM u WHERE n=\'" . $n . "\' AND id=" . $id);')
        self.assertIn('db_query("SELECT * FROM u WHERE n=? AND id=?", [$n, $id])', out)

    def test_unparameterizable_sql_flagged(self):
        out, f = conv('<?php $r = mysqli_query($c, "SELECT * FROM u ORDER BY " . get_order() . " LIMIT 5");')
        self.assertIn(("HIGH", "sql-concat"), f)

    def test_fetch_loop(self):
        out, _ = conv('<?php while ($row = mysqli_fetch_assoc($res)) { echo $row["a"]; }')
        self.assertIn("foreach ($res as $row)", out)

    def test_pdo_idiom(self):
        out, _ = conv('<?php $st = $pdo->prepare("SELECT * FROM u WHERE id = ?"); $st->execute([$id]); '
                      '$rows = $st->fetchAll(PDO::FETCH_ASSOC); $n = $st->rowCount();')
        self.assertIn('$st = db_query("SELECT * FROM u WHERE id = ?", [$id]);', out)
        self.assertIn("$rows = $st;", out)
        self.assertIn("$n = count($st);", out)

    def test_sessions(self):
        out, _ = conv("<?php session_start(); $_SESSION['u'] = $name; if (isset($_SESSION['u'])) { echo $_SESSION['u']; } "
                      "unset($_SESSION['u']); session_regenerate_id(true);")
        self.assertIn("session_set('u', $name);", out)
        self.assertIn("session_has('u')", out)
        self.assertIn("echo session_get('u');", out)
        self.assertIn("session_delete('u');", out)
        self.assertIn("session_regenerate()", out)
        parse(out)

    def test_location_header(self):
        out, _ = conv('<?php header("Location: index.php"); header(\'Location: /x?id=\' . $id); header("X-A: b");')
        self.assertIn('redirect("index.php")', out)
        self.assertIn("redirect('/x?id=' . $id)", out)
        self.assertIn('header("X-A: b")', out)

    def test_dangerous_calls_removed(self):
        src = '<?php eval($_POST["c"]); system("ls " . $d); $o = unserialize($s); extract($_GET); $x = `id`; include $page;'
        out, f = conv(src)
        for name in ("eval", "system", "unserialize", "extract"):
            self.assertIn('warden_removed("%s"' % name, out)
        self.assertIn('warden_removed("shell")', out)
        self.assertIn('warden_removed("dynamic include")', out)
        self.assertGreaterEqual(sum(1 for s, _ in f if s == "CRITICAL"), 6)
        parse(out)

    def test_static_include_rewritten(self):
        out, _ = conv("<?php require_once __DIR__ . '/lib/util.php'; include('header.php');")
        self.assertIn('include_once "pages/lib/util.wdn";', out)
        self.assertIn('include "pages/header.wdn";', out)

    def test_sort_and_push(self):
        out, _ = conv("<?php sort($a); rsort($b); usort($c, 'cmp'); array_push($d, 5);")
        self.assertIn("$a = sorted($a);", out)
        self.assertIn("$b = sorted($b, true);", out)
        self.assertIn("$c = usorted($c, 'cmp');", out)
        self.assertIn("$d[] = 5;", out)

    def test_flags(self):
        _, f = conv('<?php $h = md5($_POST["password"]); preg_match("/x/", $s); switch ($a) {} '
                    'function f(&$x) {} $y = $$name; class A {} $u = $_FILES["f"];')
        rules = {r for _, r in f}
        for r in ("weak-password-hash", "regex", "switch", "reference-param", "variable-variables", "oop", "uploads"):
            self.assertIn(r, rules)

    def test_strings_comments_untouched(self):
        out, _ = conv("<?php // eval(\"x\") in a comment\n$s = 'system(\"rm\")'; echo $s;")
        self.assertIn("// eval(\"x\") in a comment", out)
        self.assertIn("'system(\"rm\")'", out)

    def test_heredoc(self):
        out, _ = conv('<?php $n = "W"; echo <<<EOT\nHi "$n"\nEOT;\n')
        self.assertEqual(run(out, code=False), 'Hi "W"')


class TreeMigration(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.report = migrate_tree(os.path.join(ROOT, "examples", "php_legacy"), self.out)

    def tearDown(self):
        rm(self.out)

    def test_report(self):
        self.assertEqual(self.report["syntax_errors"], [])
        self.assertEqual(self.report["critical"], 4)
        self.assertGreaterEqual(self.report["high"], 1)  # md5 passwords
        self.assertTrue(os.path.exists(os.path.join(self.out, "MIGRATION_REPORT.md")))
        self.assertTrue(os.path.exists(os.path.join(self.out, "pages", "inc", "_db.wdn")))  # partial is private
        self.assertTrue(os.path.exists(os.path.join(self.out, "public", "style.css")))

    def test_migrated_app_runs_securely(self):
        os.makedirs(os.path.join(self.out, "data"), exist_ok=True)
        con = sqlite3.connect(os.path.join(self.out, "data", "app.db"))
        con.execute("CREATE TABLE products (id TEXT, title TEXT, price TEXT)")
        con.execute("INSERT INTO products VALUES ('1', '<b>Widget</b>', '9.99')")
        con.execute("CREATE TABLE users (name TEXT, pw TEXT)")
        con.execute("INSERT INTO users VALUES ('admin', '5f4dcc3b5aa765d61d8327deb882cf99')")
        con.commit()
        con.close()
        app = App(self.out)
        self.assertEqual(app.compile_errors, [])
        r = app.handle("GET", "/index.php?id=1&name=" + urllib.parse.quote("<script>alert(1)</script>"), H)
        body = r.body.decode()
        self.assertEqual(r.status, 200, body)
        self.assertIn("Welcome &lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertIn("&lt;b&gt;Widget&lt;/b&gt; - 9.99", body)
        r = app.handle("GET", "/index.php?id=" + urllib.parse.quote("1' OR '1'='1"), H)
        self.assertNotIn("Widget", r.body.decode())   # injection returns no rows
        r = app.handle("GET", "/admin.php?page=x", H)
        self.assertEqual(r.status, 400)                # removed dangerous include fails closed
        self.assertEqual(app.handle("GET", "/inc/_db.php", H).status, 404)


if __name__ == "__main__":
    unittest.main()
