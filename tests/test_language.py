"""Core language semantics."""
import unittest

from helpers import run
from warden.errors import WardenError, WardenSyntaxError


class Basics(unittest.TestCase):
    def test_echo_arith(self):
        self.assertEqual(run('echo 1 + 2 * 3, " ", 10 / 4, " ", 9 / 3, " ", 7 % 3, " ", -7 % 3;'), "7 2.5 3 1 -1")

    def test_concat_precedence_php8(self):
        self.assertEqual(run('echo "a" . 1 + 2;'), "a3")

    def test_variables_and_assign_ops(self):
        self.assertEqual(run('$x = 5; $x += 3; $x -= 1; $x *= 2; $s = "a"; $s .= "b"; echo $x, $s;'), "14ab")

    def test_incdec(self):
        self.assertEqual(run('$i = 1; echo $i++, $i, ++$i, $i--, $i;'), "12332")

    def test_strings_and_escapes(self):
        self.assertEqual(run(r'echo "a\tb\n", ' + r"'c\n';"), "a\tb\nc\\n")

    def test_interpolation(self):
        self.assertEqual(run('$n = "Ann"; $a = ["k" => "v", 0 => "z"]; $i = 0; '
                             'echo "Hi $n {$a[\'k\']} $a[k] $a[0] $a[$i]";'), "Hi Ann v v z z")

    def test_unicode_escape(self):
        self.assertEqual(run(r'echo "\u{263A}";'), "\u263a")

    def test_if_elseif_else(self):
        src = 'function t($x) { if ($x > 5) { return "big"; } elseif ($x > 2) { return "mid"; } else if ($x > 0) { return "small"; } else { return "none"; } } echo t(9), t(3), t(1), t(0);'
        self.assertEqual(run(src), "bigmidsmallnone")

    def test_loops_break_continue(self):
        src = '''$o = "";
        for ($i = 0; $i < 10; $i++) { if ($i == 2) { continue; } if ($i == 5) { break; } $o .= $i; }
        $j = 0; while (true) { $j++; if ($j > 3) { break; } }
        foreach ([1,2,3] as $a) { foreach ([1,2] as $b) { if ($b == 2) { continue 2; } $o .= "-$a"; } }
        echo $o, $j;'''
        self.assertEqual(run(src), "0134-1-2-34")

    def test_foreach_keys(self):
        self.assertEqual(run('foreach (["a" => 1, "b" => 2] as $k => $v) { echo "$k=$v;"; }'), "a=1;b=2;")

    def test_alt_syntax(self):
        src = '<?wdn $xs = [1,2]; ?><?wdn foreach ($xs as $x): ?>[<?= $x ?>]<?wdn endforeach; ?>' \
              '<?wdn if (count($xs) == 3): ?>three<?wdn elseif (count($xs) == 2): ?>two<?wdn else: ?>other<?wdn endif; ?>' \
              '<?wdn $n = 0; while ($n < 2): $n++; ?>w<?wdn endwhile; ?><?wdn for ($i=0;$i<2;$i++): ?>f<?wdn endfor; ?>'
        self.assertEqual(run(src, code=False), "[1][2]twowwff")

    def test_template_newline_swallow(self):
        self.assertEqual(run("<?wdn $a = 1; ?>\nX<?= $a ?>\nY", code=False), "X1Y")

    def test_functions_defaults_recursion_hoisting(self):
        src = 'echo f(5), g(), g("x"); function f($n) { return $n <= 1 ? 1 : $n * f($n - 1); } function g($s = "d") { return $s; }'
        self.assertEqual(run(src), "120dx")

    def test_closures_capture_by_value(self):
        src = '$k = 2; $m = function($x) use ($k) { return $x * $k; }; $k = 100; echo $m(5); ' \
              '$add = function($a, $b) { return $a + $b; }; echo call_user_func($add, 1, 2);'
        self.assertEqual(run(src), "103")

    def test_type_hints_ignored(self):
        self.assertEqual(run('function f(int $a, ?string $b = null): string { return "ok"; } echo f(1);'), "ok")

    def test_casts(self):
        self.assertEqual(run('echo (int)"42abc", (float)"1.5", (string)7, (bool)"0" ? "T" : "F";'), "421.57T")

    def test_ternary_coalesce(self):
        self.assertEqual(run('$a = null; echo $a ?? "d", $undefined ?? "u", 0 ?: "e", true ? "y" : "n";'), "duey")

    def test_coalesce_assign(self):
        self.assertEqual(run('$c = []; $c["x"] ??= 5; $c["x"] ??= 9; echo $c["x"];'), "5")

    def test_isset_empty_unset(self):
        src = '$a = ["k" => 1, "n" => null]; echo isset($a["k"]) ? 1 : 0, isset($a["n"]) ? 1 : 0, isset($zz) ? 1 : 0, ' \
              'empty($a["missing"]) ? 1 : 0; unset($a["k"]); echo count($a);'
        self.assertEqual(run(src), "10011")

    def test_try_catch_finally_throw(self):
        src = 'try { throw "boom"; } catch (Exception $e) { echo "caught:" . $e; } finally { echo "|fin"; }' \
              'try { $x = 1 / 0; } catch ($e) { echo "|", $e; }'
        self.assertEqual(run(src), "caught:boom|fin|division by zero")

    def test_constants(self):
        self.assertEqual(run('const A = 3; define("B", 4); echo A + B, PHP_EOL === "\\n" ? "ok" : "no";'), "7ok")

    def test_exit(self):
        self.assertEqual(run('echo "a"; exit("b"); echo "c";'), "ab")

    def test_comments(self):
        self.assertEqual(run('# hash\n// line\n/* block\n */ echo "ok";'), "ok")


class Arrays(unittest.TestCase):
    def test_value_semantics(self):
        src = '$a = [1, [2, 3]]; $b = $a; $b[0] = 9; $b[1][0] = 8; echo $a[0], $a[1][0], $b[0], $b[1][0];'
        self.assertEqual(run(src), "1298")

    def test_function_args_copied(self):
        self.assertEqual(run('function m($x) { $x[] = 4; return count($x); } $a = [1]; echo m($a), count($a);'), "21")

    def test_nested_autovivify_and_append(self):
        src = '$m = []; $m["a"]["b"][] = 1; $m["a"]["b"][] = 2; echo count($m["a"]["b"]), json_encode($m);'
        self.assertEqual(run(src), '2{"a":{"b":[1,2]}}')

    def test_php_key_normalisation(self):
        self.assertEqual(run('$a = []; $a["5"] = "x"; $a[] = "y"; echo json_encode(array_keys($a));'), "[5,6]")

    def test_array_functions(self):
        src = '''$a = [3, 1, 2];
        echo implode(",", sorted($a)), "|", implode(",", sorted($a, true)), "|",
             implode(",", array_map(function($x) { return $x * 2; }, $a)), "|",
             implode(",", array_values(array_filter($a, function($x) { return $x > 1; }))), "|",
             array_sum($a), "|", in_array(2, $a) ? "y" : "n", "|", in_array("2", $a) ? "y" : "n", "|",
             implode(",", array_merge([1], [2, 3])), "|", count(range(1, 10)), "|", max($a), min(4, 2, 8), "|",
             implode(",", array_slice([1,2,3,4], 1, 2)), "|", array_search(2, $a), "|",
             implode(",", usorted($a, function($x, $y) { return $y - $x; }));'''
        self.assertEqual(run(src), "1,2,3|3,2,1|6,2,4|3,2|6|y|n|1,2,3|10|32|2,3|2|3,2,1")

    def test_foreach_snapshot(self):
        self.assertEqual(run('$a = [1, 2]; foreach ($a as $v) { $a[] = $v; } echo count($a);'), "4")

    def test_array_union(self):
        self.assertEqual(run('echo json_encode(["a" => 1] + ["a" => 2, "b" => 3]);'), '{"a":1,"b":3}')


class Strings(unittest.TestCase):
    def test_string_functions(self):
        src = '''echo strlen("héllo"), strtoupper("ab"), ucfirst("x"), trim("  t  "), "|", substr("abcdef", 1, 3),
        substr("abcdef", -2), "|", str_replace("a", "b", "aaa"), "|", strpos("abc", "c"),
        strpos("abc", "z") === false ? "F" : "T", "|", implode("-", explode(",", "a,b,c")), "|",
        sprintf("%s=%d %05.2f %%", "x", 42, 3.14159), "|", str_pad("7", 3, "0", STR_PAD_LEFT), "|",
        number_format(1234567.891, 2), "|", ucwords("hello big world"), "|", str_repeat("ab", 3),
        "|", strrev("abc"), "|", str_contains("haystack", "st") ? 1 : 0;'''
        self.assertEqual(run(src), "5ABXt|bcdef|bbb|2F|a-b-c|x=42 03.14 %|007|1,234,567.89|Hello Big World|ababab|cba|1")

    def test_string_offsets(self):
        self.assertEqual(run('$s = "abc"; echo $s[0], $s[-1];'), "ac")

    def test_json_roundtrip(self):
        src = '$d = json_decode("{\\"a\\":[1,2,{\\"b\\":null}],\\"c\\":true}"); echo count($d["a"]), $d["c"] ? "T" : "F", json_encode($d);'
        self.assertEqual(run(src), '3T{"a":[1,2,{"b":null}],"c":true}')

    def test_json_html_safe(self):
        self.assertEqual(run('echo json_encode(["x" => "</script><b>&\'"]);'),
                         '{"x":"\\u003c/script\\u003e\\u003cb\\u003e\\u0026\\u0027"}')

    def test_date(self):
        self.assertEqual(run('echo date("Y-m-d H:i:s D N", 0);'), "1970-01-01 00:00:00 Thu 4")

    def test_hashes(self):
        self.assertEqual(run('echo md5("a"), " ", hash("sha256", "");'),
                         "0cc175b9c0f1b6a831c399e269772661 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


class Errors(unittest.TestCase):
    def expect(self, src, msg):
        with self.assertRaises(WardenError) as cm:
            run(src)
        self.assertIn(msg, cm.exception.msg)

    def test_undefined_variable(self):
        self.expect("echo $nope;", "undefined variable")

    def test_undefined_key(self):
        self.expect('$a = []; echo $a["x"];', "undefined array key")

    def test_undefined_function(self):
        self.expect("nope();", "undefined function")

    def test_wrong_arg_count(self):
        self.expect("function f($a) {} f(1, 2);", "at most 1")
        self.expect("function g($a) {} g();", "missing argument")

    def test_cannot_redefine_builtin(self):
        self.expect('function password_verify($a, $b) { return true; }', "cannot redefine built-in")

    def test_superglobals_read_only(self):
        self.expect('$_GET = [];', "read-only")

    def test_syntax_errors(self):
        for src in ['echo "unterminated;', 'if (1) { echo 1;', 'echo 1 +;', '$x = ;']:
            with self.assertRaises(WardenSyntaxError):
                run(src)


if __name__ == "__main__":
    unittest.main()
