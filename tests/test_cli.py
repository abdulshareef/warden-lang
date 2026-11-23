"""Command-line interface end to end."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

from helpers import ROOT, rm


def warden(*args, **kw):
    return subprocess.run([sys.executable, "-m", "warden"] + list(args), cwd=ROOT, capture_output=True,
                          text=True, timeout=60, **kw)


class CLI(unittest.TestCase):
    def test_version_run_check(self):
        self.assertIn("Warden 1.0.0", warden("version").stdout)
        d = tempfile.mkdtemp()
        try:
            f = os.path.join(d, "hello.wdn")
            with open(f, "w") as fh:
                fh.write('<?wdn echo "hi " . (2 + 3);')
            self.assertEqual(warden("run", f).stdout, "hi 5")
            self.assertEqual(warden("check", d).returncode, 0)
            with open(os.path.join(d, "bad.wdn"), "w") as fh:
                fh.write("<?wdn eval('x');")
            r = warden("check", d)
            self.assertEqual(r.returncode, 1)
            self.assertIn("eval() does not exist", r.stdout)
        finally:
            rm(d)

    def test_new_and_serve(self):
        d = tempfile.mkdtemp()
        app = os.path.join(d, "myapp")
        try:
            self.assertEqual(warden("new", app).returncode, 0)
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            p = subprocess.Popen([sys.executable, "-m", "warden", "serve", app, "--port", str(port)], cwd=ROOT,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                body = None
                for _ in range(50):
                    try:
                        body = urllib.request.urlopen("http://127.0.0.1:%d/?name=%%3Cb%%3E" % port, timeout=2).read()
                        break
                    except OSError:
                        time.sleep(0.1)
                self.assertIsNotNone(body)
                self.assertIn(b"Hello, &lt;b&gt;!", body)
                h = urllib.request.urlopen("http://127.0.0.1:%d/api/health" % port, timeout=2).read()
                self.assertIn(b'"status":"ok"', h)
            finally:
                p.terminate()
                p.wait(5)
        finally:
            rm(d)

    def test_migrate_cli(self):
        d = tempfile.mkdtemp()
        try:
            r = warden("migrate", os.path.join(ROOT, "examples", "php_legacy"), os.path.join(d, "out"))
            self.assertEqual(r.returncode, 1)  # critical findings present -> non-zero for CI
            self.assertIn("4 critical call(s) removed", r.stdout)
        finally:
            rm(d)


if __name__ == "__main__":
    unittest.main()
