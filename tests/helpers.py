import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden.interp import Interp, Limits          # noqa: E402
from warden.htmlctx import render_html             # noqa: E402
from warden.tstr import TStr                       # noqa: E402
from warden.values import BArray                   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(src, limits=None, root=None, get=None, code=True, render=True):
    """Run Warden code; return rendered output (HTML-context encoded)."""
    it = Interp(root or tempfile.gettempdir(), limits)
    if get:
        it.superglobals["_GET"] = BArray.from_pairs((TStr.tainted(k), TStr.tainted(v)) for k, v in get.items())
    it.run_source(("<?wdn " + src) if code else src, "test.wdn")
    out = it.output()
    return render_html(out) if render else out.s


def tmp_app(files):
    d = tempfile.mkdtemp(prefix="warden-test-")
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
    return d


def rm(d):
    shutil.rmtree(d, ignore_errors=True)
