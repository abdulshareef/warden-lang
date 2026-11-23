"""Command line: warden run|serve|check|migrate|new|version"""

import argparse
import os
import shutil
import sys

from . import __version__
from .errors import WardenError, WardenSyntaxError, SecurityViolation, LimitExceeded


def cmd_run(a):
    from .interp import Interp
    it = Interp(os.path.dirname(os.path.abspath(a.file)))
    code = 0
    try:
        it.run_file(a.file)
    except WardenSyntaxError as e:
        print(e, file=sys.stderr)
        code = 2
    except (WardenError, SecurityViolation, LimitExceeded) as e:
        sys.stdout.write(it.output().s)
        print("\nerror: %s (line %s)" % (e, getattr(e, "line", "?")), file=sys.stderr)
        return 1
    sys.stdout.write(it.output().s)
    return code


def cmd_check(a):
    from .parser import parse
    bad = 0
    targets = []
    for p in a.paths:
        if os.path.isdir(p):
            for d, _, fs in os.walk(p):
                targets += [os.path.join(d, f) for f in fs if f.endswith(".wdn")]
        else:
            targets.append(p)
    for t in sorted(targets):
        try:
            with open(t, encoding="utf-8") as f:
                parse(f.read(), t)
        except WardenSyntaxError as e:
            print(e)
            bad += 1
    print("%d file(s) checked, %d error(s)" % (len(targets), bad))
    return 1 if bad else 0


def cmd_serve(a):
    from .server import serve
    cfg = {}
    if a.debug:
        cfg["debug"] = True
    serve(a.app, a.host, a.port, cfg)
    return 0


def cmd_migrate(a):
    from .migrate import migrate_tree
    report = migrate_tree(a.src, a.out)
    print(report["summary"])
    print("Full report: %s" % os.path.join(a.out, "MIGRATION_REPORT.md"))
    return 1 if report["critical"] else 0


def cmd_new(a):
    skel = os.path.join(os.path.dirname(__file__), "skeleton")
    if os.path.exists(a.dir):
        print("directory exists: %s" % a.dir, file=sys.stderr)
        return 1
    shutil.copytree(skel, a.dir)
    print("Created %s. Start it with: warden serve %s" % (a.dir, a.dir))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="warden", description="Warden secure web language")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a .wdn script from the command line")
    r.add_argument("file")
    r.set_defaults(fn=cmd_run)
    c = sub.add_parser("check", help="syntax-check files or directories")
    c.add_argument("paths", nargs="+")
    c.set_defaults(fn=cmd_check)
    s = sub.add_parser("serve", help="serve a Warden app")
    s.add_argument("app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--debug", action="store_true", help="show error details to localhost only")
    s.set_defaults(fn=cmd_serve)
    m = sub.add_parser("migrate", help="convert a PHP project and produce a security report")
    m.add_argument("src")
    m.add_argument("out")
    m.set_defaults(fn=cmd_migrate)
    n = sub.add_parser("new", help="create a new app skeleton")
    n.add_argument("dir")
    n.set_defaults(fn=cmd_new)
    v = sub.add_parser("version")
    v.set_defaults(fn=lambda a: print("Warden %s" % __version__) or 0)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
