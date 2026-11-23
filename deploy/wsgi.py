"""Production entry point: gunicorn -c deploy/gunicorn.conf.py deploy.wsgi:app"""
import os
from warden.server import App

app = App(os.environ.get("WARDEN_APP", "/srv/app"))
if app.compile_errors:
    raise SystemExit("\n".join(app.compile_errors))
