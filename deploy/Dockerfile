FROM python:3.13-slim
RUN useradd --system --uid 10001 warden && pip install --no-cache-dir gunicorn==23.0.0
WORKDIR /srv/warden
COPY warden ./warden
COPY deploy ./deploy
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir . && python -c "import warden"
# your application
COPY app /srv/app
RUN mkdir -p /srv/app/data && chown -R warden:warden /srv/app/data
USER warden
ENV WARDEN_APP=/srv/app PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
CMD ["gunicorn", "-c", "deploy/gunicorn.conf.py", "--bind", "0.0.0.0:8080", "deploy.wsgi:app"]
