# syntax=docker/dockerfile:1

# ---- shared base: dependencies only ---------------------------------------
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ---- app: the bundle download service --------------------------------------
FROM base AS app
COPY app ./app
COPY client ./client
RUN useradd --system --uid 10001 app \
    && mkdir -p /data /keys /keys-public /keys-private \
    && chown -R app:app /data /keys /keys-public /keys-private
USER app
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=12 \
  CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2).status==200 else 1)"
CMD ["uvicorn", "app.asgi:app", "--host", "0.0.0.0", "--port", "8000"]

# ---- verify: one-shot tests + build + smoke, reports via exit code ---------
FROM base AS verify
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY app ./app
COPY client ./client
COPY verify ./verify
COPY tests ./tests
COPY pytest.ini ./
CMD ["python", "-m", "verify.run"]
