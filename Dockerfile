# Security Control Center — SAST (Semgrep) + secret scanning (Gitleaks) + benchmark
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Runtime deps: git es necesario para los clones endurecidos; curl solo en build.
ARG GITLEAKS_VERSION=8.21.2
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates tar \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer.py benchmark_service.py api_server.py ./
COPY rules/ rules/
COPY static/ static/
COPY bench/ bench/

RUN useradd --create-home appuser \
    && mkdir -p /app/storage/analyses /app/storage/benchmark \
    && chown -R appuser:appuser /app
USER appuser

ENV HOST=0.0.0.0 \
    PORT=5000 \
    MAX_CONCURRENT_ANALYSES=2 \
    RATE_LIMIT_PER_MINUTE=30

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s' % os.getenv('PORT', '5000'), timeout=4)" || exit 1

CMD ["python", "api_server.py"]
