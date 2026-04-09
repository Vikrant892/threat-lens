# --- Build stage ---
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Runtime stage ---
FROM python:3.12-slim

LABEL maintainer="ThreatLens Contributors"

RUN groupadd -r threatlens && useradd -r -g threatlens -s /usr/sbin/nologin threatlens

WORKDIR /app
COPY --from=builder /install /usr/local
COPY threat_lens/ threat_lens/
COPY api.py .

RUN chown -R threatlens:threatlens /app
USER threatlens

ENV PYTHONUNBUFFERED=1 \
    LOG_LEVEL=INFO \
    FEED_AUTO_REFRESH=true \
    FEED_REFRESH_INTERVAL=900

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
