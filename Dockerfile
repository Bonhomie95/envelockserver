# Production image for the Envelock API (FastAPI/uvicorn).
#
#   docker build -t envelock-server ./server
#   docker run -p 8010:8010 --env-file server/.env envelock-server
#
# Managed Postgres/Redis/ClickHouse run separately (see docker-compose.yml for the
# local equivalents). Multi-stage so the runtime image carries no build toolchain.

# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.13-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
# Install into a venv we can copy wholesale into the runtime image.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only what pip needs first, so dependency install is cached across code edits.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.13-slim AS runtime

# Run as a non-root user.
RUN useradd --create-home --uid 10001 envelock
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVELOCK_ENV=production

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --from=build /app/src ./src
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
USER envelock

EXPOSE 8010

# Container-native healthcheck hitting the app's own /health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8010/health').status==200 else 1)" || exit 1

# Bind to $PORT when the platform sets one (Render/Fly/Heroku style), else 8010.
CMD ["sh", "-c", "uvicorn envelock.main:app --host 0.0.0.0 --port ${PORT:-8010}"]
