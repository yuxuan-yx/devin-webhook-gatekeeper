# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: builder
# WHY a separate build stage: compiling wheels needs toolchains and leaves pip
# caches behind. None of that should exist in the image that faces the
# internet — it inflates the image and widens the attack surface. We build a
# self-contained virtualenv here and copy only that forward.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Dependencies are copied and installed before the source. WHY: the layer cache
# then survives every source-only change, so ordinary code edits rebuild in
# seconds instead of re-resolving the dependency tree.
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    # Unbuffered stdout: without it, our JSON log lines sit in a pipe buffer and
    # arrive late (or not at all on a crash), which is exactly when they matter.
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# curl is needed by HEALTHCHECK below and is the only addition to the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# WHY a non-root user: a webhook receiver is directly reachable from the public
# internet. If it is ever compromised, the process should not be able to modify
# its own code or the OS. --system, no shell, no home.
RUN useradd --system --create-home --shell /usr/sbin/nologin gatekeeper

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=gatekeeper:gatekeeper main.py config.py services.py ./

USER gatekeeper

EXPOSE 8000

# Container-native liveness signal, so the orchestrator can restart a wedged
# process even where no external probe is configured.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

# A single worker, deliberately. The service is I/O bound and does almost no
# work in-process; one asyncio event loop saturates the upstream long before
# CPU matters. One worker also means one httpx connection pool and one set of
# in-flight BackgroundTasks, so a rolling restart has a single, predictable
# drain. Scale out with replicas, not with workers.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
