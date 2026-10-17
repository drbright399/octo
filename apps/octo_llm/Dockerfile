# octo-llm — Layer 2 LLM sibling container.
#
# One OCTO core per bundle, and the agent is the analyst's partner:
# octo-llm is the OPTIONAL intelligence-augmentation sibling to
# octo-core. It must NEVER be load-bearing — octo-core falls back to
# heuristic-only behavior when this service is unhealthy. See the
# slice 1 README.
#
# Build from the repository root:
#   docker build -f apps/octo_llm/Dockerfile -t athena/octo-llm:v0.1 .
#
# Run in stub mode (slice 1 — no model required):
#   docker run --rm -p 8101:8101 athena/octo-llm:v0.1
#
# Slice 2 wires llama-cpp; the runtime invocation will gain:
#   -e OCTO_LLM_BACKEND=llama-cpp \
#   -v /opt/octo-llm/models:/var/lib/octo-llm/models:ro

FROM python:3.12-slim AS base

# Non-root user. Inference reads model files; no privilege needed.
RUN groupadd --system --gid 1000 octo-llm \
    && useradd --system --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin octo-llm

# Model weights live here; volume-mount in slice 2 deploys.
RUN mkdir -p /var/lib/octo-llm/models \
    && chown -R octo-llm:octo-llm /var/lib/octo-llm

WORKDIR /app

# System deps: tini for signal forwarding (graceful shutdown on docker
# stop) + the toolchain llama-cpp-python compiles against. There is no
# prebuilt wheel for the pinned version on PyPI, so pip builds llama.cpp
# from source → it needs a C/C++ compiler + cmake.
# (Future optimization: multi-stage build to keep the toolchain out of
# the runtime image.)
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        tini build-essential cmake \
    && rm -rf /var/lib/apt/lists/*

# Install runtime deps before code copy so dep changes don't bust the
# code-layer cache.
COPY apps/octo_llm/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Project layout: COPY only what we need so the image doesn't carry
# octo-core, athena/web, or test fixtures.
COPY apps/__init__.py /app/apps/__init__.py
COPY apps/octo_llm /app/apps/octo_llm

# Strip tests + caches from the image so they're not surface area in
# production.
RUN find /app/apps/octo_llm -type d \( -name tests -o -name __pycache__ \) -exec rm -rf {} + 2>/dev/null || true

USER octo-llm:octo-llm

ENV OCTO_LLM_BACKEND=stub \
    OCTO_LLM_MODEL_PATH=/var/lib/octo-llm/models/granite-3b-q4.gguf \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

# octo-core reaches us on the docker network at this port. The host
# port is not exposed publicly — the auth-proxy + Console layer have
# no business calling octo-llm directly.
EXPOSE 8101

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["uvicorn", "apps.octo_llm.server:app", \
     "--host", "0.0.0.0", \
     "--port", "8101", \
     "--access-log"]

# Liveness probe — orchestrator hits /v1/healthz. Critical that this
# returns 200 only when the backend is actually loaded; octo-core
# checks the same endpoint to decide whether to attempt enrichment.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:8101/v1/healthz', timeout=3).status == 200 else 1)"
