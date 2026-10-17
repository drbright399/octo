# OCTO Core — data plane container.
#
# v1 ships as a single octo-core container hosting bridge surface +
# (eventually) ingest paths. The Layer 2 LLM is a sibling container,
# conditionally enabled.
#
# Build from the repository root:
#   docker build -f apps/octo/Dockerfile -t athena/octo-core:v0.1 .
#
# Run the bridge-only app with persistence + a bootstrap token (dev only —
# production wires the auth-core resolver and leaves OCTO_BOOTSTRAP_TOKENS
# unset; only apps.octo.main reads it, hence the command override, the
# default CMD below ignores it). Each token must be at least 32 random
# characters with no whitespace, and every entry well-formed, or the app
# refuses to start. Generate your own, never reuse an example:
#   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
#   docker run --rm -p 8001:8001 \
#     -v /opt/octo-state:/var/lib/octo/state \
#     -e OCTO_BOOTSTRAP_TOKENS="<random-32+-char-token>=1:super_admin:msp_root:sess1" \
#     athena/octo-core:v0.1 \
#     uvicorn apps.octo.main:app --host 0.0.0.0 --port 8001

FROM python:3.12-slim AS base

# Run as a non-root user. octo-core does not need privileged access.
RUN groupadd --system --gid 1000 octo \
    && useradd --system --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin octo

# Persistent state lives here; production mounts a volume here so
# registry.db + bridge_audit.db survive container restarts.
RUN mkdir -p /var/lib/octo/state /var/lib/octo/secrets \
    && chown -R octo:octo /var/lib/octo \
    && chmod 700 /var/lib/octo/secrets

WORKDIR /app

# System deps: minimal — sqlite is in the python stdlib, FastAPI runs on
# pure-python uvicorn[standard]. tini handles signal forwarding so SIGTERM
# during graceful shutdown actually reaches uvicorn.
RUN apt-get update \
    && apt-get install --no-install-recommends -y tini \
    && rm -rf /var/lib/apt/lists/*

# Install runtime deps before code copy so dep changes don't bust the
# code-layer cache.
COPY apps/octo/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# Install the in-repo contract packages. These are imported via dotted-path
# names (shared_adapter_contract, shared_widget_contract, shared_bridge);
# pip install -e wires them into site-packages without copying source.
COPY packages/shared-adapter-contract /opt/packages/shared-adapter-contract
COPY packages/shared-widget-contract /opt/packages/shared-widget-contract
COPY packages/shared-bridge /opt/packages/shared-bridge
RUN pip install --no-cache-dir \
    /opt/packages/shared-adapter-contract \
    /opt/packages/shared-widget-contract \
    /opt/packages/shared-bridge

# Application code
COPY apps/ /app/apps/

# Operator scripts the bundle needs at cutover + steady state (no repo or
# venv exists on a bundle host). Run via `docker compose exec octo-core
# python /app/scripts/<name>.py`; all honour OCTO_DATA_ROOT / --data-root.
COPY scripts/mint_client_token.py scripts/backup_databases.py \
     scripts/restore_databases.py scripts/verify_audit_chain.py \
     scripts/rotate_audit_chain.py scripts/verify_datto_ingest.py \
     scripts/backfill_event_presentation.py \
     scripts/move_telemetry_out_of_events.py scripts/enforce_retention.py \
     scripts/restore_telemetry_archive.py scripts/encrypt_archive.py \
     scripts/seal_backup_runs.py \
     scripts/rollback_v013.py scripts/rollback_v014.py \
     scripts/rollback_v015.py scripts/rollback_v016.py scripts/rollback_v017.py \
     scripts/rollback_v0172.py scripts/rollback_v0173.py scripts/rollback_v0175.py \
     /app/scripts/

# Set up __init__.py at the apps level so dotted imports work
RUN test -f /app/apps/__init__.py || touch /app/apps/__init__.py

# Drop privileges
USER octo:octo

# Default state dir; volume mount overrides at runtime
ENV OCTO_REGISTRY_DB_PATH=/var/lib/octo/state/registry.db \
    OCTO_AUDIT_DB_PATH=/var/lib/octo/state/bridge_audit.db \
    OCTO_STATE_DIR=/var/lib/octo/state \
    OCTO_DATA_ROOT=/var/lib/octo/state \
    OCTO_PEPPER_PATH=/var/lib/octo/secrets/pepper.env \
    OCTO_MFA_KEY_PATH=/var/lib/octo/secrets/mfa-key.env \
    OCTO_ADAPTER_CREDENTIALS_KEY_PATH=/var/lib/octo/secrets/adapter-credentials-key.env \
    OCTO_ADAPTERS_PACKAGE=apps.octo.adapters \
    OCTO_SYSTEM_WIDGETS_PACKAGE=apps.athena.widgets.system \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

EXPOSE 8001

# tini reaps zombies + forwards signals so `docker stop` actually triggers
# uvicorn's graceful shutdown
ENTRYPOINT ["/usr/bin/tini", "--"]

# Production entrypoint is the bedrock API (console + auth + ingest +
# webhooks) — the same factory a systemd-unit deploy runs. The bridge-only
# app is still runnable by overriding the command with
# `uvicorn apps.octo.main:app ...`.
#
# Secrets (pepper / MFA key / credentials key) are NOT generated at
# container start — a missing secrets mount must surface as (unhealthy)
# via /readyz, never mint fresh keys over a live registry. First-run
# provisioning is explicit:
#   docker compose run --rm octo-core python -m apps.octo.bundle_bootstrap
CMD ["uvicorn", "apps.octo.api:create_app", "--factory", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--no-access-log"]

# Readiness probe — /readyz is 200 only when the MFA + vault keys load, the registry
# schema is current and the data root is writable (/healthz = liveness
# only). A missing secrets mount therefore shows as (unhealthy), not green.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:8001/readyz', timeout=3).status == 200 else 1)"
