#!/usr/bin/env bash
# scripts/dev.sh — one-shot restart of the Athena local-dev pair.
#
# Kills any running backend (uvicorn apps.octo.api) and frontend (Vite)
# dev processes, then starts a fresh pair in this terminal with their
# logs prefixed + interleaved. Ctrl+C cleans up everything.
#
# Usage:
#   ./scripts/dev.sh                  # backend + frontend + seeder
#   OCTO_LLM_DEV=1 ./scripts/dev.sh   # also start octo-llm on :8101
#                                     # (stub backend — no model weights)
#
# Once the boot banner stabilizes:
#   - frontend: http://localhost:5173
#   - backend:  http://localhost:8001
#   - octo-llm: http://localhost:8101 (only with OCTO_LLM_DEV=1)
#   - dev creds: user dev-admin + a password + TOTP, set up once on first
#     run by scripts/start-dev-backend.sh. There is no static password:
#     export OCTO_DEV_PASSWORD (at least 12 characters) before the first
#     run to choose it, or a random one is generated. This script pipes
#     the backend output, so nothing secret is printed: the password and
#     the TOTP enrollment go to
#     ${OCTO_DEV_ROOT:-~/.octo-dev}/secrets/dev-admin.initial-credentials
#     (mode 600) and only that path is shown. Read it once, enroll the
#     TOTP, then delete the file.
#
# To see STUB enrichment (canned text, no model needed):
#   1. OCTO_LLM_DEV=1 ./scripts/dev.sh
#   2. In a second terminal: ./scripts/dev_enable_llm.sh
#   3. Click "Ask Octo" on any alert/event drawer
#
# To see REAL natural-language enrichment (Slice 7b):
#   1. Drop a GGUF file at ~/.octo-dev/data/octo-llm-models/<name>.gguf
#      (TinyLlama 1.1B Chat Q4_K_M is fastest — ~670MB)
#   2. OCTO_LLM_DEV=1 OCTO_LLM_BACKEND=llama-cpp \
#        OCTO_LLM_MODEL_PATH=~/.octo-dev/data/octo-llm-models/<name>.gguf \
#        ./scripts/dev.sh
#   3. In a second terminal: ./scripts/dev_enable_llm.sh
#   4. First click triggers lazy model load (~5-15s); subsequent
#      calls inference-bound (~5-15s per response on CPU).
#
# Persistent state lives at ~/.octo-dev/ (override with OCTO_DEV_ROOT).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

# Kill any pre-existing dev processes so a re-run is a clean restart.
# Patterns are deliberately specific to avoid matching unrelated commands.
echo "[dev] stopping any running dev processes…"
pkill -f "uvicorn apps.octo.api:create_app" 2>/dev/null || true
pkill -f "uvicorn apps.octo_llm.server:app" 2>/dev/null || true
pkill -f "node .*/apps/athena/web/.*/vite" 2>/dev/null || true
pkill -f "apps/athena/web.*vite" 2>/dev/null || true
# Orphaned dev_seed processes from a prior run (e.g., dev_resync_llm.sh
# launched one with nohup + disown, or a crashed dev.sh left one
# behind). Without this, restart would result in TWO seeders writing
# to the same registry concurrently.
pkill -f "dev_seed.py.*--continuous" 2>/dev/null || true
# Give the OS a moment to release the ports.
sleep 0.5

OCTO_LLM_DEV="${OCTO_LLM_DEV:-1}"   # default ON for dev so the sibling
                                     # always runs (stub mode unless
                                     # OCTO_LLM_BACKEND=llama-cpp +
                                     # OCTO_LLM_MODEL_PATH are set).
                                     # Set OCTO_LLM_DEV=0 to disable.

PIDS=()
cleanup() {
  trap - INT TERM EXIT
  echo
  echo "[dev] shutting down…"
  # Send TERM to the children we started; they own their own descendants.
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  # Belt-and-suspenders: kill any straggler matching our patterns.
  pkill -f "uvicorn apps.octo.api:create_app" 2>/dev/null || true
  pkill -f "uvicorn apps.octo_llm.server:app" 2>/dev/null || true
  pkill -f "apps/athena/web.*vite" 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM EXIT

# Backend — output piped through sed for a [backend] prefix. The subshell
# keeps the redirect attached and lets PIDS pick up its pid.
#
# When OCTO_LLM_DEV=1, the backend gets OCTO_LLM_URL pointing at the
# local sibling launched below. Without the env, the bridge endpoint
# tries the docker-network default and fail-closes (which is fine —
# the operator sees "octo unavailable" inline, no error).
#
# OCTO_LLM_MODELS_DIR points the Settings → System "L2 LLM Model"
# panel at the dev models directory (the prod default is /var/lib/
# octo-llm/models which doesn't exist on dev). Unrelated to
# OCTO_LLM_MODEL_PATH which tells octo-llm WHICH specific file to load.
if [[ "$OCTO_LLM_DEV" == "1" ]]; then
  export OCTO_LLM_URL="http://127.0.0.1:8101"
  export OCTO_LLM_MODELS_DIR="${OCTO_LLM_MODELS_DIR:-$HOME/.octo-dev/data/octo-llm-models}"
fi
( "${REPO_ROOT}/scripts/start-dev-backend.sh" 2>&1 | sed -u 's/^/[backend] /' ) &
PIDS+=($!)
# OCTO_DEV_PASSWORD (if exported) is only for the backend's first-run
# provisioning, and the backend subshell above already has its copy:
# keep it out of the frontend, octo-llm and seeder environments.
unset OCTO_DEV_PASSWORD

# Frontend — Vite dev server. Same prefix pattern.
( cd "${REPO_ROOT}/apps/athena/web" && npm run dev 2>&1 | sed -u 's/^/[frontend] /' ) &
PIDS+=($!)

# octo-llm — optional sibling on port 8101. Stub backend by default
# (no model weights required); flip to llama-cpp by setting
# OCTO_LLM_BACKEND=llama-cpp + OCTO_LLM_MODEL_PATH=<.gguf path>
# before running this script.
#
# To get REAL natural-language enrichment in dev:
#   1. Drop a GGUF file at ~/.octo-dev/data/octo-llm-models/
#   2. Export both:
#        OCTO_LLM_DEV=1 \
#        OCTO_LLM_BACKEND=llama-cpp \
#        OCTO_LLM_MODEL_PATH=~/.octo-dev/data/octo-llm-models/<file>.gguf \
#        ./scripts/dev.sh
if [[ "$OCTO_LLM_DEV" == "1" ]]; then
  # Auto-detect backend: prefer the first .gguf in the dev models dir
  # so the operator doesn't have to remember the env-var dance. If
  # they explicitly set OCTO_LLM_BACKEND or OCTO_LLM_MODEL_PATH, those
  # take precedence.
  OCTO_LLM_MODELS_DIR_VAL="${OCTO_LLM_MODELS_DIR:-$HOME/.octo-dev/data/octo-llm-models}"
  if [[ -z "${OCTO_LLM_BACKEND:-}" ]]; then
    # Find the first .gguf, if any.
    FIRST_GGUF=""
    if [[ -d "$OCTO_LLM_MODELS_DIR_VAL" ]]; then
      FIRST_GGUF=$(find "$OCTO_LLM_MODELS_DIR_VAL" -maxdepth 1 -type f -name '*.gguf' 2>/dev/null | head -1)
    fi
    if [[ -n "$FIRST_GGUF" ]]; then
      OCTO_LLM_BACKEND_VAL="llama-cpp"
      OCTO_LLM_MODEL_PATH_VAL="${OCTO_LLM_MODEL_PATH:-$FIRST_GGUF}"
      echo "[dev] auto-detected GGUF: $OCTO_LLM_MODEL_PATH_VAL"
    else
      OCTO_LLM_BACKEND_VAL="stub"
      OCTO_LLM_MODEL_PATH_VAL=""
      echo "[dev] no GGUF in $OCTO_LLM_MODELS_DIR_VAL — octo-llm in stub mode"
    fi
  else
    OCTO_LLM_BACKEND_VAL="$OCTO_LLM_BACKEND"
    OCTO_LLM_MODEL_PATH_VAL="${OCTO_LLM_MODEL_PATH:-}"
  fi
  # Respawn loop — when the admin "Restart octo-llm" UI button
  # SIGTERMs the uvicorn child, this loop relaunches it within ~1s
  # so the operator doesn't need to leave the dashboard. Loops as
  # long as dev.sh itself is running (cleanup trap kills the loop
  # on Ctrl+C).
  (
    cd "$REPO_ROOT"
    while true; do
      OCTO_LLM_BACKEND="$OCTO_LLM_BACKEND_VAL" \
      OCTO_LLM_MODEL_PATH="$OCTO_LLM_MODEL_PATH_VAL" \
      PYTHONPATH="$REPO_ROOT" \
      "${REPO_ROOT}/packages/.venv/bin/python" -u -m uvicorn \
        apps.octo_llm.server:app \
        --host 127.0.0.1 --port 8101 --reload 2>&1 \
        | sed -u 's/^/[octo-llm] /'
      RC=$?
      # Exit code 0 = clean shutdown (SIGTERM); anything else = crash.
      # Either way, respawn unless dev.sh is shutting down.
      echo "[octo-llm] uvicorn exited rc=$RC, respawning in 1s…"
      sleep 1
    done
  ) &
  PIDS+=($!)
fi

# Seed synthetic event data so the dashboard widgets have a curve to
# render against. Idempotent — only tops up to the target window, so
# re-running dev.sh is cheap. Skip by exporting DEV_SEED_SKIP=1.
# Run via the dev-tree venv against the dev data root only — the
# seeder refuses any path that doesn't look like a dev root.
#
# DEV_SEED_CONTINUOUS=1 (default) keeps the seeder running after the
# initial top-up, emitting a steady trickle on a 15s tick so the
# /search default 15m window stays populated without manual re-runs.
# Export DEV_SEED_CONTINUOUS=0 if you want a one-shot top-up and no
# background traffic — useful when you're trying to reproduce a
# specific event pattern by hand.
DEV_SEED_SKIP="${DEV_SEED_SKIP:-0}"
DEV_SEED_CONTINUOUS="${DEV_SEED_CONTINUOUS:-1}"
# Synthetic agent_notes off by default — the /tickets triage feed
# shows ONLY real octo-llm + heuristic-generated notes. Flip to 1
# to restore the legacy behavior (useful when you want a populated
# feed without octo-llm running).
DEV_SEED_AGENT_LAYER="${DEV_SEED_AGENT_LAYER:-0}"
export DEV_SEED_AGENT_LAYER
if [[ "$DEV_SEED_SKIP" != "1" ]]; then
  CONTINUOUS_FLAG=""
  if [[ "$DEV_SEED_CONTINUOUS" == "1" ]]; then
    CONTINUOUS_FLAG="--continuous --tick-seconds 15"
  fi
  (
    # Wait a few seconds for start-dev-backend.sh to provision registry.db
    # via init_data_root() before the seeder tries to insert into it.
    sleep 4
    OCTO_DATA_ROOT="${OCTO_DEV_ROOT:-$HOME/.octo-dev}/data" \
      "${REPO_ROOT}/packages/.venv/bin/python" -u \
      "${REPO_ROOT}/scripts/dev_seed.py" --days 3 $CONTINUOUS_FLAG 2>&1 \
      | sed -u 's/^/[dev_seed] /'
  ) &
  PIDS+=($!)
fi

echo "[dev] started ${PIDS[*]} — Ctrl+C to stop everything"
echo "[dev] frontend: http://localhost:5173"
echo "[dev] backend:  http://localhost:8001"
if [[ "$OCTO_LLM_DEV" == "1" ]]; then
  echo "[dev] octo-llm: http://localhost:8101 (stub backend)"
  echo "[dev]   run ./scripts/dev_enable_llm.sh in another terminal to grant + flip flags"
fi
echo

# wait blocks until either child exits or we get a signal.
wait
