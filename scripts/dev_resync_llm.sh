#!/usr/bin/env bash
# scripts/dev_resync_llm.sh — one-shot "wipe synthetic notes + stop
# the synthetic seeder + relaunch a clean one" helper.
#
# Solves the symptom Rick hit 2026-05-21: cleanup ran, synthetic
# notes came back. Cause: stale dev_seed.py --continuous process
# launched before scripts/dev.sh got the DEV_SEED_AGENT_LAYER=0
# default — Python loaded the OLD module code at process start,
# kept re-inserting on every 15s tick.
#
# This script:
#   1. pkill any dev_seed.py --continuous still running
#   2. Run dev_clean_synthetic_notes.sh
#   3. Relaunch dev_seed.py --continuous WITH DEV_SEED_AGENT_LAYER=0
#      in the background, log to /tmp/dev_seed.log, disown so it
#      survives this shell exiting
#
# Leaves your dev.sh's uvicorn + Vite + octo-llm untouched. Just
# the seeder gets swapped.
#
# Run anytime the triage feed shows synthetic notes you didn't want.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_ROOT="${OCTO_DATA_ROOT:-$HOME/.octo-dev/data}"

echo "[resync] stopping any running synthetic seeders…"
pkill -f "dev_seed.py.*--continuous" 2>/dev/null || true
sleep 0.5

echo "[resync] wiping synthetic notes…"
"${REPO_ROOT}/scripts/dev_clean_synthetic_notes.sh"

echo "[resync] relaunching seeder (events-only, no agent layer)…"
PY="${REPO_ROOT}/packages/.venv/bin/python"
LOG="/tmp/dev_seed.log"
DEV_SEED_AGENT_LAYER=0 \
OCTO_DATA_ROOT="$DATA_ROOT" \
nohup "$PY" -u "${REPO_ROOT}/scripts/dev_seed.py" \
  --days 3 --continuous --tick-seconds 15 \
  >> "$LOG" 2>&1 &
SEEDER_PID=$!
disown $SEEDER_PID
echo "[resync] seeder pid $SEEDER_PID, log at $LOG"
echo
echo "Hard-refresh /tickets — the triage feed will now show ONLY real"
echo "octo-llm + heuristic notes. Click 'Ask Octo' on any alert to"
echo "populate it."
