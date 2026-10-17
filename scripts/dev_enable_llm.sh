#!/usr/bin/env bash
# scripts/dev_enable_llm.sh — flip every flag needed for the dev
# operator to see octo-llm enrichment end-to-end.
#
# What it does (idempotent):
#   1. Sets bundle_config.l2_llm_enabled = true
#   2. Sets bundle_config.l2_llm_active_model = "granite-3b-q4" (default)
#   3. Sets l2_llm_granted = 1 on the dev-admin operator
#   4. Marks the dev-admin operator is_factory = 1 so they can also
#      change models from the UI (handy for poking the model
#      selector without spinning up a separate factory operator)
#
# Usage:
#   ./scripts/dev_enable_llm.sh
#
# After running, in the same terminal that dev.sh is running, you
# should see "octo replied" responses when clicking the Ask Octo
# buttons. If the bridge still says "octo unavailable", the octo-llm
# sibling isn't running — `OCTO_LLM_DEV=1 ./scripts/dev.sh` brings
# it up automatically alongside uvicorn + Vite.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DATA_ROOT="${OCTO_DATA_ROOT:-$HOME/.octo-dev/data}"
REGISTRY="${DATA_ROOT}/registry.db"

if [[ ! -f "$REGISTRY" ]]; then
  echo "error: registry.db not found at $REGISTRY" >&2
  echo "       start the dev backend at least once before running this." >&2
  exit 2
fi

# Resolve the dev venv's python so we have sqlite3.
PY="${REPO_ROOT}/packages/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="$(command -v python3 || true)"
fi
if [[ -z "$PY" ]]; then
  echo "error: no python found" >&2
  exit 2
fi

# The strict dev-root check every dev tool shares (apps/octo/dev/dev_root.py):
# this grants LLM and factory rights, so it only ever writes a dev data root.
if ! problem="$(PYTHONPATH="$REPO_ROOT" "$PY" -c 'import sys
from apps.octo.dev.dev_root import dev_root_problem
problem = dev_root_problem(sys.argv[1])
print(problem or "")
sys.exit(1 if problem else 0)' "$DATA_ROOT")"; then
  echo "REFUSING: ${problem:-dev-root check failed}. Dev grants never touch a real OCTO bundle." >&2
  exit 3
fi

"$PY" - "$REGISTRY" <<'PY'
import json
import sqlite3
import sys
from datetime import datetime, timezone

registry_path = sys.argv[1]
now = datetime.now(timezone.utc).isoformat()
conn = sqlite3.connect(registry_path)
try:
    # bundle_config.l2_llm_enabled
    conn.execute(
        "INSERT OR REPLACE INTO bundle_config "
        "(key, value_json, updated_at) VALUES (?, ?, ?)",
        ("l2_llm_enabled", json.dumps(True), now),
    )
    conn.execute(
        "INSERT OR REPLACE INTO bundle_config "
        "(key, value_json, updated_at) VALUES (?, ?, ?)",
        ("l2_llm_active_model", json.dumps("granite-3b-q4"), now),
    )

    # Grant the dev-admin operator (the username start-dev-backend.sh
    # provisions). Tolerant of alternate names.
    cur = conn.execute(
        "SELECT id, username FROM operators "
        "WHERE username IN ('dev-admin', 'Root') "
        "ORDER BY id ASC"
    ).fetchall()
    if not cur:
        # No dev-admin yet. Grant ALL active operators — fail-safe for
        # whatever test data this env happens to have.
        cur = conn.execute(
            "SELECT id, username FROM operators WHERE disabled_at IS NULL"
        ).fetchall()
    for op_id, username in cur:
        try:
            conn.execute(
                "UPDATE operators SET l2_llm_granted = 1, is_factory = 1 "
                "WHERE id = ?", (op_id,),
            )
            print(f"  granted + factory: {username} (id={op_id})")
        except sqlite3.OperationalError as e:
            print(f"  WARN: cannot update {username}: {e}", file=sys.stderr)

    conn.commit()
    print()
    print("octo-llm dev mode ENABLED:")
    print("  bundle_config.l2_llm_enabled       = true")
    print("  bundle_config.l2_llm_active_model  = granite-3b-q4")
    print()
    print("Now click Ask Octo on any alert/event/ticket drawer.")
    print("If 'octo unavailable', run with OCTO_LLM_DEV=1 set:")
    print("    OCTO_LLM_DEV=1 ./scripts/dev.sh")
finally:
    conn.close()
PY
