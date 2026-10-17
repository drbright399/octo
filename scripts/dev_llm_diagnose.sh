#!/usr/bin/env bash
# scripts/dev_llm_diagnose.sh — show the state of every LLM gate +
# the octo-llm sibling so we can see which link is broken.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_ROOT="${OCTO_DATA_ROOT:-$HOME/.octo-dev/data}"
REGISTRY="${DATA_ROOT}/registry.db"
MODELS_DIR="${OCTO_LLM_DEV_MODELS_DIR:-$DATA_ROOT/octo-llm-models}"

echo "=== octo-llm dev diagnostic ==="
echo

echo "[1] octo-llm sibling on :8101"
HZ=$(curl -s -m 3 http://localhost:8101/v1/healthz 2>&1 || true)
if [[ -z "$HZ" ]]; then
  echo "  ❌ NOT REACHABLE — is OCTO_LLM_DEV=1 set on dev.sh?"
else
  echo "  ✓ reachable"
  echo "  $HZ"
fi
echo

echo "[2] backend at :8001"
BHZ=$(curl -s -m 3 http://localhost:8001/healthz 2>&1 || true)
if [[ -z "$BHZ" ]]; then
  echo "  ❌ NOT REACHABLE — is ./scripts/dev.sh running?"
else
  echo "  ✓ reachable: $BHZ"
fi
echo

echo "[3] model file on disk"
if [[ -d "$MODELS_DIR" ]]; then
  ls -lh "$MODELS_DIR" 2>&1 | tail -10 | sed 's/^/  /'
else
  echo "  ❌ models dir doesn't exist: $MODELS_DIR"
fi
echo

echo "[4] OCTO_LLM_* env in this shell"
env | grep '^OCTO_LLM' | sed 's/^/  /' || echo "  (none set in this shell — fine if dev.sh has them in its env)"
echo

echo "[5] registry state"
if [[ ! -f "$REGISTRY" ]]; then
  echo "  ❌ registry.db not at $REGISTRY — dev backend not initialized"
  exit 1
fi
PY="${REPO_ROOT}/packages/.venv/bin/python"
if [[ ! -x "$PY" ]]; then PY="$(command -v python3)"; fi

"$PY" - "$REGISTRY" <<'PY'
import json, sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.row_factory = sqlite3.Row

print("  bundle_config:")
try:
    for k in ("l2_llm_enabled", "l2_llm_active_model"):
        r = conn.execute(
            "SELECT value_json FROM bundle_config WHERE key = ?", (k,)
        ).fetchone()
        v = r["value_json"] if r else "<unset>"
        print(f"    {k} = {v}")
except sqlite3.OperationalError as e:
    print(f"    ❌ bundle_config error: {e}")

print()
print("  operators (id, username, is_factory, l2_llm_granted, preferences):")
try:
    rows = conn.execute(
        "SELECT id, username, is_factory, l2_llm_granted, preferences "
        "FROM operators WHERE disabled_at IS NULL ORDER BY id"
    ).fetchall()
    for r in rows:
        prefs = r["preferences"] or "{}"
        try:
            p = json.loads(prefs)
            llm_pref = p.get("l2_llm_enabled", "default(True)")
        except Exception:
            llm_pref = "?"
        print(f"    id={r['id']:<3} {r['username']:<20} "
              f"factory={r['is_factory']} granted={r['l2_llm_granted']} "
              f"pref.l2_llm_enabled={llm_pref}")
except sqlite3.OperationalError as e:
    print(f"    ❌ operators error: {e}")
finally:
    conn.close()
PY
echo
echo "=== fixes ==="
echo "  • if [1] failed: restart with OCTO_LLM_DEV=1 ./scripts/dev.sh"
echo "  • if model file missing: ./scripts/dev_download_tinyllama.sh"
echo "  • if bundle_config or grant is off: ./scripts/dev_enable_llm.sh"
echo "  • after any change: hard refresh the browser (Ctrl+Shift+R)"
