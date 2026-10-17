#!/usr/bin/env bash
# scripts/dev_clean_synthetic_notes.sh — wipe synthetic agent_notes
# + agent_pattern_links from every dev tenant's events.db so the
# /tickets triage feed shows only real model output.
#
# What gets deleted:
#   agent_notes WHERE audit_request_id LIKE 'synthetic-%'
#     (the seeder stamps these with a 'synthetic-XXXXXXXX' UUID,
#      so we identify them by prefix — real bridge writes use UUIDs)
#
#   agent_pattern_links that reference one of those deleted notes'
#     events. We can't filter pattern_links by a synthetic stamp
#     because the table doesn't have audit_request_id; instead we
#     delete every pattern_link in the dev tenant directories
#     because all of them were dev-seeded (production bundles never
#     have seeded links).
#
# Real notes (created by the agent_query bridge endpoint, audit
# request_id = uuid4) are preserved.
#
# Idempotent — safe to re-run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_ROOT="${OCTO_DATA_ROOT:-$HOME/.octo-dev/data}"
CLIENTS_DIR="${DATA_ROOT}/clients"

# The strict dev-root check every dev tool shares (apps/octo/dev/dev_root.py),
# before anything under the root is read or deleted.
PY="${REPO_ROOT}/packages/.venv/bin/python"
[[ -x "$PY" ]] || PY="$(command -v python3 || true)"
if [[ -z "$PY" ]]; then
  echo "error: no python found" >&2
  exit 2
fi
if ! problem="$(PYTHONPATH="$REPO_ROOT" "$PY" -c 'import sys
from apps.octo.dev.dev_root import dev_root_problem
problem = dev_root_problem(sys.argv[1])
print(problem or "")
sys.exit(1 if problem else 0)' "$DATA_ROOT")"; then
  echo "REFUSING: ${problem:-dev-root check failed}. This tool only cleans dev tenants." >&2
  exit 3
fi

if [[ ! -d "$CLIENTS_DIR" ]]; then
  echo "no clients dir at $CLIENTS_DIR — nothing to clean."
  exit 0
fi

TOTAL_NOTES=0
TOTAL_LINKS=0
for client_dir in "$CLIENTS_DIR"/dev-*; do
  [[ -d "$client_dir" ]] || continue
  edb="$client_dir/events.db"
  [[ -f "$edb" ]] || continue
  slug="$(basename "$client_dir")"

  # Count then delete. -separator chosen so the count line is parseable.
  NOTES_BEFORE=$(sqlite3 "$edb" \
    "SELECT COUNT(*) FROM agent_notes WHERE audit_request_id LIKE 'synthetic-%'" \
    2>/dev/null || echo 0)
  LINKS_BEFORE=$(sqlite3 "$edb" \
    "SELECT COUNT(*) FROM agent_pattern_links" \
    2>/dev/null || echo 0)

  if [[ "$NOTES_BEFORE" -gt 0 || "$LINKS_BEFORE" -gt 0 ]]; then
    sqlite3 "$edb" <<'SQL'
DELETE FROM agent_notes WHERE audit_request_id LIKE 'synthetic-%';
DELETE FROM agent_pattern_links;
SQL
    echo "  $slug: deleted $NOTES_BEFORE synthetic note(s) + $LINKS_BEFORE pattern link(s)"
    TOTAL_NOTES=$((TOTAL_NOTES + NOTES_BEFORE))
    TOTAL_LINKS=$((TOTAL_LINKS + LINKS_BEFORE))
  fi
done

echo
echo "Cleaned: $TOTAL_NOTES synthetic note(s) + $TOTAL_LINKS pattern link(s) across all dev tenants."
echo "Real model-generated notes preserved (audit_request_id is uuid4, not 'synthetic-')."
echo
echo "Next: hard-refresh /tickets — the Agent Triage Feed will repopulate"
echo "from real bridge inserts as you click 'Ask Octo' on alerts."
