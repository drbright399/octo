# .githooks/lib-scan.sh: sourced by the hooks next to it; not a hook itself.
#
# Finds the scanner relative to the hooks: <hooks dir>/../scripts/scan_sensitive.py.
# That is the repository's own copy when the hooks run from .githooks/, and the
# pinned copy when they run from the clone's git directory (where
# scripts/install_hooks.sh puts them, so EVERY branch and worktree is guarded,
# including ones that predate the guardrails). No scanner or no python: refuse.
# Every scan the hooks run uses --publish, the pre-push ref-name check included:
# the private repo meets the public standard (Rick, 2026-10-15).
guard_hook="$(basename "$0")"
guard_dir="$(cd "$(dirname "$0")/.." && pwd)"
scanner="$guard_dir/scripts/scan_sensitive.py"
if [[ ! -f "$scanner" ]]; then
  echo "$guard_hook: $scanner is missing; refusing (the scanner is the guard). Run scripts/install_hooks.sh." >&2
  exit 1
fi
py="$(command -v python3 || command -v python || true)"
if [[ -z "$py" ]]; then
  echo "$guard_hook: python3 not found; refusing (the secret scan cannot run)." >&2
  exit 1
fi

# Pinned hooks older than the scanner this branch carries: say so (never block on it).
guard_version() { sed -n 's/^GUARDRAILS_VERSION = \([0-9][0-9]*\).*/\1/p' "$1" 2>/dev/null | head -n 1; }
guard_top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -n "$guard_top" && -f "$guard_top/scripts/scan_sensitive.py" && "$guard_dir" != "$guard_top" ]]; then
  guard_pinned="$(guard_version "$scanner")"
  guard_tree="$(guard_version "$guard_top/scripts/scan_sensitive.py")"
  if [[ -n "$guard_tree" && "$guard_tree" -gt "${guard_pinned:-0}" ]]; then
    echo "$guard_hook: this branch carries scanner v$guard_tree, the installed hooks v${guard_pinned:-?}: run scripts/install_hooks.sh" >&2
  fi
fi
