#!/usr/bin/env bash
# dev_buoys.sh — one-shot wrapper around scripts/dev_seed_buoys.py.
#
# Resolves the dev venv + OCTO_DATA_ROOT so the operator doesn't have
# to. Usage from anywhere:
#
#   <repo>/scripts/dev_buoys.sh                # seed once
#   <repo>/scripts/dev_buoys.sh --refresh 30   # keep green fresh
#
# Picks up the dev venv at the canonical dev-tree location. Override
# DEV_VENV or OCTO_DATA_ROOT in the environment if you have non-default
# paths.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Dev venv: defaults to <REPO_ROOT>/packages/.venv. Override with
# DEV_VENV=<path> if your venv lives somewhere else (e.g. a sibling
# checkout that bundles dependencies).
DEV_VENV="${DEV_VENV:-$REPO_ROOT/packages/.venv}"
OCTO_DATA_ROOT="${OCTO_DATA_ROOT:-$HOME/.octo-dev/data}"

if [[ ! -x "$DEV_VENV/bin/python" ]]; then
  echo "error: dev venv python not found at $DEV_VENV/bin/python" >&2
  echo "       override with DEV_VENV=<path> if your venv lives elsewhere" >&2
  exit 2
fi
if [[ ! -d "$OCTO_DATA_ROOT" ]]; then
  echo "error: OCTO_DATA_ROOT $OCTO_DATA_ROOT not found" >&2
  echo "       override with OCTO_DATA_ROOT=<path> if your dev data lives elsewhere" >&2
  exit 2
fi

# Translate --refresh N → --refresh-interval N for the seeder.
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --refresh) ARGS+=("--refresh-interval" "$2"); shift 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

echo "dev venv:       $DEV_VENV"
echo "data root:      $OCTO_DATA_ROOT"
echo

cd "$REPO_ROOT"
exec env OCTO_DATA_ROOT="$OCTO_DATA_ROOT" \
  "$DEV_VENV/bin/python" scripts/dev_seed_buoys.py "${ARGS[@]}"
