#!/usr/bin/env bash
# dev_up.sh — bring the local dev pair online in one command.
#
# Kills any orphan vite/uvicorn on the dev ports, symlinks the dev
# venv into this checkout if absent, starts the backend on :8001
# and the Vite dev server on :5173 (both backgrounded with their logs
# in a per-user, owner-only directory: ${TMPDIR:-/tmp}/octo-dev-<uid>/,
# or $OCTO_DEV_LOG_DIR), waits for both to come up healthy, and prints a
# summary that names the log files.
#
# Optional flags:
#   --seed-buoys           run scripts/dev_buoys.sh after backend is up
#   --refresh-buoys N      run dev_buoys.sh with --refresh N (foreground;
#                          script keeps green buoy heartbeating every N s
#                          until Ctrl-C — useful for testing rotator
#                          transitions)
#
# It exists to remove five dev-pair setup papercuts (orphaned servers
# on the dev ports, a missing venv, and so on) that bit on 2026-05-15
# during the buoy-fleet dev iteration.
#
# Re-runnable. Safe to call when nothing's running yet OR when one
# half of the pair is already up.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Source venv: defaults to a sibling venv at <REPO_ROOT>/packages/.venv-src,
# but most setups override with DEV_VENV_SRC=<path> pointing at the venv
# you maintain elsewhere (e.g. one shared with another checkout).
DEV_VENV_SRC="${DEV_VENV_SRC:-$REPO_ROOT/packages/.venv-src}"
DEV_VENV_DST="$REPO_ROOT/packages/.venv"

# Logs go to a directory only this user can enter, and the files are
# created 0600: the backend log can carry operator-facing output, and a
# fixed name directly in /tmp could be pre-created (or read) by another
# user. The directory must be a real directory owned by us — never a
# symlink or someone else's — or we stop.
LOG_DIR="${OCTO_DEV_LOG_DIR:-${TMPDIR:-/tmp}/octo-dev-$(id -u)}"
# Absolute, so the `cd`s below cannot move it.
case "$LOG_DIR" in /*) ;; *) LOG_DIR="$PWD/$LOG_DIR" ;; esac
BACKEND_LOG="$LOG_DIR/dev-backend.log"
VITE_LOG="$LOG_DIR/dev-vite.log"

prepare_log_dir() {
  ( umask 077 && mkdir -p -- "$LOG_DIR" )
  if [[ -L "$LOG_DIR" || ! -d "$LOG_DIR" || ! -O "$LOG_DIR" ]]; then
    echo "error: log dir $LOG_DIR is not a directory owned by $(id -un)" >&2
    echo "       (remove it, or set OCTO_DEV_LOG_DIR=<path>)" >&2
    exit 2
  fi
  chmod 700 -- "$LOG_DIR"
}

# Create (or truncate) a log file owner-only before a server writes to it;
# the `>` redirect that follows keeps the mode.
prepare_log_file() {
  local f="$1"
  if [[ -L "$f" ]]; then
    echo "error: log file $f is a symlink; refusing" >&2
    exit 2
  fi
  ( umask 077 && : > "$f" )
  chmod 600 -- "$f"
}

SEED_BUOYS=0
REFRESH_INTERVAL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --seed-buoys) SEED_BUOYS=1; shift ;;
    --refresh-buoys) REFRESH_INTERVAL="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# 1. Kill orphans
# ---------------------------------------------------------------------------

kill_port() {
  local port="$1" pid
  pid=$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {print $NF}' \
        | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  if [[ -n "${pid:-}" ]]; then
    echo "  killing orphan PID $pid on :$port"
    kill "$pid" 2>/dev/null || true
    # Brief grace period for the socket to release.
    for _ in 1 2 3; do
      sleep 0.5
      ss -tlnp 2>/dev/null | grep -q ":$port " || return 0
    done
    kill -9 "$pid" 2>/dev/null || true
  fi
}

echo "==> Killing orphans on :8001 / :5173"
kill_port 8001
kill_port 5173

# ---------------------------------------------------------------------------
# 2. Symlink venv if missing
# ---------------------------------------------------------------------------

if [[ ! -x "$DEV_VENV_DST/bin/python" ]]; then
  if [[ ! -x "$DEV_VENV_SRC/bin/python" ]]; then
    echo "error: source venv missing at $DEV_VENV_SRC" >&2
    echo "       override with DEV_VENV_SRC=<path>" >&2
    exit 2
  fi
  echo "==> Symlinking venv: $DEV_VENV_DST -> $DEV_VENV_SRC"
  ln -sf "$DEV_VENV_SRC" "$DEV_VENV_DST"
fi

# ---------------------------------------------------------------------------
# 3. Start backend in background
# ---------------------------------------------------------------------------

prepare_log_dir

echo "==> Starting backend (log: $BACKEND_LOG)"
cd "$REPO_ROOT"
prepare_log_file "$BACKEND_LOG"
nohup ./scripts/start-dev-backend.sh > "$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
echo "  backend PID $BACKEND_PID"

# Health probe — wait up to 20 s for :8001
for i in $(seq 1 40); do
  if curl -fsS -m 1 -o /dev/null http://localhost:8001/healthz 2>/dev/null; then
    echo "  backend healthy"
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "  backend died before becoming healthy. See $BACKEND_LOG:" >&2
    tail -20 "$BACKEND_LOG" >&2
    exit 2
  fi
  sleep 0.5
  if [[ $i -eq 40 ]]; then
    echo "  backend not responding after 20s. See $BACKEND_LOG:" >&2
    tail -20 "$BACKEND_LOG" >&2
    exit 2
  fi
done

# ---------------------------------------------------------------------------
# 4. Start vite in background
# ---------------------------------------------------------------------------

echo "==> Starting vite (log: $VITE_LOG)"
cd "$REPO_ROOT/apps/athena/web"
prepare_log_file "$VITE_LOG"
# npm is the canonical package manager (per package.json#packageManager).
# The earlier `pnpm dev` invocation was leftover from a brief pnpm
# experiment and bit us 2026-05-19 with a react/react-dom version
# mismatch caused by node_modules being half-shaped by pnpm.
nohup npm run dev > "$VITE_LOG" 2>&1 &
VITE_PID=$!
echo "  vite PID $VITE_PID"

for i in $(seq 1 40); do
  if curl -fsS -m 1 -o /dev/null http://localhost:5173/ 2>/dev/null; then
    echo "  vite healthy"
    break
  fi
  if ! kill -0 "$VITE_PID" 2>/dev/null; then
    echo "  vite died before becoming healthy. See $VITE_LOG:" >&2
    tail -20 "$VITE_LOG" >&2
    exit 2
  fi
  sleep 0.5
  if [[ $i -eq 40 ]]; then
    echo "  vite not responding after 20s. See $VITE_LOG:" >&2
    tail -20 "$VITE_LOG" >&2
    exit 2
  fi
done

# ---------------------------------------------------------------------------
# 5. Optional: seed synthetic buoys
# ---------------------------------------------------------------------------

if [[ $SEED_BUOYS -eq 1 || $REFRESH_INTERVAL -gt 0 ]]; then
  echo "==> Seeding synthetic buoys"
  if [[ $REFRESH_INTERVAL -gt 0 ]]; then
    echo "  ('--refresh-buoys $REFRESH_INTERVAL' runs in foreground; Ctrl-C to stop)"
    "$REPO_ROOT/scripts/dev_buoys.sh" --refresh "$REFRESH_INTERVAL"
  else
    "$REPO_ROOT/scripts/dev_buoys.sh"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

cat <<EOF

==> Dev pair up
    UI:       http://localhost:5173
    Backend:  http://localhost:8001
    Backend log:  tail -f $BACKEND_LOG
    Vite log:     tail -f $VITE_LOG

    Stop both:    $REPO_ROOT/scripts/dev_down.sh
    Seed buoys:   $REPO_ROOT/scripts/dev_buoys.sh [--refresh N]
EOF
