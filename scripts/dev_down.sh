#!/usr/bin/env bash
# dev_down.sh — kill the local dev pair (uvicorn + vite).
#
# Reverse of dev_up.sh. Targets the listening sockets on :8001 and
# :5173 so it's resilient to PID changes / multiple restarts.

set -euo pipefail

kill_port() {
  local port="$1" pid
  pid=$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {print $NF}' \
        | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  if [[ -n "${pid:-}" ]]; then
    echo "  killing PID $pid on :$port"
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3; do
      sleep 0.5
      ss -tlnp 2>/dev/null | grep -q ":$port " || return 0
    done
    kill -9 "$pid" 2>/dev/null || true
  else
    echo "  nothing on :$port"
  fi
}

echo "==> Stopping dev pair"
kill_port 8001
kill_port 5173
echo "done."
