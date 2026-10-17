#!/usr/bin/env bash
# install-buoy-heartbeat.sh — install or update buoy-heartbeat on one buoy.
#
# Usage:
#   install-buoy-heartbeat.sh <buoy-ssh-alias> <octo-slug>
#
# Example:
#   install-buoy-heartbeat.sh buoy-<tenant> <tenant-slug>
#
# Credential model:
#   Single token per buoy. The OCTO bearer that buoy-forwarder already
#   uses on this host is reused for the heartbeat daemon — same slug,
#   same `buoy` kind, same authority. The buoy-side install body reads
#   /etc/buoy-forwarder/forwarder.env's OCTO_TOKEN_FILE path and copies
#   that file to /etc/buoy-heartbeat/token. Rotating the forwarder's
#   token rotates both daemons at once.
#
# Idempotent — rsync overwrites code, install body re-runs cleanly.
#
# Sudo TTY note:
#   The install body is a standalone .sh file on the buoy so that
#   `ssh -t buoy 'sudo bash <path>'` allocates a real TTY for the
#   sudo password prompt. Stdin-redirected heredocs disable TTY
#   allocation and break sudo on default-config hosts. Operator
#   types the buoy sudo password once when prompted.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <buoy-ssh-alias> <octo-slug>" >&2
  exit 2
fi

BUOY="$1"
SLUG="$2"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$REPO_ROOT/apps/octo/buoy"

echo ">>> Installing buoy-heartbeat on $BUOY (slug=$SLUG)"

# 1. Stage: rsync code + unit + install body to /tmp on the buoy. No sudo.
ssh "$BUOY" 'mkdir -p /tmp/buoy-heartbeat-stage'
rsync -av \
  "$SRC_DIR/heartbeat.py" \
  "$SRC_DIR/services.py" \
  "$SRC_DIR/buoy-heartbeat.service" \
  "$SRC_DIR/heartbeat.env.template" \
  "$SRC_DIR/install-step2.sh" \
  "$BUOY:/tmp/buoy-heartbeat-stage/" >/dev/null

# 2. Run the install body under sudo with a real TTY. Operator types the
#    buoy sudo password once when prompted.
ssh -t "$BUOY" "sudo bash /tmp/buoy-heartbeat-stage/install-step2.sh '$SLUG'"

echo ">>> Done. Tail logs with:  ssh $BUOY 'sudo journalctl -u buoy-heartbeat -f'"
