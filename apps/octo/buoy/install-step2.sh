#!/usr/bin/env bash
# install-step2.sh — buoy-side install body. Invoked under sudo from
# scripts/install-buoy-heartbeat.sh after the stage rsync completes.
#
# Takes the slug as $1. Reads OCTO_URL + OCTO_TOKEN_FILE from the
# existing buoy-forwarder env. Idempotent (re-runnable).

set -euo pipefail

SLUG="${1:-}"
if [[ -z "$SLUG" ]]; then
  echo "error: install-step2.sh requires <slug>" >&2
  exit 2
fi

STAGE=/tmp/buoy-heartbeat-stage
FWD_ENV=/etc/buoy-forwarder/forwarder.env

if [[ ! -r "$FWD_ENV" ]]; then
  echo "error: $FWD_ENV not readable. Provision buoy-forwarder first." >&2
  exit 2
fi

FWD_OCTO_URL=$(sed -n 's/^OCTO_URL=//p' "$FWD_ENV" | tr -d '"' | head -1)
TOKEN_FILE_PATH=$(sed -n 's/^OCTO_TOKEN_FILE=//p' "$FWD_ENV" | tr -d '"' | head -1)

if [[ -z "$FWD_OCTO_URL" || -z "$TOKEN_FILE_PATH" ]]; then
  echo "error: forwarder.env missing OCTO_URL or OCTO_TOKEN_FILE" >&2
  exit 2
fi

# The forwarder points at the LEGACY admin-api service (port 8770 by
# default); the new heartbeat + dashboard routers live on the bedrock
# service (port 8771). Port-swap to derive the heartbeat URL. Bearer
# token works on both since /whoami exists on each.
#
# If the operator already overrode OCTO_URL in heartbeat.env (preserved
# by the "only write if not present" branch below), this derivation is
# ignored. So a future bundle that consolidates the two services into
# one port keeps working — just stop overriding here.
case "$FWD_OCTO_URL" in
  *:8770) OCTO_URL_VAL="${FWD_OCTO_URL%:8770}:8771" ;;
  *)      OCTO_URL_VAL="$FWD_OCTO_URL" ;;
esac
if [[ ! -r "$TOKEN_FILE_PATH" ]]; then
  echo "error: forwarder token file $TOKEN_FILE_PATH not readable" >&2
  exit 2
fi

# Binary + sibling probe module (services.py is imported by heartbeat.py
# at runtime; ships next to it under /usr/local/bin so the relative
# import resolves on the standalone-script deploy)
install -m 0755 -o root -g root "$STAGE/heartbeat.py" /usr/local/bin/buoy-heartbeat.py
install -m 0644 -o root -g root "$STAGE/services.py"  /usr/local/bin/services.py

# Config dir + token (copied from the forwarder's token, 0600 root:root)
mkdir -p /etc/buoy-heartbeat
install -m 0600 -o root -g root "$TOKEN_FILE_PATH" /etc/buoy-heartbeat/token

# heartbeat.env — only write if not present
if [[ ! -f /etc/buoy-heartbeat/heartbeat.env ]]; then
  sed -e "s|^OCTO_URL=.*|OCTO_URL=$OCTO_URL_VAL|" \
      -e "s|__SET_BY_INSTALLER__|$SLUG|g" \
      "$STAGE/heartbeat.env.template" \
    > /etc/buoy-heartbeat/heartbeat.env
  chmod 0640 /etc/buoy-heartbeat/heartbeat.env
  chown root:root /etc/buoy-heartbeat/heartbeat.env
  echo "  wrote /etc/buoy-heartbeat/heartbeat.env (slug=$SLUG)"
else
  echo "  /etc/buoy-heartbeat/heartbeat.env already exists — preserved"
  if ! grep -q "^OCTO_SLUG=$SLUG\b" /etc/buoy-heartbeat/heartbeat.env; then
    echo "  WARNING: /etc/buoy-heartbeat/heartbeat.env OCTO_SLUG != $SLUG" >&2
  fi
fi

# State dir
mkdir -p /var/lib/buoy-heartbeat
chown root:root /var/lib/buoy-heartbeat
chmod 0750 /var/lib/buoy-heartbeat

# systemd unit
install -m 0644 -o root -g root "$STAGE/buoy-heartbeat.service" \
  /etc/systemd/system/buoy-heartbeat.service

# Reload + enable + restart
systemctl daemon-reload
systemctl enable buoy-heartbeat.service >/dev/null 2>&1 || true
systemctl restart buoy-heartbeat.service

# Settle, then status
sleep 3
systemctl --no-pager --lines=15 status buoy-heartbeat.service || true

# Clean up stage
rm -rf "$STAGE"
