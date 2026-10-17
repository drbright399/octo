#!/usr/bin/env python3
"""Verify the Datto RMM ingest path — normalization (dry) or live delivery.

Two modes:

  --dry
      No server needed. Runs DattoSourceAdapter.extract_event() on a sample
      alert in BOTH shapes (flat webhook body + nested /api/v2 poll object) and
      prints the normalized CanonicalEvent. Fails loudly if either shape
      degrades (severity=info / source_host=None / no tenant) — the regression
      guard for the 2026-09-16 dual-shape fix.

  --url https://<ingest-fqdn> [--token <DATTO_WEBHOOK_SECRET>]
      Live smoke test: POSTs a sample alert to
      <url>/api/v1/webhooks/datto with the X-Webhook-Token header and prints the
      handler's JSON response ({ingested, tenant, event_id}). Prefer passing the
      token via the DATTO_WEBHOOK_TOKEN environment variable — an argv token
      lands in shell history and the process list.

Examples:
    python scripts/verify_datto_ingest.py --dry
    DATTO_WEBHOOK_TOKEN=... python scripts/verify_datto_ingest.py --url https://ingest.example.net

Stdlib only (urllib) so it runs anywhere; --dry adds the repo + shared-adapter
package to sys.path itself.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# A sample alert in the FLAT operator-templated WEBHOOK shape (matches the
# recommended Datto body template).
SAMPLE_WEBHOOK = {
    "schema": "octo.datto-rmm.v1",
    "event": "alert_raised",
    "alertUid": "verify-web-0001",
    "alertPriority": "High",
    "alertCategory": "perf_threshold",
    "alertContext": {"message": "CPU > 95% for 5 min (verify sample)"},
    "device": {"hostname": "VERIFY-WS-01", "uid": "dev-verify-1"},
    "siteUid": "site-verify-uid",
    "siteName": "Verify Sample Site",
    "ticketNumber": "",
    "timestamp": 1700000000,
}

# The SAME alert in the nested /api/v2 alert-object shape the poller feeds in.
SAMPLE_API = {
    "alertUid": "verify-api-0001",
    "priority": "Critical",
    "alertContext": {
        "@class": "perf_resource_usage_ctx",
        "message": "Memory 99% (verify sample)",
    },
    "alertSourceInfo": {
        "siteUid": "site-verify-uid",
        "siteName": "Verify Sample Site",
        "deviceName": "VERIFY-API-01",
        "deviceUid": "dev-verify-2",
    },
    "resolved": False,
    "timestamp": 1700000000,
}


def _bootstrap_path() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)  # scripts/ sits at repo root
    for p in (root, os.path.join(root, "packages", "shared-adapter-contract")):
        if p not in sys.path:
            sys.path.insert(0, p)


def run_dry() -> int:
    _bootstrap_path()
    from apps.octo.adapters.datto import DattoSourceAdapter

    adapter = DattoSourceAdapter()
    ok = True
    for label, raw in (("WEBHOOK shape", SAMPLE_WEBHOOK), ("API/poll shape", SAMPLE_API)):
        event = adapter.extract_event(raw)
        tenant = adapter.route_to_tenant(raw)
        print(f"--- {label} ---")
        print(f"  vendor_event_id : {event.vendor_event_id}")
        print(f"  severity        : {event.severity}")
        print(f"  source_host     : {event.source_host}")
        print(f"  received_at     : {event.received_at}")
        print(f"  summary         : {event.summary}")
        print(f"  route_to_tenant : {tenant}")
        print(f"  payload_sha256  : {event.payload_sha256[:16]}...")
        # Regression guard: neither shape may degrade.
        if event.severity == "info":
            print("  !! FAIL: severity degraded to 'info' (priority key not read)")
            ok = False
        if not event.source_host:
            print("  !! FAIL: source_host is empty (device key not read)")
            ok = False
        if not tenant:
            print("  !! FAIL: route_to_tenant returned nothing (siteUid not read)")
            ok = False
    print()
    print("DRY CHECK:", "PASS — both shapes normalize cleanly" if ok else "FAIL")
    return 0 if ok else 1


def run_live(url: str, token: str) -> int:
    import urllib.error
    import urllib.request

    endpoint = url.rstrip("/") + "/api/v1/webhooks/datto"
    body = json.dumps(SAMPLE_WEBHOOK).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Webhook-Token": token},
    )
    print(f"POST {endpoint}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = resp.read().decode("utf-8")
            print(f"HTTP {resp.status}")
            print(payload)
            try:
                data = json.loads(payload)
                if data.get("ingested"):
                    print(f"OK — ingested into tenant {data.get('tenant')!r} "
                          f"(event {data.get('event_id')})")
                    return 0
                print(f"ACCEPTED but not ingested: {data.get('reason')} "
                      "(map the siteUid to a provisioned client and retry)")
            except ValueError:
                pass
        return 0
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}")
        print(exc.read().decode("utf-8", "replace"))
        if exc.code == 401:
            print("-> rejected. Every pre-auth failure is this same 401 on purpose, "
                  "so the cause is only in the SERVER LOG — look for "
                  "'[webhook:datto] REJECTED'. It is one of: the token does not "
                  "match DATTO_WEBHOOK_SECRET; the instance has no (or an "
                  "unusable) webhook secret; NO active Datto instance exists; "
                  "or the credential vault could not be read.")
        return 1
    except urllib.error.URLError as exc:
        print(f"CONNECT FAILED: {exc.reason}")
        print("-> is the PUBLIC ingress up? (must not be a tailnet/MagicDNS name)")
        return 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry", action="store_true",
                    help="run extract_event locally on both alert shapes (no server)")
    ap.add_argument("--url", help="ingress base URL, e.g. https://ingest.example.net")
    ap.add_argument("--token",
                    help="DATTO_WEBHOOK_SECRET for the X-Webhook-Token header "
                         "(default: $DATTO_WEBHOOK_TOKEN — preferred, keeps it off argv)")
    args = ap.parse_args(argv)

    if args.dry:
        return run_dry()
    token = args.token or os.environ.get("DATTO_WEBHOOK_TOKEN", "")
    if args.url and token:
        return run_live(args.url, token)
    ap.error("use --dry, or provide --url plus a token (--token or $DATTO_WEBHOOK_TOKEN)")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
