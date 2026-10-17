#!/usr/bin/env python3
"""dev_seed_buoys.py — seed synthetic buoy heartbeats into the dev registry.

Three synthetic buoys with deliberately-mixed health states so the
/fleet page + dashboard Source-health rotator can be iterated without
needing real heartbeats from physical Pis:

  - dev-buoy-acme        — GREEN  (all services active, fresh heartbeat)
  - dev-buoy-globex      — YELLOW (wazuh-agent failed, inspect flag set)
  - dev-buoy-initech     — STALE  (heartbeat backdated > 2× interval)

Run via:
    OCTO_DATA_ROOT=~/.octo-dev/data \\
      ./packages/.venv/bin/python scripts/dev_seed_buoys.py

Or with --refresh-interval N to keep the GREEN buoy heartbeating every N
seconds (the others stay flagged so the operator can see what the UI
looks like with a degraded fleet).

Idempotent — UPSERTs by slug. Synthetic-only: every slug starts with
`dev-buoy-` so it's impossible to confuse with a real customer buoy.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Repo root on sys.path so the strict dev-root check (apps.octo.dev.dev_root,
# standard library only) imports when this runs as a plain script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from apps.octo.dev.dev_root import dev_root_problem  # noqa: E402


def _iso_now(offset_sec: int = 0) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_sec)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _all_active() -> dict:
    """Default all-green services map — most synthetic buoys use this."""
    return {
        "tailscaled":     "active",
        "wazuh-agent":    "active",
        "opencanary":     "active",
        "suricata":       "active",
        "buoy-forwarder": "active",
        "octo-forwarder": "active",
        "pihole-FTL":     "active",
        "nextdns":        "active",
    }


def _services(**overrides) -> dict:
    base = _all_active()
    base.update(overrides)
    return base


# Synthetic MSP fleet — 15 buoys spread across major US metros with a
# realistic mix of health tiers. Slug names use generic fictional-company
# placeholders (acme/globex/initech-style — the kind of names that read
# as 'demo data' to any operator). City lat/lng are major-metro centers.
#
# Health distribution (when re-derived server-side from services +
# staleness):
#   green:  10  — most of the fleet is healthy on any given day
#   yellow:  2  — one service flapping; needs inspection
#   red:     1  — heartbeat genuinely stale (5×+ interval)
#   stale:   2  — heartbeat 2–5× interval; rotated through over time
#
# That's enough variety to exercise:
#   - All four FleetSearch tier-filter chips
#   - All four FleetRollup tones (success / warning / critical / dim)
#   - Both views (cards + map) with enough density to feel populated

SYNTHETIC_BUOYS = [
    # ─── GREEN tier — healthy, fresh heartbeats ────────────────────────
    {
        "slug": "dev-buoy-acme", "hostname": "buoy-acme-corp",
        "uptime_sec": 1_234_567, "load_1": 0.05, "load_5": 0.08, "load_15": 0.10,
        "mem_used_mb": 1700, "mem_total_mb": 4096, "disk_used_pct": 34,
        "interval_sec": 60, "staleness_offset_sec": -15,
        "lat": 39.099724, "lng": -94.578331,   # Kansas City, MO
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-vandelay", "hostname": "buoy-vandelay-imports",
        "uptime_sec": 2_400_000, "load_1": 0.12, "load_5": 0.18, "load_15": 0.22,
        "mem_used_mb": 1850, "mem_total_mb": 4096, "disk_used_pct": 41,
        "interval_sec": 60, "staleness_offset_sec": -8,
        "lat": 47.6062, "lng": -122.3321,      # Seattle, WA
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-soylent", "hostname": "buoy-soylent-foods",
        "uptime_sec": 850_000, "load_1": 0.32, "load_5": 0.41, "load_15": 0.38,
        "mem_used_mb": 2100, "mem_total_mb": 4096, "disk_used_pct": 56,
        "interval_sec": 60, "staleness_offset_sec": -12,
        "lat": 34.0522, "lng": -118.2437,      # Los Angeles, CA
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-dunder", "hostname": "buoy-dunder-mifflin",
        "uptime_sec": 3_120_000, "load_1": 0.04, "load_5": 0.05, "load_15": 0.06,
        "mem_used_mb": 1400, "mem_total_mb": 4096, "disk_used_pct": 28,
        "interval_sec": 60, "staleness_offset_sec": -23,
        "lat": 39.7392, "lng": -104.9903,      # Denver, CO
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-los-pollos", "hostname": "buoy-los-pollos",
        "uptime_sec": 1_650_000, "load_1": 0.18, "load_5": 0.21, "load_15": 0.19,
        "mem_used_mb": 2380, "mem_total_mb": 4096, "disk_used_pct": 47,
        "interval_sec": 60, "staleness_offset_sec": -34,
        "lat": 30.2672, "lng": -97.7431,       # Austin, TX
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-waystar", "hostname": "buoy-waystar-media",
        "uptime_sec": 1_980_000, "load_1": 0.22, "load_5": 0.28, "load_15": 0.31,
        "mem_used_mb": 2740, "mem_total_mb": 4096, "disk_used_pct": 52,
        "interval_sec": 60, "staleness_offset_sec": -19,
        "lat": 33.4484, "lng": -112.0740,      # Phoenix, AZ
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-hooli", "hostname": "buoy-hooli-cloud",
        "uptime_sec": 4_200_000, "load_1": 0.08, "load_5": 0.10, "load_15": 0.11,
        "mem_used_mb": 1550, "mem_total_mb": 4096, "disk_used_pct": 31,
        "interval_sec": 60, "staleness_offset_sec": -7,
        "lat": 25.7617, "lng": -80.1918,       # Miami, FL
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-gringotts", "hostname": "buoy-gringotts-financial",
        "uptime_sec": 980_000, "load_1": 0.14, "load_5": 0.16, "load_15": 0.17,
        "mem_used_mb": 1920, "mem_total_mb": 4096, "disk_used_pct": 38,
        "interval_sec": 60, "staleness_offset_sec": -29,
        "lat": 42.3601, "lng": -71.0589,       # Boston, MA
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-cyberdyne", "hostname": "buoy-cyberdyne-robotics",
        "uptime_sec": 720_000, "load_1": 0.27, "load_5": 0.33, "load_15": 0.31,
        "mem_used_mb": 2580, "mem_total_mb": 4096, "disk_used_pct": 49,
        "interval_sec": 60, "staleness_offset_sec": -16,
        "lat": 44.9778, "lng": -93.2650,       # Minneapolis, MN
        "services": _all_active(),
    },
    {
        "slug": "dev-buoy-pied-piper", "hostname": "buoy-pied-piper-tech",
        "uptime_sec": 540_000, "load_1": 0.16, "load_5": 0.19, "load_15": 0.21,
        "mem_used_mb": 1780, "mem_total_mb": 4096, "disk_used_pct": 36,
        "interval_sec": 60, "staleness_offset_sec": -11,
        "lat": 37.7749, "lng": -122.4194,      # San Francisco, CA
        "services": _all_active(),
    },

    # ─── YELLOW tier — one service flapping, needs operator inspection ─
    {
        "slug": "dev-buoy-globex", "hostname": "buoy-globex-medical",
        "uptime_sec": 800_000, "load_1": 0.92, "load_5": 0.78, "load_15": 0.65,
        "mem_used_mb": 3200, "mem_total_mb": 4096, "disk_used_pct": 72,
        "interval_sec": 60, "staleness_offset_sec": -20,
        "lat": 41.881832, "lng": -87.623177,   # Chicago, IL
        "services": _services(**{"wazuh-agent": "failed", "pihole-FTL": "inactive"}),
    },
    {
        "slug": "dev-buoy-wonka", "hostname": "buoy-wonka-industries",
        "uptime_sec": 1_350_000, "load_1": 0.41, "load_5": 0.38, "load_15": 0.35,
        "mem_used_mb": 2890, "mem_total_mb": 4096, "disk_used_pct": 64,
        "interval_sec": 60, "staleness_offset_sec": -24,
        "lat": 32.7767, "lng": -96.7970,       # Dallas, TX
        "services": _services(**{"opencanary": "failed"}),
    },
    {
        "slug": "dev-buoy-planet-express", "hostname": "buoy-planet-express",
        "uptime_sec": 600_000, "load_1": 0.51, "load_5": 0.48, "load_15": 0.46,
        "mem_used_mb": 2640, "mem_total_mb": 4096, "disk_used_pct": 58,
        "interval_sec": 60, "staleness_offset_sec": -33,
        "lat": 45.5152, "lng": -122.6784,      # Portland, OR
        "services": _services(**{"suricata": "inactive"}),
    },

    # ─── STALE tier — heartbeat 2–5× interval (in the gap) ─────────────
    {
        "slug": "dev-buoy-duff", "hostname": "buoy-duff-brewing",
        "uptime_sec": 2_700_000, "load_1": 0.13, "load_5": 0.15, "load_15": 0.16,
        "mem_used_mb": 1670, "mem_total_mb": 4096, "disk_used_pct": 33,
        "interval_sec": 60, "staleness_offset_sec": -180,   # ~3× interval
        "lat": 33.7490, "lng": -84.3880,       # Atlanta, GA
        "services": _all_active(),
    },

    # ─── RED tier — heartbeat genuinely stale (> 5× interval) ──────────
    {
        "slug": "dev-buoy-initech", "hostname": "buoy-initech-legal",
        "uptime_sec": 60 * 60 * 6, "load_1": 0.02, "load_5": 0.04, "load_15": 0.03,
        "mem_used_mb": 950, "mem_total_mb": 4096, "disk_used_pct": 19,
        "interval_sec": 60, "staleness_offset_sec": -420,   # ~7× interval = red
        "lat": 40.712776, "lng": -74.005974,   # New York, NY
        "services": _all_active(),
    },
]


def _ensure_clients_rows(conn: sqlite3.Connection) -> None:
    """The buoys table doesn't FK to clients.slug, but tenant-scope
    resolution does — for the dashboard endpoint to RETURN these rows,
    the operator needs scope_slugs that include them OR scope='*'.
    Insert matching clients rows for cleanliness."""
    for buoy in SYNTHETIC_BUOYS:
        conn.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, status, kind) "
            "VALUES (?, ?, 'active', 'dev')",
            (buoy["slug"], f"[DEV] {buoy['slug']}"),
        )
    conn.commit()


def _upsert_buoy(conn: sqlite3.Connection, buoy: dict) -> None:
    last_hb = _iso_now(buoy["staleness_offset_sec"])
    boot_time = _iso_now(-buoy["uptime_sec"])
    services_json = json.dumps(buoy["services"], sort_keys=True,
                                separators=(",", ":"))
    conn.execute(
        """
        INSERT INTO buoys (
            slug, hostname, last_heartbeat_at, boot_time,
            uptime_sec, interval_sec,
            load_1, load_5, load_15,
            mem_used_mb, mem_total_mb, disk_used_pct,
            services_json, last_event_at,
            lat, lng,
            created_at, updated_at
        ) VALUES (
            :slug, :hostname, :last_hb, :boot_time,
            :uptime_sec, :interval_sec,
            :load_1, :load_5, :load_15,
            :mem_used_mb, :mem_total_mb, :disk_used_pct,
            :services_json, :last_hb,
            :lat, :lng,
            :last_hb, :last_hb
        )
        ON CONFLICT(slug) DO UPDATE SET
            hostname          = excluded.hostname,
            last_heartbeat_at = excluded.last_heartbeat_at,
            boot_time         = excluded.boot_time,
            uptime_sec        = excluded.uptime_sec,
            interval_sec      = excluded.interval_sec,
            load_1            = excluded.load_1,
            load_5            = excluded.load_5,
            load_15           = excluded.load_15,
            mem_used_mb       = excluded.mem_used_mb,
            mem_total_mb      = excluded.mem_total_mb,
            disk_used_pct     = excluded.disk_used_pct,
            services_json     = excluded.services_json,
            last_event_at     = excluded.last_event_at,
            lat               = COALESCE(excluded.lat, buoys.lat),
            lng               = COALESCE(excluded.lng, buoys.lng),
            updated_at        = excluded.last_heartbeat_at
        """,
        {
            "slug": buoy["slug"],
            "hostname": buoy["hostname"],
            "lat": buoy.get("lat"),
            "lng": buoy.get("lng"),
            "last_hb": last_hb,
            "boot_time": boot_time,
            "uptime_sec": buoy["uptime_sec"],
            "interval_sec": buoy["interval_sec"],
            "load_1": buoy["load_1"],
            "load_5": buoy["load_5"],
            "load_15": buoy["load_15"],
            "mem_used_mb": buoy["mem_used_mb"],
            "mem_total_mb": buoy["mem_total_mb"],
            "disk_used_pct": buoy["disk_used_pct"],
            "services_json": services_json,
        },
    )
    conn.commit()


def _ensure_buoys_schema(conn: sqlite3.Connection) -> None:
    """Apply migration 018 (buoys table) if not already present.
    Idempotent: CREATE TABLE IF NOT EXISTS so re-running is safe.
    Saves the operator from having to restart the dev backend just to
    pick up a schema change before seeding."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master "
        " WHERE type='table' AND name='buoys' LIMIT 1"
    ).fetchone()
    if row is not None:
        return
    repo_root = Path(__file__).resolve().parent.parent
    mig_path = repo_root / "apps" / "octo" / "migrations" / "018-buoys.sql"
    if not mig_path.exists():
        sys.exit(f"migration 018-buoys.sql missing at {mig_path}")
    sql = mig_path.read_text()
    # Strip the `@target: registry` marker — sqlite3 will ignore the
    # comment but the migration body is otherwise pure SQL.
    conn.executescript(sql)
    conn.commit()
    print(f"  applied migration 018 (created buoys table)")


def seed_once(data_root: Path) -> None:
    registry = data_root / "registry.db"
    if not registry.exists():
        sys.exit(f"registry.db missing at {registry}. Run init_data_root first.")
    conn = sqlite3.connect(registry)
    try:
        _ensure_buoys_schema(conn)
        _ensure_clients_rows(conn)
        for buoy in SYNTHETIC_BUOYS:
            _upsert_buoy(conn, buoy)
            print(f"  seeded {buoy['slug']} (staleness offset "
                  f"{buoy['staleness_offset_sec']}s)")
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh-interval", type=int, default=0,
        help="If > 0, keep ALL GREEN buoys' heartbeats fresh by re-seeding "
             "every N seconds. The 3 yellow + 1 stale + 1 red buoys are "
             "left untouched so the synthetic mix stays realistic. "
             "Ctrl-C to stop.",
    )
    args = parser.parse_args()

    data_root_str = os.environ.get("OCTO_DATA_ROOT")
    if not data_root_str:
        sys.exit("OCTO_DATA_ROOT env var required.")
    # The strict check every dev tool shares, before anything under the root
    # is touched: a resolved path under ~/.octo-dev, /tmp or /var/tmp, never
    # a production data-root location.
    problem = dev_root_problem(data_root_str)
    if problem is not None:
        print(f"REFUSING: {problem}. Synthetic buoys MUST NOT touch real OCTO "
              "bundles.", file=sys.stderr)
        sys.exit(3)
    data_root = Path(data_root_str).expanduser().resolve()

    print(f"seeding synthetic buoys into {data_root}/registry.db")
    seed_once(data_root)
    print("done.")

    if args.refresh_interval > 0:
        # Refresh ALL buoys at their authored `staleness_offset_sec` on
        # every tick. The offset is what determines the tier:
        #   - offset > -60s   → green   (fresh, all services active)
        #   - offset ~ -30s   → yellow  (fresh heartbeat + degraded svc)
        #   - offset ~ -180s  → stale   (between 2× and 5× interval)
        #   - offset ~ -420s  → red     (> 5× interval)
        #
        # Without per-tick refresh, each buoy's effective staleness grows
        # by `refresh_interval` seconds per cycle. Green (-15s) reaches
        # red within ~5 min; stale (-180s) reaches red within ~2 min.
        # Per-tick re-seed pins every buoy at its authored offset so the
        # canonical 10g/3y/1stale/1red mix is preserved indefinitely
        # without operator intervention.
        from collections import Counter

        def _tier(b: dict) -> str:
            offset = b.get("staleness_offset_sec", 0)
            services = b.get("services", {})
            interval = b.get("interval_sec", 60)
            if offset < -5 * interval: return "red"
            if offset < -2 * interval: return "stale"
            if all(s == "active" for s in services.values()): return "green"
            return "yellow"

        all_buoys = list(SYNTHETIC_BUOYS)
        breakdown = Counter(_tier(b) for b in all_buoys)
        print(f"\nrefreshing all {len(all_buoys)} buoys every "
              f"{args.refresh_interval}s — pinning "
              f"{breakdown.get('green', 0)}g/"
              f"{breakdown.get('yellow', 0)}y/"
              f"{breakdown.get('stale', 0)}stale/"
              f"{breakdown.get('red', 0)}red mix "
              f"(Ctrl-C to stop)…")
        try:
            while True:
                time.sleep(args.refresh_interval)
                conn = sqlite3.connect(data_root / "registry.db")
                try:
                    for b in all_buoys:
                        _upsert_buoy(conn, b)
                finally:
                    conn.close()
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] "
                      f"refreshed all {len(all_buoys)} buoys")
        except KeyboardInterrupt:
            print("\nstopped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
