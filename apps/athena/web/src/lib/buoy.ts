/**
 * Buoy fleet API — client-side bindings to the OCTO dashboard endpoint.
 *
 * Backed by:
 *   GET /api/v1/dashboard/buoy-fleet   (apps/octo/api/routers/dashboard.py)
 *
 * One row per buoy the caller has visibility into. `health` and
 * `staleness_sec` are derived server-side so the UI doesn't have to
 * know the staleness thresholds.
 *
 * Added 2026-05-15 — Buoy Heartbeat slice 5.
 */

import { ApiError } from "@/lib/api";

export type BuoyHealth =
  | "green"      // all probed services active, fresh heartbeat
  | "yellow"     // tailscaled up but at least one non-active service
  | "red"        // tailscaled down OR > 5× interval since last heartbeat
  | "stale"      // > 2× interval but < 5× interval since last heartbeat
  | "unknown";   // services map empty (pre-first-heartbeat fixture rows)

/** Per-unit service info from the heartbeat (2026-05-19 contract
 *  extension). Server normalizes both legacy `{ unit: state_string }`
 *  and new `{ unit: { state, version, ... } }` into this shape. */
export interface ServiceInfo {
  state: string;
  /** `systemctl is-enabled` (heartbeat daemons from v0.11): "disabled" /
   *  "masked" = switched off ON PURPOSE. Absent/null from older daemons. */
  enabled?: string | null;
  version: string | null;
  stat: string | null;
  last_activity: string | null;
}

export interface BuoyFleetRow {
  slug: string;
  hostname: string;
  last_heartbeat_at: string;       // ISO-8601 UTC
  staleness_sec: number;           // server-computed: now - last_heartbeat
  health: BuoyHealth;
  uptime_sec: number;
  interval_sec: number;
  boot_time: string | null;        // ISO, derived from uptime at receipt
  load_1: number | null;
  load_5: number | null;
  load_15: number | null;
  mem_used_mb: number | null;
  mem_total_mb: number | null;
  disk_used_pct: number | null;
  services: Record<string, ServiceInfo>;
  /** Units disabled on purpose and not running — shown grey as "retired",
   *  never a fault (server-computed; the health rollup ignores them). */
  retired_services?: string[];
  last_event_at: string | null;    // when buoy-forwarder last relayed
  // Fleet redesign (2026-05-19 handoff) optional fields. Heartbeat
  // contract extension is its own slice — until that lands, these
  // come back undefined and the map view skips the buoy.
  lat?: number | null;
  lng?: number | null;
  city?: string | null;
  /** Slug of the OCTO this buoy reports to (`OCTOS[]` reference in
   *  the kit). Falls back to the hub's slug client-side until populated. */
  octo?: string | null;
}

export interface BuoyFleetResponse {
  buoys: readonly BuoyFleetRow[];
  scope_slugs: readonly string[];
}

export async function fetchBuoyFleet(): Promise<BuoyFleetResponse> {
  const res = await fetch("/api/v1/dashboard/buoy-fleet", {
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Failed to load buoy fleet",
      res.status,
    );
  }
  return (await res.json()) as BuoyFleetResponse;
}


/** OCTO hub location, read from /api/v1/dashboard/octo-location.
 *  Drives the Fleet map's central hub marker. Mirrors the OctoNode
 *  shape from fleet-map-overlay so the response drops in directly. */
export interface OctoLocationResponse {
  slug: string;
  display: string;
  city: string;
  msp: string;
  lat: number;
  lng: number;
}

export async function fetchOctoLocation(): Promise<OctoLocationResponse> {
  const res = await fetch("/api/v1/dashboard/octo-location", {
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Failed to load OCTO location", res.status);
  }
  return (await res.json()) as OctoLocationResponse;
}

// ---------------------------------------------------------------------------
// Slice 7-8 — Buoy command queue
// ---------------------------------------------------------------------------

export type BuoyCommandKind =
  | "ping"
  | "refresh"
  | "tail-log"
  | "restart-service"
  | "reboot"
  | "update";

export type BuoyCommandStatus =
  | "queued"
  | "dispatched"
  | "completed"
  | "failed"
  | "expired";

/** Minimum role tier required to queue each command_kind. Mirrors the
 *  backend matrix in apps/octo/api/routers/buoy.py (server is the
 *  load-bearing check; this is for UI affordance-hiding only). */
export const BUOY_COMMAND_MIN_ROLE: Record<BuoyCommandKind,
  "viewer" | "analyst" | "admin" | "super_admin"> = {
  ping:              "analyst",
  refresh:           "analyst",
  "tail-log":        "analyst",
  "restart-service": "admin",
  reboot:            "super_admin",
  update:            "super_admin",
};

const ROLE_TIER: Record<string, number> = {
  viewer: 1, analyst: 2, admin: 3, super_admin: 4,
};

/** True if the caller's role tier meets the minimum for this command. */
export function canIssueBuoyCommand(
  callerRole: string | null | undefined,
  kind: BuoyCommandKind,
): boolean {
  const caller = ROLE_TIER[callerRole ?? ""] ?? 0;
  const min = ROLE_TIER[BUOY_COMMAND_MIN_ROLE[kind]] ?? 99;
  return caller >= min;
}


export interface BuoyCommandQueueResponse {
  id: number;
  slug: string;
  command_kind: string;
  status: string;
  requested_at: string;
  expires_at: string;
}

export interface BuoyCommandHistoryRow {
  id: number;
  slug: string;
  command_kind: string;
  args: Record<string, string>;
  status: string;
  requested_by: number;
  requested_at: string;
  dispatched_at: string | null;
  completed_at: string | null;
  expires_at: string;
  result_ok: boolean | null;
  result_exit_code: number | null;
  result_error: string | null;
}


export async function queueBuoyCommand(
  slug: string,
  kind: BuoyCommandKind,
  args: Record<string, string> = {},
): Promise<BuoyCommandQueueResponse> {
  const res = await fetch(`/api/v1/buoy/${encodeURIComponent(slug)}/command`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command_kind: kind, args }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Failed to queue command",
      res.status,
    );
  }
  return (await res.json()) as BuoyCommandQueueResponse;
}


export async function listBuoyCommands(
  slug: string, limit = 50,
): Promise<readonly BuoyCommandHistoryRow[]> {
  const res = await fetch(
    `/api/v1/buoy/${encodeURIComponent(slug)}/commands?limit=${limit}`,
    { credentials: "include" },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string }).code || "Failed to load command history",
      res.status,
    );
  }
  const j = (await res.json()) as { commands: BuoyCommandHistoryRow[] };
  return j.commands;
}


/** "12d 4h" / "37m" / "11s" formatter for uptime + staleness columns.
 *  Always two units max, biggest first; drops zero-leading components. */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return sec > 0 ? `${m}m ${sec}s` : `${m}m`;
  return `${sec}s`;
}

/** `systemctl is-enabled` answers meaning "switched off". */
const RETIRED_ENABLEMENT = new Set(["disabled", "masked", "masked-runtime"]);

/** The server's default list of units an OPERATOR retired
 *  (OCTO_BUOY_RETIRED_UNITS). The buoy saying "disabled" is never enough on
 *  its own — that is what `systemctl disable --now wazuh-agent` leaves. */
const DEFAULT_RETIRED_UNITS = new Set(["octo-forwarder"]);

/** A unit retired on purpose: grey, not a fault. The server's
 *  `retired_services` (its operator list applied) wins when present; a row
 *  without it gets the same rule with the default list. */
export function isRetiredService(
  unit: string,
  info: ServiceInfo | undefined,
  retired?: readonly string[] | undefined,
): boolean {
  if (retired) return retired.includes(unit);
  if (!info) return false;
  return DEFAULT_RETIRED_UNITS.has(unit)
    && info.state !== "active" && RETIRED_ENABLEMENT.has(info.enabled ?? "");
}
