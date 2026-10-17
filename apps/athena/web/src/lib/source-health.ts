/**
 * Source health — client binding for the dashboard's one source view.
 *
 * Backed by:
 *   GET /api/v1/dashboard/source-health   (apps/octo/api/routers/source_health.py)
 *
 * Every age is computed server-side (receive clock) so a skewed browser
 * clock cannot make a feed look fresh or stale. `view` says what the caller
 * may see: "full" (analyst+) lists every source in scope; "tenant" (viewer —
 * a client user) carries only their own tenants' freshness, never a vendor
 * or instance name, a threshold or a health verdict.
 */

import { ApiError } from "@/lib/api";

export type SourceKind = "adapter" | "ingest_token" | "buoy";
export type SourceStatus = "ok" | "degraded" | "down" | "pending" | "unknown";
/** Which clock the stale threshold applies to: a poller's last successful
 *  poll, a push source's last event, a buoy's last heartbeat. */
export type FreshnessBasis = "contact" | "event" | "heartbeat";

export interface SourceHealthRow {
  readonly id: string;
  readonly kind: SourceKind;
  readonly name: string;
  readonly vendor: string | null;
  /** Null for an integration instance (it serves many tenants). */
  readonly tenant_slug: string | null;
  readonly status: SourceStatus;
  readonly stale: boolean;
  readonly detail: string | null;
  readonly freshness_basis: FreshnessBasis;
  readonly stale_after_sec: number;
  /** A token's: its last ACCEPTED post. */
  readonly last_event_at: string | null;
  readonly last_event_age_sec: number | null;
  /** Last successful poll / last heartbeat / a token's last request
   *  (accepted or not). */
  readonly last_contact_at: string | null;
  readonly last_contact_age_sec: number | null;
  /** The vendor is rate limiting this integration right now (NextDNS):
   *  calls wait out a backoff. Shown as "throttled" — never as a failure. */
  readonly throttled?: boolean;
  /** Per-profile DNS-filtering protection (NextDNS), scoped to the caller. */
  readonly protection?: ProtectionSummary | null;
}

export interface ProtectionProfile {
  readonly profile_id: string;
  readonly name: string;
  readonly tenant_slug: string | null;
  readonly state: "new" | "pending" | "active" | "lapsed";
  readonly since: string | null;
  readonly queries_24h: number | null;
  /** NextDNS no longer shows the profile to the key (HTTP 404). */
  readonly missing?: boolean;
  /** The poller's current problem with this profile (operator text). */
  readonly problem?: string | null;
}

export interface ProtectionSummary {
  readonly active: number;
  readonly pending: number;
  readonly lapsed: number;
  readonly missing?: number;
  readonly problems?: number;
  readonly profiles: readonly ProtectionProfile[];
}

export interface TenantFreshnessRow {
  readonly slug: string;
  readonly display_name: string;
  readonly last_event_at: string | null;
  readonly last_event_age_sec: number | null;
  /** "none" = nothing received yet. "degraded" (full view only) = a source
   *  delivering into the tenant is degraded or down. The age of the last
   *  alert alone never makes a tenant degraded — no alerts is good news. */
  readonly state: "ok" | "degraded" | "none";
}

export interface SourceHealthResponse {
  readonly view: "full" | "tenant";
  readonly generated_at: string;
  readonly sources: readonly SourceHealthRow[];
  readonly tenants: readonly TenantFreshnessRow[];
}

export async function fetchSourceHealth(): Promise<SourceHealthResponse> {
  const res = await fetch("/api/v1/dashboard/source-health", {
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Failed to load source health", res.status);
  }
  return (await res.json()) as SourceHealthResponse;
}

/** "4m ago" from a server-computed age in seconds. */
export function formatAge(seconds: number): string {
  if (seconds < 60) return `${Math.max(0, Math.floor(seconds))}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** "2h" / "90m" / "2m" — a threshold, not an age. */
export function formatSpan(seconds: number): string {
  if (seconds % 3600 === 0 && seconds >= 3600) return `${seconds / 3600}h`;
  if (seconds >= 60) return `${Math.round(seconds / 60)}m`;
  return `${seconds}s`;
}
