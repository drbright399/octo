/**
 * DNS summary contract — GET /api/v1/dashboard/dns-summary (analyst+).
 *
 * Buoy DNS telemetry (answered Pi-hole lookups, Suricata DNS / TLS / HTTP /
 * flow metadata) lives in each tenant's telemetry store since migration 036;
 * this is its dashboard summary. Domains are MASKED by the server (the same
 * rule as the threat-intel pulse — a domain a client looked up is tenant
 * data) and no device name or address is ever sent; the full values come
 * only from the step-up-gated POST /api/v1/search/dns.
 *
 * `lookups` counts ONE sensor (`lookups_source`): Pi-hole's answered
 * queries when the tenant has Pi-hole data, else Suricata's DNS QUERY
 * records (Suricata also logs an answer record per lookup, and Pi-hole's own
 * upstream re-queries, so summing or taking the max would double-count).
 */

export type DnsLookupsSource = "pihole" | "suricata";

export interface DnsDomainRow {
  readonly masked_domain: string;
  /** The tenant's `lookups_source` count for this domain. */
  readonly lookups: number;
  readonly pihole: number;
  readonly suricata: number;
  readonly devices: number;
}

export interface DnsFirstSeenRow {
  readonly masked_domain: string;
  readonly first_seen: string;
  readonly first_event_type: string;
}

export interface DnsTenantSummary {
  readonly tenant: string;
  readonly lookups: number;
  /** Which sensor `lookups` counts (null: no DNS lookups in the window). */
  readonly lookups_source?: DnsLookupsSource | null;
  readonly by_type: Readonly<Record<string, number>>;
  /** Pi-hole lookups filed as signals (blocked, or of unknown status). */
  readonly blocked: number;
  /** Answered lookups sitting in events.db because the telemetry store
   *  refused them at ingest (the nightly sweep moves them): a store fault. */
  readonly fallback_rows?: number;
  /** Answered lookups stored BEFORE the upgrade, still in events.db until
   *  the one-off move runs — not a fault. */
  readonly awaiting_move_rows?: number;
  /** Telemetry writes stored in events.db instead in the last
   *  `store_fallback_window_hours` (recent faults only). */
  readonly recent_store_fallbacks?: number;
  readonly store_fallback_window_hours?: number;
  readonly top_domains: readonly DnsDomainRow[];
  readonly first_seen: readonly DnsFirstSeenRow[];
  readonly first_seen_count: number;
  readonly baseline_since: string | null;
  /** The first-seen ledger is younger than a week: nearly everything is "new". */
  readonly baseline_building: boolean;
}

export type DnsEmptyReason = "no_tenants" | "no_telemetry" | "unavailable";

export interface DnsSummaryResponse {
  readonly window_hours: number;
  readonly tenants: readonly DnsTenantSummary[];
  readonly totals: {
    readonly lookups: number;
    readonly blocked: number;
    readonly first_seen: number;
    readonly fallback_rows?: number;
    readonly awaiting_move_rows?: number;
  };
  readonly masked: boolean;
  readonly unreadable_tenants: number;
  readonly empty_reason: DnsEmptyReason | null;
  readonly empty_detail: string | null;
}
