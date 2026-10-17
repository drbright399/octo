/**
 * Indicator (IOC) contract — the threat-intel pulse widget + indicator search.
 *
 * `IndicatorType` is the indicators.db CHECK list (migration 002), exactly:
 * the only types a stored indicator can have. tests/indicator-contract.test.ts
 * fails if the two drift.
 *
 * `IndicatorSourceKind` is provenance, as GET /dashboard/ti-pulse reports it:
 *   - "integration" — sighted in an event from one of the MSP's integrations
 *     (the ingest sink records the IOC an event carries: today Wazuh- and
 *     UniFi-sourced events carry an IP; Datto RMM and RocketCyber alerts carry
 *     none). Every stored indicator today is this kind.
 *   - "internal" — agent-derived. Reserved; nothing writes it yet.
 *   - "msp_pool" — the cross-MSP sanitized pool. Reserved; the pool is on a
 *     pre-LIVE hold and not running.
 * No public threat-intel feed is connected, so there is no feed kind.
 *
 * Values: the pulse only ever carries a MASKED value (owner decision
 * 2026-09-28). The full value is tenant data, read through the step-up-gated
 * /search/indicators using the row's `search_ref`.
 */

export const INDICATOR_TYPES = [
  "ip",
  "ipv6",
  "domain",
  "url",
  "md5",
  "sha1",
  "sha256",
  "email",
  "cidr",
  "cve",
  "other",
] as const;

export type IndicatorType = (typeof INDICATOR_TYPES)[number];

export const INDICATOR_TYPE_LABEL: Record<IndicatorType, string> = {
  ip: "IP",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  email: "Email",
  cidr: "CIDR",
  cve: "CVE",
  other: "Other",
};

export type IndicatorSourceKind = "integration" | "internal" | "msp_pool";

export const INDICATOR_SOURCE_LABEL: Record<IndicatorSourceKind, string> = {
  integration: "integration",
  internal: "internal analysis",
  msp_pool: "MSP pool",
};

/** One row of GET /api/v1/dashboard/ti-pulse. */
export interface TiPulseItem {
  readonly tenant: string;
  readonly type: IndicatorType;
  /** Display-safe form (203.0.x.x, ex*****.test, first 8 of a hash…). */
  readonly masked_value: string;
  /** Severity of the event that first recorded it. */
  readonly severity: "low" | "medium" | "high" | "critical";
  readonly first_seen: string;
  readonly last_seen: string;
  /** Times sighted. */
  readonly count: number;
  readonly source_kind: IndicatorSourceKind;
  /** "<tenant>:<indicator id>" — names the row, never the value. */
  readonly search_ref: string;
}

export type TiPulseEmptyReason =
  | "no_tenants"
  | "no_indicators"
  | "none_recent"
  | "unavailable";

export interface TiPulseResponse {
  readonly items: readonly TiPulseItem[];
  /** The cross-MSP pool — always "not_running" on this build. */
  readonly pool_status: "not_running" | "running";
  readonly empty_reason: TiPulseEmptyReason | null;
  /** One sentence explaining an empty `items`, from the server. */
  readonly empty_detail: string | null;
  /** In-scope tenants whose indicators couldn't be read this time; non-zero
   *  with items = a PARTIAL list. */
  readonly unreadable_tenants: number;
  readonly lookback_days: number;
}

/** Split a pulse `search_ref` ("<tenant>:<id>") — null when malformed. */
export function parseIndicatorRef(
  ref: string | null | undefined,
): { readonly tenant: string; readonly id: number } | null {
  if (!ref) return null;
  const idx = ref.lastIndexOf(":");
  if (idx <= 0) return null;
  const tenant = ref.slice(0, idx);
  const idText = ref.slice(idx + 1);
  if (!/^\d+$/.test(idText)) return null;
  const id = Number(idText);
  return Number.isSafeInteger(id) && id > 0 ? { tenant, id } : null;
}

/** The step-up-gated search that shows a pulse row's full value. */
export function indicatorSearchHref(ref: string): string {
  return `/search/indicators?indicator=${encodeURIComponent(ref)}`;
}
