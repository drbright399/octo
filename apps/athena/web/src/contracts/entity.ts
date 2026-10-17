/**
 * Entity resolution (migration 040) — "where and who, at the moment of the
 * alert, how sure, and why". Shapes of `/api/v1/entity/*` and
 * `/api/v1/admin/known-benign`.
 *
 * Every string here is server text or vendor text (device names are shown
 * unmasked — owner decision 2026-10-01): render as TEXT NODES only.
 */

export type EntityMode = "off" | "shadow" | "on";

export type Tier =
  | "exact"
  | "strong"
  | "medium"
  | "weak"
  | "candidate"
  | "suggest"
  | "conflict"
  | "none";

export interface ResolutionWhere {
  readonly site_id: string | null;
  readonly label: string | null;
  readonly basis: "located" | "policy" | "both" | "not_located" | "none" | null;
  readonly score: number | null;
  readonly tier: Tier | null;
  readonly tier_word: string;
}

export interface ResolutionDevice {
  readonly ref: string | null;
  readonly tier: Tier;
  readonly tier_word: string;
  readonly score: number | null;
  readonly n_candidates: number | null;
}

export interface ResolutionCandidate {
  readonly label: string;
  readonly score: number | null;
  readonly features: readonly string[];
  readonly conn: string | null;
  readonly match: string | null;
  readonly lease_id: number | null;
  readonly mac_kind: string | null;
}

export interface ReviewLinkRef {
  readonly kind: "site";
  readonly id: number;
  readonly vendor: string;
  readonly scope: string;
  readonly state: "suggested" | "auto";
  readonly rule: string;
  readonly score: number;
}

export interface Resolution {
  readonly slug: string;
  readonly event_id: number;
  readonly mode: EntityMode;
  readonly visible: boolean;
  readonly resolved: boolean;
  readonly reason?: string | null;
  readonly status?: "final" | "provisional" | "stale" | "superseded" | null;
  readonly at?: string | null;
  readonly where?: ResolutionWhere | null;
  readonly device?: ResolutionDevice | null;
  readonly why: readonly string[];
  readonly flags: readonly string[];
  readonly candidates: readonly ResolutionCandidate[];
  readonly candidates_aged_out: boolean;
  readonly review: readonly ReviewLinkRef[];
  readonly resolver_version?: string | null;
}

export interface SiteRefRow {
  readonly id: number;
  readonly site_id: string;
  readonly site_label: string | null;
  /** The site's location text (the UniFi console's), when known. */
  readonly site_location?: string | null;
  /** The vendor's own name for the scope (a NextDNS profile's name). */
  readonly vendor_label?: string | null;
  readonly vendor: string;
  readonly vendor_scope_id: string;
  readonly state: string;
  readonly score: number;
  readonly rule_id: string;
  readonly evidence: Record<string, unknown>;
}

export interface DeviceLinkRow {
  readonly id: number;
  readonly state: string;
  readonly rule: string;
  readonly score: number;
  readonly evidence: Record<string, unknown>;
  readonly nextdns: { name: string | null; model: string | null; client: string | null; last_seen: string | null } | null;
  readonly datto: { hostname: string | null; online: number | null; last_seen: string | null; os: string | null } | null;
  readonly watch: { state: string; since: string | null; alert_event_id: number | null } | null;
}

export interface ConflictRow {
  readonly id: number;
  readonly kind: string;
  readonly subject: string;
  readonly detail: Record<string, unknown>;
  readonly first_seen: string;
  readonly last_seen: string;
  readonly hits: number;
  /** How an operator closed it: resolved (sticks until the evidence
   *  materially changes) or accepted (expected; the check is suppressed). */
  readonly resolution?: "resolved" | "accepted" | null;
  readonly resolved_at?: string | null;
  readonly resolved_by?: string | null;
}

export interface ReviewQueue {
  readonly slug: string;
  readonly resolved: boolean;
  readonly sites: readonly SiteRefRow[];
  readonly names: readonly SiteRefRow[];
  readonly devices: readonly DeviceLinkRow[];
  readonly conflicts: readonly ConflictRow[];
  /** Routing conflicts accepted as expected (Reopen ends the acceptance). */
  readonly accepted?: readonly ConflictRow[];
}

export interface EntityStatus {
  readonly slug: string;
  readonly mode: EntityMode;
  readonly resolved: boolean;
  readonly sites: number;
  readonly open_leases: number;
  readonly resolutions: number;
  readonly to_review: number;
  readonly conflicts: number;
}

export interface KnownBenignRule {
  readonly id: number;
  readonly vendor: "nextdns";
  readonly match_kind: "exact" | "suffix" | "regex";
  readonly pattern: string;
  readonly reasons: readonly string[];
  readonly level: "low" | "medium";
  readonly label: string;
  readonly note: string;
  readonly enabled: boolean;
}

export interface KnownBenignInput {
  readonly vendor: "nextdns";
  readonly match_kind: "exact" | "suffix" | "regex";
  readonly pattern: string;
  readonly reasons: readonly string[];
  readonly level: "low" | "medium";
  readonly label: string;
  readonly note: string;
  readonly enabled: boolean;
  readonly reason: string;
}

/** Plain words for a tier — the badge text. */
export const TIER_LABEL: Record<Tier, string> = {
  exact: "EXACT",
  strong: "STRONG",
  medium: "PROBABLE",
  weak: "POSSIBLE",
  candidate: "CANDIDATES",
  suggest: "NAME MATCH ONLY",
  conflict: "CONFLICT",
  none: "NOT IDENTIFIED",
};

export const BASIS_LABEL: Record<string, string> = {
  both: "located + policy",
  located: "located (internet address)",
  policy: "policy (the alert's profile / site)",
  not_located: "not located (the address is not this client's)",
  none: "unknown",
};
