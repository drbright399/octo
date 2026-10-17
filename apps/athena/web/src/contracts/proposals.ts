/**
 * Proposals — an integration proposes, an operator confirms
 * (`/api/v1/proposals`, admin+ only; a client user never sees one).
 *
 * The first kind is "site_location": Autotask company / company-location
 * addresses proposed as Fleet site pins. A proposal is "proposed" until an
 * admin confirms (the pin is written, origin "autotask") or rejects it —
 * both with a reason, audited. A rejected one is never proposed again while
 * Autotask says the same; a change supersedes the open one.
 */

export type ProposalStatus = "proposed" | "confirmed" | "rejected" | "superseded";

/** A warning on a proposal. Codes:
 *  - shared_address: the same address is another client's too (`tenants`:
 *    their names in your scope; `others_hidden`: more outside it);
 *  - shared_company: the Autotask company is mapped to other clients too
 *    (`tenants`, `others_hidden` as above);
 *  - incomplete: `missing` street / zip / city / state (`po_box`: the
 *    street is only a PO box);
 *  - several_addresses: `count` distinct addresses for a one-site client;
 *  - site_name_differs: the client's only site (`site`) is named for
 *    something the address is not;
 *  - current_pin_differs: the target has a pin set by hand (`pin`: source
 *    "site" = its own, "manual" = the client's fallback location);
 *  - far_from_console: the lookup's first match is `km` from the console. */
export interface ProposalFlag {
  code: string;
  tenants?: string[];
  others_hidden?: boolean;
  missing?: string[];
  po_box?: boolean;
  count?: number;
  km?: number;
  site?: string;
  pin?: { lat: number; lng: number; label: string; source: string; origin?: string };
}

/** The pin a target shows now: "site" (its own, set by hand or confirmed),
 *  "manual" (the client's fallback location) or "unifi" (the console's). */
export interface ProposalCurrentPin {
  lat: number; lng: number; label: string; source: string;
  origin?: string | null; by?: string | null;
}

export interface ProposalMatch {
  lat: number;
  lng: number;
  label: string;
  km_from_console?: number;
}

export interface LocationProposal {
  id: number;
  kind: string;
  source: string;
  status: ProposalStatus;
  tenant_slug: string;
  tenant_name: string;
  /** Null: "pick a site" — the operator chooses when confirming. */
  target_key: string | null;
  target_name: string | null;
  target_mode: "site" | "tenant" | "pick";
  source_ref: string;
  /** "company" (the company address) | "location" (a company location). */
  origin: string;
  name: string;
  /** The address as proposed (with its suite) — the pin's default label. */
  label: string;
  address: Record<string, unknown>;
  flags: ProposalFlag[];
  /** Autotask changed the address: what it said before (and what became of it). */
  previous: { id: number; status: string; label: string | null; target_key: string | null } | null;
  /** The same address was confirmed earlier for an entry that is gone (the
   *  client gained a UniFi site): offered again for the new one. */
  confirmed_before?: boolean;
  matches: ProposalMatch[];
  looked_up_at: string | null;
  /** The target's pin today (console, fallback or hand-set). */
  current: ProposalCurrentPin | null;
  created_at: string;
  /** Sent back with a confirm: what was reviewed (a change since is a 409). */
  updated_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_reason: string | null;
}

export interface ProposalTarget {
  key: string;
  name: string;
  kind: "site" | "tenant";
  /** What the map shows there now. */
  current?: ProposalCurrentPin | null;
  /** When its own pin was set (null: none) — sent back with a confirm. */
  pin_set_at?: string | null;
  /** Where its UniFi console says it is. */
  console?: { lat: number; lng: number } | null;
}

export interface ProposalsResponse {
  kind: string;
  items: LocationProposal[];
  open: number;
  /** "census" when the address lookup is on; null → no Look up. */
  geocoder: string | null;
  /** An Autotask instance is running (Refresh works). */
  autotask: boolean;
  last_refresh: {
    at?: string;
    trigger?: string;
    /** "read" | "refused" (company addresses only) | "unavailable" | "none". */
    locations?: string;
    skipped_non_us?: string[];
    [k: string]: unknown;
  } | null;
  targets: Record<string, ProposalTarget[]>;
}

export interface ProposalSummary {
  kind: string;
  open: number;
}

export interface ProposalRefreshResponse {
  kind: string;
  open: number;
  summary: Record<string, unknown>;
}
