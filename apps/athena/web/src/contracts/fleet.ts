/**
 * Fleet v2 — the site-centric fleet (`GET /api/v1/fleet/sites`).
 *
 * `view: "operator"` (analyst+): every site in scope WITH location, vendor
 * names, deep links, vendor ids, ISP-outage incidents.
 * `view: "client"` (a client user): their own sites only, neutral wording,
 * no location, no link, no vendor id — the UI must not add vendor names back.
 *
 * `notice` (the quiet tier, 2026-10-02): seen, not a problem — a one-off
 * internet blip, an access point offline, trouble that is likely regional.
 * Listed in grey; the map pin stays green (a grey ring at most).
 *
 * Tier Black (slice 1): `black` ranks above `bad` (Red). Red and Black come
 * ONLY from incident records — the `threat` layer — never from a health
 * layer (network / security / endpoints / buoy stop at `warn`). The wire
 * codes `warn` / `bad` are unchanged: only their labels became Yellow / Red.
 */

export type SiteState = "ok" | "notice" | "warn" | "bad" | "unknown" | "black";
export type LayerState = SiteState | "absent";
export type HealthLayerName = "network" | "security" | "endpoints" | "buoy";
export type LayerName = "threat" | HealthLayerName;
export const LAYER_NAMES: readonly LayerName[] = ["threat", "network", "security", "endpoints", "buoy"];
export const HEALTH_LAYER_NAMES: readonly HealthLayerName[] = ["network", "security", "endpoints", "buoy"];

export interface FleetReason {
  state: SiteState;
  text: string;
  layer: string;
}

export interface FleetLayer {
  name: LayerName;
  present: boolean;
  state: LayerState;
  /** "site" = this site's own data; "tenant" = the client's, on each of its sites. */
  scope: "site" | "tenant";
  reasons: FleetReason[];
  data: Record<string, unknown>;
  as_of: string | null;
  note?: string | null;
}

export interface FleetLocation {
  lat: number;
  lng: number;
  label: string;
  /** "site": this site's own hand-set (locked) pin; "unifi": what the
   *  console reports; "manual": the client's fallback location. */
  source: "unifi" | "manual" | "site";
}

export interface FleetLink {
  vendor: string;
  label: string;
  url: string;
  verified: boolean;
}

export interface FleetVendorRef {
  instance_id: number;
  host_id: string;
  site_id: string;
  problem?: string | null;
}

/** The site's worst OPEN incident — operators. */
export interface SiteIncident {
  tenant_slug?: string;
  id: number;
  tier: "red" | "black";
  status: string;
  acked: boolean;
  acked_by: string | null;
  /** Who acknowledged it, by name — the acknowledged Black pin's initials. */
  acked_by_name?: string | null;
  contained: boolean;
  opened_at: string;
  age_s: number;
  rule_id: string;
  rule_version?: number;
  summary?: string;
  device_label: string | null;
  unknown_location?: boolean;
  open_count?: number;
  /** A RESTRICTED incident (B7, CSAM): no rule, summary or device here for
   *  any operator; only an admin opens its (audited) detail. */
  restricted?: boolean;
}

/** What a CLIENT user receives about an incident: the neutral line and the
 *  two actions — never a device, an indicator, a rule or an acknowledgement. */
export interface ClientSiteIncident {
  ref: string;
  tier: "red" | "black" | null;
  status_neutral: string;
  opened_at: string;
  actions: { kind: "lockdown" | "allow"; label: string }[];
}

/** Where a hand-set pin came from (operators only): "autotask" = an
 *  Autotask address an operator confirmed from a proposal. */
export interface SiteProvenance {
  origin: string;
  by: string | null;
  at: string | null;
}

export interface FleetSite {
  key: string;
  kind: "site" | "tenant";
  name: string;
  tenant_slug: string | null;
  tenant_name: string;
  console_name: string | null;
  state: SiteState;
  reason: string;
  reasons: FleetReason[];
  location: FleetLocation | null;
  /** Operators: set when the pin was confirmed from a proposal. */
  provenance?: SiteProvenance | null;
  /** The four health layers always; `threat` (incident records) from slice 1. */
  layers: Record<HealthLayerName, FleetLayer> & { threat?: FleetLayer };
  links: FleetLink[];
  vendor_ref: FleetVendorRef | null;
  tenant_sites: number;
  partial: boolean;
  /** Operators: the worst open incident; a client user: a VISIBLE one, neutral. */
  incident?: SiteIncident | ClientSiteIncident | null;
}

/** An open Red / Black for the banner and the strip (operators). */
export interface ThreatItem {
  tenant: string;
  tenant_name: string;
  id: number;
  tier: "red" | "black";
  status: string;
  acked: boolean;
  acked_by: string | null;
  acked_by_name?: string | null;
  contained: boolean;
  opened_at: string;
  age_s: number;
  rule_id: string;
  rule_version?: number;
  summary: string;
  device_label: string | null;
  unknown_location: boolean;
  site_keys: string[];
  /** A RESTRICTED incident (B7, CSAM): "restricted incident — admins only";
   *  an admin acknowledges it, nobody else. */
  restricted?: boolean;
}

/** FR2 — "Athena is blind to <source> since …" (operators). */
export interface BlindSource {
  source: string;
  label: string;
  since: string;
  fleet_wide: boolean;
  why: string;
  tenants: string[];
}

/** WAN coverage over the UniFi sites in scope (operators). */
export interface WanCoverage {
  sites_with_backup: number;
  sites_without_backup: number;
  sites_backup_unknown: number;
}

export interface IspOutageMember {
  tenant: string | null;
  name: string | null;
  since: string | null;
  why: string | null;
  recovered_at: string | null;
  key: string | null;
}

export interface IspOutage {
  vid?: string | null;
  open: boolean;
  asn?: number;
  isp?: string;
  since?: string;
  opened_at?: string;
  closed_at?: string | null;
  sites?: number;
  sites_down?: number;
  members?: IspOutageMember[];
  tenant?: string | null;
  event_id?: number | null;
  suppressed?: { at: string; sites: number; asns: number; observed: number };
}

/** Sites whose internet issues are held at "notice" as likely regional
 *  (operators; the members in the caller's scope only). */
export interface RegionalGroup {
  kind: "isp" | "area";
  sites: number;
  keys: string[];
  asn?: number | null;
  isp?: string | null;
  km?: number | null;
}

export interface FleetSitesResponse {
  view: "operator" | "client";
  generated_at: string;
  partial: boolean;
  sites: FleetSite[];
  counts: Record<string, number>;
  isp_outages: IspOutage[];
  unmapped_sites: number | null;
  tenants: { slug: string; name: string }[];
  regional?: RegionalGroup[];
  threats?: ThreatItem[];
  blind?: BlindSource[];
  coverage?: WanCoverage | null;
  /** Operators: "Threats stopped this week: N" — security-category DNS
   *  blocks over 7 days across the caller's scope. A client user: absent. */
  threats_stopped_week?: number | null;
}

/** v0.17.2 — where an alert stands after the humans' verdicts. "open" and
 *  "resurfaced" need attention; "acknowledged" / "expected" are listed only
 *  with "show acknowledged" (greyed). */
export type AlertStatus = "open" | "acknowledged" | "expected" | "resurfaced";

/** v0.17.5 — the recall of an acknowledgement: it covers nothing since. */
export interface AlertAckRecall {
  /** null only when the follow-ups could not be read (the time is known). */
  by: number | null;
  by_name: string | null;
  at: string;
  reason: string | null;
}

/** v0.17.5 — context added under an acknowledgement after it was made. */
export interface AlertAckNote {
  by: number;
  by_name: string | null;
  at: string;
  note: string;
}

export interface AlertAck {
  /** v0.17.5 — the ack's id: the recall and notes routes name it. */
  verdict_id?: number;
  by: number;
  by_name: string | null;
  at: string;
  note: string | null;
  repeat_until: string | null;
  by_repeat: boolean;
  /** v0.17.5 — set on an OPEN alert whose deciding ack was recalled. */
  recalled?: AlertAckRecall | null;
  /** v0.17.5 — follow-up notes, oldest first (newest last). */
  notes?: AlertAckNote[];
}

export interface AlertRule {
  id: number;
  label: string;
  review_at: string;
  remote: string | null;
}

export interface RemoteLabel {
  kind: "scanner" | "vendor";
  name: string;
  basis: "network" | "ptr" | "rdap";
}

/** A remote address as the enrichment cache knows it (operators only). */
export interface RemoteIntel {
  ptr?: string | null;
  ptr_confirmed?: boolean;
  org?: string | null;
  net_name?: string | null;
  cidr?: string | null;
  country?: string | null;
  labels: RemoteLabel[];
  pending: boolean;
  failed: boolean;
  as_of?: string | null;
}

export interface IpsEnrichment {
  kind: "unifi_ips";
  direction: "inbound" | "outbound" | null;
  action: "blocked" | "detected";
  signature: string | null;
  remote_ip: string | null;
  local_ip: string | null;
  local_name: string | null;
  local_name_source: "datto" | "unifi" | null;
  remote: RemoteIntel | null;
  repeats_24h: number | null;
  repeats_approximate: boolean;
  hits: number | null;
  last_seen: string | null;
}

export interface DattoEnrichment {
  kind: "datto";
  line: string;
  class: string;
  host: string | null;
  resolved: boolean;
  priority: string | null;
  noc: boolean;
  details: string[];
  repeats: number;
  since: string | null;
  /** WHICH device (v0.17.2): repeats are keyed by this Datto device uid,
   *  never the host name. */
  device_uid?: string | null;
  site?: string | null;
  lan_ip?: string | null;
  wan_ip?: string | null;
  /** How many devices of the client carry this host name (0 = only this
   *  one) and at how many Datto sites. */
  shared_hostname?: number;
  shared_sites?: number;
  /** v0.17.3 — from the device's Datto audit (operators only): its serial
   *  number, manufacturer and model; null = not known (not read yet, or the
   *  vendor's value is a placeholder). */
  serial?: string | null;
  manufacturer?: string | null;
  model?: string | null;
  /** The serials of the OTHER devices with this host name, where known. */
  shared_serials?: string[];
}

export type AlertEnrichment = IpsEnrichment | DattoEnrichment;

export interface SiteAlert {
  event_id: number;
  occurred_at: string;
  severity: string;
  source: string;
  title: string;
  tenant_wide: boolean;
  status?: AlertStatus;
  ack?: AlertAck | null;
  rule?: AlertRule | null;
  new_since_ack?: number;
  /** May it be marked expected — else `expected_refusal` says why. */
  can_expect?: boolean;
  expected_refusal?: string | null;
  /** May "acknowledge repeats for 24 h" be offered (not for an alert that
   *  names no device, nor a CSAM lookup). */
  can_repeat?: boolean;
  /** A network (IPS) alert: an expected condition may name its remote. */
  network?: boolean;
  hits?: number | null;
  last_seen?: string | null;
  enrichment?: AlertEnrichment | null;
}

export interface SiteAlertsResponse {
  key: string;
  items: SiteAlert[];
  /** Acknowledged / expected alerts left out of "needs attention". */
  hidden?: number;
  include_acknowledged?: boolean;
}

/** v0.17.2 — an expected condition (Settings → Threats). */
export interface ExpectedRule {
  id: number;
  tenant_slug: string;
  source: string;
  device_key: string;
  signature_key: string;
  remote: string | null;
  label: string;
  reason: string;
  origin_event_id: number;
  created_by: number;
  created_by_name: string | null;
  created_at: string;
  review_at: string;
  reminded_at: string | null;
  revoked_at: string | null;
  revoked_by: number | null;
  revoked_by_name: string | null;
  revoke_reason: string | null;
  status: "active" | "expired" | "revoked";
}

export interface TenantLocation {
  slug: string;
  tenant_name: string;
  override: { lat: number; lng: number; label: string; set_at: string } | null;
  unifi_sites: { name: string; lat: number; lng: number; label: string }[];
  unlocated_unifi_sites: number;
  /** The tenant's sites on a console carrying several sites: the console
   *  reports its OWN location, not each site's. */
  multi_site_console_sites?: number;
  /** The client's sites pinned by their OWN location (the Fleet drawer). */
  site_pins?: number;
  /** "manual": every pinned site uses this fallback; "mixed": some do;
   *  "unifi": none does (consoles / site pins); "none": nothing pinned. */
  effective: "unifi" | "manual" | "mixed" | "none";
}

export interface FleetPoint {
  lat: number;
  lng: number;
  label: string;
}

/** One site's location editor (`/api/v1/fleet/sites/{key}/location`, admin+). */
export interface SiteLocation {
  key: string;
  kind: "site" | "tenant";
  name: string;
  tenant_slug: string;
  tenant_name: string;
  /** This site's own hand-set (locked) location; `origin` "autotask" = an
   *  Autotask address confirmed by `set_by_name`. */
  override: {
    lat: number; lng: number; label: string; set_at: string;
    origin?: string; set_by_name?: string | null;
  } | null;
  /** What the UniFi console REPORTS — shown even when overridden. */
  console: FleetPoint | null;
  console_sites: number;
  console_shared: boolean;
  tenant_fallback: FleetPoint | null;
  current: FleetLocation | null;
  effective: "site" | "unifi" | "tenant" | "none";
  /** "census" when the address lookup is on; null → no Find button. */
  geocoder: string | null;
  /** Open location proposals for this site ("Autotask suggests …") and,
   *  `unassigned`, the client's not yet assigned to any site. */
  proposals?: { id: number; source: string; label: string; unassigned?: boolean }[];
}

export interface GeocodeResponse {
  provider: string;
  matches: FleetPoint[];
}
