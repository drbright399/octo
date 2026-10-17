/**
 * Fleet v2 API + the pure helpers the Fleet tab filters and colours with.
 * Cookies only (credentials: "include"), nothing cached in storage. A 401
 * from a dead console session hard-redirects to /login.
 */
import { ApiError } from "@/lib/api";
import type { OctoLocationResponse } from "@/lib/buoy";
import type {
  ExpectedRule,
  FleetSite,
  FleetSitesResponse,
  GeocodeResponse,
  LayerName,
  SiteAlertsResponse,
  SiteIncident,
  SiteLocation,
  SiteState,
  TenantLocation,
  ThreatItem,
} from "@/contracts/fleet";

/** One JSON call (cookies, no cache); also the proposals API's (lib/proposals). */
export async function call<T>(
  url: string, init: RequestInit = {}, fallback = "Request failed", redirectOn401 = true,
): Promise<T> {
  const opts: RequestInit = { credentials: "include", cache: "no-store", ...init };
  if (init.body) {
    opts.headers = { "Content-Type": "application/json" };
  }
  const res = await fetch(url, opts);
  const body = (await res.json().catch(() => ({}))) as { message?: string; code?: string };
  if (redirectOn401 && res.status === 401 && (body.code ?? "").startsWith("AUTH_SESSION_")) {
    window.location.href = "/login";
    throw new ApiError("Your session has expired — signing in again", 401, body.code);
  }
  if (!res.ok) {
    throw new ApiError(body.message || body.code || fallback, res.status, body.code);
  }
  return body as T;
}

const seg = (s: string): string => encodeURIComponent(s);

/** `quiet`: a dead session is just an error (the sidebar badge polls on
 *  every route, the login page included — it must never redirect). */
export function fetchFleetSites(opts: { quiet?: boolean } = {}): Promise<FleetSitesResponse> {
  return call<FleetSitesResponse>("/api/v1/fleet/sites", {}, "The fleet could not be loaded",
    !opts.quiet);
}

/** The drawer's "needs attention" list; `acknowledged` adds the
 *  acknowledged / expected alerts (greyed). */
export function fetchSiteAlerts(
  key: string, opts: { acknowledged?: boolean } = {},
): Promise<SiteAlertsResponse> {
  const q = opts.acknowledged ? "?include=acknowledged" : "";
  return call<SiteAlertsResponse>(`/api/v1/fleet/sites/${seg(key)}/alerts${q}`, {},
    "Recent alerts could not be loaded");
}

// ---- v0.17.2: acknowledge / expected (analyst+; the routes enforce it) ----

export const ACK_NOTE_MAX = 500;
export const EXPECTED_REASON_MIN = 10;
export const REVIEW_MAX_DAYS = 90;

const postJson = <T,>(path: string, body: object, fallback: string): Promise<T> =>
  call<T>(path, { method: "POST", body: JSON.stringify(body) }, fallback);

export interface VerdictOut {
  verdict_id: number;
  event_id: number;
  tenant_slug: string;
  verdict: string;
  at: string;
  repeat_until: string | null;
  rule_id: number | null;
}

/** `seen_hits` / `seen_last`: the coalesced row as the list showed it — the
 *  ack never covers hits that arrived after. */
export function ackAlert(
  slug: string, eventId: number,
  body: { note?: string; repeat_24h?: boolean; seen_hits?: number; seen_last?: string },
): Promise<VerdictOut> {
  return postJson<VerdictOut>(`/api/v1/alerts/${seg(slug)}/${eventId}/ack`, body,
    "The alert could not be acknowledged");
}

export function expectAlert(
  slug: string, eventId: number, body: { reason: string; review_days: number; remote?: string },
): Promise<VerdictOut> {
  return postJson<VerdictOut>(`/api/v1/alerts/${seg(slug)}/${eventId}/expected`, body,
    "The alert could not be marked expected");
}

// ---- v0.17.5: recall an acknowledgement / a note under it (analyst+) ----

/** A recall's reason is at least this long (the server says so too). */
export const RECALL_REASON_MIN = 10;

export interface FollowUpOut {
  followup_id: number;
  verdict_id: number;
  event_id: number;
  tenant_slug: string;
  kind: "note" | "recall";
  at: string;
}

/** The ack no longer covers anything — final (acknowledging again is a new
 *  ack). */
export function recallAck(slug: string, verdictId: number, reason: string): Promise<FollowUpOut> {
  return postJson<FollowUpOut>(`/api/v1/alerts/${seg(slug)}/verdicts/${verdictId}/recall`,
    { reason }, "The acknowledgement could not be recalled");
}

/** Context under an ack (recalled or not); its own note is never edited. */
export function noteAck(slug: string, verdictId: number, note: string): Promise<FollowUpOut> {
  return postJson<FollowUpOut>(`/api/v1/alerts/${seg(slug)}/verdicts/${verdictId}/notes`,
    { note }, "The note could not be saved");
}

export async function fetchExpectedRules(state: "active" | "all" = "active"):
  Promise<ExpectedRule[]> {
  const r = await call<{ rows: ExpectedRule[] }>(`/api/v1/alerts/expected?state=${state}`, {},
    "The expected conditions could not be loaded");
  return Array.isArray(r.rows) ? r.rows : [];
}

export async function revokeExpectedRule(id: number, reason: string): Promise<ExpectedRule[]> {
  const r = await postJson<{ rows: ExpectedRule[] }>(`/api/v1/alerts/expected/${id}/revoke`,
    { reason }, "The expected condition could not be revoked");
  return r.rows;
}

export function getTenantLocation(slug: string): Promise<TenantLocation> {
  return call<TenantLocation>(`/api/v1/fleet/locations/${seg(slug)}`, {},
    "The location could not be loaded");
}

export function saveTenantLocation(
  slug: string, body: { lat: number; lng: number; label: string; reason: string },
): Promise<TenantLocation> {
  return call<TenantLocation>(`/api/v1/fleet/locations/${seg(slug)}`,
    { method: "PUT", body: JSON.stringify(body) }, "The location could not be saved");
}

export function clearTenantLocation(slug: string, reason: string): Promise<TenantLocation> {
  return call<TenantLocation>(`/api/v1/fleet/locations/${seg(slug)}`,
    { method: "DELETE", body: JSON.stringify({ reason }) }, "The location could not be cleared");
}

/** One SITE's location (admin+): its own locked pin, what its console
 *  reports, the client's fallback. */
export function getSiteLocation(key: string): Promise<SiteLocation> {
  return call<SiteLocation>(`/api/v1/fleet/sites/${seg(key)}/location`, {},
    "The site's location could not be loaded");
}

export function saveSiteLocation(
  key: string, body: { lat: number; lng: number; label: string; reason: string },
): Promise<SiteLocation> {
  return call<SiteLocation>(`/api/v1/fleet/sites/${seg(key)}/location`,
    { method: "PUT", body: JSON.stringify(body) }, "The site's location could not be saved");
}

export function clearSiteLocation(key: string, reason: string): Promise<SiteLocation> {
  return call<SiteLocation>(`/api/v1/fleet/sites/${seg(key)}/location`,
    { method: "DELETE", body: JSON.stringify({ reason }) },
    "The site's location could not be cleared");
}

/** An address → up to 3 candidate points (the server asks the US Census
 *  geocoder with the typed address only; nothing is stored). */
export function geocodeAddress(address: string): Promise<GeocodeResponse> {
  return call<GeocodeResponse>("/api/v1/fleet/geocode",
    { method: "POST", body: JSON.stringify({ address }) }, "The address could not be looked up");
}

/** Is the address lookup on ("census") or off (null)? admin+ — the host
 *  pin's editor (no site to read it from) shows or hides Find with it. */
export async function fetchGeocoder(): Promise<string | null> {
  const r = await call<{ provider: string | null }>("/api/v1/fleet/geocoder", {},
    "The address lookup setting could not be read");
  return r.provider ?? null;
}

/** Move the host pin (the OCTO hub on the map) — super_admin, with a
 *  reason, audited by the server before it writes. */
export function saveHostLocation(body: {
  lat: number; lng: number; display?: string; city?: string; reason: string;
}): Promise<OctoLocationResponse> {
  return call<OctoLocationResponse>("/api/v1/dashboard/octo-location",
    { method: "PUT", body: JSON.stringify(body) }, "The host location could not be saved");
}

const _PAIR = String.raw`(-?\d{1,3}(?:\.\d+)?)`;

/** Coordinates from what an operator pastes — "41.25, -100.75", or a map
 *  link (Google Maps `/@lat,lng,zoom`, `!3dlat!4dlng`, `?q=lat,lng`,
 *  `ll=lat,lng`). Parsed HERE: nothing leaves the browser. Null when no
 *  valid pair is found (±90 / ±180, not (0, 0)). */
export function parseCoordinates(text: string): { lat: number; lng: number } | null {
  const t = text.trim();
  if (!t) return null;
  let decoded = t;
  try { decoded = decodeURIComponent(t); } catch { /* keep the raw text */ }
  const patterns = [
    new RegExp(String.raw`!3d${_PAIR}!4d${_PAIR}`),               // the place pin itself
    new RegExp(String.raw`[?&](?:q|query|ll|center|destination)=${_PAIR}\s*,\s*${_PAIR}`),
    new RegExp(String.raw`@${_PAIR},${_PAIR}`),                    // the map view's centre
    new RegExp(String.raw`^${_PAIR}\s*[,;\s]\s*${_PAIR}$`),     // a bare pair
  ];
  for (const re of patterns) {
    const m = re.exec(decoded);
    if (!m) continue;
    const lat = Number(m[1]);
    const lng = Number(m[2]);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue;
    if (Math.abs(lat) > 90 || Math.abs(lng) > 180 || (lat === 0 && lng === 0)) continue;
    return { lat, lng };
  }
  return null;
}

// ---------------------------------------------------------------------------
// States, labels
// ---------------------------------------------------------------------------

/** Worst first: black (an attack now) > bad (Red: a confirmed threat) >
 *  warn (Yellow: needs eyes) > unknown (stale) > notice > ok. */
export const STATE_ORDER: Record<SiteState, number> = {
  black: 0, bad: 1, warn: 2, unknown: 3, notice: 4, ok: 5,
};

/** What each state MEANS (the legend, titles, the drawer's verdict). */
export const STATE_LABEL: Record<SiteState, string> = {
  black: "Black: active attack", bad: "Red: confirmed threat", warn: "Yellow: needs eyes",
  unknown: "Stale", notice: "Notice", ok: "Normal",
};

/** The short word a chip has room for. */
export const STATE_SHORT: Record<SiteState, string> = {
  black: "black", bad: "red", warn: "yellow", unknown: "stale", notice: "notice", ok: "normal",
};

/** Tailwind classes per state — semantic tokens, so every theme (Midas
 *  Touch, Ultra-black, light mode) recolours them. Black uses the curated
 *  `--fleet-threat` (near-black) / `--fleet-threat-ring` (bright) pair. */
export const STATE_TONE: Record<SiteState, { dot: string; text: string; chip: string }> = {
  black:   { dot: "bg-[var(--fleet-threat)] ring-2 ring-[var(--fleet-threat-ring)]", text: "text-[var(--fleet-threat-ring)] font-semibold", chip: "border-[var(--fleet-threat-ring)] bg-[var(--fleet-threat)] text-[var(--fleet-threat-text)] font-semibold" },
  bad:     { dot: "bg-critical", text: "text-critical", chip: "border-critical/50 bg-critical/10 text-critical" },
  warn:    { dot: "bg-medium", text: "text-medium", chip: "border-medium/50 bg-medium/10 text-medium" },
  unknown: { dot: "bg-text-dim", text: "text-text-dim", chip: "border-border bg-bg-surface text-text-dim" },
  // A notice is seen, not a problem: grey words, a green dot with a grey ring.
  notice:  { dot: "bg-success ring-1 ring-text-dim ring-offset-1 ring-offset-bg-card", text: "text-text-secondary", chip: "border-border bg-bg-surface text-text-secondary" },
  ok:      { dot: "bg-success", text: "text-success", chip: "border-success/40 bg-success/10 text-success" },
};

/** The CSS colour a map pin of `state` is painted with (SVG fill). A notice
 *  does NOT colour the pin: green, with a grey ring drawn by the overlay. */
export const STATE_COLOR: Record<SiteState, string> = {
  black: "var(--fleet-threat)", bad: "var(--critical)", warn: "var(--medium)",
  unknown: "var(--text-dim)", notice: "var(--success)", ok: "var(--success)",
};

/** A pin an operator placed by hand (this site's own, or the client's
 *  fallback) — drawn as a diamond. */
export function handPlaced(source: string | null | undefined): boolean {
  return source === "site" || source === "manual";
}

/** Layer names: operators see the sources, client users never a vendor. */
export const LAYER_LABEL: Record<"operator" | "client", Record<LayerName, string>> = {
  operator: {
    threat: "Threat · incidents",
    network: "Network · UniFi",
    security: "Security · IPS · NextDNS · RocketCyber",
    endpoints: "Endpoints · Datto RMM",
    buoy: "Buoy",
  },
  client: {
    threat: "Security incidents",
    network: "Network",
    security: "Security",
    endpoints: "Computers",
    buoy: "On-site sensor",
  },
};

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

export type LayerFilter = "all" | LayerName;

export interface SiteFilters {
  query: string;
  problemsOnly: boolean;
  layer: LayerFilter;
  tenant: string | null;
}

export const NO_FILTERS: SiteFilters = { query: "", problemsOnly: false, layer: "all", tenant: null };

/** The state a site shows under the layer filter: its worst ("all"), or that
 *  one layer's (null when the site does not have that layer). A Black or
 *  Red site keeps its own state under EVERY layer filter — a filter never
 *  recolours, dims or hides an open incident (the spotlight rule). */
export function effectiveState(site: FleetSite, layer: LayerFilter): SiteState | null {
  if (layer === "all" || isThreat(site.state)) return site.state;
  const l = site.layers[layer];
  if (!l || !l.present || l.state === "absent") return null;
  return l.state;
}

export function matchesSite(site: FleetSite, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [site.name, site.tenant_name, site.tenant_slug, site.console_name,
    site.location?.label, site.reason]
    .some((v) => (v ?? "").toLowerCase().includes(q));
}

export function filterSites(sites: readonly FleetSite[], f: SiteFilters): FleetSite[] {
  return sites.filter((s) => {
    const st = effectiveState(s, f.layer);
    if (st === null) return false;
    if (f.problemsOnly && (st === "ok" || st === "notice")) return false;
    if (f.tenant && s.tenant_slug !== f.tenant) return false;
    return matchesSite(s, f.query);
  });
}

export function sortSites(sites: readonly FleetSite[], layer: LayerFilter = "all"): FleetSite[] {
  return [...sites].sort((a, b) => {
    const sa = effectiveState(a, layer) ?? "unknown";
    const sb = effectiveState(b, layer) ?? "unknown";
    const d = STATE_ORDER[sa] - STATE_ORDER[sb];
    if (d !== 0) return d;
    return a.tenant_name.localeCompare(b.tenant_name) || a.name.localeCompare(b.name);
  });
}

/** Sites that need someone: Black, Red, Yellow. */
export function problemCount(sites: readonly FleetSite[]): number {
  return sites.filter((s) => s.state === "black" || s.state === "bad" || s.state === "warn")
    .length;
}

export function isThreat(state: SiteState | null | undefined): boolean {
  return state === "black" || state === "bad";
}

/** The worst state among `sites` (null for none) — black > bad > warn >
 *  unknown > notice > ok. */
export function worstState(sites: readonly FleetSite[]): SiteState | null {
  let out: SiteState | null = null;
  for (const s of sites) {
    if (out === null || STATE_ORDER[s.state] < STATE_ORDER[out]) out = s.state;
  }
  return out;
}

/** The fleet as shown when the console has NOT been able to refresh it:
 *  every condition-only site, and every present health layer, is unknown —
 *  stale data is never shown as ok (nor as its last colour). A site with a
 *  Black or Red KEEPS it (an incident is a floor: a stale view never lowers
 *  one), with "view stale N min" added. The reason says how old the data is. */
export function staleSites(sites: readonly FleetSite[], ageMin: number): FleetSite[] {
  const min = Math.max(1, Math.round(ageMin));
  const text = `no fresh data for ${min} min`;
  return sites.map((s) => {
    const layers = Object.fromEntries(Object.entries(s.layers).map(([name, l]) => [
      name, l && l.present && name !== "threat" ? { ...l, state: "unknown" } : l,
    ])) as FleetSite["layers"];
    if (isThreat(s.state)) {
      return { ...s, reason: `${s.reason} · view stale ${min} min`, layers };
    }
    return {
      ...s,
      state: "unknown",
      reason: text,
      reasons: [{ state: "unknown", text, layer: "" }],
      layers: Object.fromEntries(Object.entries(layers).map(([name, l]) => [
        name, l && l.present ? { ...l, state: "unknown" } : l,
      ])) as FleetSite["layers"],
    };
  });
}

/** Paint order for map pins: ok first, black LAST (SVG paints later
 *  elements on top, so a threat pin is never hidden under an ok one). */
export function paintOrder<T extends { state: SiteState }>(items: readonly T[]): T[] {
  return [...items].sort((a, b) => STATE_ORDER[b.state] - STATE_ORDER[a.state]);
}


/** Who acknowledged an incident BY NAME (the acknowledged Black pin's
 *  initials) — never the operator id (initials("12") would draw "1"); ""
 *  (→ "?") when the name is not known. */
export function ownerName(threats: readonly ThreatItem[], inc: SiteIncident): string {
  const t = threats.find((x) => x.id === inc.id && x.tenant === inc.tenant_slug);
  return (inc.acked_by_name ?? t?.acked_by_name) ?? "";
}

/** Initials of an operator's name ("Alice Example" → "AE") — the
 *  acknowledged Black pin's owner mark. */
export function initials(name: string | null | undefined): string {
  const parts = (name ?? "").trim().split(/[\s._@-]+/).filter(Boolean);
  return parts.slice(0, 2).map((p) => p[0]!.toUpperCase()).join("") || "?";
}

/** "12 min", "3 h", "2 d". */
export function ageText(seconds: number): string {
  if (seconds < 3600) return `${Math.max(1, Math.floor(seconds / 60))} min`;
  if (seconds < 172800) return `${Math.floor(seconds / 3600)} h`;
  return `${Math.floor(seconds / 86400)} d`;
}
