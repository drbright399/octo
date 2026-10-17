/**
 * /fleet — Fleet v2: SITE-CENTRIC.
 *
 * Pins are SITES (UniFi sites mapped to clients, and clients without UniFi
 * that an operator placed by hand), coloured by the site's WORST state across
 * four layers — network (UniFi), security (IPS, NextDNS, RocketCyber),
 * endpoints (Datto inventory), buoy — with the reason ("2 IPS blocks today",
 * "NextDNS lapsed", "gateway offline"). Stale data is unknown, never ok.
 *
 *   - map (self-hosted tiles: no coordinate leaves the box) or list view;
 *     sites without a location are listed under the map, never guessed;
 *   - filters: problems only, by layer, by client; a search box; the buoy
 *     layer toggle (the buoy markers, their traces and their drawer);
 *   - a drawer per site: the four layers, deep links, recent alerts;
 *   - open ISP-outage incidents as a banner (operators);
 *   - the legend;
 *   - admin+: "proposed locations" (Autotask addresses to confirm or reject,
 *     a badge with the open count); super_admin: the host pin (the OCTO hub
 *     — "set host location", or a click on the hub).
 *
 * The previous buoy fleet (cards, rollup, buoy map) is the "buoys" mode,
 * unchanged — for OPERATORS only. A client user (viewer) gets the site list
 * only: no map, no buoys mode (it maps buoys and the hub) — site locations
 * are for operator roles (2026-09-30 plan) — with neutral wording (help text
 * and attributes included). The mode preference is saved only when the user
 * picks it (a ?focus= deep link opens the buoys mode without saving it).
 *
 * Polls /api/v1/fleet/sites every 30 s (the server caches 30 s and never
 * calls a vendor on a page load). When it cannot refresh (two failed polls,
 * or no answer for more than two poll intervals), every site shows as
 * unknown — stale data is never shown as ok, nor as its last colour — except
 * a site with an open Black or Red, which keeps it ("view stale N min"):
 * an incident is a floor.
 *
 * Tier Black (slice 1): one non-dismissible banner per open BLACK above the
 * ISP-outage banners (tenant, site, device, rule, age, who acknowledged it —
 * [Acknowledge] [Open]); "Athena is blind to <source>" (FR2) and the WAN
 * coverage count for operators; the strip counts black · red · yellow ·
 * notices. A client user sees their visible incidents' neutral line with
 * their two actions — never a pulse, a device or a rule.
 */
import {
  type FC, lazy, Suspense, useCallback, useEffect, useMemo, useState,
} from "react";

import type {
  BlindSource,
  ClientSiteIncident,
  FleetSite,
  FleetSitesResponse,
  IspOutage,
  RegionalGroup,
  SiteIncident,
  ThreatItem,
} from "@/contracts/fleet";
import { ApiError, fetchStepUpStatus, getMe } from "@/lib/api";
import {
  fetchBuoyFleet,
  fetchOctoLocation,
  type BuoyFleetResponse,
  type BuoyFleetRow,
  type OctoLocationResponse,
} from "@/lib/buoy";
import {
  NO_FILTERS,
  ageText,
  effectiveState,
  fetchFleetSites,
  filterSites,
  initials,
  ownerName,
  problemCount,
  sortSites,
  staleSites,
  worstState,
  type SiteFilters,
} from "@/lib/fleet";
import { ackIncident } from "@/lib/incidents";
import { ClientIncidentPanel } from "@/components/incident-panel";
import { fetchProposalSummary } from "@/lib/proposals";
import BuoyDrawer from "@/components/buoy-drawer";
import BuoyFleetView, { FALLBACK_OCTO } from "@/components/fleet-buoys";
import FleetLegend from "@/components/fleet-legend";
import type { BuoyMarker, OctoNode, SiteMarker } from "@/components/fleet-map-overlay";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import FleetSiteFilters from "@/components/fleet-site-filters";
import FleetSiteList from "@/components/fleet-site-list";
import HelpTip from "@/components/help-tip";
import HostLocationDialog from "@/components/host-location-dialog";
import LocationProposalsPanel from "@/components/location-proposals-panel";
import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";

// Lazy: maplibre-gl is ~1.5MB and only needed in map view.
const FleetMapView = lazy(() => import("@/components/fleet-map-view"));

export const POLL_MS = 30_000;
/** No successful refresh for this long (two polls + slack) = stale. */
export const STALE_AFTER_MS = 2 * POLL_MS + 15_000;
const OPERATOR_ROLES = ["super_admin", "admin", "analyst"];
export const MODE_STORAGE_KEY = "athena.fleet.mode.v1";
export const SITE_VIEW_STORAGE_KEY = "athena.fleet.sites.view.v1";
export const BUOY_LAYER_STORAGE_KEY = "athena.fleet.sites.buoys.v1";

type FleetMode = "sites" | "buoys";
type SiteView = "map" | "list";

function readPref<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return (allowed as readonly string[]).includes(v ?? "") ? (v as T) : fallback;
  } catch {
    return fallback;
  }
}

function writePref(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* noop */ }
}

const toggleCls = (on: boolean): string => [
  "rounded-sm px-2 py-0.5 transition-colors",
  on ? "bg-accent text-text-on-accent" : "text-text-secondary hover:text-accent",
].join(" ");

/** `/fleet?focus=<buoy slug>` (Source health → "Manage →") opens that buoy's
 *  drawer — in the buoys mode, which owns it. */
function wantsBuoyFocus(): boolean {
  try {
    return new URLSearchParams(window.location.search).has("focus");
  } catch {
    return false;
  }
}

const FleetPage: FC = () => {
  // A deep link opens the buoys mode WITHOUT saving it: the saved preference
  // changes only when the user picks a mode.
  const [mode, setMode] = useState<FleetMode>(() => (
    wantsBuoyFocus() ? "buoys" : readPref(MODE_STORAGE_KEY, ["sites", "buoys"], "sites")));
  const pickMode = (m: FleetMode): void => { setMode(m); writePref(MODE_STORAGE_KEY, m); };
  useEffect(() => {
    const onNavigate = (): void => { if (wantsBuoyFocus()) setMode("buoys"); };
    window.addEventListener("athena:navigate", onNavigate);
    return () => window.removeEventListener("athena:navigate", onNavigate);
  }, []);
  // Who is looking: the fleet response's `view` is authoritative; the
  // identity's roles answer first. Until either says "operator", only the
  // site view (a client user's list) is shown — never the buoy map.
  const [view, setView] = useState<"operator" | "client" | null>(null);
  useEffect(() => {
    let cancelled = false;
    void getMe().then((me) => {
      if (cancelled || !me || !Array.isArray(me.role)) return;
      const operator = (me.role as string[]).some((r) => OPERATOR_ROLES.includes(r));
      setView((v) => v ?? (operator ? "operator" : "client"));
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, []);
  const operator = view === "operator";
  const shown: FleetMode = operator ? mode : "sites";
  return (
    <div className="flex flex-col gap-3">
      {operator && (
        <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-text-dim">
          <div className="flex items-center gap-1 rounded-sm border border-border bg-bg-card p-0.5"
               role="group" aria-label="Fleet mode">
            <button type="button" aria-pressed={shown === "sites"} onClick={() => pickMode("sites")}
                    className={toggleCls(shown === "sites")}>sites</button>
            <button type="button" aria-pressed={shown === "buoys"} onClick={() => pickMode("buoys")}
                    className={toggleCls(shown === "buoys")}>buoys</button>
          </div>
        </div>
      )}
      {shown === "sites" ? <SiteFleetView onView={setView} /> : <BuoyFleetView />}
    </div>
  );
};


// ---------------------------------------------------------------------------
// The site-centric view
// ---------------------------------------------------------------------------

export const SiteFleetView: FC<{ onView?: (view: "operator" | "client") => void }> = ({ onView }) => {
  const [resp, setResp] = useState<FleetSitesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Staleness: consecutive failed loads, when the last good answer arrived
  // (the browser's clock only — never compared with the server's), and a
  // clock that ticks with the polls.
  const [failures, setFailures] = useState(0);
  const [receivedAt, setReceivedAt] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [filters, setFilters] = useState<SiteFilters>(NO_FILTERS);
  const [siteView, setSiteView] = useState<SiteView>(() => readPref(SITE_VIEW_STORAGE_KEY, ["map", "list"], "map"));
  const [showBuoys, setShowBuoys] = useState<boolean>(() => readPref(BUOY_LAYER_STORAGE_KEY, ["1", "0"], "0") === "1");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  // Bumped after a site's location is saved: one immediate refresh.
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => { writePref(SITE_VIEW_STORAGE_KEY, siteView); }, [siteView]);
  useEffect(() => { writePref(BUOY_LAYER_STORAGE_KEY, showBuoys ? "1" : "0"); }, [showBuoys]);

  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const r = await fetchFleetSites();
        if (cancelled) return;
        setResp(r);
        setError(null);
        setFailures(0);
        setReceivedAt(Date.now());
      } catch (e) {
        if (cancelled) return;
        setFailures((n) => n + 1);
        setError(e instanceof ApiError ? e.message : "Failed to load the fleet");
      } finally {
        if (!cancelled) {
          setLoading(false);
          setNowMs(Date.now());
        }
      }
    };
    void load();
    const id = setInterval(() => { setNowMs(Date.now()); void load(); }, POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, []);
  useEffect(() => {
    if (reloadKey === 0) return undefined;
    let cancelled = false;
    fetchFleetSites().then((r) => {
      if (cancelled) return;
      setResp(r);
      setReceivedAt(Date.now());
      setNowMs(Date.now());
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [reloadKey]);

  const view = resp?.view ?? "client";
  useEffect(() => { if (resp?.view && onView) onView(resp.view); }, [resp?.view, onView]);
  const ageMs = receivedAt !== null ? Math.max(0, nowMs - receivedAt) : 0;
  const stale = resp !== null && (failures >= 2 || ageMs > STALE_AFTER_MS);
  const isClient = view === "client";
  // A client user gets no locations: the list is their view.
  const effectiveView: SiteView = isClient ? "list" : siteView;

  // ---- buoy layer (operators, map view) ---------------------------------
  const [buoyResp, setBuoyResp] = useState<BuoyFleetResponse | null>(null);
  const [openBuoy, setOpenBuoy] = useState<BuoyFleetRow | null>(null);
  const [callerRole, setCallerRole] = useState<string | null>(null);
  const [callerId, setCallerId] = useState<number | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [stepUpReason, setStepUpReason] = useState<StepUpReason>("required");
  const wantBuoys = !isClient && effectiveView === "map" && showBuoys;
  useEffect(() => {
    if (!wantBuoys) return undefined;
    let cancelled = false;
    const load = (): void => {
      fetchBuoyFleet().then((r) => { if (!cancelled) setBuoyResp(r); }).catch(() => undefined);
    };
    load();
    const id = setInterval(load, POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, [wantBuoys]);
  // The caller's highest role: the buoy drawer's actions and the site
  // drawer's "Set location" (admin+) read it. The server enforces both.
  useEffect(() => {
    if (isClient) return undefined;
    let cancelled = false;
    void getMe().then((me) => {
      if (cancelled || !me || !Array.isArray(me.role)) return;
      const order = ["super_admin", "admin", "analyst", "viewer"];
      setCallerRole(order.find((r) => (me.role as string[]).includes(r)) ?? null);
      setCallerId(typeof me.operator_id === "number" ? me.operator_id : null);
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [isClient]);
  const canEditLocation = callerRole === "admin" || callerRole === "super_admin";
  // The host pin (the OCTO hub) is bundle-wide: super_admin only.
  const canEditHost = callerRole === "super_admin";
  const [hostEditing, setHostEditing] = useState(false);
  // Proposed locations (Autotask addresses to confirm) — admin+.
  const [proposalsOpen, setProposalsOpen] = useState<{ tenant: string | null; focusId: number | null } | null>(null);
  const [openProposals, setOpenProposals] = useState<number | null>(null);
  const [proposalsKey, setProposalsKey] = useState(0);
  useEffect(() => {
    if (!canEditLocation) return undefined;
    let cancelled = false;
    fetchProposalSummary()
      .then((r) => { if (!cancelled) setOpenProposals(typeof r.open === "number" ? r.open : null); })
      .catch(() => { if (!cancelled) setOpenProposals(null); });
    return () => { cancelled = true; };
  }, [canEditLocation, proposalsKey, reloadKey]);

  const [octoLocation, setOctoLocation] = useState<OctoLocationResponse | null>(null);
  useEffect(() => {
    if (isClient) return undefined;
    let cancelled = false;
    void fetchOctoLocation().then((r) => { if (!cancelled) setOctoLocation(r); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [isClient]);
  const octoNode: OctoNode = octoLocation
    ? { slug: octoLocation.slug, display: octoLocation.display, city: octoLocation.city,
        msp: octoLocation.msp, lat: octoLocation.lat, lng: octoLocation.lng }
    : FALLBACK_OCTO;

  // ---- derived ---------------------------------------------------------
  const staleMin = stale ? Math.max(1, Math.round(ageMs / 60_000)) : 0;
  const sites = useMemo(
    () => (stale ? staleSites(resp?.sites ?? [], staleMin) : resp?.sites ?? []),
    [resp, stale, staleMin]);
  const filtered = useMemo(() => sortSites(filterSites(sites, filters), filters.layer),
    [sites, filters]);
  const located = useMemo(() => filtered.filter((s) => s.location), [filtered]);
  const unlocated = useMemo(() => filtered.filter((s) => !s.location), [filtered]);
  const markers = useMemo<SiteMarker[]>(() => located.map((s) => {
    const inc = s.incident && "id" in s.incident ? s.incident as SiteIncident : null;
    return {
      key: s.key, name: s.name, label: s.location?.label, tenant: s.tenant_name,
      lat: s.location!.lat, lng: s.location!.lng,
      state: effectiveState(s, filters.layer) ?? "unknown",
      source: s.location?.source, reason: s.reason,
      ...(inc ? { acked: inc.acked, contained: inc.contained,
                  owner: inc.acked ? initials(ownerName(resp?.threats ?? [], inc)) : undefined }
        : {}),
    };
  }), [located, filters.layer, resp?.threats]);
  const buoyMarkers = useMemo<BuoyMarker[]>(() => (buoyResp?.buoys ?? []).map((b) => ({
    slug: b.slug, hostname: b.hostname, city: b.city ?? undefined,
    lat: b.lat ?? Number.NaN, lng: b.lng ?? Number.NaN, health: b.health,
    octo: b.octo ?? octoNode.slug,
  })), [buoyResp, octoNode.slug]);
  const selected = useMemo(() => sites.find((s) => s.key === selectedKey) ?? null,
    [sites, selectedKey]);
  const openOutages = useMemo(
    () => (resp?.isp_outages ?? []).filter((o) => o.open && !o.suppressed), [resp]);
  const suppressedWave = useMemo(
    () => (resp?.isp_outages ?? []).find((o) => o.suppressed)?.suppressed ?? null, [resp]);
  const unlocatedProblems = unlocated.filter(
    (s) => s.state === "black" || s.state === "bad" || s.state === "warn").length;
  const unlocatedWorst = worstState(unlocated);
  const scrollToUnlocated = useCallback(() => {
    document.getElementById("fleet-unlocated-list")?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  }, []);
  const closeDrawer = useCallback(() => setSelectedKey(null), []);

  const problems = problemCount(sites);
  const unknown = sites.filter((s) => s.state === "unknown").length;
  const notices = sites.filter((s) => s.state === "notice").length;
  const blacks = sites.filter((s) => s.state === "black").length;
  const reds = sites.filter((s) => s.state === "bad").length;
  const yellows = sites.filter((s) => s.state === "warn").length;
  const blackThreats = useMemo(
    () => (isClient ? [] : (resp?.threats ?? []).filter((t) => t.tier === "black")), [resp, isClient]);
  const blind = isClient ? [] : resp?.blind ?? [];
  const clientIncidents = useMemo(() => {
    if (!isClient) return [];
    const seen = new Map<string, ClientSiteIncident>();
    for (const s of sites) {
      if (s.incident && "ref" in s.incident) seen.set(s.incident.ref, s.incident as ClientSiteIncident);
    }
    return [...seen.values()];
  }, [sites, isClient]);
  const [ackError, setAckError] = useState<string | null>(null);
  const acknowledge = useCallback((t: ThreatItem) => {
    setAckError(null);
    ackIncident(t.tenant, t.id)
      .then(() => setReloadKey((k) => k + 1))
      .catch((e: unknown) => setAckError(e instanceof ApiError ? e.message : "Could not acknowledge"));
  }, []);
  const regional = isClient || stale ? [] : resp?.regional ?? [];
  const asOf = resp?.generated_at ? new Date(resp.generated_at).toLocaleTimeString(undefined, { hour12: false }) : null;

  return (
    <section className="flex flex-col gap-4" aria-labelledby="fleet-title">
      {/* Status strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-sm border border-border bg-bg-surface px-3 py-1.5 font-mono text-[11px]">
        <div className="flex items-center gap-2 text-text-secondary">
          <span aria-hidden="true" className="text-accent">▸</span>
          <span id="fleet-title" className="uppercase tracking-wider">fleet</span>
          <span aria-hidden="true" className="text-text-dim">·</span>
          <span data-testid="fleet-summary">
            {loading && !resp ? "loading…"
              : `${sites.length} site${sites.length === 1 ? "" : "s"} · ${problems} need attention`
                + (blacks || reds || yellows
                  ? ` · ${blacks} black · ${reds} red · ${yellows} yellow` : "")
                + (unknown ? ` · ${unknown} stale` : "")
                + (notices ? ` · ${notices} notice${notices === 1 ? "" : "s"}` : "")}
          </span>
          {isClient ? (
            <HelpTip>
              One row per site, coloured by its worst part: network, security, computers and
              the on-site sensor. Data that is out of date is shown as unknown, never as ok.
            </HelpTip>
          ) : (
            <HelpTip>
              One pin per site, coloured by its worst layer: network (UniFi), security (IPS,
              DNS protection, open incidents), endpoints (Datto inventory) and the buoy. Data
              older than two polls of its feed is shown as unknown, never as ok. Built from what
              Athena already stores — opening this page never calls a vendor.
            </HelpTip>
          )}
        </div>
        <div className="flex items-center gap-3 font-mono text-[10px] uppercase tracking-widest text-text-dim">
          {!isClient && canEditLocation && (
            <button type="button" data-testid="proposals-button"
                    onClick={() => setProposalsOpen({ tenant: null, focusId: null })}
                    className="flex items-center gap-1 rounded-sm border border-border bg-bg-card px-2 py-0.5 text-text-secondary transition-colors hover:border-accent hover:text-accent">
              proposed locations
              {openProposals !== null && openProposals > 0 && (
                <span data-testid="proposals-badge"
                      className="rounded-sm bg-accent px-1 text-text-on-accent">{openProposals}</span>
              )}
            </button>
          )}
          {!isClient && canEditHost && (
            <button type="button" data-testid="host-location-button" onClick={() => setHostEditing(true)}
                    className="rounded-sm border border-border bg-bg-card px-2 py-0.5 text-text-secondary transition-colors hover:border-accent hover:text-accent">
              set host location
            </button>
          )}
          {!isClient && (
            <div className="flex items-center gap-1 rounded-sm border border-border bg-bg-card p-0.5"
                 role="group" aria-label="Site view">
              <button type="button" aria-pressed={siteView === "map"} onClick={() => setSiteView("map")}
                      className={toggleCls(siteView === "map")}>map</button>
              <button type="button" aria-pressed={siteView === "list"} onClick={() => setSiteView("list")}
                      className={toggleCls(siteView === "list")}>list</button>
            </div>
          )}
          {asOf && <span>as of {asOf} · ui poll {POLL_MS / 1000}s</span>}
        </div>
      </div>

      {!isClient && typeof resp?.threats_stopped_week === "number" && (
        <div className="flex items-center gap-1 font-mono text-[11px] text-text-secondary"
             data-testid="fleet-threats-week">
          <span data-testid="fleet-threats-week-text">
            Threats stopped this week:{" "}
            <strong className="text-text-primary">
              {resp.threats_stopped_week.toLocaleString("en-US")}
            </strong>
          </span>
          <HelpTip>
            Security-category DNS blocks over the last 7 days across your clients (threat
            intelligence, malware, phishing, newly registered domains, …). A block is DNS
            protection doing its job: it is counted, not alarmed — a device that looks wrong
            (repeated high-risk lookups, algorithm-generated or tunneling lookups) turns
            yellow on its own.
          </HelpTip>
        </div>
      )}

      {error && (
        <div className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 text-[12px] text-critical">
          {error}
        </div>
      )}
      {stale && (
        <div role="status" data-testid="fleet-stale"
             className="rounded-sm border border-border bg-bg-surface px-3 py-1.5 text-[11px] text-text-secondary">
          The fleet could not be refreshed for {staleMin} min — every site shows as unknown
          until it is.
        </div>
      )}
      {resp?.partial && (
        <div className="rounded-sm border border-border bg-bg-surface px-3 py-1.5 text-[11px] text-text-dim"
             data-testid="fleet-partial">
          Some sites were not read within the page&apos;s time budget; their layers show as unknown
          until the next refresh.
        </div>
      )}

      {clientIncidents.map((inc) => <ClientIncidentPanel key={inc.ref} incident={inc} />)}

      {blackThreats.map((t) => (
        <ThreatBanner key={`${t.tenant}-${t.id}`} threat={t} sites={sites}
                      onAck={() => acknowledge(t)}
                      canAck={!t.restricted || canEditLocation}
                      onOpen={(key) => setSelectedKey(key)} />
      ))}
      {ackError && (
        <div className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-1.5 text-[11px] text-critical">
          {ackError}
        </div>
      )}
      {blind.map((b) => <BlindBanner key={`${b.source}-${b.since}`} blind={b} />)}

      {openOutages.map((o) => (
        <OutageBanner key={o.vid ?? `${o.asn}`} outage={o} sites={sites}
                      onOpen={(key) => setSelectedKey(key)} />
      ))}
      {!isClient && suppressedWave && (
        <div role="status" data-testid="fleet-wave-banner"
             className="flex flex-wrap items-center gap-2 rounded-sm border border-border bg-bg-surface px-3 py-2 text-[12px] text-text-secondary">
          <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">fleet-wide drop</span>
          <span>
            {suppressedWave.sites} of {suppressedWave.observed} sites across {suppressedWave.asns} ISPs
            dropped together
            {suppressedWave.at ? ` at ${new Date(suppressedWave.at).toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit" })}` : ""}
            {" "}— likely on the UniFi side, not an ISP: no ISP-outage incident was raised.
          </span>
        </div>
      )}

      {regional.map((g, i) => (
        <RegionalBanner key={`${g.kind}-${g.asn ?? i}`} group={g} sites={sites}
                        onOpen={(key) => setSelectedKey(key)} />
      ))}

      {!isClient && resp?.coverage && resp.coverage.sites_without_backup > 0 && (
        <div className="font-mono text-[10px] text-text-dim" data-testid="fleet-wan-coverage">
          {resp.coverage.sites_without_backup} site{resp.coverage.sites_without_backup === 1 ? "" : "s"}
          {" "}without a backup line
          {resp.coverage.sites_with_backup ? ` · ${resp.coverage.sites_with_backup} with one` : ""}
          {resp.coverage.sites_backup_unknown ? ` · ${resp.coverage.sites_backup_unknown} not known` : ""}
        </div>
      )}

      {!isClient && (resp?.unmapped_sites ?? 0) > 0 && (
        <div className="font-mono text-[10px] text-text-dim" data-testid="fleet-unmapped">
          {resp?.unmapped_sites} UniFi site{resp?.unmapped_sites === 1 ? "" : "s"} neither mapped
          to a client nor ignored — not on the map (Settings → Integrations → UniFi).
        </div>
      )}

      {sites.length === 0 && !loading && !error && (
        <div className="rounded-sm border border-border bg-bg-surface px-4 py-8 text-center text-[12px] text-text-dim"
             data-testid="fleet-empty">
          {isClient
            ? "No sites to show yet."
            : "No sites yet. Map UniFi sites to clients under Settings → Integrations, or place a client by hand under Settings → Tenants (Location…)."}
        </div>
      )}

      {sites.length > 0 && (
        <FleetSiteFilters
          view={view}
          filters={filters}
          onChange={setFilters}
          tenants={resp?.tenants ?? []}
          resultCount={filtered.length}
          totalCount={sites.length}
          showBuoys={!isClient && effectiveView === "map" ? showBuoys : undefined}
          onShowBuoys={!isClient && effectiveView === "map" ? setShowBuoys : undefined}
        />
      )}

      {sites.length > 0 && effectiveView === "map" && (
        <Suspense fallback={
          <div className="flex h-[640px] items-center justify-center rounded-sm border border-border bg-bg-surface font-mono text-[11px] uppercase tracking-widest text-text-dim">
            ·· loading map ··
          </div>
        }>
          <FleetMapView
            octos={[octoNode]}
            buoys={buoyMarkers}
            showBuoys={showBuoys}
            selectedSlug={openBuoy?.slug ?? null}
            onBuoyClick={(b) => {
              const row = buoyResp?.buoys.find((r) => r.slug === b.slug);
              if (row) setOpenBuoy(row);
            }}
            sites={markers}
            selectedSiteKey={selectedKey}
            onSiteClick={(s) => setSelectedKey(s.key)}
            unlocatedSites={unlocated.length}
            unlocatedProblems={unlocatedProblems}
            unlocatedWorst={unlocatedWorst}
            onUnlocatedClick={scrollToUnlocated}
            onOctoClick={canEditHost ? () => setHostEditing(true) : undefined}
          />
        </Suspense>
      )}

      {sites.length > 0 && <FleetLegend view={view} showBuoys={effectiveView === "map" && showBuoys} />}

      {sites.length > 0 && effectiveView === "map" && unlocated.length > 0 && (
        <div id="fleet-unlocated-list">
          <FleetSiteList
            view={view} sites={unlocated} layer={filters.layer}
            title="sites without a location" selectedKey={selectedKey}
            onOpen={(s: FleetSite) => setSelectedKey(s.key)}
          />
        </div>
      )}

      {sites.length > 0 && effectiveView === "list" && (
        <FleetSiteList
          view={view} sites={filtered} layer={filters.layer}
          title={isClient ? "your sites" : "sites"} selectedKey={selectedKey}
          empty="No sites match the current search + filters."
          onOpen={(s: FleetSite) => setSelectedKey(s.key)}
        />
      )}

      {selected && (
        <FleetSiteDrawer site={selected} view={view} onClose={closeDrawer}
                         canEditLocation={canEditLocation}
                         callerRole={callerRole}
                         callerId={callerId}
                         onIncidentChanged={() => setReloadKey((k) => k + 1)}
                         onStepUpRequired={() => { setStepUpReason("required"); setStepUpOpen(true); }}
                         onLocationSaved={() => setReloadKey((k) => k + 1)}
                         onReviewProposals={(tenant, focusId) => setProposalsOpen({ tenant, focusId })}
                         suspendEscape={proposalsOpen !== null || hostEditing} />
      )}

      {proposalsOpen && canEditLocation && (
        <LocationProposalsPanel
          tenant={proposalsOpen.tenant}
          focusId={proposalsOpen.focusId}
          onClose={() => setProposalsOpen(null)}
          onChanged={() => { setProposalsKey((k) => k + 1); setReloadKey((k) => k + 1); }}
        />
      )}

      {hostEditing && canEditHost && (
        <HostLocationDialog
          current={octoLocation}
          onClose={() => setHostEditing(false)}
          onSaved={(saved) => { setOctoLocation(saved); setHostEditing(false); }}
        />
      )}

      {openBuoy && (
        <BuoyDrawer
          buoy={openBuoy}
          callerRole={callerRole}
          onClose={() => setOpenBuoy(null)}
          onStepUpRequired={() => { setStepUpReason("required"); setStepUpOpen(true); }}
        />
      )}
      <StepUpModal
        open={stepUpOpen}
        reason={stepUpReason}
        onClose={() => setStepUpOpen(false)}
        onSuccess={async () => {
          setStepUpOpen(false);
          await fetchStepUpStatus().catch(() => null);
        }}
      />
    </section>
  );
};


/** One open BLACK — non-dismissible: it goes away only when the incident
 *  is closed (by a person). [Acknowledge] stops the paging and the pulse;
 *  [Open] opens its site's drawer. */
const ThreatBanner: FC<{
  threat: ThreatItem;
  sites: readonly FleetSite[];
  onAck: () => void;
  onOpen: (key: string) => void;
  /** A restricted incident (B7) is acknowledged by an admin only. */
  canAck?: boolean;
}> = ({ threat, sites, onAck, onOpen, canAck = true }) => {
  const site = sites.find((s) => threat.site_keys.includes(s.key));
  return (
    <div role="alert" data-testid="threat-banner" data-restricted={threat.restricted ? "true" : undefined}
         className={["flex flex-wrap items-center gap-2 rounded-sm border-2 border-[var(--fleet-threat-ring)] bg-[var(--fleet-threat)] px-3 py-2 text-[12px] text-[var(--fleet-threat-text)]",
                     threat.acked ? "" : "fleet-strip-black"].join(" ")}>
      <span className="font-mono text-[10px] font-bold uppercase tracking-widest">⯃! black</span>
      <span className="font-semibold">{threat.tenant_name}</span>
      {site && !threat.restricted && <span>· {site.name}{threat.unknown_location ? " (device location unknown)" : ""}</span>}
      {threat.device_label && !threat.restricted && <span>· {threat.device_label}</span>}
      <span>· {threat.restricted ? "restricted incident — admins only" : threat.summary}</span>
      {!threat.restricted && (
        <span className="font-mono text-[10px]">· {threat.rule_id} · {ageText(threat.age_s)}</span>
      )}
      <span className="font-mono text-[10px] uppercase" data-testid="threat-banner-ack-state">
        · {threat.contained ? "contained" : threat.acked ? "acknowledged" : "unacknowledged"}
      </span>
      <span className="ml-auto flex gap-1">
        {!threat.acked && canAck && (
          <button type="button" onClick={onAck} data-testid="threat-banner-ack"
                  className="rounded-sm border border-[var(--fleet-threat-ring)] px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest hover:bg-[var(--fleet-threat-ring)] hover:text-[var(--fleet-threat)]">
            acknowledge
          </button>
        )}
        {site && (
          <button type="button" onClick={() => onOpen(site.key)} data-testid="threat-banner-open"
                  className="rounded-sm border border-[var(--fleet-threat-ring)] px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest">
            open
          </button>
        )}
      </span>
    </div>
  );
};

/** FR2 — detection blindness (operators): measured by intake health. */
const BlindBanner: FC<{ blind: BlindSource }> = ({ blind }) => {
  const since = blind.since
    ? new Date(blind.since).toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit" })
    : "?";
  return (
    <div role="status" data-testid="fleet-blind-banner"
         className="rounded-sm border border-medium/50 bg-medium/10 px-3 py-1.5 text-[12px] text-medium">
      <span className="font-mono text-[10px] uppercase tracking-widest">blind</span>
      {" "}Athena is blind to {blind.label} since {since}
      {blind.fleet_wide ? " (fleet-wide)" : ""} — {blind.why}.
    </div>
  );
};


/** Several sites' internet trouble at once — one ISP, or one area — held at
 *  "notice" as likely regional (weather / provider): one line here instead
 *  of a ring of yellow pins. Hard failures are never held. */
const RegionalBanner: FC<{
  group: RegionalGroup;
  sites: readonly FleetSite[];
  onOpen: (key: string) => void;
}> = ({ group, sites, onOpen }) => {
  const byKey = new Map(sites.map((s) => [s.key, s]));
  const where = group.kind === "isp"
    ? `on ${group.isp ?? "one ISP"}${group.asn ? ` (AS${group.asn})` : ""}`
    : `within ~${Math.round(group.km ?? 80)} km of each other`;
  return (
    <div role="status" data-testid="fleet-regional-banner"
         className="flex flex-wrap items-center gap-2 rounded-sm border border-border bg-bg-surface px-3 py-2 text-[12px] text-text-secondary">
      <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">likely regional</span>
      <span>
        Internet trouble at {group.sites} site{group.sites === 1 ? "" : "s"} {where} in the last
        hour — weather or the provider, held as a notice instead of yellow.
      </span>
      <span className="flex flex-wrap gap-1">
        {group.keys.slice(0, 8).map((key) => {
          const s = byKey.get(key);
          return s ? (
            <button key={key} type="button" onClick={() => onOpen(key)}
                    className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[10px] text-text-secondary hover:text-text-primary">
              {s.name}
            </button>
          ) : null;
        })}
      </span>
    </div>
  );
};


const OutageBanner: FC<{
  outage: IspOutage;
  sites: readonly FleetSite[];
  onOpen: (key: string) => void;
}> = ({ outage, sites, onOpen }) => {
  const keys = new Set(sites.map((s) => s.key));
  const since = outage.since ? new Date(outage.since).toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit" }) : "?";
  return (
    <div role="alert" data-testid="isp-outage-banner"
         className="flex flex-wrap items-center gap-2 rounded-sm border border-critical/50 bg-critical/10 px-3 py-2 text-[12px] text-critical">
      <span className="font-mono text-[10px] uppercase tracking-widest">isp outage</span>
      <span className="font-semibold">
        {outage.isp ?? `AS${outage.asn}`} — {outage.sites} sites
      </span>
      <span className="text-text-secondary">
        since {since}{outage.sites_down !== undefined ? ` · ${outage.sites_down} still down` : ""}
        {" · one provider problem, one incident"}
      </span>
      <span className="flex flex-wrap gap-1">
        {(outage.members ?? []).slice(0, 8).map((m, i) => (
          m.key && keys.has(m.key) ? (
            <button key={m.key} type="button" onClick={() => onOpen(m.key!)}
                    className="rounded-sm border border-critical/40 px-1.5 py-0.5 font-mono text-[10px] text-critical hover:bg-critical/10">
              {m.name}
            </button>
          ) : (
            <span key={`${m.name}-${i}`} className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
              {m.name}
            </span>
          )
        ))}
      </span>
    </div>
  );
};


export default FleetPage;
