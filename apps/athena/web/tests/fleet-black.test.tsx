/**
 * Tier Black slice 1 — the console: the Black pin (octagon + "!", pulsing
 * until acknowledged, the radar's motion toggle does NOT stop it, the OS's
 * reduced motion gives a static double ring), Red never pulses, staleSites
 * keeps Black and Red, Black on the list entry and the no-location chip with
 * no pin at all, the global strip on every route, the title prefix, the
 * banner's Acknowledge, the drawer's incident panel, the client's two
 * actions — and a client user never sees a pulse. Fixtures are made up:
 * Example names, a synthetic grid.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import type {
  FleetLayer,
  FleetSite,
  FleetSitesResponse,
  HealthLayerName,
  SiteState,
  ThreatItem,
} from "@/contracts/fleet";
import type { EvidenceWindow, IncidentDetail, IncidentSummary } from "@/contracts/incidents";
import FleetMapOverlay, { type ProjectFn, type SiteMarker } from "@/components/fleet-map-overlay";
import FleetMapView from "@/components/fleet-map-view";
import FleetSiteList from "@/components/fleet-site-list";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import FleetLegend from "@/components/fleet-legend";
import ThreatStrip, { threatTitle } from "@/components/threat-strip";
import App from "@/App";
import FleetPage from "@/pages/fleet";
import {
  STATE_LABEL,
  effectiveState,
  filterSites,
  initials,
  ownerName,
  paintOrder,
  problemCount,
  sortSites,
  staleSites,
} from "@/lib/fleet";

const ok = (body: object, status = 200): Response =>
  new Response(JSON.stringify(body), { status });

const project: ProjectFn = (lat, lng) => ({ x: (lng + 102) * 100, y: (42 - lat) * 100 });

function layer(name: string, state: SiteState | "absent", extra: Partial<FleetLayer> = {}): FleetLayer {
  return {
    name: name as FleetLayer["name"], present: state !== "absent", state, scope: "site",
    reasons: [], data: {}, as_of: "2026-10-03T12:00:00.000Z", ...extra,
  };
}

function site(n: number, state: SiteState, o: Partial<FleetSite> = {}): FleetSite {
  const health: Record<HealthLayerName, FleetLayer> = {
    network: layer("network", state === "black" || state === "bad" ? "ok" : state),
    security: layer("security", "ok"),
    endpoints: layer("endpoints", "absent"),
    buoy: layer("buoy", "absent"),
  };
  return {
    key: `u-${String(n).padStart(20, "0")}`, kind: "site", name: `Example Site ${n}`,
    tenant_slug: "acme-corp", tenant_name: "Acme Corp", console_name: `console-${n}`,
    state, reason: state === "black" ? "BLACK: someone is controlling the screen on ws-01 (12 min, unacknowledged)" : `reason ${n}`,
    reasons: [{ state, text: `reason ${n}`, layer: state === "black" || state === "bad" ? "threat" : "network" }],
    location: { lat: 41.1 + n * 0.05, lng: -101, label: `${n} Example Road`, source: "unifi" },
    layers: { ...health, threat: layer("threat", state === "black" || state === "bad" ? state : "ok") },
    links: [], vendor_ref: null, tenant_sites: 1, partial: false, ...o,
  };
}

const blackMarker = (o: Partial<SiteMarker> = {}): SiteMarker => ({
  key: "k1", name: "Example Site 1", lat: 41.2, lng: -101, state: "black", ...o,
});

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => {
  global.fetch = originalFetch;
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
  document.title = "Athena";
  window.history.pushState({}, "", "/");
});

function reducedMotion(matches: boolean): void {
  Object.defineProperty(window, "matchMedia", {
    configurable: true, writable: true,
    value: vi.fn((query: string) => ({
      matches: matches && query.includes("reduce"), media: query, onchange: null,
      addEventListener: vi.fn(), removeEventListener: vi.fn(),
      addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(),
    })),
  });
}

// ---------------------------------------------------------------------------
// The pin
// ---------------------------------------------------------------------------

describe("the Black pin", () => {
  beforeEach(() => reducedMotion(false));

  it("is an octagon with a ! glyph, near-black inside a bright ring", () => {
    const { getByTestId } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[blackMarker()]} />);
    const pin = getByTestId("site-pin-k1");
    expect(pin).toHaveAttribute("data-state", "black");
    const oct = within(pin).getByTestId("site-pin-octagon");
    expect(oct.tagName.toLowerCase()).toBe("polygon");
    expect(oct.getAttribute("points")!.split(" ")).toHaveLength(8);
    expect(oct).toHaveAttribute("fill", "var(--fleet-threat)");
    expect(oct).toHaveAttribute("stroke", "var(--fleet-threat-ring)");
    expect(within(pin).getByTestId("site-pin-glyph")).toHaveTextContent("!");
  });

  it("pulses until acknowledged, then stays solid with the owner's initials", () => {
    const { getByTestId, rerender } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[blackMarker()]} />);
    expect(getByTestId("site-pin-k1").querySelector(".fleet-pin-black")).not.toBeNull();
    rerender(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[blackMarker({ acked: true, owner: initials("Alice Example") })]} />);
    const pin = getByTestId("site-pin-k1");
    expect(pin.querySelector(".fleet-pin-black")).toBeNull();
    expect(within(pin).getByTestId("site-pin-black-solid")).toBeInTheDocument();
    expect(within(pin).getByTestId("site-pin-owner")).toHaveTextContent("AE");
  });

  it("contained is a static double ring", () => {
    const { getByTestId } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[blackMarker({ acked: true, contained: true })]} />);
    const ring = within(getByTestId("site-pin-k1")).getByTestId("site-pin-contained");
    expect(ring.querySelectorAll("circle")).toHaveLength(2);
    expect(getByTestId("site-pin-k1").querySelector(".fleet-pin-black")).toBeNull();
  });

  it("the radar's motion=off keeps the Black pulse (only Black pulses)", () => {
    const { getByTestId } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       motion="off" spotlight
                       sites={[blackMarker(), { key: "k2", name: "Red", lat: 41.5, lng: -100.5,
                                                state: "bad" }]} />);
    expect(getByTestId("site-pin-k1").querySelector(".fleet-pin-black")).not.toBeNull();
    // Red never pulses — a static halo, motion or not.
    expect(getByTestId("site-pin-k2").querySelector(".fleet-pin-pulse")).toBeNull();
    expect(within(getByTestId("site-pin-k2")).getByTestId("site-pin-red-halo")).toBeInTheDocument();
  });

  it("the OS's reduced motion gives a static thick double ring plus the glyph", () => {
    reducedMotion(true);
    const { getByTestId } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[blackMarker()]} />);
    const pin = getByTestId("site-pin-k1");
    expect(pin.querySelector(".fleet-pin-black")).toBeNull();
    const rings = within(pin).getByTestId("site-pin-black-static").querySelectorAll("circle");
    expect(rings).toHaveLength(2);
    rings.forEach((c) => expect(Number(c.getAttribute("stroke-width"))).toBeGreaterThanOrEqual(3));
    expect(within(pin).getByTestId("site-pin-glyph")).toHaveTextContent("!");
  });

  it("is painted last and sorted first", () => {
    const ordered = paintOrder([{ state: "black" as SiteState }, { state: "bad" as SiteState },
                                { state: "ok" as SiteState }]);
    expect(ordered.map((x) => x.state)).toEqual(["ok", "bad", "black"]);
    const sites = [site(1, "warn"), site(2, "black"), site(3, "bad")];
    expect(sortSites(sites).map((s) => s.state)).toEqual(["black", "bad", "warn"]);
    expect(problemCount(sites)).toBe(3);
    expect(STATE_LABEL.black).toBe("Black: active attack");
    expect(STATE_LABEL.bad).toBe("Red: confirmed threat");
    expect(STATE_LABEL.warn).toBe("Yellow: needs eyes");
  });
});

describe("staleSites", () => {
  it("keeps Black and Red (an incident is a floor); the rest turns unknown", () => {
    const out = staleSites([site(1, "black"), site(2, "bad"), site(3, "warn"), site(4, "ok")], 3);
    expect(out.map((s) => s.state)).toEqual(["black", "bad", "unknown", "unknown"]);
    expect(out[0]!.reason).toMatch(/view stale 3 min$/);
    expect(out[0]!.layers.threat!.state).toBe("black");
    expect(out[0]!.layers.network.state).toBe("unknown");             // conditions go stale
    expect(out[2]!.reason).toBe("no fresh data for 3 min");
  });
});

// ---------------------------------------------------------------------------
// No pins yet: the list entry, the no-location chip, the legend
// ---------------------------------------------------------------------------

describe("Black without a map pin", () => {
  it("renders on the list entry — pulsing for an operator until acknowledged", () => {
    const black = site(1, "black", { location: null, incident: {
      tenant_slug: "acme-corp", id: 7, tier: "black", status: "open", acked: false,
      acked_by: null, contained: false, opened_at: "2026-10-03T12:00:00.000Z", age_s: 720,
      rule_id: "B6", device_label: "ws-01" } });
    render(<FleetSiteList view="operator" sites={[black]} layer="all" title="sites"
                          onOpen={() => undefined} />);
    const row = screen.getByTestId(`site-row-${black.key}`);
    expect(row).toHaveAttribute("data-state", "black");
    const chip = screen.getByTestId(`row-black-chip-${black.key}`);
    expect(chip).toHaveTextContent("black");
    expect(within(chip).getByTestId("row-glyph")).toHaveTextContent("!");
    expect(chip.className).toContain("fleet-strip-black");
  });

  it("the no-location chip carries Black", () => {
    render(<FleetMapView octos={[]} buoys={[]} showBuoys={false} sites={[]} unlocatedSites={2}
                         unlocatedProblems={1} unlocatedWorst="black" />);
    const chip = screen.getByTestId("unlocated-sites-banner");
    expect(chip).toHaveAttribute("data-state", "black");
    expect(chip.className).toContain("fleet-threat");
  });

  it("the legend has Black and Red rows (octagon swatch)", () => {
    render(<FleetLegend view="operator" />);
    expect(screen.getByTestId("legend-black")).toHaveTextContent("Black: active attack");
    expect(screen.getByTestId("legend-swatch-black")).toBeInTheDocument();
    expect(screen.getByTestId("legend-bad")).toHaveTextContent("never pulses");
  });
});

// ---------------------------------------------------------------------------
// The page: banner, acknowledge, the client's view
// ---------------------------------------------------------------------------

const THREAT: ThreatItem = {
  tenant: "acme-corp", tenant_name: "Acme Corp", id: 7, tier: "black", status: "open",
  acked: false, acked_by: null, contained: false, opened_at: "2026-10-03T12:00:00.000Z",
  age_s: 720, rule_id: "B6", summary: "someone is controlling the screen",
  device_label: "ws-01", unknown_location: false, site_keys: ["u-00000000000000000001"],
};

function operatorBody(sites: FleetSite[], extra: Partial<FleetSitesResponse> = {}): FleetSitesResponse {
  return {
    view: "operator", generated_at: new Date().toISOString(), partial: false, sites,
    counts: { total: sites.length }, isp_outages: [], unmapped_sites: 0, tenants: [],
    threats: [THREAT], blind: [], coverage: { sites_with_backup: 1, sites_without_backup: 3,
                                              sites_backup_unknown: 0 }, ...extra,
  };
}

describe("FleetPage — Tier Black", () => {
  beforeEach(() => {
    localStorage.setItem("athena.fleet.sites.view.v1", "list");
  });

  it("one non-dismissible banner per open Black; Acknowledge posts the ack", async () => {
    const black = site(1, "black", { incident: {
      tenant_slug: "acme-corp", id: 7, tier: "black", status: "open", acked: false,
      acked_by: null, contained: false, opened_at: "2026-10-03T12:00:00.000Z", age_s: 720,
      rule_id: "B6", device_label: "ws-01" } });
    const posts: string[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/fleet/sites")) {
        return Promise.resolve(ok(operatorBody([black, site(2, "warn")], {
          blind: [{ source: "datto", label: "Datto RMM", since: "2026-10-03T11:00:00.000Z",
                    fleet_wide: true, why: "every poll has failed since then", tenants: [] }],
        })));
      }
      if (url.includes("/ack") && init?.method === "POST") {
        posts.push(url);
        return Promise.resolve(ok({}));
      }
      if (url.includes("/auth/me")) {
        return Promise.resolve(ok({ username: "alice", role: ["analyst"] }));
      }
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    render(<FleetPage />);
    const banner = await screen.findByTestId("threat-banner");
    expect(banner).toHaveTextContent("Acme Corp");
    expect(banner).toHaveTextContent("someone is controlling the screen");
    expect(banner).toHaveTextContent("ws-01");
    expect(banner).toHaveTextContent("B6");
    expect(within(banner).getByTestId("threat-banner-ack-state")).toHaveTextContent("unacknowledged");
    expect(banner.querySelector("button[aria-label*='dismiss']")).toBeNull();
    fireEvent.click(within(banner).getByTestId("threat-banner-ack"));
    await waitFor(() => expect(posts).toEqual(["/api/v1/incidents/acme-corp/7/ack"]));
    expect(screen.getByTestId("fleet-summary")).toHaveTextContent("1 black · 0 red · 1 yellow");
    expect(screen.getByTestId("fleet-blind-banner")).toHaveTextContent("Athena is blind to Datto RMM");
    expect(screen.getByTestId("fleet-wan-coverage")).toHaveTextContent("3 sites without a backup line");
  });

  it("a client user gets the neutral line and exactly two actions — and no pulse", async () => {
    const clientSite = site(1, "black", {
      tenant_slug: null, console_name: null, location: null, layers: {
        network: layer("network", "ok"), security: layer("security", "ok"),
        endpoints: layer("endpoints", "absent"), buoy: layer("buoy", "absent"),
        threat: layer("threat", "black"),
      },
      reason: "Urgent security incident: your IT provider is responding",
      incident: { ref: "i-0123456789abcdef0123", tier: "black",
                  status_neutral: "Urgent security incident: your IT provider is responding",
                  opened_at: "2026-10-03T12:00:00.000Z",
                  actions: [{ kind: "lockdown", label: "Lock down my network and contact my analyst" },
                            { kind: "allow", label: "Allow this traffic" }] },
    });
    const posted: { url: string; body: string }[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/fleet/sites")) {
        return Promise.resolve(ok({ view: "client", generated_at: new Date().toISOString(),
                                    partial: false, sites: [clientSite], counts: {},
                                    isp_outages: [], unmapped_sites: null, tenants: [] }));
      }
      if (url.includes("/decision")) {
        posted.push({ url, body: String(init?.body) });
        return Promise.resolve(ok({
          confirmation: "Recorded. Your analyst has been paged and will contact you. Nothing on "
            + "your network has been changed yet. 911 / life-safety systems are never blocked.",
          decision: { kind: "lockdown", status: "recorded", created_at: "2026-10-03T12:05:00Z" } }));
      }
      if (url.includes("/auth/me")) return Promise.resolve(ok({ username: "erin", role: ["viewer"] }));
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    const { container } = render(<FleetPage />);
    const panel = await screen.findByTestId("client-incident");
    expect(panel).toHaveTextContent("Urgent security incident: your IT provider is responding");
    const buttons = within(panel).getAllByRole("button");
    expect(buttons.map((b) => b.textContent)).toEqual([
      "Lock down my network and contact my analyst", "Allow this traffic"]);
    expect(container.querySelector(".fleet-strip-black, .fleet-pin-black")).toBeNull();
    expect(screen.queryByTestId("threat-banner")).toBeNull();
    fireEvent.click(within(panel).getByTestId("client-action-lockdown"));
    const done = await within(panel).findByTestId("client-incident-confirmation");
    expect(done).toHaveTextContent("911 / life-safety systems are never blocked");
    expect(posted).toEqual([{ url: "/api/v1/incidents/client/i-0123456789abcdef0123/decision",
                              body: JSON.stringify({ kind: "lockdown" }) }]);
    const text = container.textContent!.toLowerCase();
    for (const word of ["ws-01", "b6", "unacknowledged"]) expect(text).not.toContain(word);
  });
});

// ---------------------------------------------------------------------------
// The drawer's incident panel
// ---------------------------------------------------------------------------

const DETAIL: IncidentDetail = {
  incident: {
    tenant_slug: "acme-corp", tenant_name: "Acme Corp", id: 7, tier: "black", status: "open",
    open: true, rule_id: "B6", rule_version: 1, rule_title: "analyst-declared Black",
    summary: "someone is controlling the screen", opened_at: "2026-10-03T12:00:00.000Z",
    age_s: 720, site_key: "u-00000000000000000001", device_ref: "dispatch-01",
    device_label: "dispatch-01", scope: "device", acked: false, acked_by: null,
    acked_by_name: null, acknowledged_at: null, assigned_to: null, assigned_to_name: null,
    contained: false, contained_at: null, closed_at: null, close_reason_code: null,
    reclassified_from: null, reopened_count: 0, escalation_step: 1, client_visible: false,
    opened_by: "1",
  },
  timeline: [{ id: 1, author: "1", kind: "open", text: "opened BLACK (B6)",
               created_at: "2026-10-03T12:00:00.000Z" }],
  evidence: [], snapshot: {}, stages: [],
  why: [{ condition: "a person's declaration", met: true, detail: "the client called", event_ids: [] }],
  ruled_out: [], ruled_out_note: "A person's declaration (B6 / R8): no automated attribution checks apply",
  kill_chain: [{ phase: "access", seen: false }, { phase: "impact", seen: false }],
  coverage: [{ rule_id: "R6", covered: false, missing: ["no buoy at this client"] }],
  mode: { mode: "propose_only", source: "slice 1 — nothing executes", caps: ["Analyze-only (life-safety asset: never blocked)"] },
  proposed_steps: ["911 / life-safety systems are never blocked: this asset is carved out", "Block C2"],
  decisions: [{ id: 3, incident_id: 7, kind: "allow", requested_by: "9", requested_role: "client",
                tier_at_request: "black", status: "pending_analyst", scope: [], excluded: [],
                notice: "", note: null, created_at: "2026-10-03T12:10:00Z", decided_by: null,
                decided_at: null, decision_note: null, executed: 0 }],
  client_view: null, asset_tags: ["life_safety"],
};

/** The incident's automatic evidence window: first detection → open. */
const WINDOW: EvidenceWindow = {
  id: 11, tenant_slug: "acme-corp", tenant_name: "Acme Corp", incident_id: 7,
  origin_incident_id: 7, incident_tier: "black", incident_status: "open", incident_open: true,
  incident_summary: "someone is controlling the screen", kind: "incident",
  start: "2026-10-03T11:58:00.000Z", end: null, open: true, held: true, opened_by: "1",
  opened_by_name: "Alice Example", opened_at: "2026-10-03T12:00:00.000Z",
  reason: "a confirmed threat (Red / Black)", released_at: null, released_by: null,
  released_by_name: null, release_reason: null, kept_rows: null, kept_counted_at: null,
  events_in_window: 42, events_capped: false,
};

describe("the drawer's incident panel", () => {
  it("shows why, what was ruled out, the mode, the steps and the client's pending request", async () => {
    const calls: string[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push(`${init?.method ?? "GET"} ${url}`);
      if (url.endsWith("/incidents/acme-corp/7")) return Promise.resolve(ok(DETAIL));
      if (url.includes("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    const s = site(1, "black", { incident: {
      tenant_slug: "acme-corp", id: 7, tier: "black", status: "open", acked: false,
      acked_by: null, contained: false, opened_at: "2026-10-03T12:00:00.000Z", age_s: 720,
      rule_id: "B6", rule_version: 1, device_label: "dispatch-01" } });
    render(<FleetSiteDrawer site={s} view="operator" onClose={() => undefined} callerRole="analyst" />);
    const panel = await screen.findByTestId("incident-panel");
    expect(within(panel).getByTestId("incident-tier")).toHaveTextContent("black");
    expect(within(panel).getByTestId("incident-rule")).toHaveTextContent("B6@1");
    await within(panel).findByTestId("incident-why");
    expect(within(panel).getByTestId("incident-ruled-out")).toHaveTextContent("no automated attribution");
    expect(within(panel).getByTestId("incident-mode")).toHaveTextContent("propose only");
    expect(within(panel).getByTestId("incident-steps")).toHaveTextContent("911 / life-safety");
    expect(within(panel).getByTestId("incident-kill-chain")).toBeInTheDocument();
    expect(within(panel).getByTestId("incident-coverage")).toHaveTextContent("not covered: R6");
    // An analyst may not close a Black; no lower / mute / snooze exists.
    expect(within(panel).queryByTestId("incident-close")).toBeNull();
    expect(within(panel).getByTestId("incident-close-admin")).toBeInTheDocument();
    expect(panel.textContent!.toLowerCase()).not.toMatch(/\b(mute|snooze|lower)\b/);
    fireEvent.click(within(panel).getByTestId("decision-confirm-3"));
    await waitFor(() => expect(calls).toContain(
      "POST /api/v1/incidents/acme-corp/7/decisions/3/answer"));
    fireEvent.click(within(panel).getByTestId("incident-ack"));
    await waitFor(() => expect(calls).toContain("POST /api/v1/incidents/acme-corp/7/ack"));
  });
});

// ---------------------------------------------------------------------------
// The global strip, the title, every route
// ---------------------------------------------------------------------------

describe("the global threat strip", () => {
  it("the title prefix", () => {
    const s: IncidentSummary = { view: "operator", black: 2, red: 1, black_unacked: 1, items: [] };
    expect(threatTitle("Athena", s)).toBe("BLACK (2) · Athena");
    expect(threatTitle("BLACK (2) · Athena", { ...s, black: 0, red: 1 })).toBe("RED (1) · Athena");
    expect(threatTitle("RED (1) · Athena", { ...s, black: 0, red: 0 })).toBe("Athena");
    expect(threatTitle("Athena", null)).toBe("Athena");
  });

  it("operators: counts and a pulse while a Black is unacknowledged", () => {
    const { rerender } = render(
      <ThreatStrip summary={{ view: "operator", black: 2, red: 1, black_unacked: 1, items: [] }} />);
    const strip = screen.getByTestId("threat-strip");
    expect(strip).toHaveTextContent("black 2 (1 unacknowledged)");
    expect(screen.getByTestId("threat-strip-black").className).toContain("fleet-strip-black");
    rerender(<ThreatStrip summary={{ view: "operator", black: 2, red: 0, black_unacked: 0 }} />);
    expect(screen.getByTestId("threat-strip-black").className).not.toContain("fleet-strip-black");
    rerender(<ThreatStrip summary={{ view: "operator", black: 0, red: 0, black_unacked: 0 }} />);
    expect(screen.queryByTestId("threat-strip")).toBeNull();
  });

  it("a client user: the neutral line only, no pulse, no counts", () => {
    const { container } = render(<ThreatStrip summary={{ view: "client", black: 1, red: 0 }} />);
    const strip = screen.getByTestId("threat-strip");
    expect(strip).toHaveTextContent("Urgent security incident: your IT provider has been alerted");
    expect(strip.textContent).not.toMatch(/\d/);
    expect(container.querySelector(".fleet-strip-black")).toBeNull();
  });

  it.each(["/tickets", "/settings", "/dashboard"])("is on every route (%s) with the title prefix",
    async (route) => {
      reducedMotion(false);
      window.history.pushState({}, "", route);
      global.fetch = vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/incidents/summary")) {
          return Promise.resolve(ok({ view: "operator", black: 2, red: 0, black_unacked: 1,
                                      items: [THREAT] }));
        }
        if (url.includes("/auth/me")) {
          return Promise.resolve(ok({ operator_id: 1, username: "alice", email: "alice@example.test",
                                      display_name: null, role: ["analyst"], scope_slugs: ["*"],
                                      must_change_password: false, mfa_enabled: true,
                                      backup_codes_remaining: 8, needs_setup: false }));
        }
        if (url.includes("/fleet/sites")) {
          return Promise.resolve(ok(operatorBody([site(1, "black")])));
        }
        return Promise.resolve(ok({ code: "NOT_FOUND", message: "fixture" }, 404));
      }) as unknown as typeof fetch;
      render(<App />);
      const strip = await screen.findByTestId("threat-strip", {}, { timeout: 4000 });
      expect(strip).toHaveTextContent("black 2 (1 unacknowledged)");
      await waitFor(() => expect(document.title.startsWith("BLACK (2) · ")).toBe(true));
      const chips = await screen.findAllByTestId("sidebar-black-chip");
      expect(chips[0]).toHaveTextContent("2");
    });
});

// ---------------------------------------------------------------------------
// Review fixes (feat/tier-black-slice1-fixed)
// ---------------------------------------------------------------------------

describe("review fixes", () => {
  it("the client strip shows the server's worst line, never always 'has been alerted'", () => {
    render(<ThreatStrip summary={{ view: "client", black: 1, red: 0,
                                   status_neutral: "Security incident contained: your IT provider is monitoring" }} />);
    const strip = screen.getByTestId("threat-strip");
    expect(strip).toHaveTextContent("Security incident contained: your IT provider is monitoring");
    expect(strip.textContent).not.toMatch(/alerted/);
  });

  it("the acknowledged Black's owner initials come from the NAME, never the operator id", () => {
    const inc = { tenant_slug: "acme-corp", id: 7, tier: "black" as const, status: "acknowledged",
                  acked: true, acked_by: "12", acked_by_name: "Alice Example", contained: false,
                  opened_at: "2026-10-03T12:00:00.000Z", age_s: 720, rule_id: "B6",
                  device_label: "ws-01" };
    expect(initials(ownerName([], inc))).toBe("AE");
    expect(initials(ownerName([], { ...inc, acked_by_name: null }))).toBe("?");   // never "1"
    const { acked_by_name: _name, ...nameless } = inc;               // no name on the pin
    expect(initials(ownerName([{ ...THREAT, acked: true, acked_by: "12",
                                 acked_by_name: "Bob Example" }],
                              nameless))).toBe("BE");
  });

  it("a layer filter never recolours or hides a Black or Red site", () => {
    const black = site(1, "black");
    const red = site(2, "bad");
    const quiet = site(3, "ok");
    expect(effectiveState(black, "network")).toBe("black");
    expect(effectiveState(red, "endpoints")).toBe("bad");          // absent layer: still shown
    const shown = filterSites([black, red, quiet], { query: "", problemsOnly: true,
                                                      layer: "endpoints", tenant: null });
    expect(shown.map((s) => s.state)).toEqual(["black", "bad"]);
  });

  it("an operator declares Black from the drawer (B6): site, optional device, a reason", async () => {
    const posts: { url: string; body: unknown }[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === "POST") {
        posts.push({ url, body: JSON.parse(String(init.body)) });
        return Promise.resolve(ok({ id: 9, tier: "black" }));
      }
      if (url.includes("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    const changed = vi.fn();
    const s = site(1, "ok");
    render(<FleetSiteDrawer site={s} view="operator" onClose={() => undefined}
                            callerRole="analyst" onIncidentChanged={changed} />);
    fireEvent.click(screen.getByTestId("declare-black"));
    const submit = screen.getByTestId("declare-black-submit");
    expect(submit).toBeDisabled();                                  // a reason is required
    fireEvent.change(screen.getByTestId("declare-black-summary"),
                     { target: { value: "someone is controlling the screen" } });
    fireEvent.change(screen.getByTestId("declare-black-device"), { target: { value: "ws-01" } });
    fireEvent.change(screen.getByTestId("declare-black-reason"),
                     { target: { value: "the client called" } });
    fireEvent.click(submit);
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(posts).toEqual([{ url: "/api/v1/incidents/declare", body: {
      tenant: "acme-corp", site_key: s.key, summary: "someone is controlling the screen",
      reason: "the client called", device_ref: "ws-01" } }]);
  });

  it("an operator confirms a recent alert as a threat (R8): a reason of 20 characters", async () => {
    const posts: { url: string; body: unknown }[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === "POST") {
        posts.push({ url, body: JSON.parse(String(init.body)) });
        return Promise.resolve(ok({ id: 4, tier: "red" }));
      }
      if (url.includes("/alerts")) {
        return Promise.resolve(ok({ key: "x", items: [{
          event_id: 41, occurred_at: "2026-10-03T11:00:00.000Z", severity: "high",
          source: "wazuh", title: "Malware verdict", tenant_wide: false }] }));
      }
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    const changed = vi.fn();
    render(<FleetSiteDrawer site={site(1, "warn")} view="operator" onClose={() => undefined}
                            callerRole="analyst" onIncidentChanged={changed} />);
    fireEvent.click(await screen.findByTestId("confirm-threat-41"));
    const submit = screen.getByTestId("confirm-threat-submit-41");
    fireEvent.change(screen.getByTestId("confirm-threat-reason-41"),
                     { target: { value: "looks bad" } });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-threat-reason-41"),
                     { target: { value: "the hash is on a ransomware family list" } });
    fireEvent.click(submit);
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(posts).toEqual([{ url: "/api/v1/signals/acme-corp/41/confirm",
                             body: { reason: "the hash is on a ransomware family list" } }]);
  });

  it("a client user's drawer has neither declare nor confirm", () => {
    global.fetch = vi.fn() as unknown as typeof fetch;
    render(<FleetSiteDrawer site={site(1, "warn", { tenant_slug: null })} view="client"
                            onClose={() => undefined} />);
    expect(screen.queryByTestId("declare-black")).toBeNull();
    expect(screen.queryByTestId("site-alerts")).toBeNull();
  });

  it("the panel: assign to me, reclassify and evidence windows (admin), ready to close, why this device, freshness", async () => {
    const calls: { method: string; url: string; body?: unknown }[] = [];
    const detail: IncidentDetail = {
      ...DETAIL,
      incident: { ...DETAIL.incident, contained: true, contained_at: "2026-09-29T12:00:00.000Z",
                  ready_to_close: true, evidence_held: true, assigned_to: null },
      evidence_windows: [WINDOW],
      why_device: ["named by the person who declared it (operator #1) — typed, not resolved"],
      freshness: [{ source: "datto", label: "Datto RMM", last_ok_at: "2026-10-03T11:58:00.000Z",
                    failing_since: null, blind: false },
                  { source: "tier_worker", label: "threat correlation", last_ok_at: null,
                    failing_since: null, blind: true }],
    };
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ method: init?.method ?? "GET", url,
                   ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
      if (url.endsWith("/incidents/acme-corp/7")) return Promise.resolve(ok(detail));
      if (url.includes("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    const s = site(1, "black", { incident: {
      tenant_slug: "acme-corp", id: 7, tier: "black", status: "open", acked: true,
      acked_by: "1", contained: true, opened_at: "2026-10-03T12:00:00.000Z", age_s: 720,
      rule_id: "B6", rule_version: 1, device_label: "dispatch-01" } });
    render(<FleetSiteDrawer site={s} view="operator" onClose={() => undefined}
                            callerRole="admin" callerId={5} />);
    const panel = await screen.findByTestId("incident-panel");
    expect(await within(panel).findByTestId("incident-ready-to-close"))
      .toHaveTextContent("ready to close?");
    expect(within(panel).getByTestId("incident-why-device")).toHaveTextContent("named by the person");
    expect(within(panel).getByTestId("freshness-tier_worker")).toHaveTextContent("BLIND");
    expect(within(panel).getByTestId("freshness-datto")).toHaveTextContent("fresh");
    fireEvent.click(within(panel).getByTestId("incident-assign-me"));
    await waitFor(() => expect(calls).toContainEqual({
      method: "POST", url: "/api/v1/incidents/acme-corp/7/assign", body: { to: 5 } }));
    fireEvent.click(within(panel).getByTestId("incident-reclassify"));
    fireEvent.change(within(panel).getByTestId("incident-text"),
                     { target: { value: "a vendor's session, unannounced" } });
    fireEvent.click(within(panel).getByTestId("incident-submit"));
    await waitFor(() => expect(calls).toContainEqual({
      method: "POST", url: "/api/v1/incidents/acme-corp/7/reclassify",
      body: { reason: "a vendor's session, unannounced" } }));
    // Evidence windows: the incident's window, what it keeps; the former
    // legal hold is "add evidence window" (admin, step-up on the server).
    expect(panel).toHaveTextContent("EVIDENCE KEPT");
    expect(within(panel).getByTestId("evidence-window-11")).toHaveTextContent(
      "#11 · auto · 2026-10-03 11:58 UTC → open (until the all-clear) · rows kept: not counted yet · ~42 events");
    expect(within(panel).queryByTestId("evidence-release-11")).toBeNull();   // not before the all-clear
    fireEvent.click(within(panel).getByTestId("incident-evidence-add"));
    fireEvent.change(within(panel).getByTestId("evidence-start"),
                     { target: { value: "2026-09-01T00:00" } });
    fireEvent.change(within(panel).getByTestId("incident-text"),
                     { target: { value: "claim CL-0001" } });
    fireEvent.click(within(panel).getByTestId("incident-submit"));
    await waitFor(() => expect(calls).toContainEqual({
      method: "POST", url: "/api/v1/incidents/acme-corp/7/evidence-window",
      body: { start: "2026-09-01T00:00", reason: "claim CL-0001" } }));
    fireEvent.click(within(panel).getByTestId("evidence-extend-11"));
    expect((within(panel).getByTestId("evidence-start") as HTMLInputElement).value)
      .toBe("2026-10-03T11:58:00.000Z");                               // prefilled: no surprise
    fireEvent.change(within(panel).getByTestId("evidence-start"),
                     { target: { value: "2026-09-20T00:00" } });
    fireEvent.change(within(panel).getByTestId("incident-text"),
                     { target: { value: "the claim covers September" } });
    fireEvent.click(within(panel).getByTestId("incident-submit"));
    await waitFor(() => expect(calls).toContainEqual({
      method: "POST", url: "/api/v1/incidents/acme-corp/7/evidence-window",
      body: { window_id: 11, start: "2026-09-20T00:00", reason: "the claim covers September" } }));
  });

  it("after the all-clear an admin releases a window, with a reason", async () => {
    const calls: { method: string; url: string; body?: unknown }[] = [];
    const detail: IncidentDetail = {
      ...DETAIL,
      incident: { ...DETAIL.incident, open: false, status: "closed",
                  closed_at: "2026-10-04T09:00:00.000Z", evidence_held: true },
      evidence_windows: [{ ...WINDOW, end: "2026-10-04T09:00:00.000Z", open: false,
                           incident_open: false, incident_status: "closed", kept_rows: 1200,
                           kept_counted_at: "2026-10-05T09:00:00.000Z" }],
    };
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ method: init?.method ?? "GET", url,
                   ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
      if (url.endsWith("/incidents/acme-corp/7")) return Promise.resolve(ok(detail));
      return Promise.resolve(ok({ key: "x", items: [] }));
    }) as unknown as typeof fetch;
    const s = site(1, "black", { incident: {
      tenant_slug: "acme-corp", id: 7, tier: "black", status: "closed", acked: true,
      acked_by: "1", contained: true, opened_at: "2026-10-03T12:00:00.000Z", age_s: 720,
      rule_id: "B6", rule_version: 1, device_label: "dispatch-01" } });
    render(<FleetSiteDrawer site={s} view="operator" onClose={() => undefined}
                            callerRole="admin" callerId={5} />);
    const panel = await screen.findByTestId("incident-panel");
    const row = await within(panel).findByTestId("evidence-window-11");
    expect(row).toHaveTextContent(
      "2026-10-03 11:58 UTC → 2026-10-04 09:00 UTC · 1,200 rows kept past retention");
    fireEvent.click(within(panel).getByTestId("evidence-release-11"));
    expect(within(panel).queryByTestId("evidence-start")).toBeNull();     // a reason only
    fireEvent.change(within(panel).getByTestId("incident-text"),
                     { target: { value: "the claim is settled" } });
    fireEvent.click(within(panel).getByTestId("incident-submit"));
    await waitFor(() => expect(calls).toContainEqual({
      method: "POST", url: "/api/v1/incidents/acme-corp/7/evidence-window/11/release",
      body: { reason: "the claim is settled" } }));
  });

  it("an analyst widens a window but gets neither reclassify, add, extend nor release", async () => {
    const calls: { method: string; url: string; body?: unknown }[] = [];
    const detail: IncidentDetail = { ...DETAIL, evidence_windows: [WINDOW] };
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ method: init?.method ?? "GET", url,
                   ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
      if (url.endsWith("/incidents/acme-corp/7")) return Promise.resolve(ok(detail));
      return Promise.resolve(ok({ key: "x", items: [] }));
    }) as unknown as typeof fetch;
    const s = site(1, "black", { incident: {
      tenant_slug: "acme-corp", id: 7, tier: "black", status: "open", acked: false,
      acked_by: null, contained: false, opened_at: "2026-10-03T12:00:00.000Z", age_s: 720,
      rule_id: "B6", rule_version: 1, device_label: "dispatch-01" } });
    render(<FleetSiteDrawer site={s} view="operator" onClose={() => undefined}
                            callerRole="analyst" callerId={5} />);
    const panel = await screen.findByTestId("incident-panel");
    await within(panel).findByTestId("incident-why");
    expect(within(panel).queryByTestId("incident-reclassify")).toBeNull();
    expect(within(panel).queryByTestId("incident-evidence-add")).toBeNull();
    expect(within(panel).queryByTestId("evidence-extend-11")).toBeNull();
    expect(within(panel).queryByTestId("evidence-release-11")).toBeNull();
    expect(within(panel).getByTestId("incident-assign-me")).toBeInTheDocument();
    fireEvent.click(within(panel).getByTestId("evidence-widen-11"));
    expect(within(panel).queryByTestId("evidence-end")).toBeNull();       // the start only
    fireEvent.change(within(panel).getByTestId("evidence-start"),
                     { target: { value: "2026-09-25T06:00" } });
    fireEvent.change(within(panel).getByTestId("incident-text"),
                     { target: { value: "dwell time: the first beacon was on the 25th" } });
    fireEvent.click(within(panel).getByTestId("incident-submit"));
    await waitFor(() => expect(calls).toContainEqual({
      method: "POST", url: "/api/v1/incidents/acme-corp/7/evidence-window/11/widen",
      body: { start: "2026-09-25T06:00",
              reason: "dwell time: the first beacon was on the 25th" } }));
  });

  it("a client user's drawer shows nothing of an evidence window", async () => {
    const calls: string[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      calls.push(String(input));
      return Promise.resolve(ok({ items: [] }));
    }) as unknown as typeof fetch;
    const s = site(1, "black", {
      tenant_slug: null,
      incident: { ref: "i-0123456789abcdef0123", tier: "black",
                  status_neutral: "Urgent security incident: your IT provider is responding",
                  opened_at: "2026-10-03T12:00:00.000Z",
                  actions: [{ kind: "lockdown", label: "Lock down my network and contact my analyst" },
                            { kind: "allow", label: "Allow this traffic" }] },
    });
    render(<FleetSiteDrawer site={s} view="client" onClose={() => undefined} />);
    await screen.findByTestId("client-incident");
    expect(screen.queryByTestId("incident-evidence")).toBeNull();
    expect(document.body.textContent ?? "").not.toMatch(/evidence|window/i);
    expect(calls.some((u) => u.includes("evidence"))).toBe(false);
  });
});
