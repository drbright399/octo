/**
 * Fleet v2 (site-centric) — the pure filters, the map's site pins, the
 * legend, the list view, the drawer, the filters on the page, the client
 * (viewer) view, the location dialog, and a 40-site fixture fleet render
 * check. Fixture names are example.test / "Example …"; coordinates are a
 * synthetic grid, never a real site.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import type { FleetLayer, FleetSite, FleetSitesResponse, LayerName, SiteState } from "@/contracts/fleet";
import FleetMapOverlay, { __test__ as overlayTest, type ProjectFn, type SiteMarker } from "@/components/fleet-map-overlay";
import FleetMapView, { FIT_MAX_ZOOM, FIT_PADDING_PX, pinBounds } from "@/components/fleet-map-view";
import maplibregl from "maplibre-gl";
import FleetLegend from "@/components/fleet-legend";
import FleetSiteList from "@/components/fleet-site-list";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import TenantLocationDialog, { coordError } from "@/components/tenant-location-dialog";
import FleetPage from "@/pages/fleet";
import {
  NO_FILTERS,
  effectiveState,
  filterSites,
  problemCount,
  sortSites,
} from "@/lib/fleet";

const ok = (body: object): Response => new Response(JSON.stringify(body), { status: 200 });

function layer(name: LayerName, state: SiteState | "absent", extra: Partial<FleetLayer> = {}): FleetLayer {
  return {
    name, present: state !== "absent", state, scope: "site", reasons: [], data: {},
    as_of: "2026-10-02T12:00:00.000Z", ...extra,
  };
}

function makeSite(n: number, o: Partial<FleetSite> = {}, state: SiteState = "ok"): FleetSite {
  return {
    key: `u-${String(n).padStart(20, "0")}`,
    kind: "site",
    name: `Example Site ${n}`,
    tenant_slug: `example-client-${n % 5}`,
    tenant_name: `Example Client ${n % 5}`,
    console_name: `console-${n}`,
    state,
    reason: state === "ok" ? "all clear" : `reason ${n}`,
    reasons: state === "ok" ? [] : [{ state, text: `reason ${n}`, layer: "network" }],
    location: { lat: 41 + (n % 8) * 0.06, lng: -101 + Math.floor(n / 8) * 0.08, label: `${n} Example Road`, source: "unifi" },
    layers: {
      network: layer("network", state),
      security: layer("security", "ok"),
      endpoints: layer("endpoints", "absent"),
      buoy: layer("buoy", "absent"),
    },
    links: [],
    vendor_ref: null,
    tenant_sites: 1,
    partial: false,
    ...o,
  };
}

const project: ProjectFn = (lat, lng) => ({ x: (lng + 102) * 400, y: (42 - lat) * 400 });

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe("fleet filters", () => {
  const sites = [
    makeSite(1, {}, "bad"),
    makeSite(2, {}, "ok"),
    makeSite(3, { layers: { ...makeSite(3).layers, buoy: layer("buoy", "warn") } }, "warn"),
    makeSite(4, { location: null }, "unknown"),
  ];

  it("problems only keeps everything that is not ok (unknown included)", () => {
    expect(filterSites(sites, { ...NO_FILTERS, problemsOnly: true }).map((s) => s.name))
      .toEqual(["Example Site 1", "Example Site 3", "Example Site 4"]);
  });

  it("a layer filter hides sites without that layer and uses its state — never a Red / Black", () => {
    const buoy = filterSites(sites, { ...NO_FILTERS, layer: "buoy" });
    // Site 1 is Red: an open incident is never hidden or recoloured by a filter.
    expect(buoy.map((s) => s.name)).toEqual(["Example Site 1", "Example Site 3"]);
    expect(effectiveState(sites[2]!, "buoy")).toBe("warn");
    expect(effectiveState(sites[1]!, "endpoints")).toBeNull();
    expect(effectiveState(sites[0]!, "endpoints")).toBe("bad");
  });

  it("tenant + search", () => {
    expect(filterSites(sites, { ...NO_FILTERS, tenant: "example-client-2" }).map((s) => s.name))
      .toEqual(["Example Site 2"]);
    expect(filterSites(sites, { ...NO_FILTERS, query: "3 example road" }).map((s) => s.name))
      .toEqual(["Example Site 3"]);
    expect(filterSites(sites, { ...NO_FILTERS, query: "reason 4" })).toHaveLength(1);
  });

  it("sorts worst first and counts problems", () => {
    expect(sortSites(sites).map((s) => s.state)).toEqual(["bad", "warn", "unknown", "ok"]);
    expect(problemCount(sites)).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Map pins
// ---------------------------------------------------------------------------

describe("site pins on the map overlay", () => {
  const marker = (n: number, state: SiteState, source: "unifi" | "manual" = "unifi"): SiteMarker => ({
    key: `k${n}`, name: `Example Site ${n}`, lat: 41 + n * 0.1, lng: -101 + n * 0.1, state, source,
    reason: `r${n}`,
  });

  it("draws one pin per located site, coloured and shaped by state", () => {
    const onSiteClick = vi.fn();
    const { container, getByTestId } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[marker(1, "bad"), marker(2, "warn"), marker(3, "unknown"),
                               marker(4, "ok", "manual"),
                               { ...marker(5, "ok"), lat: Number.NaN }]}
                       onSiteClick={onSiteClick} />,
    );
    const pins = container.querySelectorAll(".fleet-map-overlay__site");
    expect(pins).toHaveLength(4);                                   // NaN skipped
    expect(getByTestId("site-pin-k1")).toHaveAttribute("data-state", "bad");
    // Red never pulses (Tier Black slice 1): a static halo.
    expect(getByTestId("site-pin-k1").querySelector(".fleet-pin-pulse")).toBeNull();
    expect(getByTestId("site-pin-k1").querySelector("[data-testid='site-pin-red-halo']")).not.toBeNull();
    expect(getByTestId("site-pin-k3").querySelector("circle")).toHaveAttribute("stroke-dasharray", "2 2");
    expect(getByTestId("site-pin-k4")).toHaveAttribute("data-source", "manual");
    expect(getByTestId("site-pin-k4").querySelector("rect")).not.toBeNull();   // a diamond
    fireEvent.click(getByTestId("site-pin-k2"));
    expect(onSiteClick).toHaveBeenCalledWith(expect.objectContaining({ key: "k2" }));
  });

  it("problem pins are painted last (on top), whatever the input order", () => {
    const { container } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[marker(1, "bad"), marker(2, "warn"), marker(3, "unknown"), marker(4, "ok")]} />,
    );
    const order = [...container.querySelectorAll(".fleet-map-overlay__site")].map((el) => el.getAttribute("data-state"));
    expect(order).toEqual(["ok", "unknown", "warn", "bad"]);
  });

  it("selection is a dashed square in the text colour, never an accent ring", () => {
    const { getByTestId } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[marker(1, "ok"), marker(2, "warn")]} selectedSiteKey="k1" />,
    );
    const sel = getByTestId("site-pin-k1").querySelector("[data-testid='site-pin-selected']")!;
    expect(sel.tagName.toLowerCase()).toBe("rect");
    expect(sel).toHaveAttribute("stroke", "var(--text-primary)");
    expect(sel).toHaveAttribute("stroke-dasharray", "4 3");
    expect(getByTestId("site-pin-k1").innerHTML).not.toContain("var(--accent)");
  });

  it("a big cluster spreads into a ring that grows with it", () => {
    const { spreadOverlappingSites, siteRingRadius } = overlayTest;
    expect(siteRingRadius(3)).toBe(14);
    expect(siteRingRadius(40)).toBeGreaterThan(80);
    const placed = Array.from({ length: 40 }, (_, i) => ({
      slug: `k${String(i).padStart(2, "0")}`, xy: { x: 400 + (i % 3), y: 300 },
      marker: marker(i, "ok"),
    }));
    spreadOverlappingSites(placed);
    let min = Infinity;
    for (let i = 0; i < placed.length; i++) {
      for (let j = i + 1; j < placed.length; j++) {
        min = Math.min(min, Math.hypot(placed[i]!.xy.x - placed[j]!.xy.x, placed[i]!.xy.y - placed[j]!.xy.y));
      }
    }
    expect(min).toBeGreaterThanOrEqual(12);                 // a pin's width apart
  });

  it("spotlight dims ok sites; motion off stops the pulse", () => {
    const { container, getByTestId } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[]} buoys={[]} project={project}
                       sites={[marker(1, "bad")]} spotlight motion="off" />,
    );
    expect(container.querySelector("svg")).toHaveClass("fleet-map-overlay--spotlight");
    expect(getByTestId("site-pin-k1").querySelector(".fleet-pin-pulse")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Legend, list, drawer
// ---------------------------------------------------------------------------

describe("the map view", () => {
  const pins: SiteMarker[] = [
    { key: "a", name: "Example Site A", lat: 41.1, lng: -100.9, state: "ok" },
    { key: "b", name: "Example Site B", lat: 41.4, lng: -100.2, state: "bad" },
    { key: "c", name: "Example Site C", lat: Number.NaN, lng: Number.NaN, state: "warn" },
  ];

  it("fits the map to the pins once, and on the fit button", () => {
    expect(pinBounds(pins)).toEqual([[-100.9, 41.1], [-100.2, 41.4]]);
    expect(pinBounds([])).toBeNull();
    const { rerender } = render(<FleetMapView octos={[]} buoys={[]} showBuoys={false} sites={pins} />);
    const calls = vi.mocked(maplibregl.Map).mock.results;
    const map = calls[calls.length - 1]!.value as { fitBounds: ReturnType<typeof vi.fn> };
    expect(map.fitBounds).toHaveBeenCalledTimes(1);
    expect(map.fitBounds).toHaveBeenCalledWith([[-100.9, 41.1], [-100.2, 41.4]],
      expect.objectContaining({ padding: FIT_PADDING_PX, maxZoom: FIT_MAX_ZOOM }));
    rerender(<FleetMapView octos={[]} buoys={[]} showBuoys={false} sites={[...pins]} />);
    expect(map.fitBounds).toHaveBeenCalledTimes(1);          // a poll never moves the map
    fireEvent.click(screen.getByTestId("fleet-map-fit"));
    expect(map.fitBounds).toHaveBeenCalledTimes(2);
  });

  it("the no-location chip says how many need attention and jumps to the list", () => {
    const onUnlocatedClick = vi.fn();
    render(<FleetMapView octos={[]} buoys={[]} showBuoys={false} sites={[]} unlocatedSites={6}
                         unlocatedProblems={2} unlocatedWorst="bad" onUnlocatedClick={onUnlocatedClick} />);
    const chip = screen.getByTestId("unlocated-sites-banner");
    expect(chip).toHaveTextContent("6 sites (2 need attention) listed below the map");
    expect(chip).toHaveAttribute("data-state", "bad");
    expect(chip.className).toContain("text-critical");
    fireEvent.click(chip);
    expect(onUnlocatedClick).toHaveBeenCalled();
  });
});

describe("legend", () => {
  it("operators: four states, manual placement and (when on) the buoy", () => {
    render(<FleetLegend view="operator" showBuoys />);
    for (const s of ["bad", "warn", "unknown", "ok", "manual", "buoy"]) {
      expect(screen.getByTestId(`legend-${s}`)).toBeInTheDocument();
    }
    expect(screen.getByText(/stale data is never shown as ok/)).toBeInTheDocument();
  });

  it("client users: the states only", () => {
    render(<FleetLegend view="client" showBuoys />);
    expect(screen.queryByTestId("legend-manual")).toBeNull();
    expect(screen.queryByTestId("legend-buoy")).toBeNull();
  });
});

describe("site list", () => {
  it("rows open the drawer and show each layer's state", () => {
    const onOpen = vi.fn();
    const sites = [makeSite(1, {}, "bad"), makeSite(2, { location: null })];
    render(<FleetSiteList view="operator" sites={sites} layer="all" title="sites" onOpen={onOpen} />);
    const row = screen.getByTestId(`site-row-${sites[0]!.key}`);
    expect(row).toHaveAttribute("data-state", "bad");
    expect(within(row).getByTestId("layer-dot-endpoints")).toHaveAttribute("data-state", "absent");
    expect(screen.getByText(/no location/)).toBeInTheDocument();
    fireEvent.click(row);
    expect(onOpen).toHaveBeenCalledWith(sites[0]);
  });
});

describe("site drawer", () => {
  const site = makeSite(1, {
    state: "bad", reason: "NextDNS lapsed (Example DNS) (+1 more)",
    layers: {
      network: layer("network", "warn", {
        data: { devices_total: 6, devices_online: 4, gateway_online: true, wan_up: ["WAN"],
                wan_down: [], isp: "Example ISP", asn: 64500, internet_issues: 0 },
        reasons: [{ state: "warn", text: "2 devices offline", layer: "network" }],
      }),
      security: layer("security", "bad", {
        scope: "tenant",
        data: { ips_detected_24h: 0, ips_blocked_24h: 2,
                dns_profiles: [{ profile_id: "p1", name: "Example DNS", state: "lapsed", threats_24h: 0 }],
                open_incidents: 0 },
        reasons: [{ state: "bad", text: "NextDNS lapsed (Example DNS)", layer: "security" }],
      }),
      endpoints: layer("endpoints", "absent", { note: "no Datto inventory read yet" }),
      buoy: layer("buoy", "absent"),
    },
    links: [
      { vendor: "unifi", label: "Open in UniFi Site Manager", url: "https://unifi.ui.com/consoles/x/network/default/dashboard", verified: false },
      { vendor: "nextdns", label: "Open NextDNS logs — Example DNS", url: "https://my.nextdns.io/p1/logs", verified: true },
    ],
    tenant_sites: 2,
  }, "bad");

  it("operators: four layers, deep links, recent alerts", async () => {
    global.fetch = vi.fn().mockResolvedValue(ok({ key: site.key, items: [
      { event_id: 7, occurred_at: "2026-10-02T11:00:00.000Z", severity: "medium", source: "unifi",
        title: "UniFi internet (WAN) connection failed — Example Site 1", tenant_wide: false },
    ] }));
    render(<FleetSiteDrawer site={site} view="operator" onClose={() => undefined} />);
    for (const name of ["network", "security", "endpoints", "buoy"]) {
      expect(screen.getByTestId(`layer-${name}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("layer-security")).toHaveAttribute("data-state", "bad");
    expect(screen.getByTestId("net-devices")).toHaveTextContent("4 / 6");
    expect(screen.getByTestId("net-isp")).toHaveTextContent("Example ISP (AS64500)");
    expect(screen.getByTestId("sec-dns-p1")).toHaveTextContent("Example DNS · lapsed");
    expect(screen.getByText("client-wide")).toBeInTheDocument();
    expect(screen.getByText("no Datto inventory read yet")).toBeInTheDocument();
    const links = within(screen.getByTestId("site-links")).getAllByRole("link");
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveAttribute("rel", "noopener noreferrer");
    expect(links[0]).toHaveTextContent("Open in UniFi Site Manager ·?");     // unverified path
    await waitFor(() => expect(screen.getByTestId("site-alert-7")).toBeInTheDocument(), { timeout: 5000 });
    expect(global.fetch).toHaveBeenCalledWith(`/api/v1/fleet/sites/${site.key}/alerts`, expect.anything());
  });

  it("client users: neutral layer names, no links, no alerts", () => {
    global.fetch = vi.fn();
    // What the server sends a client user: neutral texts, counts only.
    const client: FleetSite = {
      ...site, links: [], tenant_slug: null, location: null, console_name: null,
      reason: "DNS protection lapsed (+1 more)",
      reasons: [{ state: "bad", text: "DNS protection lapsed", layer: "security" }],
      layers: {
        network: layer("network", "warn", {
          data: { devices_total: 6, devices_online: 4, gateway_online: true, connections_up: 1,
                  connections_down: 0 },
          reasons: [{ state: "warn", text: "2 network devices offline", layer: "network" }],
        }),
        security: layer("security", "bad", {
          scope: "tenant",
          data: { ips_detected_24h: 0, ips_blocked_24h: 2, dns_protection: { lapsed: 1 }, open_incidents: 0 },
          reasons: [{ state: "bad", text: "DNS protection lapsed", layer: "security" }],
        }),
        endpoints: layer("endpoints", "absent"),
        buoy: layer("buoy", "absent"),
      },
    };
    render(<FleetSiteDrawer site={client} view="client" onClose={() => undefined} />);
    const text = document.body.textContent ?? "";
    for (const vendor of ["UniFi", "NextDNS", "Datto", "RocketCyber"]) {
      expect(text).not.toContain(vendor);
    }
    expect(screen.getByText("Network")).toBeInTheDocument();
    expect(screen.getByText("Computers")).toBeInTheDocument();
    expect(screen.getByText("intrusions 24 h")).toBeInTheDocument();
    expect(screen.getByText("1 lapsed")).toBeInTheDocument();
    expect(screen.queryByTestId("site-alerts")).toBeNull();
    expect(screen.queryByTestId("site-links")).toBeNull();
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("a backup line that is down reads as nice-to-have, a down primary as DOWN, an unused WAN2 as not configured", () => {
    global.fetch = vi.fn().mockResolvedValue(ok({ key: site.key, items: [] }));
    const net = site.layers.network!;
    const withWans = (up: string[], down: string[], backupDown: string[], unused: string[] = []): FleetSite => ({
      ...site,
      layers: { ...site.layers, network: { ...net, data: { ...net.data, wan_up: up, wan_down: down,
                                                             backup_down: backupDown,
                                                             wan_unconfigured: unused } } },
    });
    const { unmount } = render(<FleetSiteDrawer site={withWans(["WAN"], ["WAN2"], ["WAN2"])}
                                                view="operator" onClose={() => undefined} />);
    expect(screen.getByTestId("net-wan")).toHaveTextContent("WAN up · WAN2 down (backup line)");
    unmount();
    const second = render(<FleetSiteDrawer site={withWans(["WAN2"], ["WAN"], [])} view="operator"
                                           onClose={() => undefined} />);
    expect(screen.getByTestId("net-wan")).toHaveTextContent("WAN2 up · WAN DOWN");
    second.unmount();
    // WAN coverage: a WAN2 nobody connected is not "down" — it is not configured.
    render(<FleetSiteDrawer site={withWans(["WAN"], [], [], ["WAN2"])} view="operator"
                            onClose={() => undefined} />);
    expect(screen.getByTestId("net-wan")).toHaveTextContent("WAN up · WAN2 not configured");
  });
});

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

function operatorResponse(sites: FleetSite[], extra: Partial<FleetSitesResponse> = {}): FleetSitesResponse {
  return {
    view: "operator", generated_at: "2026-10-02T12:00:00.000Z", partial: false, sites,
    counts: { total: sites.length }, isp_outages: [], unmapped_sites: 0,
    tenants: [...new Set(sites.map((s) => s.tenant_slug!))].map((slug) => ({ slug, name: slug })),
    ...extra,
  };
}

function routed(body: FleetSitesResponse) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/fleet/sites/") && url.endsWith("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
    if (url.includes("/fleet/sites")) return Promise.resolve(ok(body));
    if (url.includes("/dashboard/buoy-fleet")) return Promise.resolve(ok({ buoys: [], scope_slugs: ["*"] }));
    if (url.includes("/octo-location")) return Promise.resolve(ok({}));
    return Promise.resolve(ok({}));
  });
}

describe("FleetPage — sites mode", () => {
  beforeEach(() => {
    localStorage.setItem("athena.fleet.sites.view.v1", "list");
  });

  it("lists the sites, filters them and opens a drawer", async () => {
    const sites = [makeSite(1, {}, "bad"), makeSite(2), makeSite(3, {}, "warn"),
                   makeSite(4, { location: null })];
    global.fetch = routed(operatorResponse(sites, {
      isp_outages: [{ vid: "isp:1", open: true, asn: 64500, isp: "Example ISP", since: "2026-10-02T11:50:00.000Z",
                      sites: 3, sites_down: 3,
                      members: [{ tenant: "example-client-1", name: "Example Site 1", since: null, why: "console unreachable",
                                  recovered_at: null, key: sites[0]!.key }] }],
      unmapped_sites: 2,
    })) as unknown as typeof fetch;
    render(<FleetPage />);
    await waitFor(() => expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(4), { timeout: 5000 });
    expect(screen.getByTestId("fleet-summary")).toHaveTextContent("4 sites · 2 need attention");
    expect(screen.getByTestId("isp-outage-banner")).toHaveTextContent("Example ISP — 3 sites");
    expect(screen.getByTestId("fleet-unmapped")).toHaveTextContent("2 UniFi sites");
    expect(screen.getByTestId("fleet-legend")).toBeInTheDocument();
    const rows = screen.getAllByTestId(/^site-row-/);
    expect(rows.map((r) => r.getAttribute("data-state"))).toEqual(["bad", "warn", "ok", "ok"]);

    fireEvent.click(screen.getByRole("button", { name: "problems only" }));
    expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(2);
    expect(screen.getByTestId("fleet-result-count")).toHaveTextContent("2 of 4 match");
    fireEvent.click(screen.getByRole("button", { name: "problems only" }));

    fireEvent.change(screen.getByLabelText("Filter by client"), { target: { value: "example-client-3" } });
    expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Filter by client"), { target: { value: "" } });

    fireEvent.change(screen.getByLabelText("Search sites"), { target: { value: "Example Site 4" } });
    expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Search sites"), { target: { value: "" } });

    fireEvent.change(screen.getByLabelText("Filter by layer"), { target: { value: "endpoints" } });
    // Nobody has an endpoints layer — but the Red site stays (a filter never
    // hides an open incident).
    expect(screen.queryAllByTestId(/^site-row-/).map((r) => r.getAttribute("data-state")))
      .toEqual(["bad"]);
    fireEvent.change(screen.getByLabelText("Filter by layer"), { target: { value: "all" } });

    // The outage banner's member opens that site's drawer.
    fireEvent.click(within(screen.getByTestId("isp-outage-banner")).getByRole("button", { name: "Example Site 1" }));
    expect(screen.getByTestId("fleet-site-drawer")).toHaveAttribute("aria-label", "site Example Site 1");
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByTestId("fleet-site-drawer")).toBeNull();
  });

  it("map view: the buoy layer toggle and the list of sites without a location", async () => {
    localStorage.setItem("athena.fleet.sites.view.v1", "map");
    const sites = [makeSite(1, {}, "bad"), makeSite(2, { location: null }, "warn")];
    const fetchMock = routed(operatorResponse(sites));
    global.fetch = fetchMock as unknown as typeof fetch;
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("fleet-site-list")).toBeInTheDocument(), { timeout: 5000 });
    expect(screen.getByText("sites without a location")).toBeInTheDocument();
    expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(1);
    const toggle = screen.getByRole("button", { name: /buoys off/ });
    fireEvent.click(toggle);
    await waitFor(() => expect(fetchMock.mock.calls.some(([u]) => String(u).includes("/dashboard/buoy-fleet"))).toBe(true), { timeout: 5000 });
    expect(localStorage.getItem("athena.fleet.sites.buoys.v1")).toBe("1");
  });

  it("a client user gets the list only: no map, no buoys mode, no vendor names", async () => {
    localStorage.setItem("athena.fleet.sites.view.v1", "map");
    localStorage.setItem("athena.fleet.mode.v1", "buoys");          // ignored for a client
    const s = makeSite(1, {
      tenant_slug: null, console_name: null, location: null, links: [],
      reason: "DNS protection lapsed",
    }, "bad");
    const fetchMock = routed({ ...operatorResponse([s]), view: "client", tenants: [], unmapped_sites: null });
    global.fetch = fetchMock as unknown as typeof fetch;
    render(<FleetPage />);
    await waitFor(() => expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(1), { timeout: 5000 });
    expect(screen.queryByRole("group", { name: "Site view" })).toBeNull();     // no map toggle
    expect(screen.queryByRole("group", { name: "Fleet mode" })).toBeNull();    // no buoys mode
    expect(screen.queryByRole("button", { name: /buoys/ })).toBeNull();
    expect(screen.queryByTestId("unlocated-sites-banner")).toBeNull();        // no map at all
    expect(screen.queryByLabelText("Filter by client")).toBeNull();
    // Neither the buoy map's data nor the hub location is fetched.
    const urls = fetchMock.mock.calls.map(([u]) => String(u));
    expect(urls.some((u) => u.includes("/dashboard/buoy-fleet") || u.includes("/octo-location"))).toBe(false);
    const layerSelect = screen.getByLabelText("Filter by layer");
    // Text AND attributes (a help tip's title / aria-label is read on hover
    // and by screen readers).
    const attrs = [...document.body.querySelectorAll("*")].flatMap((el) =>
      ["title", "aria-label", "aria-description"].map((a) => el.getAttribute(a) ?? ""));
    const text = [document.body.textContent ?? "", layerSelect.textContent ?? "", ...attrs].join(" ");
    for (const vendor of ["UniFi", "NextDNS", "Datto", "RocketCyber"]) {
      expect(text).not.toContain(vendor);
    }
  });

  it("a buoy deep link (?focus=) opens the buoys mode without saving it", async () => {
    window.history.replaceState({}, "", "/fleet?focus=alpha");
    global.fetch = routed(operatorResponse([makeSite(1)])) as unknown as typeof fetch;
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByRole("button", { name: "buoys" })).toHaveAttribute("aria-pressed", "true"), { timeout: 5000 });
    await waitFor(() => expect(screen.getByText(/No buoys are reporting heartbeats yet/)).toBeInTheDocument(), { timeout: 5000 });
    expect(localStorage.getItem("athena.fleet.mode.v1")).toBeNull();   // the next visit is site-centric
    window.history.replaceState({}, "", "/");
  });

  it("the buoys mode is the unchanged buoy fleet (operators; saved when picked)", async () => {
    global.fetch = routed(operatorResponse([makeSite(1)])) as unknown as typeof fetch;
    render(<FleetPage />);
    fireEvent.click(await screen.findByRole("button", { name: "buoys" }, { timeout: 5000 }));
    await waitFor(() => expect(screen.getByText(/No buoys are reporting heartbeats yet/)).toBeInTheDocument(), { timeout: 5000 });
    expect(localStorage.getItem("athena.fleet.mode.v1")).toBe("buoys");
  });

  it("a suppressed fleet-wide wave is explained, not shown as N problems", async () => {
    global.fetch = routed(operatorResponse([makeSite(1, {}, "bad")], {
      isp_outages: [{ open: false, suppressed: { at: "2026-10-02T12:00:00.000Z", sites: 9, asns: 3, observed: 12 } }],
    })) as unknown as typeof fetch;
    render(<FleetPage />);
    const banner = await screen.findByTestId("fleet-wave-banner", {}, { timeout: 5000 });
    expect(banner).toHaveTextContent("9 of 12 sites across 3 ISPs dropped together");
    expect(banner).toHaveTextContent(/no ISP-outage incident was raised/);
    expect(screen.queryByTestId("isp-outage-banner")).toBeNull();
  });

  it("when the fleet cannot be refreshed, every condition-only site turns unknown — a Red keeps it", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const body = operatorResponse([makeSite(1, {}, "ok"), makeSite(2, {}, "bad")]);
      let calls = 0;
      global.fetch = vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/fleet/sites")) {
          calls += 1;
          return calls === 1 ? Promise.resolve(ok(body))
            : Promise.resolve(new Response(JSON.stringify({ message: "down" }), { status: 503 }));
        }
        return Promise.resolve(ok({}));
      }) as unknown as typeof fetch;
      render(<FleetPage />);
      await waitFor(() => expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(2), { timeout: 5000 });
      expect(screen.getByTestId("fleet-summary")).toHaveTextContent("1 need attention");
      await vi.advanceTimersByTimeAsync(30_000);                        // one failure: kept
      expect(screen.queryByTestId("fleet-stale")).toBeNull();
      await vi.advanceTimersByTimeAsync(30_000);                        // two: stale
      await waitFor(() => expect(screen.getByTestId("fleet-stale")).toBeInTheDocument());
      const rows = screen.getAllByTestId(/^site-row-/);
      // An incident is a floor: the Red stays Red ("view stale"), the rest
      // reads unknown — never ok.
      expect(rows.map((r) => r.getAttribute("data-state"))).toEqual(["bad", "unknown"]);
      expect(rows[0]).toHaveTextContent(/view stale \d+ min/);
      expect(screen.getByTestId("fleet-summary")).toHaveTextContent(
        "1 need attention · 0 black · 1 red · 0 yellow · 1 stale");
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// The location dialog
// ---------------------------------------------------------------------------

describe("tenant location dialog", () => {
  it("validates like the server", () => {
    expect(coordError("41.25", "-100.75")).toBeNull();
    expect(coordError("", "1")).toMatch(/Enter a latitude/);
    expect(coordError("91", "0")).toMatch(/±90/);
    expect(coordError("0", "0")).toMatch(/not a location/);
  });

  it("saves with a reason and clears", async () => {
    const calls: { url: string; init?: RequestInit | undefined }[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      return Promise.resolve(ok({
        slug: "example-dental", tenant_name: "Example Dental",
        override: { lat: 41.3, lng: -100.7, label: "Dental office", set_at: "x" },
        unifi_sites: [], unlocated_unifi_sites: 0, effective: "manual",
      }));
    }) as unknown as typeof fetch;
    const onDone = vi.fn();
    render(<TenantLocationDialog tenant={{ slug: "example-dental", display_name: "Example Dental" }}
                                 onClose={() => undefined} onDone={onDone} />);
    await waitFor(() => expect(screen.getByLabelText("latitude")).toHaveValue("41.3"));
    fireEvent.change(screen.getByLabelText("label"), { target: { value: "New office" } });
    expect(screen.getByTestId("location-save")).toBeDisabled();               // no reason yet
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "client confirmed" } });
    fireEvent.click(screen.getByTestId("location-save"));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    const put = calls.find((c) => c.init?.method === "PUT")!;
    expect(JSON.parse(String(put.init!.body))).toEqual(
      { lat: 41.3, lng: -100.7, label: "New office", reason: "client confirmed" });
    fireEvent.click(screen.getByTestId("location-clear"));
    await waitFor(() => expect(calls.some((c) => c.init?.method === "DELETE")).toBe(true));
  });

  it("is the client's fallback: shows what the consoles report and the site pins", async () => {
    global.fetch = vi.fn().mockResolvedValue(ok({
      slug: "example-dental", tenant_name: "Example Dental",
      override: { lat: 41.3, lng: -100.7, label: "Dental office", set_at: "x" },
      unifi_sites: [{ name: "Dental HQ", lat: 39.1234, lng: -94.5678, label: "Somewhere Far" }],
      unlocated_unifi_sites: 0, site_pins: 1, effective: "unifi",
    })) as unknown as typeof fetch;
    render(<TenantLocationDialog tenant={{ slug: "example-dental", display_name: "Example Dental" }}
                                 onClose={() => undefined} onDone={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("location-reported")).toBeInTheDocument());
    expect(screen.getByTestId("location-reported"))
      .toHaveTextContent("Dental HQ — Somewhere Far (39.123, -94.568)");
    expect(screen.getByTestId("location-site-pins")).toHaveTextContent("1 site is pinned by hand");
    expect(screen.getByTestId("location-current"))
      .toHaveTextContent("each site's own location (this fallback is not used)");
    expect(screen.getByText(/Fix location/)).toBeInTheDocument();     // where a wrong pin is fixed
  });
});

// ---------------------------------------------------------------------------
// A 40-site fixture fleet: render / perf check
// ---------------------------------------------------------------------------

describe("a 40-site fleet", () => {
  const states: SiteState[] = ["ok", "ok", "ok", "warn", "bad", "unknown"];
  const fleet = Array.from({ length: 40 }, (_, i) =>
    makeSite(i + 10, i % 9 === 0 ? { location: null } : {}, states[i % states.length]!));

  it("renders 40 pins and the list quickly", () => {
    const markers: SiteMarker[] = fleet.filter((s) => s.location).map((s) => ({
      key: s.key, name: s.name, lat: s.location!.lat, lng: s.location!.lng, state: s.state,
    }));
    const t0 = performance.now();
    const { container } = render(
      <FleetMapOverlay containerSize={{ w: 1200, h: 800 }} octos={[]} buoys={[]} project={project}
                       sites={markers} />,
    );
    render(<FleetSiteList view="operator" sites={sortSites(fleet)} layer="all" title="sites" onOpen={() => undefined} />);
    const took = performance.now() - t0;
    expect(container.querySelectorAll(".fleet-map-overlay__site")).toHaveLength(markers.length);
    expect(markers.length).toBe(35);
    expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(40);
    expect(took).toBeLessThan(2000);
  });
});
