/**
 * Fleet v2 — per-site locked pins (the drawer's "Set location": address
 * lookup, pasted coordinates / map links, role gating) and the quiet tier
 * (`notice`: listed in grey, the pin stays green with a grey ring, never a
 * "problem"; the likely-regional banner). Fixtures are made up: Example
 * names, a synthetic grid, documentation ASNs.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import type { FleetLayer, FleetSite, FleetSitesResponse, LayerName, SiteLocation, SiteState } from "@/contracts/fleet";
import FleetMapOverlay, { type ProjectFn, type SiteMarker } from "@/components/fleet-map-overlay";
import FleetLegend from "@/components/fleet-legend";
import FleetSiteList from "@/components/fleet-site-list";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import SiteLocationDialog from "@/components/site-location-dialog";
import FleetPage from "@/pages/fleet";
import { NO_FILTERS, filterSites, parseCoordinates, problemCount, sortSites } from "@/lib/fleet";

const ok = (body: object): Response => new Response(JSON.stringify(body), { status: 200 });
const fail = (status: number, message: string): Response =>
  new Response(JSON.stringify({ code: "X", message }), { status });

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
    location: { lat: 41 + (n % 8) * 0.06, lng: -101, label: `${n} Example Road`, source: "unifi" },
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

const LOC: SiteLocation = {
  key: "u-00000000000000000001", kind: "site", name: "Example Site 1",
  tenant_slug: "example-client-1", tenant_name: "Example Client 1", override: null,
  console: { lat: 39.0, lng: -94.5, label: "1 Faraway Rd, Elsewhere" },
  console_sites: 1, console_shared: false,
  tenant_fallback: null,
  current: { lat: 39.0, lng: -94.5, label: "1 Faraway Rd, Elsewhere", source: "unifi" },
  effective: "unifi", geocoder: "census",
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

// ---------------------------------------------------------------------------
// Pasted coordinates / map links (parsed in the browser)
// ---------------------------------------------------------------------------

describe("parseCoordinates", () => {
  it.each([
    ["41.25, -100.75", { lat: 41.25, lng: -100.75 }],
    ["41.25 -100.75", { lat: 41.25, lng: -100.75 }],
    ["  -33.8688,151.2093 ", { lat: -33.8688, lng: 151.2093 }],
    ["https://www.google.com/maps/@41.2565,-100.7512,17z", { lat: 41.2565, lng: -100.7512 }],
    ["https://www.google.com/maps/place/Example/@41.0,-101.0,15z/data=!3m1!4b1!4m6!3m5!1s0x0:0x0!8m2!3d41.2501!4d-100.7499",
     { lat: 41.2501, lng: -100.7499 }],                           // the pin, not the view
    ["https://maps.google.com/?q=41.25,-100.75", { lat: 41.25, lng: -100.75 }],
    ["https://maps.google.com/?ll=41.25%2C-100.75&z=14", { lat: 41.25, lng: -100.75 }],
  ])("%s", (text, want) => {
    expect(parseCoordinates(text)).toEqual(want);
  });

  it.each(["", "Main Street", "0, 0", "91, 10", "41.25, -181", "https://example.test/maps"])(
    "refuses %j", (text) => {
      expect(parseCoordinates(text)).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// The site location dialog
// ---------------------------------------------------------------------------

describe("site location dialog", () => {
  it("shows what the console reports, finds an address, saves a locked pin", async () => {
    const calls: { url: string; init?: RequestInit | undefined }[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.endsWith("/fleet/geocode")) {
        return Promise.resolve(ok({ provider: "census", matches: [
          { lat: 41.2501, lng: -100.7499, label: "1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000" },
          { lat: 41.3, lng: -100.8, label: "1 EXAMPLE RD, OTHER TOWN, ZZ, 00001" }] }));
      }
      if (init?.method === "PUT") {
        return Promise.resolve(ok({ ...LOC, effective: "site",
          override: { lat: 41.2501, lng: -100.7499, label: "1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000", set_at: "x" } }));
      }
      return Promise.resolve(ok(LOC));
    }) as unknown as typeof fetch;
    const onSaved = vi.fn();
    render(<SiteLocationDialog site={{ key: LOC.key, name: "Example Site 1", tenant_name: "Example Client 1" }}
                               onClose={() => undefined} onSaved={onSaved} />);
    await waitFor(() => expect(screen.getByTestId("site-loc-console")).toBeInTheDocument());
    expect(screen.getByTestId("site-loc-current")).toHaveTextContent("Now: the UniFi console's location");
    expect(screen.getByTestId("site-loc-console")).toHaveTextContent("1 Faraway Rd, Elsewhere (39.0000, -94.5000)");

    fireEvent.change(screen.getByLabelText("address"), { target: { value: "1 Example Rd, Example Town ZZ" } });
    fireEvent.click(screen.getByTestId("site-loc-find"));
    await waitFor(() => expect(screen.getByTestId("site-loc-matches")).toBeInTheDocument());
    const geo = calls.find((c) => c.url.endsWith("/fleet/geocode"))!;
    expect(JSON.parse(String(geo.init!.body))).toEqual({ address: "1 Example Rd, Example Town ZZ" });
    fireEvent.click(screen.getByTestId("site-loc-match-0"));
    expect(screen.getByLabelText("latitude")).toHaveValue("41.2501");
    expect(screen.getByLabelText("label")).toHaveValue("1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000");
    expect(screen.getByTestId("site-loc-save")).toBeDisabled();                 // no reason yet
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "console reports the wrong state" } });
    fireEvent.click(screen.getByTestId("site-loc-save"));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    const put = calls.find((c) => c.init?.method === "PUT")!;
    expect(put.url).toBe(`/api/v1/fleet/sites/${LOC.key}/location`);
    expect(JSON.parse(String(put.init!.body))).toEqual({
      lat: 41.2501, lng: -100.7499, label: "1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000",
      reason: "console reports the wrong state" });
  });

  it("a pasted map link fills the pin with no outside call; no Find when lookup is off", async () => {
    const fetchMock = vi.fn().mockResolvedValue(ok({ ...LOC, geocoder: null }));
    global.fetch = fetchMock as unknown as typeof fetch;
    render(<SiteLocationDialog site={{ key: LOC.key, name: "Example Site 1", tenant_name: "Example Client 1" }}
                               onClose={() => undefined} onSaved={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("site-loc-current")).toBeInTheDocument());
    expect(screen.queryByTestId("site-loc-find")).toBeNull();
    fireEvent.change(screen.getByLabelText("paste coordinates or map link"),
                     { target: { value: "https://www.google.com/maps/@41.2565,-100.7512,17z" } });
    expect(screen.getByTestId("site-loc-paste-result")).toHaveTextContent("found 41.2565, -100.7512");
    expect(screen.getByLabelText("latitude")).toHaveValue("41.2565");
    expect(screen.getByLabelText("longitude")).toHaveValue("-100.7512");
    fireEvent.change(screen.getByLabelText("paste coordinates or map link"), { target: { value: "nowhere" } });
    expect(screen.getByTestId("site-loc-paste-result")).toHaveTextContent("no coordinates found");
    expect(fetchMock).toHaveBeenCalledTimes(1);                                  // the GET only
  });

  it("no match and a lookup error are said plainly", async () => {
    let geocodes = 0;
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      if (String(input).endsWith("/fleet/geocode")) {
        geocodes += 1;
        return Promise.resolve(geocodes === 1 ? ok({ provider: "census", matches: [] })
          : fail(503, "the address lookup service could not be reached"));
      }
      return Promise.resolve(ok(LOC));
    }) as unknown as typeof fetch;
    render(<SiteLocationDialog site={{ key: LOC.key, name: "Example Site 1", tenant_name: "Example Client 1" }}
                               onClose={() => undefined} onSaved={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("site-loc-find")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("address"), { target: { value: "1 Nowhere Lane" } });
    fireEvent.click(screen.getByTestId("site-loc-find"));
    await waitFor(() => expect(screen.getByTestId("site-loc-no-match")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("site-loc-find"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("could not be reached"));
  });

  it("clears a hand-set pin with a reason", async () => {
    const calls: string[] = [];
    global.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(init?.method ?? "GET");
      return Promise.resolve(ok({ ...LOC, effective: "site",
        override: { lat: 41.25, lng: -100.75, label: "Front office", set_at: "x" } }));
    }) as unknown as typeof fetch;
    const onSaved = vi.fn();
    render(<SiteLocationDialog site={{ key: LOC.key, name: "Example Site 1", tenant_name: "Example Client 1" }}
                               onClose={() => undefined} onSaved={onSaved} />);
    await waitFor(() => expect(screen.getByLabelText("latitude")).toHaveValue("41.25"));
    expect(screen.getByTestId("site-loc-clear")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "fixed in the console" } });
    fireEvent.click(screen.getByTestId("site-loc-clear"));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(calls).toEqual(["GET", "DELETE"]);
  });
});

// ---------------------------------------------------------------------------
// Role gating in the drawer
// ---------------------------------------------------------------------------

describe("the drawer's Set location", () => {
  beforeEach(() => {
    global.fetch = vi.fn((input: RequestInfo | URL) => Promise.resolve(
      String(input).endsWith("/alerts") ? ok({ key: "x", items: [] }) : ok(LOC))) as unknown as typeof fetch;
  });

  it("admin+ only, opens the site's dialog", async () => {
    const site = makeSite(1);
    const { unmount } = render(<FleetSiteDrawer site={site} view="operator" onClose={() => undefined} />);
    expect(screen.queryByTestId("site-set-location")).toBeNull();               // an analyst
    unmount();
    const { unmount: u2 } = render(<FleetSiteDrawer site={site} view="client" canEditLocation
                                                    onClose={() => undefined} />);
    expect(screen.queryByTestId("site-set-location")).toBeNull();               // a client user
    u2();
    render(<FleetSiteDrawer site={site} view="operator" canEditLocation onClose={() => undefined} />);
    expect(screen.getByTestId("site-set-location")).toHaveTextContent("Fix location");
    fireEvent.click(screen.getByTestId("site-set-location"));
    await waitFor(() => expect(screen.getByTestId("site-location-dialog")).toBeInTheDocument());
  });

  it("says Set location for an unpinned site and names the pin's source", () => {
    render(<FleetSiteDrawer site={makeSite(2, { location: null })} view="operator" canEditLocation
                            onClose={() => undefined} />);
    expect(screen.getByTestId("site-set-location")).toHaveTextContent("Set location");
    cleanup();
    render(<FleetSiteDrawer site={makeSite(3, { location: { lat: 41, lng: -101, label: "Front office", source: "site" } })}
                            view="operator" onClose={() => undefined} />);
    expect(screen.getByText(/Front office \(pinned by hand\)/)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// The quiet tier
// ---------------------------------------------------------------------------

const project: ProjectFn = (lat, lng) => ({ x: (lng + 102) * 400, y: (42 - lat) * 400 });

describe("notice", () => {
  it("never counts as a problem, sorts after unknown, leaves 'problems only'", () => {
    const sites = [makeSite(1, {}, "notice"), makeSite(2, {}, "ok"), makeSite(3, {}, "unknown"),
                   makeSite(4, {}, "warn")];
    expect(problemCount(sites)).toBe(1);
    expect(sortSites(sites).map((s) => s.state)).toEqual(["warn", "unknown", "notice", "ok"]);
    expect(filterSites(sites, { ...NO_FILTERS, problemsOnly: true }).map((s) => s.state))
      .toEqual(["unknown", "warn"]);
  });

  it("keeps the pin green with a grey ring; the list shows it in grey; the legend explains", () => {
    const markers: SiteMarker[] = [
      { key: "a", name: "A", lat: 41.1, lng: -101, state: "notice", source: "site" },
      { key: "b", name: "B", lat: 41.2, lng: -101, state: "ok" },
    ];
    const { container } = render(
      <FleetMapOverlay containerSize={{ w: 1200, h: 800 }} octos={[]} buoys={[]} project={project} sites={markers} />);
    const pin = container.querySelector('[data-testid="site-pin-a"]')!;
    expect(pin.getAttribute("data-source")).toBe("site");
    expect(within(pin as HTMLElement).getByTestId("site-pin-notice-ring")).toBeInTheDocument();
    expect(pin.querySelector("rect[transform]")?.getAttribute("fill")).toBe("var(--success)");  // a green diamond
    expect(container.querySelector('[data-testid="site-pin-b"] [data-testid="site-pin-notice-ring"]')).toBeNull();
    cleanup();
    render(<FleetSiteList view="operator" sites={[makeSite(5, { reason: "internet blip in the last hour" }, "notice")]}
                          layer="all" title="sites" onOpen={() => undefined} />);
    const row = screen.getByTestId(`site-row-${makeSite(5).key}`);
    expect(row).toHaveAttribute("data-state", "notice");
    expect(within(row).getByText("notice")).toBeInTheDocument();
    expect(within(row).getByText("internet blip in the last hour").className).toContain("text-text-secondary");
    cleanup();
    render(<FleetLegend view="operator" />);
    expect(screen.getByTestId("legend-notice")).toHaveTextContent("seen, not a problem");
  });
});

describe("FleetPage — regional banner and the refresh after a save", () => {
  beforeEach(() => {
    localStorage.setItem("athena.fleet.sites.view.v1", "list");
  });

  function response(sites: FleetSite[], extra: Partial<FleetSitesResponse> = {}): FleetSitesResponse {
    return {
      view: "operator", generated_at: "2026-10-02T12:00:00.000Z", partial: false, sites,
      counts: { total: sites.length }, isp_outages: [], unmapped_sites: 0,
      tenants: [...new Set(sites.map((s) => s.tenant_slug!))].map((slug) => ({ slug, name: slug })),
      ...extra,
    };
  }

  it("shows one likely-regional line and refreshes once a pin is saved", async () => {
    const sites = [makeSite(1, {}, "notice"), makeSite(2, {}, "notice"), makeSite(3, {}, "notice")];
    let sitesCalls = 0;
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return Promise.resolve(ok({ role: ["admin"] }));
      if (url.endsWith("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
      if (url.endsWith("/location")) {
        return Promise.resolve(ok(init?.method === "PUT" ? { ...LOC, effective: "site" } : LOC));
      }
      if (url.endsWith("/fleet/sites")) {
        sitesCalls += 1;
        return Promise.resolve(ok(response(sites, { regional: [
          { kind: "isp", sites: 3, keys: sites.map((s) => s.key), asn: 64500, isp: "Example ISP" }] })));
      }
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("fleet-regional-banner")).toBeInTheDocument(), { timeout: 5000 });
    expect(screen.getByTestId("fleet-regional-banner"))
      .toHaveTextContent("Internet trouble at 3 sites on Example ISP (AS64500)");
    expect(screen.getByTestId("fleet-summary")).toHaveTextContent("3 sites · 0 need attention · 3 notices");

    fireEvent.click(within(screen.getByTestId("fleet-regional-banner")).getByRole("button", { name: "Example Site 1" }));
    await waitFor(() => expect(screen.getByTestId("site-set-location")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("site-set-location"));
    await waitFor(() => expect(screen.getByLabelText("latitude")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("latitude"), { target: { value: "41.25" } });
    fireEvent.change(screen.getByLabelText("longitude"), { target: { value: "-100.75" } });
    fireEvent.change(screen.getByLabelText("label"), { target: { value: "Front office" } });
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "verified on site" } });
    const before = sitesCalls;
    fireEvent.click(screen.getByTestId("site-loc-save"));
    await waitFor(() => expect(sitesCalls).toBe(before + 1));
    expect(screen.queryByTestId("site-location-dialog")).toBeNull();
  });
});
