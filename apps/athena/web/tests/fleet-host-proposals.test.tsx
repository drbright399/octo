/**
 * The host pin (super_admin moves the OCTO hub: address lookup, pasted map
 * links, reason; the city line never erased by a hub not read yet) and the
 * location proposals (admin+ reviews Autotask addresses: grouped by client,
 * plain-word warnings, Look up → pick a match → Confirm / Reject with a
 * reason, "pick a site" with that site's own pin and warnings, what was
 * reviewed sent with the confirm, a conflict reloads, the refused
 * CompanyLocations note), the site editor's "Autotask suggests" hint and the
 * drawer's provenance, Escape closing only the top dialog — and who sees
 * which control. Made-up names, Example streets, fictional towns.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import maplibregl from "maplibre-gl";

import type { FleetLayer, FleetSite, FleetSitesResponse, LayerName, SiteLocation } from "@/contracts/fleet";
import type { LocationProposal, ProposalsResponse } from "@/contracts/proposals";
import FleetMapOverlay, { type ProjectFn } from "@/components/fleet-map-overlay";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import HostLocationDialog, { cityFromMatch } from "@/components/host-location-dialog";
import LocationProposalsPanel, { flagText, kmBetween, nowText } from "@/components/location-proposals-panel";
import SiteLocationDialog from "@/components/site-location-dialog";
import FleetPage from "@/pages/fleet";

const ok = (body: object): Response => new Response(JSON.stringify(body), { status: 200 });
const fail = (status: number, code: string, message: string): Response =>
  new Response(JSON.stringify({ code, message, request_id: "r" }), { status });

type Call = { url: string; method: string; body: unknown };

function mockFetch(handler: (url: string, method: string, body: unknown) => object | Response): Call[] {
  const calls: Call[] = [];
  global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) as unknown : undefined;
    calls.push({ url, method, body });
    const out = handler(url, method, body);
    return Promise.resolve(out instanceof Response ? out : ok(out));
  }) as unknown as typeof fetch;
  return calls;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

const HOST = { slug: "example-hub", display: "Example Hub", city: "Kansas City", msp: "Example MSP",
  lat: 39.0997, lng: -94.5783 };

const esc = (): void => { fireEvent.keyDown(window, { key: "Escape" }); };

// ---------------------------------------------------------------------------
// The host pin
// ---------------------------------------------------------------------------

describe("host location dialog", () => {
  it("finds an address, fills the city, needs a reason, saves", async () => {
    const calls = mockFetch((url, method) => {
      if (url.endsWith("/fleet/geocoder")) return { provider: "census" };
      if (url.endsWith("/fleet/geocode")) {
        return { provider: "census", matches: [
          { lat: 41.2565, lng: -100.7512, label: "1 EXAMPLE RD, EXAMPLETON, IL, 00001" }] };
      }
      if (method === "PUT") return { ...HOST, lat: 41.2565, lng: -100.7512, city: "Exampleton, IL" };
      return {};
    });
    const onSaved = vi.fn();
    render(<HostLocationDialog current={HOST} onClose={() => undefined} onSaved={onSaved} />);
    expect(screen.getByTestId("host-loc-current")).toHaveTextContent("Now: Kansas City (39.0997, -94.5783)");
    await waitFor(() => expect(screen.getByTestId("host-loc-find")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("address"), { target: { value: "1 Example Rd, Exampleton IL" } });
    fireEvent.click(screen.getByTestId("host-loc-find"));
    await waitFor(() => expect(screen.getByLabelText("latitude")).toHaveValue("41.2565"));
    expect(screen.getByLabelText("city")).toHaveValue("Exampleton, IL");
    expect(screen.getByTestId("host-loc-save")).toBeDisabled();                  // no reason yet
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "the office moved" } });
    fireEvent.click(screen.getByTestId("host-loc-save"));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.url).toBe("/api/v1/dashboard/octo-location");
    expect(put.body).toEqual({ lat: 41.2565, lng: -100.7512, display: "Example Hub",
      city: "Exampleton, IL", reason: "the office moved" });
  });

  it("no Find when the lookup is off; a pasted map link works", async () => {
    const calls = mockFetch((url) => (url.endsWith("/fleet/geocoder") ? { provider: null } : {}));
    render(<HostLocationDialog current={HOST} onClose={() => undefined} onSaved={() => undefined} />);
    await waitFor(() => expect(calls.length).toBe(1));
    expect(screen.queryByTestId("host-loc-find")).toBeNull();
    fireEvent.change(screen.getByLabelText("paste coordinates or map link"),
                     { target: { value: "https://www.google.com/maps/@41.26,-100.75,17z" } });
    expect(screen.getByLabelText("latitude")).toHaveValue("41.26");
    expect(screen.getByLabelText("longitude")).toHaveValue("-100.75");
    fireEvent.change(screen.getByLabelText("latitude"), { target: { value: "0" } });
    fireEvent.change(screen.getByLabelText("longitude"), { target: { value: "0" } });
    expect(screen.getByTestId("host-loc-invalid")).toHaveTextContent("(0, 0) is not a location");
  });

  it("opened before the hub was read: reads it, fills what was not typed, keeps the city", async () => {
    let release: (() => void) | null = null;
    const gate = new Promise<void>((r) => { release = r; });
    const calls: Call[] = [];
    global.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) as unknown : undefined });
      if (url.endsWith("/fleet/geocoder")) return ok({ provider: null });
      if (url.endsWith("/octo-location") && method === "GET") { await gate; return ok(HOST); }
      return ok({ ...HOST, lat: 41.26, lng: -100.75 });
    }) as unknown as typeof fetch;
    const onSaved = vi.fn();
    render(<HostLocationDialog current={null} onClose={() => undefined} onSaved={onSaved} />);
    expect(screen.getByLabelText("city")).toHaveValue("");
    // The operator pastes a point before the read lands …
    fireEvent.change(screen.getByLabelText("paste coordinates or map link"), { target: { value: "41.26, -100.75" } });
    act(() => { release!(); });
    await waitFor(() => expect(screen.getByLabelText("city")).toHaveValue("Kansas City"));
    expect(screen.getByLabelText("latitude")).toHaveValue("41.26");                 // never overwritten
    expect(screen.getByLabelText("display name")).toHaveValue("Example Hub");
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "fine tune" } });
    fireEvent.click(screen.getByTestId("host-loc-save"));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.body).toEqual({ lat: 41.26, lng: -100.75, display: "Example Hub", reason: "fine tune" });
  });

  it("the hub never read: an empty city is not sent; a save error is shown", async () => {
    const calls = mockFetch((url, method) => {
      if (url.endsWith("/fleet/geocoder")) return { provider: null };
      if (url.endsWith("/octo-location") && method === "GET") return fail(503, "UNAVAILABLE", "down");
      return fail(422, "VALIDATION_FAILED", "latitude must be within ±90");
    });
    const onSaved = vi.fn();
    render(<HostLocationDialog current={null} onClose={() => undefined} onSaved={onSaved} />);
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/octo-location"))).toBe(true));
    expect(screen.queryByTestId("host-loc-current")).toBeNull();
    fireEvent.change(screen.getByLabelText("paste coordinates or map link"), { target: { value: "41.26, -100.75" } });
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "first placement" } });
    fireEvent.click(screen.getByTestId("host-loc-save"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("latitude must be within ±90"));
    expect(onSaved).not.toHaveBeenCalled();
    expect(screen.getByTestId("host-location-dialog")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ lat: 41.26, lng: -100.75, reason: "first placement" });
  });

  it("Escape closes it; focus moves into it", async () => {
    mockFetch(() => ({ provider: null }));
    const onClose = vi.fn();
    render(<HostLocationDialog current={HOST} onClose={onClose} onSaved={() => undefined} />);
    expect(screen.getByTestId("host-location-dialog")).toHaveFocus();
    esc();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("reads a Census match's city", () => {
    expect(cityFromMatch("1 EXAMPLE RD, EXAMPLETON, IL, 00001")).toBe("Exampleton, IL");
    expect(cityFromMatch("1 EXAMPLE RD, NEW EXAMPLE CITY, TX, 75001")).toBe("New Example City, TX");
    expect(cityFromMatch("nowhere")).toBe("");
  });

  it("the hub is clickable only when a handler is given", () => {
    const project: ProjectFn = (lat, lng) => ({ x: (lng + 100) * 10, y: (45 - lat) * 10 });
    const onOcto = vi.fn();
    const { container, rerender } = render(
      <FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[HOST]} buoys={[]} project={project}
                       onOctoClick={onOcto} />);
    const hub = container.querySelector('[data-testid="octo-hub-example-hub"]')!;
    expect(hub.getAttribute("style")).toContain("pointer-events: auto");
    fireEvent.click(hub);
    expect(onOcto).toHaveBeenCalledWith(HOST);
    rerender(<FleetMapOverlay containerSize={{ w: 800, h: 600 }} octos={[HOST]} buoys={[]} project={project} />);
    expect(container.querySelector('[data-testid="octo-hub-example-hub"]')!.getAttribute("style") ?? "")
      .not.toContain("pointer-events");
  });
});

// ---------------------------------------------------------------------------
// The proposals panel
// ---------------------------------------------------------------------------

function proposal(id: number, o: Partial<LocationProposal> = {}): LocationProposal {
  return {
    id, kind: "site_location", source: "autotask", status: "proposed",
    tenant_slug: "example-bakery", tenant_name: "Example Bakery",
    target_key: "u-00000000000000000001", target_name: "Bakery main", target_mode: "site",
    source_ref: `company:${id}`, origin: "company", name: "Example Bakery",
    label: "300 W 5th St, Exampleton, IL 00001", address: {}, flags: [], previous: null,
    matches: [], looked_up_at: null,
    current: { lat: 39.0, lng: -94.5, label: "1 Faraway Rd", source: "unifi" },
    created_at: "2026-10-02T12:00:00.000Z", updated_at: `2026-10-02T12:00:0${id}.000Z`,
    decided_by: null, decided_at: null, decision_reason: null, ...o,
  };
}

const CITY_HALL = "u-00000000000000000005";
const WORKS = "u-00000000000000000006";

const PROPOSALS: ProposalsResponse = {
  kind: "site_location",
  items: [
    proposal(1, { flags: [{ code: "shared_address", tenants: ["Example Books"], others_hidden: false }] }),
    proposal(2, { tenant_slug: "example-books", tenant_name: "Example Books",
                  target_key: "u-00000000000000000002", target_name: "Books main",
                  label: "300 W. 5th Street, Exampleton, IL",
                  flags: [{ code: "shared_address", tenants: ["Example Bakery"] },
                          { code: "incomplete", missing: ["zip"] }] }),
    proposal(3, { tenant_slug: "example-city", tenant_name: "City of Example", target_key: null,
                  target_name: null, target_mode: "pick", label: "100 Example Ave, Exampleton, IL 00001",
                  current: null }),
  ],
  open: 3, geocoder: "census", autotask: true,
  last_refresh: { at: "2026-10-02T11:00:00.000Z", trigger: "daily", locations: "refused",
                  skipped_non_us: [] },
  targets: {
    "example-bakery": [{ key: "u-00000000000000000001", name: "Bakery main", kind: "site",
                        current: { lat: 39.0, lng: -94.5, label: "1 Faraway Rd", source: "unifi" },
                        pin_set_at: null, console: { lat: 39.0, lng: -94.5 } }],
    "example-books": [{ key: "u-00000000000000000002", name: "Books main", kind: "site",
                           pin_set_at: "2026-10-01T09:00:00.000Z" }],
    "example-city": [
      { key: CITY_HALL, name: "City Hall", kind: "site",
        current: { lat: 41.11, lng: -100.61, label: "City Hall (door)", source: "site", origin: "manual" },
        pin_set_at: "2026-10-01T08:00:00.000Z", console: { lat: 41.1, lng: -100.6 } },
      { key: WORKS, name: "Public Works", kind: "site",
        current: { lat: 41.0, lng: -100.5, label: "City of Example", source: "manual" },
        pin_set_at: null, console: null },
    ],
  },
};

const reasonFor = (p: LocationProposal): string => `reason for ${p.label} (${p.tenant_name})`;
const [P1, P2, P3] = PROPOSALS.items as [LocationProposal, LocationProposal, LocationProposal];

describe("location proposals panel", () => {
  it("groups by client and says every warning in plain words", async () => {
    mockFetch(() => PROPOSALS);
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposals-tenant-example-bakery")).toBeInTheDocument());
    expect(screen.getByTestId("proposals-tenant-example-city")).toHaveTextContent("City of Example · 1");
    expect(screen.getByTestId("proposal-flag-1-shared_address"))
      .toHaveTextContent("Same address as Example Books — confirm both are really here.");
    expect(screen.getByTestId("proposal-flag-2-incomplete")).toHaveTextContent("Incomplete address (no ZIP)");
    expect(screen.getByTestId("proposal-current-1")).toHaveTextContent("Now: 1 Faraway Rd (console location)");
    expect(screen.getByTestId("proposals-locations-note"))
      .toHaveTextContent("only the company addresses were used");
    expect(screen.getByTestId("proposal-target-3")).toHaveTextContent("pick a site");
    expect(screen.getByTestId("proposal-current-3")).toHaveTextContent("Pick the site this address is for.");
    expect(screen.queryByTestId("proposals-loading")).toBeNull();
    expect(screen.queryByTestId("proposals-geocoder-off")).toBeNull();
    // Each control names its address and client (a screen reader tells rows apart).
    expect(screen.getByRole("button", { name: `Confirm ${P1.label} (Example Bakery)` })).toBeDisabled();
    expect(screen.getByRole("button", { name: `Reject ${P2.label} (Example Books)` })).toBeDisabled();
    expect(screen.getByRole("button", { name: `Look up ${P3.label} (City of Example)` })).toBeEnabled();
  });

  it("looks up, picks a match, confirms with what was reviewed", async () => {
    const looked = proposal(1, {
      looked_up_at: "2026-10-02T12:01:00.000Z", updated_at: "2026-10-02T12:01:00.500Z",
      matches: [{ lat: 41.26, lng: -100.75, label: "300 W 5TH ST, EXAMPLETON, IL, 00001", km_from_console: 1.2 },
                { lat: 41.3, lng: -100.8, label: "300 W 5TH ST, OTHERTON, IL, 00002", km_from_console: 8 }],
    });
    const onChanged = vi.fn();
    const calls = mockFetch((url) => {
      if (url.endsWith("/proposals/1/lookup")) return { proposal: looked, provider: "census" };
      if (url.endsWith("/proposals/1/confirm")) return { ...looked, status: "confirmed" };
      return PROPOSALS;
    });
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={onChanged} />);
    await waitFor(() => expect(screen.getByTestId("proposal-lookup-1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("proposal-lookup-1"));
    await waitFor(() => expect(screen.getByTestId("proposal-matches-1")).toBeInTheDocument());
    expect(screen.getByTestId("proposal-match-1-0")).toHaveTextContent("1.2 km from the console");
    fireEvent.click(screen.getByTestId("proposal-match-1-1"));
    expect(screen.getByTestId("proposal-confirm-1")).toBeDisabled();             // no reason yet
    fireEvent.change(screen.getByLabelText(reasonFor(P1)), { target: { value: "verified with the client" } });
    fireEvent.click(screen.getByTestId("proposal-confirm-1"));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const confirm = calls.find((c) => c.url.endsWith("/proposals/1/confirm"))!;
    expect(confirm.method).toBe("POST");
    expect(confirm.body).toEqual({ match_index: 1, reason: "verified with the client",
      target_key: "u-00000000000000000001", expected_updated_at: "2026-10-02T12:01:00.500Z",
      expected_pin_set_at: null });
    expect(screen.getByTestId("proposals-note")).toHaveTextContent("Bakery main pinned");
  });

  it("pick a site: that site's pin and warnings, sent with the confirm; reject needs a reason", async () => {
    const calls = mockFetch((url) => {
      if (url.includes("/proposals/3/")) return { ...P3, status: "confirmed" };
      if (url.includes("/proposals/2/")) return { ...P2, status: "rejected" };
      return PROPOSALS;
    });
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposal-row-3")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText(`paste coordinates for ${P3.label} (City of Example)`),
                     { target: { value: "41.1, -100.6" } });
    fireEvent.change(screen.getByLabelText(reasonFor(P3)), { target: { value: "city hall is there" } });
    expect(screen.getByTestId("proposal-confirm-3")).toBeDisabled();             // no site yet
    const site = screen.getByLabelText(`site for ${P3.label} (City of Example)`);
    fireEvent.change(site, { target: { value: WORKS } });
    // The public works site is drawn at the client's fallback location — said so.
    expect(screen.getByTestId("proposal-current-3"))
      .toHaveTextContent("Now: City of Example (the client's fallback location (Settings → Tenants))");
    expect(screen.getByTestId("proposal-flag-3-current_pin_differs"))
      .toHaveTextContent("drawn at the client's fallback location (Settings → Tenants) now");
    fireEvent.change(site, { target: { value: CITY_HALL } });
    expect(screen.getByTestId("proposal-current-3")).toHaveTextContent("Now: City Hall (door) (pinned by hand)");
    expect(screen.getByTestId("proposal-flag-3-current_pin_differs"))
      .toHaveTextContent("This site already has a hand-set pin (City Hall (door)) — confirming replaces it.");
    fireEvent.click(screen.getByTestId("proposal-confirm-3"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/proposals/3/confirm"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/proposals/3/confirm"))!.body).toEqual({
      lat: 41.1, lng: -100.6, target_key: CITY_HALL, reason: "city hall is there",
      expected_updated_at: P3.updated_at, expected_pin_set_at: "2026-10-01T08:00:00.000Z" });

    expect(screen.getByTestId("proposal-reject-2")).toBeDisabled();
    fireEvent.change(screen.getByLabelText(reasonFor(P2)), { target: { value: "a billing address" } });
    fireEvent.click(screen.getByTestId("proposal-reject-2"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/proposals/2/reject"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/proposals/2/reject"))!.body).toEqual({ reason: "a billing address" });
  });

  it("another site picked after a lookup: distances and the far warning are that site's", async () => {
    const looked = proposal(3, {
      tenant_slug: "example-city", tenant_name: "City of Example", target_key: null, target_name: null,
      target_mode: "pick", label: P3.label, current: null, looked_up_at: "2026-10-02T12:02:00.000Z",
      matches: [{ lat: 39.1, lng: -94.5, label: "100 EXAMPLE AVE, ELSEWHERE, MO, 00009" }],
    });
    mockFetch(() => ({ ...PROPOSALS, items: [looked] }));
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposal-match-3-0")).toBeInTheDocument());
    expect(screen.getByTestId("proposal-match-3-0")).not.toHaveTextContent("km from the console");
    fireEvent.change(screen.getByLabelText(`site for ${P3.label} (City of Example)`), { target: { value: CITY_HALL } });
    const km = Math.round(kmBetween({ lat: 39.1, lng: -94.5 }, { lat: 41.1, lng: -100.6 }) * 10) / 10;
    expect(screen.getByTestId("proposal-match-3-0")).toHaveTextContent(`${km} km from the console`);
    expect(screen.getByTestId("proposal-flag-3-far_from_console")).toHaveTextContent(`${km} km`);
  });

  it("a one-site client of a shared company: never pre-picked", async () => {
    const shared = proposal(4, { target_key: null, target_name: null, target_mode: "pick", current: null,
      flags: [{ code: "shared_company", tenants: ["Example Books"], others_hidden: false }] });
    mockFetch(() => ({ ...PROPOSALS, items: [shared] }));
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposal-row-4")).toBeInTheDocument());
    expect(screen.getByLabelText(`site for ${shared.label} (Example Bakery)`)).toHaveValue("");
    expect(screen.getByTestId("proposal-flag-4-shared_company"))
      .toHaveTextContent("Autotask maps this company to Example Books too — confirm this address is really this client's.");
  });

  it("a confirm refused as stale reloads the list", async () => {
    let lists = 0;
    mockFetch((url) => {
      if (url.endsWith("/proposals/1/confirm")) {
        return fail(409, "CONFLICT", "the site's pin changed since you loaded it — reload, then confirm again");
      }
      lists += 1;
      return PROPOSALS;
    });
    const onChanged = vi.fn();
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={onChanged} />);
    await waitFor(() => expect(screen.getByTestId("proposal-row-1")).toBeInTheDocument());
    expect(lists).toBe(1);
    fireEvent.change(screen.getByLabelText(`paste coordinates for ${P1.label} (Example Bakery)`), { target: { value: "41.2, -100.7" } });
    fireEvent.change(screen.getByLabelText(reasonFor(P1)), { target: { value: "verified" } });
    fireEvent.click(screen.getByTestId("proposal-confirm-1"));
    await waitFor(() => expect(lists).toBe(2));
    expect(screen.getByTestId("proposals-note")).toHaveTextContent("pin changed since you loaded it");
    expect(within(screen.getByTestId("proposal-row-1")).getByRole("alert")).toHaveTextContent("pin changed");
    expect(onChanged).not.toHaveBeenCalled();
    // Reload re-reads the list only (never Autotask).
    fireEvent.click(screen.getByTestId("proposals-reload"));
    await waitFor(() => expect(lists).toBe(3));
  });

  it("refreshes from Autotask; says when Autotask is not connected", async () => {
    const calls = mockFetch((url) => (url.endsWith("/proposals/refresh")
      ? { kind: "site_location", open: 4, summary: { created: 1, locations: "read" } } : PROPOSALS));
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposals-refresh")).toBeEnabled());
    fireEvent.click(screen.getByTestId("proposals-refresh"));
    await waitFor(() => expect(screen.getByTestId("proposals-note")).toHaveTextContent("4 to review, 1 new"));
    expect(calls.find((c) => c.url.endsWith("/proposals/refresh"))!.method).toBe("POST");
    cleanup();
    mockFetch(() => ({ ...PROPOSALS, items: [], open: 0, autotask: false, last_refresh: null }));
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposals-empty")).toBeInTheDocument());
    expect(screen.getByTestId("proposals-refresh")).toBeDisabled();
    expect(screen.getByTestId("proposals-status")).toHaveTextContent("Autotask is not connected");
  });

  it("a failed load says so; Reload and Refresh stay usable", async () => {
    let first = true;
    mockFetch(() => {
      if (first) { first = false; return fail(503, "UNAVAILABLE", "The proposed locations could not be loaded"); }
      return PROPOSALS;
    });
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("could not be loaded"));
    expect(screen.getByTestId("proposals-refresh")).toBeEnabled();
    fireEvent.click(screen.getByTestId("proposals-reload"));
    await waitFor(() => expect(screen.getByTestId("proposal-row-1")).toBeInTheDocument());
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("lookup off: no Look up, said once; a lookup with no match; the skipped non-US clients", async () => {
    mockFetch(() => ({ ...PROPOSALS, geocoder: null,
      items: [proposal(1, { looked_up_at: "2026-10-02T12:01:00.000Z", matches: [] })],
      last_refresh: { ...PROPOSALS.last_refresh, locations: "read", skipped_non_us: ["Example Imports"] } }));
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposal-row-1")).toBeInTheDocument());
    expect(screen.queryByTestId("proposal-lookup-1")).toBeNull();
    expect(screen.getByTestId("proposals-geocoder-off")).toHaveTextContent("Address lookup is off on this server");
    expect(screen.getByTestId("proposal-no-match-1")).toHaveTextContent("No match");
    expect(screen.getByTestId("proposals-skipped")).toHaveTextContent("outside the US — the address lookup is US-only): Example Imports.");
    expect(screen.queryByTestId("proposals-locations-note")).toBeNull();
  });

  it("after a lookup, the server's warnings: far from the console, a pin already set", async () => {
    const looked = proposal(1, {
      looked_up_at: "2026-10-02T12:01:00.000Z",
      matches: [{ lat: 39.1, lng: -94.5, label: "300 W 5TH ST, ELSEWHERE, MO", km_from_console: 412.3 }],
      flags: [{ code: "far_from_console", km: 412.3 },
              { code: "current_pin_differs", pin: { lat: 41.3, lng: -100.8, label: "Front door", source: "site", origin: "autotask" } }],
    });
    mockFetch((url) => (url.endsWith("/lookup") ? { proposal: looked, provider: "census" } : PROPOSALS));
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposal-lookup-1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("proposal-lookup-1"));
    await waitFor(() => expect(screen.getByTestId("proposal-flag-1-far_from_console")).toBeInTheDocument());
    expect(screen.getByTestId("proposal-flag-1-far_from_console")).toHaveTextContent("412.3 km from where the UniFi console says");
    expect(screen.getByTestId("proposal-flag-1-current_pin_differs")).toHaveTextContent("(Front door, from Autotask)");
    expect(screen.getByTestId("proposal-lookup-1")).toHaveTextContent("Look up again");
  });

  it("a change in Autotask shows the previous address in words; a re-offer says so", async () => {
    mockFetch(() => ({ ...PROPOSALS, items: [
      proposal(1, { previous: { id: 7, status: "confirmed", label: "200 W 5th St, Exampleton, IL 00001", target_key: null } }),
      proposal(5, { previous: { id: 8, status: "superseded", label: "9 Old Rd", target_key: null } }),
      proposal(6, { confirmed_before: true }),
    ] }));
    render(<LocationProposalsPanel onClose={() => undefined} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposal-previous-1")).toBeInTheDocument());
    expect(screen.getByTestId("proposal-previous-1"))
      .toHaveTextContent("Changed in Autotask — was: 200 W 5th St, Exampleton, IL 00001 (the pin in use).");
    expect(screen.getByTestId("proposal-previous-5")).toHaveTextContent("was: 9 Old Rd (not reviewed).");
    expect(screen.queryByTestId("proposal-previous-6")).toBeNull();
    expect(screen.getByTestId("proposal-reoffered-6")).toHaveTextContent("Confirmed earlier for this client");
  });

  it("Escape closes the panel — not while Autotask is being read", async () => {
    let release: (() => void) | null = null;
    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/proposals/refresh")) {
        await new Promise<void>((r) => { release = r; });
        return ok({ kind: "site_location", open: 3, summary: {} });
      }
      return ok(PROPOSALS);
    }) as unknown as typeof fetch;
    const onClose = vi.fn();
    render(<LocationProposalsPanel onClose={onClose} onChanged={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("proposals-refresh")).toBeEnabled());
    fireEvent.click(screen.getByTestId("proposals-refresh"));
    await waitFor(() => expect(screen.getByTestId("proposals-refresh")).toHaveTextContent("Reading Autotask"));
    esc();
    expect(onClose).not.toHaveBeenCalled();
    act(() => { release!(); });
    await waitFor(() => expect(screen.getByTestId("proposals-refresh")).toHaveTextContent("Refresh from Autotask"));
    esc();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("says every warning in plain words (flag text)", () => {
    expect(flagText({ code: "shared_address", tenants: [], others_hidden: true }))
      .toBe("Same address as another client — confirm both are really here.");
    expect(flagText({ code: "shared_address", tenants: ["Example Bakery"], others_hidden: true }))
      .toBe("Same address as Example Bakery and another client — confirm both are really here.");
    expect(flagText({ code: "far_from_console", km: 412.3 })).toContain("412.3 km");
    expect(flagText({ code: "current_pin_differs", pin: { lat: 1, lng: 1, label: "Front door", source: "site", origin: "autotask" } }))
      .toBe("This site already has a hand-set pin (Front door, from Autotask) — confirming replaces it.");
    expect(flagText({ code: "current_pin_differs", pin: { lat: 1, lng: 1, label: "Example Co", source: "manual" } }))
      .toContain("the client's fallback location (Settings → Tenants)");
    expect(flagText({ code: "several_addresses", count: 3 })).toContain("3 addresses");
    expect(flagText({ code: "incomplete", missing: ["street", "zip"], po_box: true }))
      .toBe("Incomplete address (only a PO box, no ZIP) — the lookup may miss it; check before confirming.");
    expect(flagText({ code: "incomplete", missing: ["street"] })).toContain("(no street)");
    expect(flagText({ code: "site_name_differs", site: "Public Works" }))
      .toBe("This client's only site is \"Public Works\" — check this address is that site's, not another building of the client.");
    expect(nowText({ lat: 1, lng: 1, label: "HQ", source: "site", origin: "autotask", by: "alice" }))
      .toBe("Now: HQ (from Autotask, confirmed by alice)");
  });
});

// ---------------------------------------------------------------------------
// The site editor's hint, the drawer's provenance
// ---------------------------------------------------------------------------

const LOC: SiteLocation = {
  key: "u-00000000000000000001", kind: "site", name: "Bakery main",
  tenant_slug: "example-bakery", tenant_name: "Example Bakery",
  override: { lat: 41.26, lng: -100.75, label: "300 W 5th St", set_at: "x", origin: "autotask", set_by_name: "alice" },
  console: null, console_sites: 1, console_shared: false, tenant_fallback: null,
  current: { lat: 41.26, lng: -100.75, label: "300 W 5th St", source: "site" },
  effective: "site", geocoder: "census",
  proposals: [{ id: 9, source: "autotask", label: "400 W 5th St, Exampleton, IL 00001", unassigned: false },
              { id: 10, source: "autotask", label: "1 Example Plaza, Exampleton, IL 00001", unassigned: true }],
};

describe("the site editor and the drawer", () => {
  it("shows the provenance and the Autotask suggestions with Review", async () => {
    mockFetch(() => LOC);
    const onReview = vi.fn();
    render(<SiteLocationDialog site={{ key: LOC.key, name: "Bakery main", tenant_name: "Example Bakery" }}
                               onClose={() => undefined} onSaved={() => undefined} onReviewProposals={onReview} />);
    await waitFor(() => expect(screen.getByTestId("site-loc-provenance")).toBeInTheDocument());
    expect(screen.getByTestId("site-loc-provenance")).toHaveTextContent("From Autotask, confirmed by alice.");
    expect(screen.getByTestId("site-loc-suggestion-9"))
      .toHaveTextContent("Autotask suggests: 400 W 5th St, Exampleton, IL 00001");
    expect(screen.getByTestId("site-loc-suggestion-10"))
      .toHaveTextContent("Autotask has an address for this client not yet assigned to a site: 1 Example Plaza");
    fireEvent.click(screen.getByTestId("site-loc-review-9"));
    expect(onReview).toHaveBeenCalledWith("example-bakery", 9);
    fireEvent.click(screen.getByTestId("site-loc-review-10"));
    expect(onReview).toHaveBeenCalledWith("example-bakery", 10);
  });

  it("no suggestion, no Review; a hand-set pin has no provenance line", async () => {
    mockFetch(() => ({ ...LOC, proposals: [], override: { ...LOC.override!, origin: "manual" } }));
    render(<SiteLocationDialog site={{ key: LOC.key, name: "Bakery main", tenant_name: "Example Bakery" }}
                               onClose={() => undefined} onSaved={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId("site-loc-current")).toBeInTheDocument());
    expect(screen.queryByTestId("site-loc-provenance")).toBeNull();
    expect(screen.queryByTestId("site-loc-suggestion-9")).toBeNull();
  });

  it("the drawer says where a confirmed pin came from (operators only)", () => {
    mockFetch(() => ({ key: "x", items: [] }));
    const site = makeSite(1, {
      location: { lat: 41.26, lng: -100.75, label: "300 W 5th St", source: "site" },
      provenance: { origin: "autotask", by: "alice", at: "2026-10-02T12:00:00.000Z" },
    });
    render(<FleetSiteDrawer site={site} view="operator" onClose={() => undefined} />);
    expect(screen.getByTestId("site-provenance")).toHaveTextContent("from Autotask, confirmed by alice");
    cleanup();
    // The same site in a client view (even were the server to send both):
    // never the provenance, never a vendor name.
    render(<FleetSiteDrawer site={site} view="client" onClose={() => undefined} />);
    expect(screen.queryByTestId("site-provenance")).toBeNull();
    expect(screen.getByTestId("fleet-site-drawer")).not.toHaveTextContent(/autotask/i);
  });

  it("Escape closes the location dialog first, then the drawer; never the drawer under a page dialog", async () => {
    mockFetch((url) => (url.endsWith("/location") ? LOC : { key: "x", items: [] }));
    const onClose = vi.fn();
    const site = makeSite(1);
    const { rerender } = render(<FleetSiteDrawer site={site} view="operator" onClose={onClose} canEditLocation />);
    fireEvent.click(screen.getByTestId("site-set-location"));
    await waitFor(() => expect(screen.getByTestId("site-location-dialog")).toBeInTheDocument());
    esc();
    expect(screen.queryByTestId("site-location-dialog")).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
    rerender(<FleetSiteDrawer site={site} view="operator" onClose={onClose} canEditLocation suspendEscape />);
    esc();
    expect(onClose).not.toHaveBeenCalled();
    rerender(<FleetSiteDrawer site={site} view="operator" onClose={onClose} canEditLocation />);
    esc();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// Who sees which control (the Fleet page)
// ---------------------------------------------------------------------------

function layer(name: LayerName): FleetLayer {
  return { name, present: name === "network", state: name === "network" ? "ok" : "absent", scope: "site",
           reasons: [], data: {}, as_of: "2026-10-02T12:00:00.000Z" };
}

function makeSite(n: number, o: Partial<FleetSite> = {}): FleetSite {
  return {
    key: `u-${String(n).padStart(20, "0")}`, kind: "site", name: `Example Site ${n}`,
    tenant_slug: "example-bakery", tenant_name: "Example Bakery", console_name: `console-${n}`,
    state: "ok", reason: "all clear", reasons: [],
    location: { lat: 41, lng: -101, label: `${n} Example Road`, source: "unifi" },
    layers: { network: layer("network"), security: layer("security"), endpoints: layer("endpoints"), buoy: layer("buoy") },
    links: [], vendor_ref: null, tenant_sites: 1, partial: false, ...o,
  };
}

function fleet(sites: FleetSite[]): FleetSitesResponse {
  return { view: "operator", generated_at: "2026-10-02T12:00:00.000Z", partial: false, sites,
           counts: { total: sites.length }, isp_outages: [], unmapped_sites: 0,
           tenants: [{ slug: "example-bakery", name: "Example Bakery" }] };
}

describe("FleetPage — host pin and proposals by role", () => {
  beforeEach(() => {
    localStorage.setItem("athena.fleet.sites.view.v1", "list");
  });

  function page(role: string, extra: (url: string, method: string) => object | null = () => null): Call[] {
    return mockFetch((url, method) => {
      const more = extra(url, method);
      if (more) return more;
      if (url.endsWith("/auth/me")) return { role: [role] };
      if (url.endsWith("/fleet/sites")) return fleet([makeSite(1)]);
      if (url.endsWith("/proposals/summary")) return { kind: "site_location", open: 2 };
      if (url.endsWith("/octo-location")) return HOST;
      if (url.endsWith("/alerts")) return { key: "x", items: [] };
      if (url.includes("/proposals?")) return PROPOSALS;
      return {};
    });
  }

  /** The map view's basemap "loaded" (the overlay then places the hub). */
  async function mapLoaded(): Promise<void> {
    await waitFor(() => expect(vi.mocked(maplibregl.Map).mock.results.length).toBeGreaterThan(0), { timeout: 5000 });
    const results = vi.mocked(maplibregl.Map).mock.results;
    const map = results[results.length - 1]!.value as { on: ReturnType<typeof vi.fn> };
    const onLoad = map.on.mock.calls.find(([ev]) => ev === "load")?.[1] as (() => void) | undefined;
    act(() => { onLoad?.(); });
  }

  it("super_admin: the host pin and the proposals", async () => {
    const calls = page("super_admin");
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("host-location-button")).toBeInTheDocument(), { timeout: 5000 });
    await waitFor(() => expect(screen.getByTestId("proposals-badge")).toHaveTextContent("2"));
    fireEvent.click(screen.getByTestId("host-location-button"));
    await waitFor(() => expect(screen.getByTestId("host-location-dialog")).toBeInTheDocument());
    expect(screen.getByLabelText("display name")).toHaveValue("Example Hub");
    expect(calls.some((c) => c.url.endsWith("/fleet/geocoder"))).toBe(true);
  });

  it("the map's hub opens the host editor for a super_admin only", async () => {
    localStorage.setItem("athena.fleet.sites.view.v1", "map");
    page("super_admin");
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("host-location-button")).toBeInTheDocument(), { timeout: 5000 });
    await mapLoaded();
    await waitFor(() => expect(screen.getByTestId("octo-hub-example-hub")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("octo-hub-example-hub"));
    await waitFor(() => expect(screen.getByTestId("host-location-dialog")).toBeInTheDocument());
    cleanup();
    vi.mocked(maplibregl.Map).mockClear();
    localStorage.setItem("athena.fleet.sites.view.v1", "map");
    page("admin");
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("proposals-badge")).toBeInTheDocument(), { timeout: 5000 });
    await mapLoaded();
    await waitFor(() => expect(screen.getByTestId("octo-hub-example-hub")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("octo-hub-example-hub"));
    expect(screen.queryByTestId("host-location-dialog")).toBeNull();
  });

  it("admin: the proposals (badge → panel), never the host pin; a confirm refreshes the fleet and the badge", async () => {
    const calls = page("admin", (url) => (url.endsWith("/proposals/1/confirm") ? { ...P1, status: "confirmed" } : null));
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("proposals-badge")).toHaveTextContent("2"), { timeout: 5000 });
    expect(screen.queryByTestId("host-location-button")).toBeNull();
    fireEvent.click(screen.getByTestId("proposals-button"));
    await waitFor(() => expect(screen.getByTestId("proposals-panel")).toBeInTheDocument());
    await waitFor(() => expect(within(screen.getByTestId("proposals-panel"))
      .getByTestId("proposals-tenant-example-bakery")).toBeInTheDocument());
    const count = (suffix: string): number => calls.filter((c) => c.url.endsWith(suffix)).length;
    const [sites, badge] = [count("/fleet/sites"), count("/proposals/summary")];
    fireEvent.change(screen.getByLabelText(`paste coordinates for ${P1.label} (Example Bakery)`), { target: { value: "41.2, -100.7" } });
    fireEvent.change(screen.getByLabelText(reasonFor(P1)), { target: { value: "verified" } });
    fireEvent.click(screen.getByTestId("proposal-confirm-1"));
    await waitFor(() => expect(count("/fleet/sites")).toBeGreaterThan(sites));
    await waitFor(() => expect(count("/proposals/summary")).toBeGreaterThan(badge));
  });

  it("analyst: neither", async () => {
    const calls = page("analyst");
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("fleet-summary")).toHaveTextContent("1 site"), { timeout: 5000 });
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/auth/me"))).toBe(true));
    expect(screen.queryByTestId("proposals-button")).toBeNull();
    expect(screen.queryByTestId("host-location-button")).toBeNull();
    expect(calls.some((c) => c.url.includes("/proposals"))).toBe(false);
  });

  it("a client user: no proposals, no host pin, nothing of them fetched", async () => {
    const calls = page("viewer", (url) => (url.endsWith("/fleet/sites")
      ? { ...fleet([makeSite(1, { location: null, tenant_slug: null, console_name: null })]), view: "client", tenants: [], unmapped_sites: null }
      : null));
    render(<FleetPage />);
    await waitFor(() => expect(screen.getAllByTestId(/^site-row-/)).toHaveLength(1), { timeout: 5000 });
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByTestId("proposals-button")).toBeNull();
    expect(screen.queryByTestId("host-location-button")).toBeNull();
    const urls = calls.map((c) => c.url);
    expect(urls.some((u) => u.includes("/proposals") || u.includes("/fleet/geocoder") || u.includes("/octo-location"))).toBe(false);
  });

  it("the site editor's Review opens the panel on that client; Escape closes only the panel", async () => {
    const calls = page("admin", (url) => (url.endsWith("/location") ? LOC : null));
    render(<FleetPage />);
    await waitFor(() => expect(screen.getByTestId("proposals-badge")).toBeInTheDocument(), { timeout: 5000 });
    fireEvent.click(screen.getByText("Example Site 1"));
    await waitFor(() => expect(screen.getByTestId("site-set-location")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("site-set-location"));
    await waitFor(() => expect(screen.getByTestId("site-loc-review-9")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("site-loc-review-9"));
    await waitFor(() => expect(screen.getByTestId("proposals-panel")).toBeInTheDocument());
    expect(screen.queryByTestId("site-location-dialog")).toBeNull();
    await waitFor(() => expect(calls.some((c) => c.url.includes("/proposals?") && c.url.includes("tenant=example-bakery"))).toBe(true));
    expect(screen.getByTestId("proposals-panel")).toHaveFocus();
    esc();
    expect(screen.queryByTestId("proposals-panel")).toBeNull();
    expect(screen.getByTestId("fleet-site-drawer")).toBeInTheDocument();           // still open
    esc();
    expect(screen.queryByTestId("fleet-site-drawer")).toBeNull();
  });
});
