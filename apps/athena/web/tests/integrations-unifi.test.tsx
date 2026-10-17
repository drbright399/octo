import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { UniFiSitePanel } from "@/components/unifi-site-panel";
import type { MeResponse } from "@/contracts/operator";

/**
 * UniFi in the console: the integration card (site counts, the decision it
 * needs, consoles / gateways offline, retired mappings, throttled ≠ failed)
 * and the site mapping panel — every site keyed by console + site, shown with
 * its console, LOCATION and WAN, a same-name suggestion on its row only, NO
 * bulk accept, ignore, one save.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const SITES_URL = "/api/v1/integrations/unifi/14/sites";
const TENANTS_URL = "/api/v1/admin/adapters/instances/14/vendor-tenants";
const HOST_A = "F1X7A0000000000000000000000000000000000000000000000000A001:100000001";
const HOST_B = "F1X7B0000000000000000000000000000000000000000000000000B002:100000002";
const SITE = "f1x7517e0000000000000001";
const SCOPE_A = `${HOST_A}/${SITE}`;
const SCOPE_B = `${HOST_B}/${SITE}`;

function me(): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role: ["admin"] } as MeResponse;
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const SUMMARY = {
  known: 36, known_at: "2026-10-01T12:00:00.000Z", consoles: 35, consoles_offline: 1,
  mapped: 23, ignored: 5, unmapped: 8, gateways_offline: 2, problems: 1, legacy_mappings: 0,
  throttled: false, throttled_for_sec: 0, calls_per_hour_planned: 744,
};

const BASE = {
  slug: "unifi",
  id: 14,
  status: "running",
  status_detail: "connected — last contact with the vendor succeeded",
  configured_at: "2026-10-01T10:00:00.000Z",
  last_test_at: null,
  warnings: [],
  notes: [],
};

function site(over: Record<string, unknown>) {
  return {
    scope: SCOPE_A, host_id: HOST_A, site_id: SITE, name: "Acme Corp", console_name: "acme-udm",
    location_text: "100 Example St, Springfield", timezone: "America/Chicago",
    wans: [{ wan: "WAN", external_ip: "203.0.113.129", isp: "Example ISP", asn: 64500, shared_external: false }],
    gateway_online: true, host_connected: true, listed: true, tenant_slug: null, tenant_name: null,
    tenant_status: null, match_source: null, ignored: false, suggestion: null, problem: null,
    last_syslog_at: null, clients: null, ...over,
  };
}

const SITES = {
  instance_id: 14,
  discovered: true,
  fetched_at: "2026-10-01T12:00:00.000Z",
  sites: [
    site({ suggestion: { tenant_slug: "acme-corp", tenant_name: "Acme Corp", rule: "same-name" } }),
    site({ scope: SCOPE_B, host_id: HOST_B, name: "Default", console_name: "home-lab",
           location_text: "Somewhere Else",
           wans: [{ wan: "WAN", external_ip: "192.0.2.200", isp: "Home ISP", asn: 64502, shared_external: true }] }),
  ],
  legacy: [],
  counts: { known: 2, mapped: 0, ignored: 0, unmapped: 2, gateways_offline: 0, problems: 0 },
};

function stubBackend(instance: Record<string, unknown>, sites: unknown = SITES) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/v1/integrations") {
      return jsonResponse(200, {
        definitions: [{ slug: "unifi", name: "UniFi Network", category: "network", description: "Gateways." }],
        instances: { unifi: instance },
      });
    }
    if (url === "/api/v1/admin/adapters/catalog") return jsonResponse(200, { adapters: [], categories: [] });
    if (url === "/api/v1/admin/clients") {
      return jsonResponse(200, {
        clients: [
          { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
          { slug: "example-bakery", display_name: "Example Bakery", status: "active" },
        ],
      });
    }
    if (url === SITES_URL && init?.method === "PUT") return jsonResponse(200, sites);
    if (url === SITES_URL) return jsonResponse(200, sites);
    if (url.startsWith(TENANTS_URL)) {
      return jsonResponse(200, { supported: true, tenants: [], truncated: false, fetched_at: null });
    }
    return jsonResponse(404, {});
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("UniFi integration card", () => {
  it("shows site counts, the decision it needs, what is offline — and opens the site panel", async () => {
    stubBackend({ ...BASE, sites: SUMMARY });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-unifi")));
    expect(card.getByTestId("integration-site-counts-unifi")).toHaveTextContent(
      "23 sites mapped · 5 ignored · 8 unmapped · 35 consoles");
    const decide = card.getByTestId("integration-sites-unmapped-unifi");
    expect(decide).toHaveTextContent(/8 sites need a decision — map each to its client one at a time/);
    expect(card.getByTestId("integration-sites-offline-unifi")).toHaveTextContent(
      "1 console offline · 2 mapped sites with the gateway offline");
    expect(card.getByTestId("integration-site-problems-unifi")).toHaveTextContent(/1 site needs a look/);
    expect(card.queryByTestId("integration-sites-throttled-unifi")).toBeNull();
    fireEvent.click(within(decide).getByRole("button"));
    const drawer = await screen.findByTestId("tenant-mapping-drawer");
    expect(await within(drawer).findByTestId("unifi-site-panel")).toBeInTheDocument();
  });

  it("says it waits for the site mapping, names retired mappings, and throttled is not a failure", async () => {
    stubBackend({ ...BASE, waiting_for_tenant_mapping: true,
                  sites: { ...SUMMARY, mapped: 0, legacy_mappings: 2, throttled: true, throttled_for_sec: 30 } });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-unifi")));
    expect(card.getByTestId("integration-first-import-unifi")).toHaveTextContent(
      "Waiting for your site mapping — imports start as soon as you save it. Nothing is read from an unmapped site.");
    expect(card.getByTestId("integration-site-legacy-unifi")).toHaveTextContent(
      /2 mappings of the retired local-controller integration are kept but never read/);
    expect(card.getByTestId("integration-sites-throttled-unifi")).toHaveTextContent(
      /Throttled by UniFi \(rate limit\) — calls wait 30 s/);
    expect(card.queryByTestId("integration-problem-unifi")).toBeNull();
  });
});

describe("UniFi site panel", () => {
  it("shows console, location and WAN; suggests on the row only; saves mappings and ignores in one PUT", async () => {
    const fetchMock = stubBackend({ ...BASE });
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    const rowA = await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    expect(rowA).toHaveTextContent("Acme Corp on acme-udm");
    expect(screen.getByTestId(`unifi-location-${SCOPE_A}`)).toHaveTextContent(
      "100 Example St, Springfield · America/Chicago · WAN 203.0.113.129 (Example ISP)");
    expect(screen.getByTestId(`unifi-location-${SCOPE_B}`)).toHaveTextContent(
      "shared with another network");
    // There is NO bulk accept anywhere in this panel.
    expect(screen.queryByText(/suggestions/i)).toBeNull();
    expect(screen.queryByTestId("unifi-accept-all")).toBeNull();
    expect(screen.getByTestId("unifi-tally")).toHaveTextContent("0 mapped · 0 ignored · 2 need a decision");
    fireEvent.click(screen.getByTestId(`unifi-suggest-${SCOPE_A}`));
    expect((screen.getByTestId(`unifi-choice-${SCOPE_A}`) as HTMLSelectElement).value).toBe("acme-corp");
    fireEvent.change(screen.getByTestId(`unifi-choice-${SCOPE_B}`), { target: { value: "__ignore__" } });
    expect(screen.getByTestId("unifi-tally")).toHaveTextContent("1 mapped · 1 ignored · 0 need a decision");
    fireEvent.click(screen.getByTestId("unifi-save"));
    await screen.findByTestId("unifi-saved");
    const put = fetchMock.mock.calls.find(
      ([u, init]) => u === SITES_URL && (init as RequestInit | undefined)?.method === "PUT");
    expect(JSON.parse(String((put?.[1] as RequestInit).body))).toEqual({
      mappings: [{ scope: SCOPE_A, tenant_slug: "acme-corp" }],
      ignored: [SCOPE_B],
    });
  });

  it("lists the sites with ONE discovery when none are known yet, and names retired mappings", async () => {
    let discovered = false;
    const fetchMock = vi.fn(async (url: string) => {
      if (url === "/api/v1/admin/clients") return jsonResponse(200, { clients: [] });
      if (url.startsWith(TENANTS_URL)) {
        discovered = true;
        return jsonResponse(200, { supported: true, tenants: [], truncated: false, fetched_at: null });
      }
      if (url === SITES_URL) {
        return jsonResponse(200, discovered
          ? { ...SITES, legacy: [{ vendor_tenant_id: SITE, tenant_slug: "acme-corp", tenant_name: "Acme Corp" }] }
          : { ...SITES, discovered: false, sites: [] });
      }
      return jsonResponse(404, {});
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    expect(fetchMock.mock.calls.filter(([u]) => String(u).startsWith(TENANTS_URL))).toHaveLength(1);
    expect(screen.getByTestId("unifi-legacy")).toHaveTextContent(
      /1 mapping of the retired local-controller integration \(Acme Corp\) is kept but never read/);
  });

  it("asks before discarding unsaved choices", async () => {
    stubBackend({ ...BASE });
    const done = vi.fn();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<UniFiSitePanel instanceId={14} onDone={done} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    fireEvent.click(screen.getByTestId(`unifi-suggest-${SCOPE_A}`));
    fireEvent.click(screen.getByTestId("unifi-dismiss"));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(done).not.toHaveBeenCalled();
  });
});

describe("UniFi site panel — the ✕ on a mapped site (asks, then saves just that)", () => {
  // A client restored onto new hardware: the OLD console's site is still
  // mapped (gateway offline), the new one too; plus an unmapped site and a
  // frozen mapping of a client that left.
  const HOST_C = "F1X7C0000000000000000000000000000000000000000000000000C003:100000003";
  const HOST_D = "F1X7D0000000000000000000000000000000000000000000000000D004:100000004";
  const SCOPE_C = `${HOST_C}/${SITE}`;
  const SCOPE_D = `${HOST_D}/${SITE}`;
  const MAPPED = {
    ...SITES,
    sites: [
      site({ name: "Example HQ", tenant_slug: "acme-corp", tenant_name: "Acme Corp", tenant_status: "active",
             match_source: "manual" }),
      site({ scope: SCOPE_B, host_id: HOST_B, name: "Default", console_name: "home-lab", location_text: "Somewhere Else" }),
      site({ scope: SCOPE_C, host_id: HOST_C, name: "Example HQ (old)", console_name: "old-udm", gateway_online: false,
             tenant_slug: "example-bakery", tenant_name: "Example Bakery", tenant_status: "active", match_source: "manual" }),
      site({ scope: SCOPE_D, host_id: HOST_D, name: "Gone Branch", console_name: "gone-udm",
             tenant_slug: "gone-co", tenant_name: "Gone Co", tenant_status: "offboarded", match_source: "manual" }),
    ],
  };
  /** The server's answer once `scope` is unlinked (and ignored, or not). */
  const after = (scope: string, ignored: boolean) => ({
    ...MAPPED,
    sites: MAPPED.sites.map((s) =>
      s.scope === scope ? { ...s, tenant_slug: null, tenant_name: null, tenant_status: null, match_source: null, ignored } : s),
  });

  // The ✕'s accessible name carries the console: a restored client has two
  // sites of one name.
  const X_A = "Unlink Example HQ (on acme-udm) from Acme Corp";
  const X_C = "Unlink Example HQ (old) (on old-udm) from Example Bakery";

  /** `onGet(n)`: the n-th GET of the site list (1 = the panel's load). */
  function stubSites(
    onPut: (body: unknown, n: number) => unknown,
    onGet: (n: number) => unknown = () => jsonResponse(200, MAPPED),
    onTenants: () => unknown = () =>
      jsonResponse(200, { supported: true, tenants: [], truncated: false, fetched_at: null }),
  ) {
    let gets = 0;
    let puts = 0;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/v1/admin/clients") {
        return jsonResponse(200, {
          clients: [
            { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
            { slug: "example-bakery", display_name: "Example Bakery", status: "active" },
          ],
        });
      }
      if (url === SITES_URL && init?.method === "PUT") return onPut(JSON.parse(String(init.body)), ++puts);
      if (url === SITES_URL) return onGet(++gets);
      if (url.startsWith(TENANTS_URL)) return onTenants();
      return jsonResponse(404, {});
    });
    vi.stubGlobal("fetch", fetchMock);
    return () => fetchMock.mock.calls.filter(
      ([u, init]) => u === SITES_URL && (init as RequestInit | undefined)?.method === "PUT");
  }
  const bodyOf = (call: unknown[] | undefined): unknown => JSON.parse(String((call?.[1] as RequestInit).body));

  const choice = (scope: string) => screen.getByTestId(`unifi-choice-${scope}`) as HTMLSelectElement;
  const open = (name: string): { x: HTMLElement; dialog: HTMLElement } => {
    const x = screen.getByRole("button", { name });
    x.focus();
    fireEvent.click(x);
    return { x, dialog: screen.getByRole("alertdialog") };
  };

  it("a mapped site has an ✕; an unmapped site and a frozen mapping have none", async () => {
    stubSites(() => jsonResponse(200, MAPPED));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    expect(screen.getByRole("button", { name: X_A })).toBeVisible();
    expect(screen.getByRole("button", { name: X_C })).toBeVisible();
    expect(screen.queryByTestId(`unifi-unlink-${SCOPE_B}`)).toBeNull();
    expect(screen.queryByTestId(`unifi-unlink-${SCOPE_D}`)).toBeNull();
  });

  it("asks in an in-app dialog; Cancel, Escape and the backdrop change nothing and send nothing", async () => {
    const puts = stubSites(() => jsonResponse(200, MAPPED));
    const confirm = vi.spyOn(window, "confirm");
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    const { x, dialog } = open(X_A);
    expect(confirm).not.toHaveBeenCalled();
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleName("Unlink this site?");
    expect(dialog).toHaveTextContent(
      "Unlink Example HQ (on acme-udm) from Acme Corp? Athena stops reading this site — no new alerts, " +
      "status or WAN from it. Its past events stay with Acme Corp.");
    expect(dialog).toHaveAccessibleDescription(/Athena stops reading this site — no new alerts, status or WAN from it\./);
    expect(dialog).toHaveAccessibleDescription(/This is saved as soon as you choose\./);
    // The safe choice has the focus.
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();

    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(x).toHaveFocus();

    fireEvent.click(x);
    fireEvent.keyDown(document.activeElement!, { key: "Escape" });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(x).toHaveFocus();

    fireEvent.click(x);
    fireEvent.click(screen.getByTestId("unifi-unlink-dialog-backdrop"));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(x).toHaveFocus();

    expect(puts()).toHaveLength(0);
    expect(choice(SCOPE_A).value).toBe("acme-corp");
    expect(screen.getByTestId("unifi-tally")).toHaveTextContent("3 mapped · 0 ignored · 1 need a decision");
  });

  it("'Unlink and ignore' sends ONE PUT — the last server state with that site ignored, none of the staged edits", async () => {
    const puts = stubSites(() => jsonResponse(200, after(SCOPE_A, true)));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    // Staged, never saved by the ✕: a new mapping, a re-pointed one, and a
    // change on the very row being unlinked (the ✕ wins there).
    fireEvent.change(choice(SCOPE_B), { target: { value: "example-bakery" } });
    fireEvent.change(choice(SCOPE_C), { target: { value: "acme-corp" } });
    fireEvent.change(choice(SCOPE_A), { target: { value: "example-bakery" } });

    const { dialog } = open(X_A);
    expect(dialog).toHaveAccessibleDescription(/Your other unsaved changes are not saved with it/);
    fireEvent.click(within(dialog).getByRole("button", { name: "Unlink and ignore" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(puts()).toHaveLength(1);
    expect(JSON.parse(String((puts()[0]![1] as RequestInit).body))).toEqual({
      mappings: [
        { scope: SCOPE_C, tenant_slug: "example-bakery" },
        { scope: SCOPE_D, tenant_slug: "gone-co" },
      ],
      ignored: [SCOPE_A],
    });
    // The server's answer is adopted; the other staged edits are still staged.
    expect(choice(SCOPE_A).value).toBe("__ignore__");
    expect(screen.queryByTestId(`unifi-unlink-${SCOPE_A}`)).toBeNull();
    expect(choice(SCOPE_B).value).toBe("example-bakery");
    expect(choice(SCOPE_C).value).toBe("acme-corp");
    expect(screen.getByTestId("unifi-saved")).toHaveTextContent(
      "Unlinked and saved. Your other unsaved changes are still pending.");
    expect(screen.getByText(/Unsaved changes — nothing is stored until you press Save/)).toBeInTheDocument();
    // Its ✕ is gone with the mapping: focus lands on the row's dropdown.
    expect(choice(SCOPE_A)).toHaveFocus();
  });

  it("'Unlink only' leaves the site not mapped; with nothing else staged it says only that it saved", async () => {
    const puts = stubSites(() => jsonResponse(200, after(SCOPE_A, false)));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    const { dialog } = open(X_A);
    expect(dialog).not.toHaveAccessibleDescription(/other unsaved changes/);
    fireEvent.click(within(dialog).getByRole("button", { name: "Unlink only" }));
    expect(await screen.findByTestId("unifi-saved")).toHaveTextContent(/^Unlinked and saved\.$/);
    expect(puts()).toHaveLength(1);
    expect(JSON.parse(String((puts()[0]![1] as RequestInit).body))).toEqual({
      mappings: [
        { scope: SCOPE_C, tenant_slug: "example-bakery" },
        { scope: SCOPE_D, tenant_slug: "gone-co" },
      ],
      ignored: [],
    });
    expect(choice(SCOPE_A).value).toBe("");
    expect(screen.getByTestId("unifi-tally")).toHaveTextContent("2 mapped · 0 ignored · 2 need a decision");
    expect(screen.getByTestId("unifi-dismiss")).toHaveTextContent("Close");
  });

  it("recommends 'Unlink and ignore' (the primary button) for a site whose gateway is offline", async () => {
    stubSites(() => jsonResponse(200, MAPPED));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    let { dialog } = open(X_C);
    expect(dialog).toHaveAccessibleDescription(/Its gateway is offline — Unlink and ignore is recommended/);
    expect(within(dialog).getByRole("button", { name: "Unlink and ignore" })).toHaveClass("bg-critical");
    expect(within(dialog).getByRole("button", { name: "Unlink only" })).not.toHaveClass("bg-critical");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    ({ dialog } = open(X_A));
    expect(dialog).not.toHaveAccessibleDescription(/is recommended/);
    expect(within(dialog).getByRole("button", { name: "Unlink only" })).toHaveClass("bg-critical");
    expect(within(dialog).getByRole("button", { name: "Unlink and ignore" })).not.toHaveClass("bg-critical");
  });

  it("while saving the buttons are disabled; a refusal changes nothing on screen and shows the reason in the dialog", async () => {
    let answer: (r: unknown) => void = () => undefined;
    const puts = stubSites(() => new Promise((resolve) => { answer = resolve; }));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    fireEvent.change(choice(SCOPE_B), { target: { value: "example-bakery" } });
    const { x, dialog } = open(X_A);
    fireEvent.click(within(dialog).getByRole("button", { name: "Unlink and ignore" }));

    await waitFor(() => expect(puts()).toHaveLength(1));
    expect(within(dialog).getByRole("button", { name: "Unlinking…" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Unlink only" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeDisabled();
    // A disabled button drops focus in a browser: the box holds it, so Tab
    // cannot walk out to the panel — whose Save and Reload wait anyway.
    expect(dialog).toHaveFocus();
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(dialog).toHaveFocus();
    expect(screen.getByTestId("unifi-save")).toBeDisabled();
    expect(screen.getByTestId("unifi-reload")).toBeDisabled();
    fireEvent.keyDown(dialog, { key: "Escape" });
    fireEvent.click(screen.getByTestId("unifi-unlink-dialog-backdrop"));
    expect(screen.getByRole("alertdialog")).toBe(dialog);

    answer(jsonResponse(409, { code: "VALIDATION_FAILED", message: "site is mapped to a departed tenant (example refusal)" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("example refusal");
    expect(within(dialog).getByRole("button", { name: "Unlink and ignore" })).toBeEnabled();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(screen.getByTestId("unifi-save")).toBeEnabled();
    // Nothing changed on screen.
    expect(choice(SCOPE_A).value).toBe("acme-corp");
    expect(choice(SCOPE_B).value).toBe("example-bakery");
    expect(screen.queryByTestId("unifi-saved")).toBeNull();
    expect(screen.getByTestId("unifi-tally")).toHaveTextContent("4 mapped · 0 ignored · 0 need a decision");

    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(x).toHaveFocus();
    expect(puts()).toHaveLength(1);
  });

  it("keeps Tab inside the dialog", async () => {
    stubSites(() => jsonResponse(200, MAPPED));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    const { dialog } = open(X_A);
    const [cancel, , last] = within(dialog).getAllByRole("button");
    last!.focus();
    fireEvent.keyDown(last!, { key: "Tab" });
    expect(cancel).toHaveFocus();
    fireEvent.keyDown(cancel!, { key: "Tab", shiftKey: true });
    expect(last).toHaveFocus();
  });

  it("two sites of one name (a client restored onto a new console) get ✕ buttons told apart by console", async () => {
    const twins = {
      ...MAPPED,
      sites: [
        site({ name: "Acme Office", console_name: "old-udm", tenant_slug: "acme-corp", tenant_name: "Acme Corp",
               tenant_status: "active", match_source: "manual" }),
        site({ scope: SCOPE_B, host_id: HOST_B, name: "Acme Office", console_name: "new-udm",
               tenant_slug: "acme-corp", tenant_name: "Acme Corp", tenant_status: "active", match_source: "manual" }),
      ],
    };
    stubSites(() => jsonResponse(200, twins), () => jsonResponse(200, twins));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    expect(screen.getByRole("button", { name: "Unlink Acme Office (on old-udm) from Acme Corp" }))
      .toBe(screen.getByTestId(`unifi-unlink-${SCOPE_A}`));
    expect(screen.getByRole("button", { name: "Unlink Acme Office (on new-udm) from Acme Corp" }))
      .toBe(screen.getByTestId(`unifi-unlink-${SCOPE_B}`));
  });

  it("re-reads the server first: a mapping written elsewhere since the list was read is kept", async () => {
    // Another tab mapped the home-lab site after this panel loaded.
    const elsewhere = {
      ...MAPPED,
      sites: MAPPED.sites.map((s) =>
        s.scope === SCOPE_B ? { ...s, tenant_slug: "example-bakery", tenant_name: "Example Bakery", tenant_status: "active" } : s),
    };
    const answer = {
      ...elsewhere,
      sites: elsewhere.sites.map((s) =>
        s.scope === SCOPE_A ? { ...s, tenant_slug: null, tenant_name: null, tenant_status: null, match_source: null } : s),
    };
    const puts = stubSites(() => jsonResponse(200, answer), (n) => jsonResponse(200, n === 1 ? MAPPED : elsewhere));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    expect(choice(SCOPE_B).value).toBe("");
    const { dialog } = open(X_A);
    fireEvent.click(within(dialog).getByRole("button", { name: "Unlink only" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(puts()).toHaveLength(1);
    expect(bodyOf(puts()[0])).toEqual({
      mappings: [
        { scope: SCOPE_B, tenant_slug: "example-bakery" },
        { scope: SCOPE_C, tenant_slug: "example-bakery" },
        { scope: SCOPE_D, tenant_slug: "gone-co" },
      ],
      ignored: [],
    });
    // The untouched row follows the server.
    expect(choice(SCOPE_B).value).toBe("example-bakery");
    expect(choice(SCOPE_A).value).toBe("");
    expect(screen.getByTestId("unifi-saved")).toHaveTextContent(/^Unlinked and saved\.$/);
  });

  it("saves nothing when that very site changed since the list was read, and shows what it is now", async () => {
    const repointed = {
      ...MAPPED,
      sites: MAPPED.sites.map((s) =>
        s.scope === SCOPE_A ? { ...s, tenant_slug: "example-bakery", tenant_name: "Example Bakery" } : s),
    };
    const puts = stubSites(() => jsonResponse(200, MAPPED), (n) => jsonResponse(200, n === 1 ? MAPPED : repointed));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    const { dialog } = open(X_A);
    fireEvent.click(within(dialog).getByRole("button", { name: "Unlink and ignore" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(puts()).toHaveLength(0);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Nothing was saved: Example HQ changed since this list was read — it is now mapped to Example Bakery. Check it and choose again.");
    expect(choice(SCOPE_A).value).toBe("example-bakery");
    expect(screen.queryByTestId("unifi-saved")).toBeNull();
    // Its ✕ is still there (now for Example Bakery) and has the focus back.
    expect(screen.getByRole("button", { name: "Unlink Example HQ (on acme-udm) from Example Bakery" })).toHaveFocus();
  });

  it("a failure AFTER the server stored part of it: the re-read shows the truth, and the next Save does not re-link", async () => {
    // The mappings were stored, the ignore list was not: a 500.
    const partial = after(SCOPE_A, false);
    const puts = stubSites(
      (_, n) => (n === 1 ? jsonResponse(500, { message: "database is locked (example)" }) : jsonResponse(200, partial)),
      (n) => jsonResponse(200, n <= 2 ? MAPPED : partial),
    );
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    fireEvent.change(choice(SCOPE_B), { target: { value: "example-bakery" } });
    const { dialog } = open(X_A);
    fireEvent.click(within(dialog).getByRole("button", { name: "Unlink and ignore" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(screen.getByRole("alert")).toHaveTextContent(
      "database is locked (example) — yet Example HQ is no longer linked to Acme Corp: it is not mapped. The list shows what is stored now.");
    expect(choice(SCOPE_A).value).toBe("");
    expect(choice(SCOPE_B).value).toBe("example-bakery");      // still staged
    expect(screen.queryByTestId(`unifi-unlink-${SCOPE_A}`)).toBeNull();

    fireEvent.click(screen.getByTestId("unifi-save"));
    await waitFor(() => expect(puts()).toHaveLength(2));
    expect(bodyOf(puts()[1])).toEqual({
      mappings: [
        { scope: SCOPE_B, tenant_slug: "example-bakery" },
        { scope: SCOPE_C, tenant_slug: "example-bakery" },
        { scope: SCOPE_D, tenant_slug: "gone-co" },
      ],
      ignored: [],
    });
  });

  it("the ✕ and Save wait while Reload reads the list (an older list must not put back what a save changed)", async () => {
    let listed: (r: unknown) => void = () => undefined;
    let first = true;
    stubSites(
      () => jsonResponse(200, MAPPED),
      () => jsonResponse(200, MAPPED),
      () => {
        if (first) {
          first = false;
          return new Promise((resolve) => { listed = resolve; });
        }
        return jsonResponse(200, { supported: true, tenants: [], truncated: false, fetched_at: null });
      },
    );
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    fireEvent.click(screen.getByTestId("unifi-reload"));
    expect(screen.getByRole("button", { name: X_A })).toBeDisabled();
    expect(screen.getByTestId("unifi-save")).toBeDisabled();
    listed(jsonResponse(200, { supported: true, tenants: [], truncated: false, fetched_at: null }));
    await waitFor(() => expect(screen.getByRole("button", { name: X_A })).toBeEnabled());
    expect(screen.getByTestId("unifi-save")).toBeEnabled();
  });

  it("a site UniFi no longer lists: says what each choice really does; focus lands on the result when its row goes", async () => {
    const SCOPE_E = `${HOST_C}/f1x7517e0000000000000009`;
    const unlisted = {
      ...MAPPED,
      sites: [
        ...MAPPED.sites,
        site({ scope: SCOPE_E, host_id: HOST_C, site_id: "f1x7517e0000000000000009", name: "Example Annex",
               console_name: "old-udm", listed: false, gateway_online: null, host_connected: null,
               tenant_slug: "acme-corp", tenant_name: "Acme Corp", tenant_status: "active", match_source: "manual" }),
      ],
    };
    // Not mapped and not listed: the server's answer leaves it out of the panel.
    const puts = stubSites(() => jsonResponse(200, MAPPED), () => jsonResponse(200, unlisted));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_E}`);
    const { dialog } = open("Unlink Example Annex (on old-udm) from Acme Corp");
    expect(dialog).toHaveAccessibleDescription(
      /It is no longer in UniFi's list — Unlink and ignore is recommended: it stays ignored if UniFi lists it again\. Unlink only takes it off this list until UniFi lists it again; then it needs a decision\./);
    expect(dialog).not.toHaveAccessibleDescription(/to decide later/);
    expect(within(dialog).getByRole("button", { name: "Unlink and ignore" })).toHaveClass("bg-critical");
    expect(within(dialog).getByRole("button", { name: "Unlink only" })).not.toHaveClass("bg-critical");

    fireEvent.click(within(dialog).getByRole("button", { name: "Unlink only" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(bodyOf(puts()[0])).toEqual({
      mappings: [
        { scope: SCOPE_A, tenant_slug: "acme-corp" },
        { scope: SCOPE_C, tenant_slug: "example-bakery" },
        { scope: SCOPE_D, tenant_slug: "gone-co" },
      ],
      ignored: [],
    });
    expect(screen.queryByTestId(`unifi-site-${SCOPE_E}`)).toBeNull();
    // Neither its ✕ nor its dropdown is left: focus lands on what happened.
    expect(screen.getByTestId("unifi-saved")).toHaveTextContent(/^Unlinked and saved\.$/);
    expect(screen.getByTestId("unifi-saved")).toHaveFocus();
  });

  it("recommends 'Unlink and ignore' when the CONSOLE is offline, though its last counts say the gateway is fine", async () => {
    const consoleOff = {
      ...MAPPED,
      sites: MAPPED.sites.map((s) => (s.scope === SCOPE_A ? { ...s, host_connected: false, gateway_online: null } : s)),
    };
    stubSites(() => jsonResponse(200, consoleOff), () => jsonResponse(200, consoleOff));
    render(<UniFiSitePanel instanceId={14} onDone={() => undefined} />);
    await screen.findByTestId(`unifi-site-${SCOPE_A}`);
    const { dialog } = open(X_A);
    expect(dialog).toHaveAccessibleDescription(
      /Its console is offline — Unlink and ignore is recommended: it also keeps the site out of “need a decision”\./);
    expect(within(dialog).getByRole("button", { name: "Unlink and ignore" })).toHaveClass("bg-critical");
    expect(within(dialog).getByRole("button", { name: "Unlink only" })).not.toHaveClass("bg-critical");
  });
});
