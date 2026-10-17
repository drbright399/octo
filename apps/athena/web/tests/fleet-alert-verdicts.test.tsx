/**
 * v0.17.2 — the Fleet drawer's "needs attention" list: acknowledge (an
 * optional note, "repeats for 24 h"), "this is expected" (a reason of 10+
 * characters, a review date ≤ 90 days, "only from this remote" for a
 * network alert), the greyed acknowledged / expected rows behind "show
 * acknowledged", the re-surfaced line, the operator enrichment (IPS remote
 * owner / PTR / scanner label / local device / N× in 24 h; Datto one line +
 * details, and — v0.17.3 — the machine's maker / model / serial and the
 * other devices' serials when a name is shared), no "expected" where the
 * server refuses it (a RocketCyber alert: Acknowledge only) — and a client
 * user gets none of it. Settings → Threats lists the expected conditions and
 * revokes one. Fixtures are made up: Example / Acme names, TEST-NET
 * addresses.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import type { FleetLayer, FleetSite, SiteAlert } from "@/contracts/fleet";
import type { MeResponse } from "@/contracts/operator";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import { reviewDate } from "@/components/site-alert-row";
import ThreatsTab from "@/pages/settings/threats";

const ok = (body: object, status = 200): Response =>
  new Response(JSON.stringify(body), { status });

function layer(name: string, data: Record<string, unknown> = {}): FleetLayer {
  return { name: name as FleetLayer["name"], present: true, state: "ok", scope: "site",
           reasons: [], data, as_of: "2026-10-06T12:00:00.000Z" };
}

function site(o: Partial<FleetSite> = {}): FleetSite {
  return {
    key: "u-00000000000000000003", kind: "site", name: "Example Bakery", tenant_slug: "example-bakery",
    tenant_name: "Example Bakery", console_name: "console-3", state: "warn", reason: "1 IPS block today",
    reasons: [], location: null,
    layers: { threat: layer("threat"), network: layer("network"),
              security: layer("security", { ips_blocked_24h: 3, ips_detected_24h: 0, ips_hidden_24h: 2 }),
              endpoints: layer("endpoints"), buoy: { ...layer("buoy"), present: false, state: "absent" } },
    links: [], vendor_ref: null, tenant_sites: 1, partial: false, ...o,
  };
}

const IPS: SiteAlert = {
  event_id: 41, occurred_at: "2026-10-06T11:00:00.000Z", severity: "high", source: "unifi",
  title: "UniFi IPS blocked ET POLICY Example", tenant_wide: false, status: "open",
  can_expect: true, expected_refusal: null, network: true, hits: 3,
  last_seen: "2026-10-06T11:20:00.000Z", ack: null, rule: null, new_since_ack: 0,
  enrichment: {
    kind: "unifi_ips", direction: "outbound", action: "blocked", signature: "ET POLICY Example",
    remote_ip: "203.0.113.66", local_ip: "192.0.2.37", local_name: "BAKERY-POS",
    local_name_source: "datto",
    remote: { ptr: "scanner-07.ch1.censys-scanner.com", ptr_confirmed: true, org: "Censys, Inc.",
              labels: [{ kind: "scanner", name: "Censys", basis: "ptr" }], pending: false,
              failed: false },
    repeats_24h: 5, repeats_approximate: false, hits: 3, last_seen: "2026-10-06T11:20:00.000Z",
  },
};

const DATTO: SiteAlert = {
  event_id: 52, occurred_at: "2026-10-06T10:00:00.000Z", severity: "high", source: "datto",
  title: "Event log · System 7031", tenant_wide: true, status: "open", can_expect: true,
  network: false, ack: null, rule: null,
  enrichment: { kind: "datto", line: "Event 7031 · Service Control Manager · System log",
                class: "eventlog_ctx", host: "EXAMPLE-SRV", resolved: false, priority: "High",
                noc: false, details: ["The Spooler service terminated unexpectedly."],
                repeats: 2, since: "2026-10-01T08:00:00.000Z", device_uid: "0000dev1-aaaa",
                site: "Example Office", lan_ip: "192.0.2.20", wan_ip: "203.0.113.10",
                shared_hostname: 2, shared_sites: 2 },
};

const CSAM: SiteAlert = {
  event_id: 63, occurred_at: "2026-10-06T09:00:00.000Z", severity: "high", source: "nextdns",
  title: "DNS block", tenant_wide: true, status: "open", can_expect: false,
  expected_refusal: "a CSAM lookup is never expected — Athena treats it as Black", network: false,
};

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => { global.fetch = originalFetch; cleanup(); vi.restoreAllMocks(); });

interface Call { method: string; url: string; body?: unknown }

function serve(lists: { open: object; handled?: object }, calls: Call[]): void {
  global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push({ method, url, ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
    if (method === "POST") return Promise.resolve(ok({ verdict_id: 1, event_id: 41 }));
    if (url.endsWith("/alerts?include=acknowledged")) return Promise.resolve(ok(lists.handled ?? lists.open));
    if (url.endsWith("/alerts")) return Promise.resolve(ok(lists.open));
    return Promise.resolve(ok({}));
  }) as unknown as typeof fetch;
}

describe("the drawer's needs-attention list", () => {
  it("shows the enrichment, hides what is handled and lists it greyed on request", async () => {
    const calls: Call[] = [];
    const acked: SiteAlert = { ...IPS, event_id: 44, status: "acknowledged",
      ack: { by: 7, by_name: "Alice Example", at: "2026-10-06T11:30:00.000Z", note: "checked with the client",
             repeat_until: null, by_repeat: false } };
    const expected: SiteAlert = { ...IPS, event_id: 45, status: "expected",
      rule: { id: 3, label: "Siris backup", review_at: "2026-12-30T00:00:00.000Z", remote: "198.51.100.20" } };
    serve({ open: { key: "x", items: [IPS, DATTO, CSAM], hidden: 2 },
            handled: { key: "x", items: [IPS, acked, expected], hidden: 2, include_acknowledged: true } },
          calls);
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined} callerRole="analyst" />);
    const row = await screen.findByTestId("site-alert-41");
    const e = within(row).getByTestId("alert-enrichment-41");
    expect(e).toHaveTextContent("outbound · blocked · remote 203.0.113.66 — Censys, Inc. · scanner-07.ch1.censys-scanner.com");
    expect(e).toHaveTextContent("internet scanner: Censys");
    expect(e).toHaveTextContent("local 192.0.2.37 (BAKERY-POS, Datto) · 5× in 24 h from this remote");
    expect(screen.getByTestId("alerts-hidden-count")).toHaveTextContent("2 acknowledged / expected not shown");
    // The count is every hit (the facts); how many a human handled, beside it.
    expect(screen.getByTestId("sec-ips")).toHaveTextContent("3 blocked · 0 NOT blocked (2 of them acknowledged / expected)");
    // Datto: one line, open / repeats, the full text behind "details".
    expect(screen.getByTestId("alert-enrichment-52"))
      .toHaveTextContent("Event 7031 · Service Control Manager · System log · EXAMPLE-SRV · open · 2 repeats since 2026-10-01");
    expect(within(screen.getByTestId("alert-details-52")).getByText(/terminated unexpectedly/)).toBeInTheDocument();
    // WHICH device (repeats are keyed by its Datto uid) — and two machines, one name.
    expect(screen.getByTestId("alert-device-52"))
      .toHaveTextContent("site Example Office · LAN 192.0.2.20 · WAN 203.0.113.10 · device 0000dev1");
    expect(screen.getByTestId("alert-shared-host-52"))
      .toHaveTextContent("2 devices in this client are named EXAMPLE-SRV (at 2 sites)");
    // The server refuses "expected" for a CSAM lookup: no button, the reason.
    expect(screen.queryByTestId("expected-open-63")).toBeNull();
    expect(screen.getByTestId("expected-refusal-63")).toHaveTextContent("CSAM");
    expect(calls[0]!.url).toBe("/api/v1/fleet/sites/u-00000000000000000003/alerts");

    fireEvent.click(screen.getByTestId("alerts-show-acknowledged"));
    const ackRow = await screen.findByTestId("site-alert-44");
    expect(ackRow).toHaveAttribute("data-status", "acknowledged");
    expect(ackRow.className).toContain("opacity-60");
    expect(within(ackRow).getByTestId("alert-status-44"))
      .toHaveTextContent("acknowledged by Alice Example");
    expect(within(ackRow).getByTestId("alert-status-44")).toHaveTextContent("checked with the client");
    expect(within(ackRow).queryByTestId("ack-open-44")).toBeNull();
    const expRow = screen.getByTestId("site-alert-45");
    expect(within(expRow).getByTestId("alert-status-45"))
      .toHaveTextContent("expected (rule #3) · review 2026-12-30 · from 198.51.100.20");
    expect(calls.at(-1)!.url).toBe("/api/v1/fleet/sites/u-00000000000000000003/alerts?include=acknowledged");
  });

  it("acknowledges with a note and repeats, then reloads the list and the fleet", async () => {
    const calls: Call[] = [];
    serve({ open: { key: "x", items: [IPS], hidden: 0 } }, calls);
    const changed = vi.fn();
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined}
                            callerRole="analyst" onIncidentChanged={changed} />);
    fireEvent.click(await screen.findByTestId("ack-open-41"));
    fireEvent.change(screen.getByTestId("ack-note-41"), { target: { value: "  checked   with the client " } });
    fireEvent.click(screen.getByTestId("ack-repeat-41"));
    fireEvent.click(screen.getByTestId("ack-submit-41"));
    await waitFor(() => expect(changed).toHaveBeenCalled());
    // What the list SHOWED goes with it: the ack never covers later hits.
    expect(calls.filter((c) => c.method === "POST")).toEqual([{
      method: "POST", url: "/api/v1/alerts/example-bakery/41/ack",
      body: { note: "checked with the client", repeat_24h: true, seen_hits: 3,
              seen_last: "2026-10-06T11:20:00.000Z" } }]);
    await waitFor(() => expect(calls.filter((c) => c.url.endsWith("/alerts")).length).toBe(2));
    expect(screen.queryByTestId("ack-form-41")).toBeNull();
  });

  it("a RocketCyber alert offers Acknowledge only — no expected, no \"repeats for 24 h\"", async () => {
    const calls: Call[] = [];
    const rc: SiteAlert = {
      event_id: 71, occurred_at: "2026-10-06T10:00:00.000Z", severity: "high", source: "rocketcyber",
      title: "RocketCyber: Suspicious PowerShell on BAKERY-POS", tenant_wide: true, status: "open",
      can_expect: false,
      expected_refusal: "RocketCyber alerts are acknowledged one at a time — too vague for an expected condition (Rick, 2026-10-07)",
      can_repeat: false, network: false, hits: null, last_seen: null,
    };
    serve({ open: { key: "x", items: [rc] } }, calls);
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined} callerRole="analyst" />);
    expect(await screen.findByTestId("ack-open-71")).toBeInTheDocument();
    expect(screen.queryByTestId("expected-open-71")).toBeNull();
    expect(screen.getByTestId("expected-refusal-71"))
      .toHaveTextContent("RocketCyber alerts are acknowledged one at a time");
    fireEvent.click(screen.getByTestId("ack-open-71"));
    expect(screen.queryByTestId("ack-repeat-71")).toBeNull();
    fireEvent.click(screen.getByTestId("ack-submit-71"));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")).toEqual({
      method: "POST", url: "/api/v1/alerts/example-bakery/71/ack", body: {} });
  });

  it("names the machine: maker, model and serial; a shared name names the other serials", async () => {
    const calls: Call[] = [];
    const withSerial: SiteAlert = { ...DATTO, enrichment: {
      ...(DATTO.enrichment as NonNullable<SiteAlert["enrichment"]> & { kind: "datto" }),
      serial: "EXAMPLE-SN-0001", manufacturer: "Acme Computers Inc.", model: "Model 7090",
      shared_serials: ["EXAMPLE-SN-0002"] } };
    const hpDoubled: SiteAlert = { ...DATTO, event_id: 53, enrichment: {
      ...(DATTO.enrichment as NonNullable<SiteAlert["enrichment"]> & { kind: "datto" }),
      serial: null, manufacturer: "Example", model: "Example Book 840", shared_hostname: 3,
      shared_serials: ["EXAMPLE-SN-0007", "EXAMPLE-SN-0009"] } };
    const unknown: SiteAlert = { ...DATTO, event_id: 54, enrichment: {
      ...(DATTO.enrichment as NonNullable<SiteAlert["enrichment"]> & { kind: "datto" }),
      serial: null, manufacturer: null, model: null, shared_serials: [] } };
    serve({ open: { key: "x", items: [withSerial, hpDoubled, unknown] } }, calls);
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined} callerRole="analyst" />);
    expect(await screen.findByTestId("alert-device-52")).toHaveTextContent(
      "Acme Computers Inc. Model 7090 · SN EXAMPLE-SN-0001 · site Example Office · LAN 192.0.2.20");
    expect(screen.getByTestId("alert-shared-host-52")).toHaveTextContent(
      "this alert and its repeats are this device only (this one SN EXAMPLE-SN-0001; the other: SN EXAMPLE-SN-0002)");
    // The model already names its maker: not doubled; three devices → "the others".
    expect(screen.getByTestId("alert-device-53").textContent).toMatch(/^Example Book 840 · site/);
    expect(screen.getByTestId("alert-shared-host-53")).toHaveTextContent(
      "3 devices in this client are named EXAMPLE-SRV (at 2 sites)");
    expect(screen.getByTestId("alert-shared-host-53")).toHaveTextContent(
      "(the others: SN EXAMPLE-SN-0007, SN EXAMPLE-SN-0009)");
    // Nothing known: the line as before, no "SN", no brackets.
    expect(screen.getByTestId("alert-device-54").textContent).toMatch(/^site Example Office/);
    expect(screen.getByTestId("alert-device-54")).not.toHaveTextContent("SN");
    expect(screen.getByTestId("alert-shared-host-54").textContent).toMatch(/device only$/);
  });

  it("an owner-name label says so — never \"internet scanner\" outright", async () => {
    const calls: Call[] = [];
    const rdap: SiteAlert = { ...IPS, enrichment: {
      ...(IPS.enrichment as NonNullable<SiteAlert["enrichment"]> & { kind: "unifi_ips" }),
      remote: { org: "Example Shadowserver Mirror LLC", labels: [
        { kind: "scanner", name: "Shadowserver", basis: "rdap" },
        { kind: "scanner", name: "Palo Alto Cortex Xpanse", basis: "network" }],
        pending: false, failed: false } } };
    serve({ open: { key: "x", items: [rdap] } }, calls);
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined} callerRole="analyst" />);
    const labels = await screen.findAllByTestId("alert-label-41");
    expect(labels.map((l) => l.textContent)).toEqual([
      "owner name mentions Shadowserver", "internet scanner: Palo Alto Cortex Xpanse"]);
  });

  it("marks an alert expected: a reason of 10+, a review date ≤ 90 days, only from its remote", async () => {
    const calls: Call[] = [];
    serve({ open: { key: "x", items: [IPS] } }, calls);
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined} callerRole="analyst" />);
    fireEvent.click(await screen.findByTestId("expected-open-41"));
    const submit = screen.getByTestId("expected-submit-41");
    fireEvent.change(screen.getByTestId("expected-reason-41"), { target: { value: "backups" } });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByTestId("expected-reason-41"),
                     { target: { value: "Siris backup to the Datto cloud" } });
    expect(submit).toBeEnabled();
    expect((screen.getByTestId("expected-days-41") as HTMLInputElement).value).toBe("90");
    expect(screen.getByTestId("expected-form-41")).toHaveTextContent(reviewDate(90));
    fireEvent.change(screen.getByTestId("expected-days-41"), { target: { value: "91" } });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByTestId("expected-days-41"), { target: { value: "30" } });
    fireEvent.click(screen.getByTestId("expected-remote-41"));
    fireEvent.click(submit);
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.filter((c) => c.method === "POST")).toEqual([{
      method: "POST", url: "/api/v1/alerts/example-bakery/41/expected",
      body: { reason: "Siris backup to the Datto cloud", review_days: 30, remote: "203.0.113.66" } }]);
  });

  it("says a re-surfaced alert's new hits and a pending lookup", async () => {
    const calls: Call[] = [];
    const resurfaced: SiteAlert = {
      ...IPS, status: "resurfaced", new_since_ack: 4,
      ack: { by: 7, by_name: "Alice Example", at: "2026-10-06T11:30:00.000Z", note: null,
             repeat_until: null, by_repeat: false },
      enrichment: { ...(IPS.enrichment as NonNullable<SiteAlert["enrichment"]> & { kind: "unifi_ips" }),
                    remote: { labels: [], pending: true, failed: false } },
    };
    serve({ open: { key: "x", items: [resurfaced] } }, calls);
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined} callerRole="analyst" />);
    expect(await screen.findByTestId("alert-status-41")).toHaveTextContent("re-surfaced: 4 new since acknowledged by Alice Example");
    expect(screen.getByTestId("alert-enrichment-41")).toHaveTextContent("looking up…");
    expect(screen.getByTestId("ack-open-41")).toBeInTheDocument();     // it needs attention again
  });

  it("a client user gets no list, no acknowledge, no expected, no hidden count", () => {
    global.fetch = vi.fn() as unknown as typeof fetch;
    render(<FleetSiteDrawer site={site({ tenant_slug: null })} view="client" onClose={() => undefined} />);
    expect(screen.queryByTestId("site-alerts")).toBeNull();
    expect(screen.queryByTestId("alerts-show-acknowledged")).toBeNull();
    expect(screen.queryByText(/acknowledged/)).toBeNull();
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

function me(role: MeResponse["role"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", display_name: null,
           role, scope_slugs: ["*"], must_change_password: false, mfa_enabled: true,
           backup_codes_remaining: 8, needs_setup: false };
}

describe("Settings → Threats: expected conditions", () => {
  it("lists them with their review date and revokes one with a reason", async () => {
    const calls: Call[] = [];
    const row = {
      id: 3, tenant_slug: "example-bakery", source: "unifi", device_key: "scope|192.0.2.37",
      signature_key: "unifi.ips_threat:ET POLICY Example|outbound|blocked", remote: "198.51.100.20",
      label: "UniFi IPS blocked ET POLICY Example", reason: "Siris backup to the Datto cloud",
      origin_event_id: 41, created_by: 7, created_by_name: "Alice Example",
      created_at: "2026-10-06T11:30:00.000Z", review_at: "2027-01-04T11:30:00.000Z",
      reminded_at: null, revoked_at: null, revoked_by: null, revoked_by_name: null,
      revoke_reason: null, status: "active" };
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ method: init?.method ?? "GET", url,
                   ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
      if (url.includes("/alerts/expected/3/revoke")) {
        return Promise.resolve(ok({ rows: [{ ...row, status: "revoked" }] }));
      }
      if (url.includes("/alerts/expected")) return Promise.resolve(ok({ rows: [row] }));
      if (url.includes("/tiers/rules")) return Promise.resolve(ok({ rules: [] }));
      if (url.includes("/asset-tags")) return Promise.resolve(ok({ tags: [] }));
      return Promise.resolve(ok({ rows: [], items: [] }));
    }) as unknown as typeof fetch;
    vi.spyOn(window, "prompt").mockReturnValue("the backup moved to a new vault");
    render(<ThreatsTab me={me(["analyst"])} />);
    const tr = await screen.findByTestId("expected-row-3");
    expect(tr).toHaveTextContent("UniFi IPS blocked ET POLICY Example · from 198.51.100.20");
    expect(tr).toHaveTextContent("2027-01-04");
    expect(tr).toHaveTextContent("Alice Example");
    fireEvent.click(within(tr).getByTestId("expected-revoke-3"));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")).toEqual({
      method: "POST", url: "/api/v1/alerts/expected/3/revoke",
      body: { reason: "the backup moved to a new vault" } });
    fireEvent.change(screen.getByTestId("expected-state"), { target: { value: "all" } });
    await waitFor(() => expect(calls.some((c) => c.url === "/api/v1/alerts/expected?state=all")).toBe(true));
  });
});
