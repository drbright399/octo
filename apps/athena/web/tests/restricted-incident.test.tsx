/**
 * v0.17.1 (Rick, 2026-10-06) in the console.
 *
 * B — a CSAM lookup is a RESTRICTED Black (rule B7): an analyst reads
 * "Restricted incident — admins only" and the detail is not even asked for;
 * an admin gets the "DO NOT OPEN" warning, the fixed checklist and the
 * lookups DEFANGED (never a link) — and no containment, lockdown, raise or
 * reclassify (nothing touches the device). The banner names no device; an
 * analyst cannot acknowledge it. The MSP switch (client notice) is admin-only.
 *
 * A — the Fleet's "Threats stopped this week: N" headline is for operators.
 *
 * Fixtures are placeholders: `csam-placeholder[.]example[.]test`, Example /
 * Acme names, fictional devices.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import type { FleetLayer, FleetSite, FleetSitesResponse, SiteState, ThreatItem } from "@/contracts/fleet";
import type { IncidentDetail } from "@/contracts/incidents";
import type { MeResponse } from "@/contracts/operator";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import FleetPage from "@/pages/fleet";
import ThreatsTab from "@/pages/settings/threats";

const ok = (body: object, status = 200): Response =>
  new Response(JSON.stringify(body), { status });

const DOMAIN_DEFANGED = "csam-placeholder[.]example[.]test";

function layer(name: string, state: SiteState | "absent"): FleetLayer {
  return { name: name as FleetLayer["name"], present: state !== "absent", state, scope: "site",
           reasons: [], data: {}, as_of: "2026-10-06T12:00:00.000Z" };
}

function site(o: Partial<FleetSite> = {}): FleetSite {
  return {
    key: "u-00000000000000000001", kind: "site", name: "Example Site 1",
    tenant_slug: "acme-corp", tenant_name: "Acme Corp", console_name: "console-1",
    state: "black", reason: "BLACK: restricted incident — admins only (5 min, unacknowledged)",
    reasons: [{ state: "black", text: "BLACK: restricted incident — admins only", layer: "threat" }],
    location: { lat: 41.1, lng: -101, label: "1 Example Road", source: "unifi" },
    layers: { network: layer("network", "ok"), security: layer("security", "notice"),
              endpoints: layer("endpoints", "absent"), buoy: layer("buoy", "absent"),
              threat: layer("threat", "black") },
    links: [], vendor_ref: null, tenant_sites: 1, partial: false,
    incident: { tenant_slug: "acme-corp", id: 9, tier: "black", status: "open", acked: false,
                acked_by: null, contained: false, opened_at: "2026-10-06T12:00:00.000Z",
                age_s: 300, rule_id: "restricted", rule_version: 0,
                summary: "restricted incident — admins only", device_label: null,
                restricted: true },
    ...o,
  };
}

const DETAIL: IncidentDetail = {
  incident: {
    tenant_slug: "acme-corp", tenant_name: "Acme Corp", id: 9, tier: "black", status: "open",
    open: true, rule_id: "B7", rule_version: 1, rule_title: "CSAM lookup blocked (restricted)",
    summary: "CSAM-category lookup blocked by DNS protection",
    opened_at: "2026-10-06T12:00:00.000Z", age_s: 300, site_key: null, device_ref: "DPLC01",
    device_label: "ws-placeholder-07", scope: "device", acked: false, acked_by: null,
    acked_by_name: null, acknowledged_at: null, assigned_to: null, assigned_to_name: null,
    contained: false, contained_at: null, closed_at: null, close_reason_code: null,
    reclassified_from: null, reopened_count: 0, escalation_step: 1, client_visible: false,
    opened_by: "system:tier-engine", restricted: true,
  },
  timeline: [{ id: 1, author: "system:tier-engine", kind: "open", text: "opened BLACK (B7)",
               created_at: "2026-10-06T12:00:00.000Z" }],
  evidence: [], snapshot: {}, stages: [],
  why: [{ condition: "CSAM lookup blocked (restricted)", met: true, detail: "1 restricted lookup",
          event_ids: [] }],
  ruled_out: [], ruled_out_note: null, kill_chain: [], coverage: [],
  mode: { mode: "restricted", source: "no device action of any kind", caps: [] },
  proposed_steps: [], decisions: [], client_view: null, asset_tags: [],
  restricted: {
    category: "csam",
    warning: "DO NOT OPEN — do not visit, resolve or investigate the content",
    checklist: [
      "Do not open or investigate the content yourself.",
      "Preserve the device as-is.",
      "Contact law enforcement (US: report via the NCMEC CyberTipline).",
      "Inform the client's leadership / legal contact — not the user involved.",
      "Confirm your obligations with legal counsel.",
    ],
    lookups: 1, first_at: "2026-10-06T11:58:00.000Z", last_at: "2026-10-06T11:58:00.000Z",
    client_notice: false,
    evidence: [{ id: 1, category: "csam", source: "nextdns",
                 observed_at: "2026-10-06T11:58:00.000Z", received_at: "2026-10-06T11:59:00.000Z",
                 profile_id: "pfx001", device_key: "DPLC01", device_name: "ws-placeholder-07",
                 client_ip: "192.0.2.77", domain_defanged: DOMAIN_DEFANGED,
                 root_defanged: DOMAIN_DEFANGED, reasons: ["csam"], record_sha256: "ab".repeat(32) }],
  },
};

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => { global.fetch = originalFetch; cleanup(); vi.restoreAllMocks(); localStorage.clear(); });

describe("a restricted incident in the drawer", () => {
  it("an analyst reads 'restricted' and nothing more — the detail is never asked for", async () => {
    const calls: string[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      calls.push(String(input));
      if (String(input).includes("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined}
                            callerRole="analyst" />);
    const panel = await screen.findByTestId("incident-panel");
    expect(panel).toHaveAttribute("data-restricted", "true");
    expect(within(panel).getByTestId("incident-restricted-line"))
      .toHaveTextContent("Restricted incident — admins only");
    expect(within(panel).queryByTestId("incident-ack")).toBeNull();
    expect(within(panel).queryByTestId("incident-lockdown")).toBeNull();
    expect(calls.some((u) => u.endsWith("/incidents/acme-corp/9"))).toBe(false);
    expect(panel.textContent!.toLowerCase()).not.toMatch(/csam|placeholder|dplc01/);
  });

  it("an admin gets the DO NOT OPEN warning, the checklist, defanged lookups — and no device action", async () => {
    const calls: { method: string; url: string }[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ method: init?.method ?? "GET", url });
      if (url.endsWith("/incidents/acme-corp/9")) return Promise.resolve(ok(DETAIL));
      if (url.includes("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined}
                            callerRole="admin" callerId={5} />);
    const panel = await screen.findByTestId("incident-panel");
    const warning = await within(panel).findByTestId("restricted-warning");
    expect(warning).toHaveTextContent("DO NOT OPEN — do not visit, resolve or investigate the content");
    expect(warning).toHaveAttribute("role", "alert");
    const checklist = within(panel).getByTestId("restricted-checklist");
    expect(checklist).toHaveTextContent("NCMEC CyberTipline");
    expect(checklist).toHaveTextContent("not the user involved");
    expect(checklist).toHaveTextContent("legal counsel");
    const lookups = within(panel).getByTestId("restricted-evidence");
    expect(lookups).toHaveTextContent(DOMAIN_DEFANGED);
    expect(lookups).toHaveTextContent("ws-placeholder-07");
    expect(lookups.querySelectorAll("a")).toHaveLength(0);        // never a link
    expect(panel.textContent).not.toContain("csam-placeholder.example.test");
    expect(within(panel).getByTestId("restricted-client-notice")).toHaveTextContent("sees nothing");
    // Only what touches no device.
    for (const id of ["incident-ack", "incident-note", "incident-close", "incident-assign-me"]) {
      expect(within(panel).getByTestId(id)).toBeInTheDocument();
    }
    for (const id of ["incident-lockdown", "incident-contain", "incident-raise",
                      "incident-reclassify", "incident-steps", "incident-kill-chain"]) {
      expect(within(panel).queryByTestId(id)).toBeNull();
    }
    expect(within(panel).getByTestId("incident-timeline")).toHaveTextContent("opened BLACK (B7)");
    fireEvent.click(within(panel).getByTestId("incident-ack"));
    await waitFor(() => expect(calls).toContainEqual(
      { method: "POST", url: "/api/v1/incidents/acme-corp/9/ack" }));
  });

  it("an admin reads the other sensors' records (a buoy's Pi-hole) — defanged, never a link", async () => {
    const detail: IncidentDetail = {
      ...DETAIL,
      restricted: {
        ...DETAIL.restricted!,
        related: [{ event_id: 41, received_at: "2026-10-06T11:58:05.000Z", source: "buoy:acme",
                    event_type: "pihole.query", source_host: "buoy-acme-1",
                    summary_defanged: `blocked upstream: ${DOMAIN_DEFANGED}`,
                    payload_defanged: `{"raw_query":{"domain":"${DOMAIN_DEFANGED}","client":"192.0.2.77"}}` }],
      },
    };
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/incidents/acme-corp/9")) return Promise.resolve(ok(detail));
      if (url.includes("/alerts")) return Promise.resolve(ok({ key: "x", items: [] }));
      return Promise.resolve(ok({}));
    }) as unknown as typeof fetch;
    render(<FleetSiteDrawer site={site()} view="operator" onClose={() => undefined}
                            callerRole="admin" callerId={5} />);
    const panel = await screen.findByTestId("incident-panel");
    const related = await within(panel).findByTestId("restricted-related");
    expect(within(related).getByTestId("restricted-related-41")).toHaveTextContent("pihole.query");
    expect(related).toHaveTextContent("192.0.2.77");
    expect(related).toHaveTextContent(DOMAIN_DEFANGED);
    expect(related.querySelectorAll("a")).toHaveLength(0);
    expect(panel.textContent).not.toContain("csam-placeholder.example.test");
  });
});

const RESTRICTED_THREAT: ThreatItem = {
  tenant: "acme-corp", tenant_name: "Acme Corp", id: 9, tier: "black", status: "open",
  acked: false, acked_by: null, contained: false, opened_at: "2026-10-06T12:00:00.000Z",
  age_s: 300, rule_id: "restricted", summary: "restricted incident — admins only",
  device_label: null, unknown_location: false, site_keys: ["u-00000000000000000001"],
  restricted: true,
};

function body(extra: Partial<FleetSitesResponse> = {}): FleetSitesResponse {
  return {
    view: "operator", generated_at: new Date().toISOString(), partial: false, sites: [site()],
    counts: { total: 1 }, isp_outages: [], unmapped_sites: 0, tenants: [],
    threats: [RESTRICTED_THREAT], blind: [], coverage: null, threats_stopped_week: 1234,
    ...extra,
  };
}

function serve(role: string, resp: FleetSitesResponse): void {
  global.fetch = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/fleet/sites")) return Promise.resolve(ok(resp));
    if (url.includes("/auth/me")) return Promise.resolve(ok({ username: "alice", role: [role] }));
    return Promise.resolve(ok({}));
  }) as unknown as typeof fetch;
}

describe("the Fleet page", () => {
  beforeEach(() => { localStorage.setItem("athena.fleet.sites.view.v1", "list"); });

  it("the restricted banner names no device and an analyst cannot acknowledge it", async () => {
    serve("analyst", body());
    render(<FleetPage />);
    const banner = await screen.findByTestId("threat-banner");
    expect(banner).toHaveAttribute("data-restricted", "true");
    expect(banner).toHaveTextContent("Acme Corp");
    expect(banner).toHaveTextContent("restricted incident — admins only");
    expect(banner.textContent!.toLowerCase()).not.toMatch(/csam|placeholder|ws-|b7/);
    await waitFor(() => expect(within(banner).queryByTestId("threat-banner-ack")).toBeNull());
  });

  it("an admin may acknowledge it from the banner", async () => {
    serve("admin", body());
    render(<FleetPage />);
    const banner = await screen.findByTestId("threat-banner");
    expect(await within(banner).findByTestId("threat-banner-ack")).toBeInTheDocument();
  });

  it("operators see 'Threats stopped this week: N'; a client user never does", async () => {
    serve("analyst", body({ threats: [] }));
    render(<FleetPage />);
    await screen.findByTestId("fleet-threats-week");
    const headline = screen.getByTestId("fleet-threats-week-text");
    expect(headline).toHaveTextContent("Threats stopped this week: 1,234");
    cleanup();
    serve("viewer", { ...body({ threats: [] }), view: "client", threats_stopped_week: null });
    render(<FleetPage />);
    await screen.findByTestId("fleet-summary");
    expect(screen.queryByTestId("fleet-threats-week")).toBeNull();
  });
});

function me(role: MeResponse["role"], scope: string[] = ["*"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", display_name: null,
           role, scope_slugs: scope, must_change_password: false, mfa_enabled: true,
           backup_codes_remaining: 8, needs_setup: false };
}

describe("Settings → Threats: the restricted-incident client notice", () => {
  function serveSettings(puts: { url: string; body: string }[], on = false): void {
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/tiers/restricted") && init?.method === "PUT") {
        puts.push({ url, body: String(init.body) });
        return Promise.resolve(ok({ csam_client_notice: true, help: "the switch" }));
      }
      if (url.includes("/tiers/restricted")) {
        return Promise.resolve(ok({ csam_client_notice: on, help: "the switch" }));
      }
      if (url.includes("/tiers/rules")) return Promise.resolve(ok({ rules: [] }));
      if (url.includes("/asset-tags")) return Promise.resolve(ok({ tags: [] }));
      if (url.includes("/brake")) return Promise.resolve(ok({ brakes: [] }));
      if (url.includes("/evidence-windows")) return Promise.resolve(ok({ items: [] }));
      return Promise.resolve(ok({ rows: [] }));
    }) as unknown as typeof fetch;
  }

  it("an analyst never sees the switch", async () => {
    serveSettings([]);
    render(<ThreatsTab me={me(["analyst"], ["acme-corp"])} />);
    await screen.findByTestId("threats-rules");
    expect(screen.queryByTestId("threats-restricted")).toBeNull();
  });

  it("an all-scope admin turns it on with a reason; it reads OFF by default", async () => {
    const puts: { url: string; body: string }[] = [];
    serveSettings(puts);
    render(<ThreatsTab me={me(["admin"])} />);
    const state = await screen.findByTestId("restricted-state");
    await waitFor(() => expect(state).toHaveTextContent("OFF — suppressed (default)"));
    const toggle = screen.getByTestId("restricted-toggle");
    expect(toggle).toBeDisabled();                                // a reason first
    fireEvent.change(screen.getByTestId("restricted-reason"),
                     { target: { value: "the MSP informs its clients" } });
    fireEvent.click(toggle);
    await waitFor(() => expect(puts).toHaveLength(1));
    expect(JSON.parse(puts[0]!.body)).toEqual({ csam_client_notice: true,
                                                reason: "the MSP informs its clients" });
  });

  it("an admin with a concrete scope sees the state but no switch", async () => {
    serveSettings([], true);
    render(<ThreatsTab me={me(["admin"], ["acme-corp"])} />);
    const state = await screen.findByTestId("restricted-state");
    await waitFor(() => expect(state).toHaveTextContent("ON — the neutral line only"));
    expect(screen.queryByTestId("restricted-form")).toBeNull();
  });
});
