import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { NextDnsProfilePanel } from "@/components/nextdns-profile-panel";
import { toRotatable } from "@/components/source-health-panel";
import { listIntegrations } from "@/lib/api";
import type { MeResponse } from "@/contracts/operator";
import type { SourceHealthRow } from "@/lib/source-health";

/**
 * NextDNS in the console: the integration card (profile counts, the
 * decision it needs, protection, throttled ≠ failed, the no-deadline wait,
 * an auth error), the profile mapping panel (suggestions, ignore, one save),
 * and the source-health card (throttled + lapsed sites).
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const PROFILES_URL = "/api/v1/integrations/nextdns/12/profiles";
const TENANTS_URL = "/api/v1/admin/adapters/instances/12/vendor-tenants";

function me(): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role: ["admin"] } as MeResponse;
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const SUMMARY = {
  known: 60, mapped: 40, ignored: 2, unmapped: 18, active: 30, pending: 9, lapsed: 1,
  checking: 0, throttled: false, throttled_for_sec: 0,
};

const BASE = {
  slug: "nextdns",
  id: 12,
  status: "running",
  status_detail: "connected — last contact with the vendor succeeded",
  configured_at: "2026-09-30T10:00:00.000Z",
  last_test_at: null,
  warnings: [],
  notes: [],
};

function profile(over: Record<string, unknown>) {
  return {
    profile_id: "abc123", name: "Acme Corp Office", listed: true, tenant_slug: null,
    tenant_name: null, tenant_status: null, match_source: null, ignored: false,
    suggestion: null, state: null, state_since: null, queries_24h: null, ...over,
  };
}

const PROFILES = {
  instance_id: 12,
  discovered: true,
  fetched_at: "2026-09-30T10:00:00.000Z",
  profiles: [
    profile({ suggestion: { tenant_slug: "acme-corp", tenant_name: "Acme Corp", rule: "name-prefix" } }),
    profile({ profile_id: "def456", name: "Example Bakery",
              suggestion: { tenant_slug: "example-bakery", tenant_name: "Example Bakery", rule: "same-name" } }),
    profile({ profile_id: "tst001", name: "Test Profile" }),
    profile({ profile_id: "abc124", name: "Acme Corp Warehouse", tenant_slug: "acme-corp",
              tenant_name: "Acme Corp", tenant_status: "active", match_source: "manual",
              state: "active", queries_24h: 12345 }),
  ],
  counts: { known: 4, mapped: 1, ignored: 0, unmapped: 3, active: 1, pending: 0, lapsed: 0 },
};

function stubBackend(instance: Record<string, unknown>, opts: { discovered?: boolean } = {}) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/v1/integrations") {
      return jsonResponse(200, {
        definitions: [{ slug: "nextdns", name: "NextDNS", category: "network", description: "DNS filtering." }],
        instances: { nextdns: instance },
      });
    }
    if (url === "/api/v1/admin/adapters/catalog") return jsonResponse(200, { adapters: [], categories: [] });
    if (url === "/api/v1/admin/clients") {
      return jsonResponse(200, {
        clients: [
          { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
          { slug: "example-bakery", display_name: "Example Bakery", status: "active" },
          { slug: "old-client", display_name: "Old Client", status: "offboarded" },
        ],
      });
    }
    if (url === PROFILES_URL && init?.method === "PUT") {
      return jsonResponse(200, { ...PROFILES, profiles: PROFILES.profiles });
    }
    if (url === PROFILES_URL) {
      return jsonResponse(200, opts.discovered === false && fetchMock.mock.calls.filter(
        ([u]) => String(u).startsWith(TENANTS_URL)).length === 0
        ? { ...PROFILES, discovered: false, profiles: [] } : PROFILES);
    }
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

describe("NextDNS integration card", () => {
  it("carries the profile summary and the wait through the API layer", async () => {
    stubBackend({ ...BASE, profiles: SUMMARY, waiting_for_tenant_mapping: true });
    const inst = (await listIntegrations()).instances.nextdns;
    expect(inst?.profiles?.unmapped).toBe(18);
    expect(inst?.waiting_for_tenant_mapping).toBe(true);
  });

  it("shows counts, the decision it needs, protection — and opens the profile panel", async () => {
    stubBackend({ ...BASE, profiles: SUMMARY });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-nextdns")));
    expect(card.getByTestId("integration-profile-counts-nextdns")).toHaveTextContent(
      "40 profiles mapped · 2 ignored · 18 unmapped");
    const decide = card.getByTestId("integration-profiles-unmapped-nextdns");
    expect(decide).toHaveTextContent(/18 profiles need a decision — map each to its client, or ignore it/);
    expect(card.getByTestId("integration-protection-nextdns")).toHaveTextContent(
      "Protection: 30 active · 9 pending rollout · 1 stopped reporting");
    expect(card.queryByTestId("integration-throttled-nextdns")).toBeNull();
    fireEvent.click(within(decide).getByRole("button"));
    const drawer = await screen.findByTestId("tenant-mapping-drawer");
    expect(await within(drawer).findByTestId("nextdns-profile-panel")).toBeInTheDocument();
  });

  it("says throttled as information, never as a failure", async () => {
    stubBackend({ ...BASE, profiles: { ...SUMMARY, throttled: true, throttled_for_sec: 30 } });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-nextdns")));
    const line = card.getByTestId("integration-throttled-nextdns");
    expect(line).toHaveTextContent(/Throttled by NextDNS \(rate limit\) — calls wait 30 s/);
    expect(line).toHaveTextContent(/Not a failure/);
    expect(line.getAttribute("role")).toBe("status");
    expect(card.queryByTestId("integration-problem-nextdns")).toBeNull();
  });

  it("says it waits for the profile mapping — with no deadline", async () => {
    stubBackend({ ...BASE, profiles: { ...SUMMARY, mapped: 0, active: 0, pending: 0, lapsed: 0 },
                  waiting_for_tenant_mapping: true });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-nextdns")));
    const line = card.getByTestId("integration-first-import-nextdns");
    expect(line).toHaveTextContent(
      "Waiting for your profile mapping — imports start as soon as you save it. Unmapped profiles are never polled.");
    expect(line.querySelector("time")).toBeNull();
    expect(card.queryByTestId("integration-protection-nextdns")).toBeNull();
  });

  it("an auth error is a failure", async () => {
    stubBackend({ ...BASE, status: "error", contact_failure_kind: "auth",
                  status_detail: "NextDNS rejected the API key (HTTP 401 on profile list).",
                  profiles: SUMMARY });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-nextdns")));
    expect(card.getByTestId("integration-problem-nextdns")).toHaveTextContent(
      /rejected the API key \(HTTP 401/);
  });
});

describe("NextDNS profile panel", () => {
  it("offers suggestions, ignore, and saves both in one PUT — suggestions confirmed row by row", async () => {
    const fetchMock = stubBackend({ ...BASE });
    const done = vi.fn();
    render(<NextDnsProfilePanel instanceId={12} onDone={done} />);
    await screen.findByTestId("nextdns-profile-abc123");
    expect(screen.getByTestId("nextdns-tally")).toHaveTextContent(
      "1 mapped · 0 ignored · 3 need a decision");
    expect(screen.getByTestId("nextdns-profile-abc124")).toHaveTextContent(
      /active · 12,345 queries \/ 24 h/);
    // Offboarded clients are not offered.
    const choice = screen.getByTestId("nextdns-choice-tst001") as HTMLSelectElement;
    expect([...choice.options].map((o) => o.textContent)).not.toContain("Old Client");
    // One suggestion confirmed on its row; the rest only PRE-FILLED in one go.
    fireEvent.click(screen.getByTestId("nextdns-suggest-abc123"));
    expect(screen.getByTestId("nextdns-accept-all")).toHaveTextContent("Review 1 suggestion");
    fireEvent.click(screen.getByTestId("nextdns-accept-all"));
    expect(screen.getByTestId("nextdns-pending-def456")).toHaveTextContent(/not saved until confirmed/);
    fireEvent.change(choice, { target: { value: "__ignore__" } });
    expect(screen.getByTestId("nextdns-tally")).toHaveTextContent(
      "2 mapped · 1 ignored · 1 need a decision · 1 awaiting your confirmation");
    // The pending row needs its own Confirm.
    fireEvent.click(screen.getByTestId("nextdns-confirm-def456"));
    expect(screen.queryByTestId("nextdns-pending-def456")).toBeNull();
    expect(screen.getByTestId("nextdns-tally")).toHaveTextContent(
      "3 mapped · 1 ignored · 0 need a decision");
    fireEvent.click(screen.getByTestId("nextdns-save"));
    await screen.findByTestId("nextdns-saved");
    const put = fetchMock.mock.calls.find(
      ([u, init]) => u === PROFILES_URL && (init as RequestInit | undefined)?.method === "PUT");
    // Confirmed suggestions are the operator's decision: 'manual'.
    expect(JSON.parse(String((put?.[1] as RequestInit).body))).toEqual({
      mappings: [
        { profile_id: "abc123", tenant_slug: "acme-corp", match_source: "manual" },
        { profile_id: "def456", tenant_slug: "example-bakery", match_source: "manual" },
        { profile_id: "abc124", tenant_slug: "acme-corp", match_source: "manual" },
      ],
      ignored: ["tst001"],
    });
  });

  it("never saves a bulk-reviewed suggestion that was not confirmed (same-name rule)", async () => {
    const fetchMock = stubBackend({ ...BASE });
    render(<NextDnsProfilePanel instanceId={12} onDone={() => undefined} />);
    await screen.findByTestId("nextdns-profile-abc123");
    fireEvent.click(screen.getByTestId("nextdns-accept-all"));
    expect(screen.getByTestId("nextdns-tally")).toHaveTextContent(
      "1 mapped · 0 ignored · 3 need a decision · 2 awaiting your confirmation");
    fireEvent.click(screen.getByTestId("nextdns-save"));
    const saved = await screen.findByTestId("nextdns-saved");
    expect(saved).toHaveTextContent("2 suggestions were not confirmed and stay unmapped.");
    const put = fetchMock.mock.calls.find(
      ([u, init]) => u === PROFILES_URL && (init as RequestInit | undefined)?.method === "PUT");
    expect(JSON.parse(String((put?.[1] as RequestInit).body))).toEqual({
      mappings: [{ profile_id: "abc124", tenant_slug: "acme-corp", match_source: "manual" }],
      ignored: [],
    });
  });

  it("shows a stored name match as unconfirmed, sends it back unchanged, and confirms it on its row", async () => {
    const stored = {
      ...PROFILES,
      profiles: [
        profile({ profile_id: "def456", name: "Example Bakery", tenant_slug: "example-bakery",
                  tenant_name: "Example Bakery", tenant_status: "active", match_source: "auto-name",
                  state: "active", queries_24h: 10 }),
      ],
    };
    const bodies: unknown[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/v1/admin/clients") {
        return jsonResponse(200, { clients: [{ slug: "example-bakery", display_name: "Example Bakery", status: "active" }] });
      }
      if (url === PROFILES_URL && init?.method === "PUT") {
        bodies.push(JSON.parse(String(init.body)));
        return jsonResponse(200, stored);
      }
      if (url === PROFILES_URL) return jsonResponse(200, stored);
      return jsonResponse(404, {});
    }));
    render(<NextDnsProfilePanel instanceId={12} onDone={() => undefined} />);
    expect(await screen.findByTestId("nextdns-unconfirmed-def456")).toHaveTextContent("unconfirmed name match");
    expect(screen.getByTestId("nextdns-tally")).toHaveTextContent("1 unconfirmed name match");
    fireEvent.click(screen.getByTestId("nextdns-save"));
    await screen.findByTestId("nextdns-saved");
    expect(bodies[0]).toEqual({
      mappings: [{ profile_id: "def456", tenant_slug: "example-bakery", match_source: "auto-name" }],
      ignored: [],
    });
    fireEvent.click(screen.getByTestId("nextdns-confirm-def456"));
    expect(screen.queryByTestId("nextdns-unconfirmed-def456")).toBeNull();
    fireEvent.click(screen.getByTestId("nextdns-save"));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({
      mappings: [{ profile_id: "def456", tenant_slug: "example-bakery", match_source: "manual" }],
      ignored: [],
    });
  });

  it("lists the profiles with ONE discovery call when none are known yet", async () => {
    const fetchMock = stubBackend({ ...BASE }, { discovered: false });
    render(<NextDnsProfilePanel instanceId={12} onDone={() => undefined} />);
    await screen.findByTestId("nextdns-profile-abc123");
    const discovery = fetchMock.mock.calls.filter(([u]) => String(u).startsWith(TENANTS_URL));
    expect(discovery).toHaveLength(1);
    expect((discovery[0]?.[1] as RequestInit).method).toBe("POST");
  });
});

describe("NextDNS in source health", () => {
  const row: SourceHealthRow = {
    id: "adapter:12", kind: "adapter", name: "NextDNS", vendor: "nextdns", tenant_slug: null,
    status: "degraded", stale: false, detail: "Throttled by the vendor (rate limit) — calls wait 30 s; not a failure, nothing is lost.",
    freshness_basis: "contact", stale_after_sec: 1260, last_event_at: null,
    last_event_age_sec: null, last_contact_at: null, last_contact_age_sec: 40,
    throttled: true,
    protection: {
      active: 1, pending: 1, lapsed: 1,
      profiles: [
        { profile_id: "abc123", name: "Acme Corp Office", tenant_slug: "acme-corp",
          state: "lapsed", since: "2026-09-30T15:00:00.000Z", queries_24h: 0 },
        { profile_id: "abc124", name: "Acme Corp Warehouse", tenant_slug: "acme-corp",
          state: "active", since: null, queries_24h: 900 },
      ],
    },
  };

  it("tags the card THROTTLED and lists the site that stopped reporting", () => {
    const card = toRotatable(row);
    expect(card.tags).toEqual(["INTEGRATION", "THROTTLED"]);
    const protection = card.services.find((s) => s.id === "protection");
    expect(protection?.detail).toBe("1 active · 1 pending rollout · 1 stopped reporting");
    const lapsed = card.services.find((s) => s.id === "lapsed-abc123");
    expect(lapsed?.name).toBe("Acme Corp Office");
    expect(lapsed?.status).toBe("degraded");
    expect(card.services.find((s) => s.id === "lapsed-abc124")).toBeUndefined();
  });
});

describe("NextDNS fix round (2026-09-30)", () => {
  it("Reload list keeps unsaved choices and re-reads the client list", async () => {
    const fetchMock = stubBackend({ ...BASE });
    render(<NextDnsProfilePanel instanceId={12} onDone={() => undefined} />);
    await screen.findByTestId("nextdns-profile-abc123");
    fireEvent.click(screen.getByTestId("nextdns-accept-all"));
    fireEvent.change(screen.getByTestId("nextdns-choice-tst001"), { target: { value: "__ignore__" } });
    const tally = "1 mapped · 1 ignored · 2 need a decision · 2 awaiting your confirmation";
    expect(screen.getByTestId("nextdns-tally")).toHaveTextContent(tally);
    const clientsBefore = fetchMock.mock.calls.filter(([u]) => u === "/api/v1/admin/clients").length;
    fireEvent.click(screen.getByTestId("nextdns-reload"));
    await waitFor(() =>
      expect(fetchMock.mock.calls.filter(([u]) => u === "/api/v1/admin/clients").length).toBe(clientsBefore + 1));
    await waitFor(() => expect(screen.getByTestId("nextdns-reload")).toHaveTextContent("Reload list"));
    expect(screen.getByTestId("nextdns-tally")).toHaveTextContent(tally);
    expect(screen.getByTestId("nextdns-pending-abc123")).toBeInTheDocument();
    expect(screen.getByTestId("nextdns-profile-panel")).toHaveTextContent(/create it in Settings → Tenants first/);
  });

  it("asks before discarding unsaved choices, and says Close after a save", async () => {
    stubBackend({ ...BASE });
    const done = vi.fn();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<NextDnsProfilePanel instanceId={12} onDone={done} />);
    await screen.findByTestId("nextdns-profile-abc123");
    expect(screen.getByTestId("nextdns-dismiss")).toHaveTextContent("Skip for now");
    fireEvent.click(screen.getByTestId("nextdns-suggest-abc123"));
    fireEvent.click(screen.getByTestId("nextdns-dismiss"));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(done).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId("nextdns-save"));
    await screen.findByTestId("nextdns-saved");
    expect(screen.getByTestId("nextdns-saved")).toHaveTextContent(/first pass takes a few minutes/);
    expect(screen.getByTestId("nextdns-dismiss")).toHaveTextContent("Close");
    fireEvent.click(screen.getByTestId("nextdns-dismiss"));
    expect(done).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it("the drawer's ✕ asks too while the panel has unsaved choices", async () => {
    stubBackend({ ...BASE, profiles: SUMMARY });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-nextdns")));
    fireEvent.click(within(card.getByTestId("integration-profiles-unmapped-nextdns")).getByRole("button"));
    const drawer = await screen.findByTestId("tenant-mapping-drawer");
    await within(drawer).findByTestId("nextdns-profile-abc123");
    fireEvent.click(within(drawer).getByTestId("nextdns-suggest-abc123"));
    fireEvent.click(within(drawer).getByText("✕"));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("tenant-mapping-drawer")).toBeInTheDocument();
    confirm.mockReturnValue(true);
    fireEvent.click(within(drawer).getByText("✕"));
    await waitFor(() => expect(screen.queryByTestId("tenant-mapping-drawer")).toBeNull());
  });

  it("never bulk-accepts a personal / test-looking suggestion; shows missing and problems", async () => {
    const withExtras = {
      ...PROFILES,
      profiles: [
        ...PROFILES.profiles,
        profile({ profile_id: "abc125", name: "Acme Corp Home",
                  suggestion: { tenant_slug: "acme-corp", tenant_name: "Acme Corp", rule: "name-prefix", bulk: false } }),
        profile({ profile_id: "abc126", name: "Acme Corp Annex", tenant_slug: "acme-corp",
                  tenant_name: "Acme Corp", tenant_status: "active", match_source: "manual",
                  state: "lapsed", queries_24h: 0, missing: true,
                  problem: "NextDNS does not show this profile to the API key any more (HTTP 404)." }),
      ],
    };
    const fetchMock = vi.fn(async (url: string) => {
      if (url === "/api/v1/admin/clients") {
        return jsonResponse(200, { clients: [{ slug: "acme-corp", display_name: "Acme Corp", status: "active" }] });
      }
      if (url === PROFILES_URL) return jsonResponse(200, withExtras);
      return jsonResponse(404, {});
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<NextDnsProfilePanel instanceId={12} onDone={() => undefined} />);
    await screen.findByTestId("nextdns-profile-abc125");
    expect(screen.getByTestId("nextdns-accept-all")).toHaveTextContent("Review 2 suggestions");
    fireEvent.click(screen.getByTestId("nextdns-accept-all"));
    expect((screen.getByTestId("nextdns-choice-abc125") as HTMLSelectElement).value).toBe("");
    expect(screen.getByTestId("nextdns-suggest-abc125")).toBeInTheDocument();   // still on its row
    expect(screen.getByTestId("nextdns-missing-abc126")).toHaveTextContent("not visible to the API key");
    expect(screen.getByTestId("nextdns-problem-abc126")).toHaveTextContent(/HTTP 404/);
  });

  it("the card says what needs a look — and that a first pass takes minutes", async () => {
    stubBackend({ ...BASE, profiles: { ...SUMMARY, missing: 1, problems: 2, rollup_lag_hours: 3,
                                       analytics_gaps: 1 } });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-nextdns")));
    expect(card.getByTestId("integration-protection-nextdns")).toHaveTextContent(/1 not visible to the key/);
    expect(card.getByTestId("integration-profile-problems-nextdns")).toHaveTextContent(/2 profiles need a look/);
    expect(card.getByTestId("integration-rollup-lag-nextdns")).toHaveTextContent(/3 h behind/);
    expect(card.getByTestId("integration-analytics-gap-nextdns")).toHaveTextContent(/NextDNS-side gap/);
    expect(card.queryByTestId("integration-first-pass-nextdns")).toBeNull();
  });

  it("the card names a fleet-wide outage, and where its ONE alert is", async () => {
    stubBackend({ ...BASE, profiles: { ...SUMMARY, lapsed: 30, fleet_outage_sites: 30,
                                       fleet_outage_watched: 40, fleet_outage_tenant: "msp-ops",
                                       analytics_gaps: 2 } });
    render(<IntegrationsTab me={me()} />);
    const line = await screen.findByTestId("integration-fleet-outage-nextdns");
    expect(line).toHaveTextContent("30 of 40 sites stopped reporting at the same time");
    expect(line).toHaveTextContent("check NextDNS status and the UniFi DNS template");
    expect(line).toHaveTextContent("The alert is in msp-ops.");
    expect(screen.getByTestId("integration-analytics-gap-nextdns")).toHaveTextContent(
      "at most 2 hours in a row");
  });

  it("the card explains the first pass while every mapped profile is being checked", async () => {
    stubBackend({ ...BASE, profiles: { ...SUMMARY, mapped: 5, active: 0, pending: 0, lapsed: 0, checking: 5 } });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-nextdns")));
    expect(card.getByTestId("integration-first-pass-nextdns")).toHaveTextContent(/takes a few minutes/);
  });

  it("source health lists a profile the key no longer sees, and one with a problem", () => {
    const card = toRotatable({
      id: "adapter:12", kind: "adapter", name: "NextDNS", vendor: "nextdns", tenant_slug: null,
      status: "degraded", stale: false, detail: null, freshness_basis: "contact",
      stale_after_sec: 1260, last_event_at: null, last_event_age_sec: null,
      last_contact_at: null, last_contact_age_sec: 40,
      protection: {
        active: 1, pending: 0, lapsed: 1, missing: 1, problems: 1,
        profiles: [
          { profile_id: "abc126", name: "Acme Corp Annex", tenant_slug: "acme-corp", state: "lapsed",
            since: null, queries_24h: 0, missing: true, problem: "HTTP 404" },
          { profile_id: "def456", name: "Example Bakery", tenant_slug: "example-bakery", state: "active",
            since: null, queries_24h: 900, missing: false,
            problem: "The tenant's telemetry store could not be written" },
        ],
      },
    });
    expect(card.services.find((s) => s.id === "protection")?.detail).toBe(
      "1 active · 0 pending rollout · 1 stopped reporting · 1 not visible to the key · 1 need a look");
    expect(card.services.find((s) => s.id === "missing-abc126")?.detail).toBe(
      "not visible to the API key any more · acme-corp");
    const problem = card.services.find((s) => s.id === "problem-def456");
    expect(problem?.status).toBe("degraded");
    expect(problem?.detail).toMatch(/telemetry store/);
  });
});
