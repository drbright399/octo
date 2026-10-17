/**
 * DashboardPage widget wiring — the `widgets` memo must list every state a
 * widget reads, or the widget freezes at whatever it showed when the list
 * last changed. It used to list only throughput state, so a widget refreshed
 * only when throughput did. Here throughput NEVER settles: every widget that
 * still shows its data got there through its own state.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

import DashboardPage from "@/pages/dashboard";
import type { TiPulseResponse } from "@/contracts/indicator";
import type { SourceHealthResponse } from "@/lib/source-health";

const json = (body: unknown, status = 200): Promise<Response> =>
  Promise.resolve(new Response(JSON.stringify(body), { status }));

const PULSE: TiPulseResponse = {
  items: [{
    tenant: "acme-corp",
    type: "ip",
    masked_value: "203.0.x.x",
    severity: "high",
    first_seen: "2026-09-28T10:00:00.000Z",
    last_seen: "2026-09-28T11:56:00.000Z",
    count: 2,
    source_kind: "integration",
    search_ref: "acme-corp:42",
  }],
  pool_status: "not_running",
  empty_reason: null,
  empty_detail: null,
  unreadable_tenants: 0,
  lookback_days: 7,
};

const SOURCES_FULL: SourceHealthResponse = {
  view: "full",
  generated_at: "2026-09-28T12:00:00.000Z",
  sources: [{
    id: "adapter:1", kind: "adapter", name: "Datto RMM", vendor: "datto",
    tenant_slug: null, status: "ok", stale: false, detail: null,
    freshness_basis: "contact", stale_after_sec: 120,
    last_event_at: "2026-09-28T11:50:00.000Z", last_event_age_sec: 600,
    last_contact_at: "2026-09-28T11:59:40.000Z", last_contact_age_sec: 20,
  }],
  tenants: [],
};

let originalFetch: typeof fetch;
let pulseResponse: () => Promise<Response>;
let sourceHealthResponse: () => Promise<Response>;

beforeEach(() => {
  originalFetch = global.fetch;
  // jsdom has no canvas; the oscilloscopes already skip drawing on null.
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
  window.localStorage.clear();
  window.history.pushState({}, "", "/dashboard");
  pulseResponse = () => json(PULSE);
  sourceHealthResponse = () => json(SOURCES_FULL);
  global.fetch = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    // Throughput never answers: nothing throughput-related ever changes.
    if (url.startsWith("/api/v1/dashboard/throughput")) return new Promise<Response>(() => {});
    if (url.startsWith("/api/v1/dashboard/ti-pulse")) return pulseResponse();
    if (url.startsWith("/api/v1/dashboard/source-health")) return sourceHealthResponse();
    if (url.startsWith("/api/v1/dashboard/devices-attention")) {
      return json({
        items: [{
          tenant: "acme-corp", host: "srv-web-02", severity: "critical",
          reason: "1 critical event · auth.brute_force", event_count: 1,
          vendor_device_ref: null,
        }],
        scope_slugs: ["acme-corp"],
      });
    }
    // Everything else fails; every loader treats that as "no data".
    return json({ code: "NOT_FOUND" }, 404);
  }) as typeof fetch;
});

afterEach(() => {
  cleanup();
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("DashboardPage widgets", () => {
  it("re-render when a non-throughput state changes", async () => {
    render(<DashboardPage username="alice" />);
    // Both arrive after the first render, through their own state only.
    expect(await screen.findByText("203.0.x.x")).toBeInTheDocument();
    expect(await screen.findByText("srv-web-02")).toBeInTheDocument();
  });

  it("source health fills from its own state, not the widget memo", async () => {
    render(<DashboardPage username="alice" />);
    expect(await screen.findByLabelText("Show Datto RMM")).toBeInTheDocument();
    expect(screen.getByTestId("source-count-ok")).toHaveTextContent("1");
  });

  it("a viewer's source health is their own tenants' freshness only", async () => {
    pulseResponse = () => json({ code: "ISOLATION_VIOLATION" }, 403);
    sourceHealthResponse = () => json({
      view: "tenant",
      generated_at: "2026-09-28T12:00:00.000Z",
      sources: [],
      tenants: [{
        slug: "acme-corp", display_name: "Acme Corp",
        last_event_at: "2026-09-28T11:56:00.000Z", last_event_age_sec: 240,
        state: "ok",
      }],
    } satisfies SourceHealthResponse);
    render(<DashboardPage username="bob" />);
    const line = await screen.findByTestId("tenant-freshness-acme-corp");
    expect(line).toHaveTextContent("alerts last received 4m ago");
    expect(screen.queryByTestId("source-health-full")).toBeNull();
    expect(await screen.findByText(/available to analysts and above/i)).toBeInTheDocument();
  });

  it("names no vendor product in the pulse or traffic help a viewer can open", async () => {
    // Owner decision 2026-09-28 (b): a client user must not learn which
    // integrations the MSP runs — and the dashboard shows these widgets to
    // every role.
    pulseResponse = () => json({ code: "ISOLATION_VIOLATION" }, 403);
    render(<DashboardPage username="bob" />);
    await screen.findByText(/available to analysts and above/i);
    const vendors = /wazuh|unifi|datto|rocketcyber|suricata|pihole|opencanary/i;
    const helpText = async (label: string): Promise<string> => {
      const trigger = screen.getByRole("button", { name: label });
      fireEvent.focus(trigger);
      const text = (await screen.findByRole("tooltip")).textContent ?? "";
      fireEvent.blur(trigger);
      await waitFor(() => expect(screen.queryByRole("tooltip")).toBeNull());
      return text;
    };
    const pulse = await helpText("About: Threat-intel pulse");
    expect(pulse).toMatch(/not every integration/i);
    expect(pulse).not.toMatch(vendors);
    // The hero panel shows one tab's help at a time.
    fireEvent.click(screen.getByRole("tab", { name: /Traffic flow/ }));
    const traffic = await helpText("About: Traffic flow");
    expect(traffic).toMatch(/API-pull integrations/);
    expect(traffic).not.toMatch(vendors);
  });

  it("shows a viewer's 403 as not-for-your-role, not as an empty pulse", async () => {
    pulseResponse = () => json({ code: "ISOLATION_VIOLATION" }, 403);
    render(<DashboardPage username="bob" />);
    expect(await screen.findByText(/available to analysts and above/i)).toBeInTheDocument();
  });

  it("states why the pulse is empty, from the server", async () => {
    pulseResponse = () => json({
      ...PULSE,
      items: [],
      empty_reason: "no_indicators",
      empty_detail: "No indicators recorded yet — only Wazuh- and UniFi-sourced events carry one.",
    });
    render(<DashboardPage username="alice" />);
    expect(await screen.findByText(/only Wazuh- and UniFi-sourced events carry one/))
      .toBeInTheDocument();
  });

  it("opens a pulse row in the step-up-gated indicator search", async () => {
    render(<DashboardPage username="alice" />);
    fireEvent.click(await screen.findByRole("button", { name: /203\.0\.x\.x in acme-corp/i }));
    await waitFor(() => {
      expect(window.location.pathname).toBe("/search/indicators");
    });
    expect(new URLSearchParams(window.location.search).get("indicator")).toBe("acme-corp:42");
  });
});
