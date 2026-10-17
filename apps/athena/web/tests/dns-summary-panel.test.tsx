/**
 * DnsSummaryPanel — every state says what it is, and nothing but masked
 * domains and counts is ever rendered (the server never sends more).
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";

import DnsSummaryPanel from "@/components/dns-summary-panel";
import type { DnsSummaryResponse } from "@/contracts/dns-summary";

afterEach(cleanup);

const NOW = new Date("2026-09-29T12:00:00.000Z");

const READY: DnsSummaryResponse = {
  window_hours: 24,
  masked: true,
  unreadable_tenants: 0,
  empty_reason: null,
  empty_detail: null,
  totals: { lookups: 1300, blocked: 12, first_seen: 3 },
  tenants: [
    {
      tenant: "acme-corp",
      lookups: 1200,
      by_type: { "pihole.query": 1200, "suricata.dns": 1100 },
      blocked: 12,
      top_domains: [
        { masked_domain: "wi*****.com", lookups: 400, pihole: 400, suricata: 380, devices: 9 },
        { masked_domain: "ed*****.com", lookups: 120, pihole: 120, suricata: 90, devices: 1 },
      ],
      first_seen: [
        { masked_domain: "ne*****.test", first_seen: "2026-09-29T11:30:00.000Z",
          first_event_type: "pihole.query" },
      ],
      first_seen_count: 3,
      baseline_since: "2026-08-01T00:00:00.000Z",
      baseline_building: false,
    },
    {
      tenant: "globex",
      lookups: 100,
      by_type: { "pihole.query": 100 },
      blocked: 0,
      top_domains: [],
      first_seen: [],
      first_seen_count: 0,
      baseline_since: "2026-09-28T00:00:00.000Z",
      baseline_building: true,
    },
  ],
};

describe("DnsSummaryPanel", () => {
  it("renders loading, forbidden and error states", () => {
    const { rerender } = render(<DnsSummaryPanel state={{ status: "loading" }} />);
    expect(screen.getByText(/Loading DNS summary/)).toBeInTheDocument();
    rerender(<DnsSummaryPanel state={{ status: "forbidden" }} />);
    expect(screen.getByText(/available to analysts and above/)).toBeInTheDocument();
    rerender(<DnsSummaryPanel state={{ status: "error" }} />);
    expect(screen.getByText(/Couldn't load the DNS summary/)).toBeInTheDocument();
  });

  it("shows the server's empty reason", () => {
    render(
      <DnsSummaryPanel
        state={{
          status: "ready",
          data: {
            ...READY, tenants: [], totals: { lookups: 0, blocked: 0, first_seen: 0 },
            empty_reason: "no_telemetry",
            empty_detail: "No DNS telemetry yet. It comes from buoys.",
          },
        }}
      />,
    );
    expect(screen.getByText("No DNS telemetry yet. It comes from buoys.")).toBeInTheDocument();
  });

  it("renders masked domains, counts, first-seen and the baseline note", () => {
    render(<DnsSummaryPanel state={{ status: "ready", data: READY }} now={NOW} />);
    expect(screen.getByText(/1,300 lookups · 12 blocked · 3 first-seen · last 24h/)).toBeInTheDocument();
    const acme = screen.getByTestId("dns-tenant-acme-corp");
    expect(within(acme).getByText("wi*****.com")).toBeInTheDocument();
    expect(within(acme).getByText("400 · 9 devices")).toBeInTheDocument();
    expect(within(acme).getByText("120 · 1 device")).toBeInTheDocument();
    expect(within(acme).getByText(/3 first-seen domains/)).toBeInTheDocument();
    expect(within(acme).getByText(/ne\*\*\*\*\*\.test \(30m ago\)/)).toBeInTheDocument();
    expect(within(acme).queryByText(/Baseline still building/)).toBeNull();
    const globex = screen.getByTestId("dns-tenant-globex");
    expect(within(globex).getByText(/Baseline still building/)).toBeInTheDocument();
    expect(within(globex).getByText(/0 first-seen domains/)).toBeInTheDocument();
    expect(screen.getByText(/Domains are masked here/)).toBeInTheDocument();
  });

  it("says when the list is partial", () => {
    render(
      <DnsSummaryPanel state={{ status: "ready", data: { ...READY, unreadable_tenants: 2 } }} />,
    );
    expect(screen.getByTestId("dns-summary-partial")).toHaveTextContent(
      "2 tenants' telemetry couldn't be read",
    );
  });
});

describe("DnsSummaryPanel — sensor and store fault", () => {
  it("names the sensor that counted the lookups", () => {
    const acme = { ...READY.tenants[0], lookups_source: "pihole" as const };
    const glob = { ...READY.tenants[1], lookups_source: "suricata" as const };
    render(
      <DnsSummaryPanel state={{ status: "ready", data: { ...READY, tenants: [acme, glob] } }} now={NOW} />,
    );
    expect(within(screen.getByTestId("dns-tenant-acme-corp")).getByText(/1,200 lookups \(Pi-hole\) · 12 blocked/)).toBeInTheDocument();
    expect(within(screen.getByTestId("dns-tenant-globex")).getByText(/100 lookups \(Suricata queries\) · 0 blocked/)).toBeInTheDocument();
  });

  it("warns when answered lookups were stored with the events instead", () => {
    const acme = { ...READY.tenants[0], fallback_rows: 37, recent_store_fallbacks: 5,
                   store_fallback_window_hours: 24 };
    render(
      <DnsSummaryPanel state={{ status: "ready", data: { ...READY, tenants: [acme] } }} now={NOW} />,
    );
    expect(screen.getByTestId("dns-fallback-acme-corp")).toHaveTextContent(
      "Telemetry store fault: 37 answered lookups stored with the events instead",
    );
    expect(screen.getByTestId("dns-fallback-acme-corp")).toHaveTextContent(
      "5 refused in the last 24 h",
    );
    expect(screen.queryByTestId("dns-fallback-globex")).toBeNull();
  });

  it("says pre-upgrade lookups await the one-off move — neutrally, not as a fault", () => {
    const acme = { ...READY.tenants[0], fallback_rows: 0, recent_store_fallbacks: 0,
                   awaiting_move_rows: 40 };
    render(
      <DnsSummaryPanel state={{ status: "ready", data: { ...READY, tenants: [acme] } }} now={NOW} />,
    );
    expect(screen.queryByTestId("dns-fallback-acme-corp")).toBeNull();
    expect(screen.queryByText(/Telemetry store fault/)).toBeNull();
    expect(screen.getByTestId("dns-awaiting-move-acme-corp")).toHaveTextContent(
      "40 answered lookups from before the upgrade still in the events store (not counted above) — run the one-off move_telemetry_out_of_events.py.",
    );
  });

  it("says plainly that the DNS search is API-only", () => {
    render(<DnsSummaryPanel state={{ status: "ready", data: READY }} now={NOW} />);
    expect(screen.getByText(/have no page\s+yet: the API POST \/api\/v1\/search\/dns/)).toBeInTheDocument();
  });

  it("is quiet once the fault is older than the window", () => {
    // The server counts refused writes over the last 24 h only; with none
    // recent and no stuck rows there is no warning.
    const acme = { ...READY.tenants[0], fallback_rows: 0, recent_store_fallbacks: 0 };
    render(
      <DnsSummaryPanel state={{ status: "ready", data: { ...READY, tenants: [acme] } }} now={NOW} />,
    );
    expect(screen.queryByTestId("dns-fallback-acme-corp")).toBeNull();
  });
});
