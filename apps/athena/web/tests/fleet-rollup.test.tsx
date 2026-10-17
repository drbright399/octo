/**
 * Tests for components/fleet-rollup.tsx.
 *
 * Covers the computeRollup math (the tone selection is the load-bearing
 * part — operators read the chip color to triage) plus a couple of
 * render assertions to confirm the labels + ratios surface correctly.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

import FleetRollup, { __test__ } from "@/components/fleet-rollup";
import type { BuoyFleetRow, ServiceInfo } from "@/lib/buoy";


afterEach(cleanup);


const svc = (state: string): ServiceInfo => ({
  state, version: null, stat: null, last_activity: null,
});

const buoyBase: BuoyFleetRow = {
  slug: "alpha", hostname: "buoy-alpha",
  last_heartbeat_at: "2026-05-19T19:00:00Z",
  staleness_sec: 5, health: "green",
  uptime_sec: 1000, interval_sec: 60, boot_time: null,
  load_1: null, load_5: null, load_15: null,
  mem_used_mb: null, mem_total_mb: null, disk_used_pct: null,
  services: {},
  last_event_at: null,
};


describe("computeRollup", () => {
  it("does not count a unit an operator retired (v0.11 B1) — grey, not N-1/N", () => {
    const off: ServiceInfo = { ...svc("inactive"), enabled: "disabled" };
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { opencanary: svc("active") } },
      { ...buoyBase, slug: "b", services: { opencanary: off },
        retired_services: ["opencanary"] },
      // Disabled on the buoy but NOT retired by the operator: still a fault.
      { ...buoyBase, slug: "c", services: { "wazuh-agent": off }, retired_services: [] },
      { ...buoyBase, slug: "d", services: { "wazuh-agent": svc("active") } },
    ];
    const cells = __test__.computeRollup(fleet);
    const canary = cells.find((c) => c.unit === "opencanary")!;
    expect([canary.active, canary.total, canary.tone]).toEqual([1, 1, "success"]);
    const wazuh = cells.find((c) => c.unit === "wazuh-agent")!;
    expect([wazuh.active, wazuh.total, wazuh.tone]).toEqual([1, 2, "warning"]);
  });

  it("without the server's list, only the default retired unit is retired", () => {
    const off: ServiceInfo = { ...svc("inactive"), enabled: "disabled" };
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { "buoy-forwarder": svc("active"),
                                            suricata: off } },
    ];
    const cells = __test__.computeRollup(fleet);
    const suricata = cells.find((c) => c.unit === "suricata")!;
    expect([suricata.active, suricata.total]).toEqual([0, 1]);
  });

  it("returns the six ROLLUP_SPECS in order", () => {
    const cells = __test__.computeRollup([]);
    expect(cells.map((c) => c.unit)).toEqual([
      "wazuh-agent", "suricata", "pihole-FTL",
      "opencanary", "buoy-forwarder", "tailscaled",
    ]);
  });

  it("counts active vs total per service across the fleet", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: {
        "wazuh-agent": svc("active"), "suricata": svc("active"),
      }},
      { ...buoyBase, slug: "b", services: {
        "wazuh-agent": svc("failed"), "suricata": svc("active"),
      }},
      { ...buoyBase, slug: "c", services: {
        "wazuh-agent": svc("active"), "suricata": svc("active"),
      }},
    ];
    const cells = __test__.computeRollup(fleet);
    const wazuh = cells.find((c) => c.unit === "wazuh-agent")!;
    expect(wazuh.total).toBe(3);
    expect(wazuh.active).toBe(2);
    expect(wazuh.failed).toBe(1);
    expect(wazuh.tone).toBe("critical");

    const sur = cells.find((c) => c.unit === "suricata")!;
    expect(sur.total).toBe(3);
    expect(sur.active).toBe(3);
    expect(sur.tone).toBe("success");
  });

  it("excludes 'missing' buoys from the denominator (legitimate omission)", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { "wazuh-agent": svc("active") }},
      { ...buoyBase, slug: "b", services: { "wazuh-agent": svc("missing") }},
      { ...buoyBase, slug: "c", services: {} },  // no wazuh-agent key at all
    ];
    const cells = __test__.computeRollup(fleet);
    const wazuh = cells.find((c) => c.unit === "wazuh-agent")!;
    // Only buoy "a" counts — b is missing, c didn't report.
    expect(wazuh.total).toBe(1);
    expect(wazuh.active).toBe(1);
    expect(wazuh.tone).toBe("success");
  });

  it("returns dim tone when no buoy bundles the service", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { "wazuh-agent": svc("active") }},
    ];
    const cells = __test__.computeRollup(fleet);
    // Suricata not in any buoy → dim (not "fleet-wide red")
    const sur = cells.find((c) => c.unit === "suricata")!;
    expect(sur.total).toBe(0);
    expect(sur.tone).toBe("dim");
  });

  it("warning tone when degraded is present without failures", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { "wazuh-agent": svc("active") }},
      { ...buoyBase, slug: "b", services: { "wazuh-agent": svc("degraded") }},
    ];
    const cells = __test__.computeRollup(fleet);
    const wazuh = cells.find((c) => c.unit === "wazuh-agent")!;
    expect(wazuh.degraded).toBe(1);
    expect(wazuh.failed).toBe(0);
    expect(wazuh.tone).toBe("warning");
  });

  it("excludes stale + red buoys from service counts (staleness-aware)", () => {
    // Same wazuh-agent state on three buoys, but only one is fresh.
    // Stale + red buoys' service states are last-known-good, possibly
    // minutes old — counting them as "active" would lie about reality.
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", health: "green",
        services: { "wazuh-agent": svc("active") }},
      { ...buoyBase, slug: "b", health: "stale",
        services: { "wazuh-agent": svc("active") }},
      { ...buoyBase, slug: "c", health: "red",
        services: { "wazuh-agent": svc("active") }},
    ];
    const cells = __test__.computeRollup(fleet);
    const wazuh = cells.find((c) => c.unit === "wazuh-agent")!;
    // Only buoy "a" counts — b is stale, c is red.
    expect(wazuh.total).toBe(1);
    expect(wazuh.active).toBe(1);
    expect(wazuh.tone).toBe("success");
  });
});


describe("computeTierCounts", () => {
  it("groups buoys by health tier", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "g1", health: "green" },
      { ...buoyBase, slug: "g2", health: "green" },
      { ...buoyBase, slug: "y",  health: "yellow" },
      { ...buoyBase, slug: "s",  health: "stale" },
      { ...buoyBase, slug: "r",  health: "red" },
      { ...buoyBase, slug: "u",  health: "unknown" },
    ];
    const tiers = __test__.computeTierCounts(fleet);
    expect(tiers).toEqual({
      green: 2, yellow: 1, stale: 1, red: 1, unknown: 1, total: 6,
    });
  });

  it("returns all-zero with total=0 on an empty fleet", () => {
    const tiers = __test__.computeTierCounts([]);
    expect(tiers.total).toBe(0);
    expect(tiers.green).toBe(0);
  });
});


describe("FleetRollup render", () => {
  it("renders the section title + buoy count", () => {
    render(<FleetRollup buoys={[buoyBase]} />);
    expect(screen.getByText(/fleet-wide health/i)).toBeTruthy();
    expect(screen.getByText(/across 1 buoy$/i)).toBeTruthy();
  });

  it("renders the ratio for a service active across the fleet", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { "wazuh-agent": svc("active") }},
      { ...buoyBase, slug: "b", services: { "wazuh-agent": svc("active") }},
    ];
    render(<FleetRollup buoys={fleet} />);
    expect(screen.getByText("2/2")).toBeTruthy();
  });

  it("shows failed + degraded breakdown when present", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { "wazuh-agent": svc("failed") }},
      { ...buoyBase, slug: "b", services: { "wazuh-agent": svc("degraded") }},
    ];
    render(<FleetRollup buoys={fleet} />);
    expect(screen.getByText(/1 failed/i)).toBeTruthy();
    expect(screen.getByText(/1 degraded/i)).toBeTruthy();
  });

  it("renders '—' for services no buoy bundles", () => {
    const fleet: BuoyFleetRow[] = [
      { ...buoyBase, slug: "a", services: { "wazuh-agent": svc("active") }},
    ];
    render(<FleetRollup buoys={fleet} />);
    // Six chips: one shows 1/1 for wazuh, five show — for the others.
    const dashes = screen.getAllByText("—");
    expect(dashes.length).toBe(5);
  });
});
