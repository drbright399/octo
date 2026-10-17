/**
 * Tests for components/buoy-drawer.tsx — the per-buoy Management drawer
 * refactored per the 2026-05-19 Fleet redesign hand-off.
 *
 * Coverage focus:
 *   - Tab strip uses the new names (management / notes / log preview)
 *   - Management tab is the default
 *   - Step-up banner reflects fetched /search/status (active vs required)
 *   - Service grid renders one card per buoy.services entry + empty state
 *   - Terminal lock overlay is visible when step-up is inactive
 *   - STEP_UP_REQUIRED_KINDS matches the role-tier memo
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";

import BuoyDrawer, { STEP_UP_REQUIRED_KINDS } from "@/components/buoy-drawer";
import type { BuoyFleetRow } from "@/lib/buoy";


const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });


const GREEN_BUOY: BuoyFleetRow = {
  slug: "alpha",
  hostname: "buoy-alpha",
  last_heartbeat_at: "2026-05-19T19:00:00.000Z",
  staleness_sec: 5,
  health: "green",
  uptime_sec: 86400 * 7,           // 7d
  interval_sec: 60,
  boot_time: "2026-05-12T19:00:00.000Z",
  load_1: 0.1, load_5: 0.2, load_15: 0.3,
  mem_used_mb: 1200, mem_total_mb: 4096,
  disk_used_pct: 34,
  services: {
    "tailscaled":     { state: "active", version: "1.86.2", stat: null, last_activity: null },
    "wazuh-agent":    { state: "active", version: "4.9.2",  stat: null, last_activity: null },
    "buoy-forwarder": { state: "active", version: null,     stat: null, last_activity: null },
  },
  last_event_at: "2026-05-19T18:59:50.000Z",
};

const RED_BUOY: BuoyFleetRow = { ...GREEN_BUOY, slug: "bravo", health: "red", hostname: "buoy-bravo" };

const EMPTY_SERVICES_BUOY: BuoyFleetRow = { ...GREEN_BUOY, slug: "fresh", services: {} };


/** Mock fetch with deterministic responses for the endpoints the drawer
 * touches: /search/status (step-up state) + /buoy/{slug}/commands (history). */
function mockFetch(stepUpElevated: boolean): void {
  global.fetch = vi.fn(async (input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    if (url.includes("/api/v1/search/status")) {
      return ok({ elevated: stepUpElevated, expires_at: null });
    }
    if (url.includes("/api/v1/buoy/") && url.includes("/commands")) {
      return ok({ commands: [] });
    }
    return new Response("not mocked: " + url, { status: 500 });
  }) as typeof fetch;
}

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => {
  global.fetch = originalFetch;
  cleanup();
  vi.restoreAllMocks();
});


// ---------------------------------------------------------------------------
// Static — the role-tier matrix shouldn't drift
// ---------------------------------------------------------------------------

describe("STEP_UP_REQUIRED_KINDS export", () => {
  it("requires step-up for exactly the three mutating command kinds", () => {
    expect(STEP_UP_REQUIRED_KINDS.has("restart-service")).toBe(true);
    expect(STEP_UP_REQUIRED_KINDS.has("reboot")).toBe(true);
    expect(STEP_UP_REQUIRED_KINDS.has("update")).toBe(true);
    expect(STEP_UP_REQUIRED_KINDS.has("ping")).toBe(false);
    expect(STEP_UP_REQUIRED_KINDS.has("refresh")).toBe(false);
    expect(STEP_UP_REQUIRED_KINDS.has("tail-log")).toBe(false);
    expect(STEP_UP_REQUIRED_KINDS.size).toBe(3);
  });
});


// ---------------------------------------------------------------------------
// Tab strip
// ---------------------------------------------------------------------------

describe("BuoyDrawer tab strip", () => {
  it("renames the slice-8 Commands tab to Management as the default", async () => {
    mockFetch(false);
    render(
      <BuoyDrawer
        buoy={GREEN_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    // All three tabs render
    expect(screen.getByRole("button", { name: /management/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^notes$/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /log preview/i })).toBeTruthy();

    // Management is selected by default — quick actions header is visible
    await waitFor(() => {
      expect(screen.getByText(/quick actions/i)).toBeTruthy();
    });
  });
});


// ---------------------------------------------------------------------------
// Step-up banner — reflects fetched state
// ---------------------------------------------------------------------------

describe("StepUpBanner state", () => {
  it("shows 'step-up required' when /search/status returns elevated=false", async () => {
    mockFetch(false);
    render(
      <BuoyDrawer
        buoy={GREEN_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    // The phrase appears in both the banner + the quick-actions hint —
    // assert at least one element renders it.
    await waitFor(() => {
      expect(screen.getAllByText(/step-up required/i).length).toBeGreaterThan(0);
    });
    // And specifically NOT the active banner.
    expect(screen.queryByText(/step-up active/i)).toBeNull();
  });

  it("shows 'step-up active' when /search/status returns elevated=true", async () => {
    mockFetch(true);
    render(
      <BuoyDrawer
        buoy={GREEN_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    await waitFor(() => {
      expect(screen.getAllByText(/step-up active/i).length).toBeGreaterThan(0);
    });
  });
});


// ---------------------------------------------------------------------------
// Service grid — content + empty state
// ---------------------------------------------------------------------------

describe("ServiceGrid", () => {
  it("renders one card per service entry from buoy.services", async () => {
    mockFetch(true);
    render(
      <BuoyDrawer
        buoy={GREEN_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    // Drawer mounts via createPortal → content is in document.body, not in
    // render()'s container — query `screen` (which searches document.body).
    await waitFor(() => {
      expect(screen.getByText("tailscaled")).toBeTruthy();
      expect(screen.getByText("wazuh-agent")).toBeTruthy();
      expect(screen.getByText("buoy-forwarder")).toBeTruthy();
    });
  });

  it("renders the empty state when buoy.services is {}", async () => {
    mockFetch(true);
    render(
      <BuoyDrawer
        buoy={EMPTY_SERVICES_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    await waitFor(() => {
      expect(screen.getByText(/no service status reported yet/i)).toBeTruthy();
    });
  });

  it("labels role correctly for known units (mesh / EDR / relay / etc.)", async () => {
    mockFetch(true);
    render(
      <BuoyDrawer
        buoy={GREEN_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    // The role chip text lives in the service grid (portal'd to document.body).
    // SERVICE_ROLE: tailscaled → "mesh", wazuh-agent → "EDR", buoy-forwarder → "relay".
    await waitFor(() => {
      expect(screen.getByText("mesh")).toBeTruthy();
      expect(screen.getByText("EDR")).toBeTruthy();
      expect(screen.getByText("relay")).toBeTruthy();
    });
  });
});


// ---------------------------------------------------------------------------
// Terminal — lock overlay
// ---------------------------------------------------------------------------

describe("BuoyTerminal lock overlay", () => {
  it("renders the lock CTA when step-up is inactive", async () => {
    mockFetch(false);
    render(
      <BuoyDrawer
        buoy={GREEN_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    await waitFor(() => {
      expect(screen.getByText(/shell is gated behind step-up auth/i)).toBeTruthy();
    });
  });

  it("removes the lock CTA when step-up is active", async () => {
    mockFetch(true);
    render(
      <BuoyDrawer
        buoy={GREEN_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    await waitFor(() => {
      // The "step-up active" banner is showing.
      expect(screen.getByText(/step-up active/i)).toBeTruthy();
    });
    expect(screen.queryByText(/shell is gated behind step-up auth/i)).toBeNull();
  });

  it("shows 'unreachable' status for red buoys + skips the lock overlay", async () => {
    mockFetch(false);
    render(
      <BuoyDrawer
        buoy={RED_BUOY}
        callerRole="super_admin"
        onClose={vi.fn()}
        onStepUpRequired={vi.fn()}
      />,
    );
    await waitFor(() => {
      // The unreachable status pill appears (rendered uppercase in the terminal header).
      expect(screen.getAllByText(/unreachable/i).length).toBeGreaterThan(0);
    });
    // The lock CTA is suppressed when buoy is unreachable (different banner takes precedence).
    expect(screen.queryByText(/shell is gated behind step-up auth/i)).toBeNull();
  });
});
