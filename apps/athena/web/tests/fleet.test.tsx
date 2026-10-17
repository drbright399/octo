import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";

import FleetPage from "@/pages/fleet";
import {
  fetchBuoyFleet,
  formatDuration,
  type BuoyFleetResponse,
} from "@/lib/buoy";
import { ApiError } from "@/lib/api";


const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });

let originalFetch: typeof fetch;
beforeEach(() => {
  originalFetch = global.fetch;
});
afterEach(() => {
  global.fetch = originalFetch;
  cleanup();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// fetchBuoyFleet — API client shape
// ---------------------------------------------------------------------------

describe("fetchBuoyFleet", () => {
  it("returns the parsed body on success", async () => {
    const fixture: BuoyFleetResponse = {
      buoys: [
        {
          slug: "alpha",
          hostname: "buoy-alpha",
          last_heartbeat_at: "2026-05-15T21:00:00.000Z",
          staleness_sec: 5,
          health: "green",
          uptime_sec: 1234567,
          interval_sec: 60,
          boot_time: "2026-05-01T00:00:00.000Z",
          load_1: 0.1, load_5: 0.2, load_15: 0.3,
          mem_used_mb: 1200, mem_total_mb: 4096,
          disk_used_pct: 34,
          services: {
            tailscaled:    { state: "active", version: "1.86.2", stat: null, last_activity: null },
            "wazuh-agent": { state: "active", version: "4.9.2",  stat: null, last_activity: null },
          },
          last_event_at: "2026-05-15T20:59:00.000Z",
        },
      ],
      scope_slugs: ["*"],
    };
    global.fetch = vi.fn().mockResolvedValueOnce(ok(fixture));
    const r = await fetchBuoyFleet();
    expect(r.buoys).toHaveLength(1);
    expect(r.buoys[0]!.slug).toBe("alpha");
    expect(r.buoys[0]!.health).toBe("green");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/dashboard/buoy-fleet",
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("throws ApiError on non-2xx", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "AUTH_SESSION_INVALID" }),
                   { status: 401 }),
    );
    await expect(fetchBuoyFleet()).rejects.toBeInstanceOf(ApiError);
  });
});


// ---------------------------------------------------------------------------
// formatDuration — uptime / staleness label
// ---------------------------------------------------------------------------

describe("formatDuration", () => {
  it("handles seconds", () => {
    expect(formatDuration(0)).toBe("0s");
    expect(formatDuration(45)).toBe("45s");
  });
  it("handles minutes", () => {
    expect(formatDuration(60)).toBe("1m");
    expect(formatDuration(125)).toBe("2m 5s");
  });
  it("handles hours", () => {
    expect(formatDuration(3600)).toBe("1h");
    expect(formatDuration(7280)).toBe("2h 1m");
  });
  it("handles days", () => {
    expect(formatDuration(86400)).toBe("1d");
    expect(formatDuration(86400 * 16 + 3600 * 18)).toBe("16d 18h");
  });
  it("rejects negative + NaN", () => {
    expect(formatDuration(-1)).toBe("—");
    expect(formatDuration(Number.NaN)).toBe("—");
  });
});


// ---------------------------------------------------------------------------
// FleetPage rendering
// ---------------------------------------------------------------------------

describe("FleetPage", () => {
  // Fleet v2 opens on the site-centric view; the buoy fleet these tests pin
  // is the "buoys" mode (unchanged), remembered per operator.
  beforeEach(() => {
    localStorage.setItem("athena.fleet.mode.v1", "buoys");
  });
  afterEach(() => {
    localStorage.removeItem("athena.fleet.mode.v1");
  });

  function fixture(rows: BuoyFleetResponse["buoys"]): BuoyFleetResponse {
    return { buoys: rows, scope_slugs: ["*"] };
  }

  /** URL-routed fetch mock — fleet page makes multiple calls on mount
   * (getMe, fetchBuoyFleet, possibly step-up-status). Route by URL
   * substring so order doesn't matter. */
  function routedFetch(buoyFleet: BuoyFleetResponse) {
    return vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/dashboard/buoy-fleet")) {
        return Promise.resolve(ok(buoyFleet));
      }
      if (url.includes("/auth/me")) {
        return Promise.resolve(ok({
          operator_id: 1, username: "tester", email: "t@example.test",
          display_name: null, role: ["admin"], scope_slugs: ["*"],
          must_change_password: false, mfa_enabled: true,
          backup_codes_remaining: 0,
        }));
      }
      // Step-up status — return not-elevated; fleet page doesn't gate on this
      return Promise.resolve(ok({ elevated: false }));
    });
  }

  it("renders an empty-state when no buoys are reporting", async () => {
    global.fetch = routedFetch(fixture([]));
    render(<FleetPage />);
    await waitFor(() => {
      expect(
        screen.getByText(/No buoys are reporting heartbeats yet/i),
      ).toBeInTheDocument();
    });
  });

  it("renders a card per buoy + sorts red/stale first", async () => {
    const greenRow = {
      slug: "alpha", hostname: "buoy-alpha",
      last_heartbeat_at: "2026-05-15T21:00:00.000Z",
      staleness_sec: 5, health: "green" as const,
      uptime_sec: 100, interval_sec: 60, boot_time: null,
      load_1: 0.1, load_5: null, load_15: null,
      mem_used_mb: 100, mem_total_mb: 4096, disk_used_pct: 20,
      services: { tailscaled: { state: "active", version: null, stat: null, last_activity: null } },
      last_event_at: null,
    };
    const redRow = { ...greenRow, slug: "zulu", hostname: "buoy-zulu",
                     health: "red" as const, staleness_sec: 9999 };
    const yellowRow = { ...greenRow, slug: "mike", hostname: "buoy-mike",
                        health: "yellow" as const,
                        services: {
                          tailscaled:    { state: "active", version: null, stat: null, last_activity: null },
                          "wazuh-agent": { state: "failed", version: null, stat: null, last_activity: null },
                        } };

    global.fetch = routedFetch(fixture([greenRow, redRow, yellowRow]));
    render(<FleetPage />);

    await waitFor(() => {
      expect(screen.getAllByRole("article")).toHaveLength(3);
    });

    // Order: red(zulu) → yellow(mike) → green(alpha)
    const cards = screen.getAllByRole("article");
    expect(cards[0]).toHaveAttribute("aria-label", "buoy zulu");
    expect(cards[1]).toHaveAttribute("aria-label", "buoy mike");
    expect(cards[2]).toHaveAttribute("aria-label", "buoy alpha");
  });

  it("shows a unit disabled on purpose as retired, not flagged (v0.11 B1)", async () => {
    const svc = (state: string, enabled: string | null) =>
      ({ state, enabled, version: null, stat: null, last_activity: null });
    const row = {
      slug: "alpha", hostname: "buoy-alpha",
      last_heartbeat_at: "2026-05-15T21:00:00.000Z",
      staleness_sec: 5, health: "green" as const,
      uptime_sec: 100, interval_sec: 60, boot_time: null,
      load_1: 0.1, load_5: null, load_15: null,
      mem_used_mb: 100, mem_total_mb: 4096, disk_used_pct: 20,
      services: {
        tailscaled: svc("active", "enabled"),
        "octo-forwarder": svc("inactive", "disabled"),
      },
      retired_services: ["octo-forwarder"],
      last_event_at: null,
    };
    const broken = {
      ...row, slug: "mike", hostname: "buoy-mike", health: "yellow" as const,
      services: { tailscaled: svc("active", "enabled"), suricata: svc("failed", "enabled") },
      retired_services: [],
    };
    global.fetch = routedFetch(fixture([row, broken]));
    render(<FleetPage />);
    await waitFor(() => {
      expect(screen.getAllByRole("article")).toHaveLength(2);
    });
    const alpha = screen.getByRole("article", { name: "buoy alpha" });
    const chip = within(alpha).getByTestId("service-chip-octo-forwarder");
    expect(chip).toHaveAttribute("data-state", "retired");
    expect(chip).toHaveAttribute("title", "octo-forwarder: retired (disabled on purpose)");
    expect(within(alpha).queryByText(/flagged/)).toBeNull();
    const mike = screen.getByRole("article", { name: "buoy mike" });
    expect(within(mike).getByTestId("service-chip-suricata")).toHaveAttribute("data-state", "failed");
    expect(within(mike).getByText(/1 service flagged/)).toBeInTheDocument();
  });

  it("surfaces an ApiError message", async () => {
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/dashboard/buoy-fleet")) {
        return Promise.resolve(new Response(
          JSON.stringify({ code: "AUTH_SESSION_INVALID" }),
          { status: 401 },
        ));
      }
      if (url.includes("/auth/me")) {
        return Promise.resolve(ok({
          operator_id: 1, username: "tester", email: "t@example.test",
          display_name: null, role: ["admin"], scope_slugs: ["*"],
          must_change_password: false, mfa_enabled: true,
          backup_codes_remaining: 0,
        }));
      }
      return Promise.resolve(ok({}));
    });
    render(<FleetPage />);
    await waitFor(() => {
      expect(screen.getByText(/AUTH_SESSION_INVALID/i)).toBeInTheDocument();
    });
  });
});
