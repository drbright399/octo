import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  BUOY_COMMAND_MIN_ROLE,
  canIssueBuoyCommand,
  queueBuoyCommand,
  listBuoyCommands,
} from "@/lib/buoy";
import { ApiError } from "@/lib/api";


const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => {
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});


// ---------------------------------------------------------------------------
// canIssueBuoyCommand — role matrix mirror
// ---------------------------------------------------------------------------

describe("canIssueBuoyCommand", () => {
  it("matrix matches the server-side BUOY_COMMAND_MIN_ROLE", () => {
    // Sanity: client matrix keys = expected set
    expect(Object.keys(BUOY_COMMAND_MIN_ROLE).sort()).toEqual([
      "ping", "refresh", "reboot", "restart-service",
      "tail-log", "update",
    ].sort());
  });

  it("analyst can ping / refresh / tail-log, not restart / reboot / update", () => {
    expect(canIssueBuoyCommand("analyst", "ping")).toBe(true);
    expect(canIssueBuoyCommand("analyst", "refresh")).toBe(true);
    expect(canIssueBuoyCommand("analyst", "tail-log")).toBe(true);
    expect(canIssueBuoyCommand("analyst", "restart-service")).toBe(false);
    expect(canIssueBuoyCommand("analyst", "reboot")).toBe(false);
    expect(canIssueBuoyCommand("analyst", "update")).toBe(false);
  });

  it("admin can restart but not reboot / update", () => {
    expect(canIssueBuoyCommand("admin", "restart-service")).toBe(true);
    expect(canIssueBuoyCommand("admin", "reboot")).toBe(false);
    expect(canIssueBuoyCommand("admin", "update")).toBe(false);
  });

  it("super_admin can do everything", () => {
    for (const kind of Object.keys(BUOY_COMMAND_MIN_ROLE) as Array<keyof typeof BUOY_COMMAND_MIN_ROLE>) {
      expect(canIssueBuoyCommand("super_admin", kind)).toBe(true);
    }
  });

  it("viewer cannot issue any command", () => {
    for (const kind of Object.keys(BUOY_COMMAND_MIN_ROLE) as Array<keyof typeof BUOY_COMMAND_MIN_ROLE>) {
      expect(canIssueBuoyCommand("viewer", kind)).toBe(false);
    }
  });

  it("null / unknown role denies everything", () => {
    expect(canIssueBuoyCommand(null, "ping")).toBe(false);
    expect(canIssueBuoyCommand("some-bogus-role", "ping")).toBe(false);
  });
});


// ---------------------------------------------------------------------------
// queueBuoyCommand — wire shape
// ---------------------------------------------------------------------------

describe("queueBuoyCommand", () => {
  it("POSTs the slug + command + args, returns parsed response", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(ok({
      id: 42, slug: "alpha", command_kind: "ping", status: "queued",
      requested_at: "2026-05-16T11:00:00.000Z",
      expires_at:   "2026-05-16T11:05:00.000Z",
    }));
    const r = await queueBuoyCommand("alpha", "ping");
    expect(r.id).toBe(42);
    expect(r.status).toBe("queued");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/buoy/alpha/command",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
      }),
    );
    const call = (global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0]!;
    const body = JSON.parse((call[1] as RequestInit).body as string);
    expect(body).toEqual({ command_kind: "ping", args: {} });
  });

  it("throws ApiError with STEP_UP_REQUIRED on 401", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "STEP_UP_REQUIRED" }),
                   { status: 401 }),
    );
    await expect(queueBuoyCommand("alpha", "ping")).rejects.toBeInstanceOf(ApiError);
  });
});


// ---------------------------------------------------------------------------
// listBuoyCommands — unwraps {commands: [...]}
// ---------------------------------------------------------------------------

describe("listBuoyCommands", () => {
  it("returns the commands array unwrapped", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(ok({
      commands: [
        {
          id: 1, slug: "alpha", command_kind: "ping",
          args: {}, status: "completed",
          requested_by: 3,
          requested_at: "2026-05-16T11:00:00.000Z",
          dispatched_at: "2026-05-16T11:00:30.000Z",
          completed_at: "2026-05-16T11:00:35.000Z",
          expires_at: "2026-05-16T11:05:00.000Z",
          result_ok: true, result_exit_code: 0, result_error: null,
        },
      ],
    }));
    const rows = await listBuoyCommands("alpha");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.command_kind).toBe("ping");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/buoy/alpha/commands?limit=50",
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("throws ApiError on 403", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "ISOLATION_VIOLATION" }),
                   { status: 403 }),
    );
    await expect(listBuoyCommands("alpha")).rejects.toBeInstanceOf(ApiError);
  });
});
