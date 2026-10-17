import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import { getAgentStatus } from "@/lib/api";
import AgentStatusPill from "@/components/agent-status-pill";

const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });

const STATUS = (over: Record<string, unknown> = {}) => ({
  state: "idle",
  online: true,
  last_tick_at: "2026-06-01T19:00:00.000000Z",
  last_run: { processed: 12, by_disposition: { noise: 10, escalate: 2 } },
  last_error: null,
  consecutive_errors: 0,
  interval_seconds: 15,
  ...over,
});

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => { global.fetch = originalFetch; vi.restoreAllMocks(); });

describe("getAgentStatus", () => {
  it("calls the status endpoint and parses the body", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(ok(STATUS()));
    const r = await getAgentStatus();
    expect(r.state).toBe("idle");
    expect(r.online).toBe(true);
    expect(r.last_run?.processed).toBe(12);
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/agent/status",
      expect.objectContaining({ credentials: "include" }),
    );
  });
});

describe("AgentStatusPill", () => {
  it("compact mode shows ONLINE when the worker is up", async () => {
    global.fetch = vi.fn().mockResolvedValue(ok(STATUS({ online: true })));
    render(<AgentStatusPill compact />);
    await waitFor(() => expect(screen.getByText(/agent · online/i)).toBeInTheDocument());
  });

  it("compact mode shows OFFLINE when disabled", async () => {
    global.fetch = vi.fn().mockResolvedValue(
      ok(STATUS({ online: false, state: "disabled" })),
    );
    render(<AgentStatusPill compact />);
    await waitFor(() => expect(screen.getByText(/agent · offline/i)).toBeInTheDocument());
  });

  it("detailed mode surfaces the fine-grained state", async () => {
    global.fetch = vi.fn().mockResolvedValue(ok(STATUS({ state: "triaging" })));
    render(<AgentStatusPill />);
    await waitFor(() => expect(screen.getByText("triaging")).toBeInTheDocument());
  });

  it("detailed mode shows error state", async () => {
    global.fetch = vi.fn().mockResolvedValue(
      ok(STATUS({ state: "error", last_error: "database is locked", consecutive_errors: 2 })),
    );
    render(<AgentStatusPill />);
    await waitFor(() => expect(screen.getByText("error")).toBeInTheDocument());
  });
});
