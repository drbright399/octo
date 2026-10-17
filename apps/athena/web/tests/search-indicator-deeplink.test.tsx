/**
 * /search/indicators?indicator=<tenant>:<id> — where a threat-intel pulse row
 * lands. The dashboard only ever has the masked value; the full value comes
 * from the step-up-gated indicator search, for exactly that row.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

import SearchPage from "@/pages/search";

const RAW = "203.0.113.200";

const json = (body: unknown, status = 200): Promise<Response> =>
  Promise.resolve(new Response(JSON.stringify(body), { status }));

const status = (elevated: boolean) => ({
  elevated,
  granted_at: elevated ? "2026-09-28T11:00:00.000Z" : null,
  expires_at: elevated ? "2026-09-28T13:00:00.000Z" : null,
  absolute_expires_at: elevated ? "2026-09-28T15:00:00.000Z" : null,
  ttl_minutes: 15,
  absolute_cap_hours: 4,
});

let originalFetch: typeof fetch;
let elevated: boolean;
let searchBodies: Array<Record<string, unknown>>;

beforeEach(() => {
  originalFetch = global.fetch;
  window.localStorage.clear();
  window.history.pushState({}, "", "/search/indicators?indicator=acme-corp%3A42");
  searchBodies = [];
  global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === "/api/v1/search/status") return json(status(elevated));
    if (url === "/api/v1/admin/clients") {
      return json({ clients: [
        { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
        { slug: "globex", display_name: "Globex", status: "active" },
      ] });
    }
    if (url === "/api/v1/search/indicators") {
      if (!elevated) return json({ code: "STEP_UP_REQUIRED" }, 401);
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      searchBodies.push(body);
      return json({
        results: [{
          client_slug: "acme-corp", indicator_id: 42, value: RAW, type: "ip",
          source: "wazuh", severity: "high", confidence: 0.5, context: null,
          first_seen: "2026-09-28T10:00:00.000Z", last_seen: "2026-09-28T11:56:00.000Z",
          hits: 2, promoted_at: null,
        }],
        total_estimate: 1, truncated: false, page_size: 100, offset: 0,
        tenants_searched: ["acme-corp"], step_up_expires_at: null,
      });
    }
    return json({ code: "NOT_FOUND" }, 404);
  }) as typeof fetch;
});

afterEach(() => {
  cleanup();
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});

const renderPage = () =>
  render(<SearchPage mode="indicators" onNavigateMode={vi.fn()} />);

describe("indicator deep link from the threat-intel pulse", () => {
  it("asks for step-up first and searches nothing until then", async () => {
    elevated = false;
    renderPage();
    expect(await screen.findByText("Re-authentication required")).toBeInTheDocument();
    // Give any stray search a chance to fire.
    await new Promise((r) => setTimeout(r, 20));
    expect(searchBodies).toEqual([]);
    expect(screen.queryByText(RAW)).toBeNull();
  });

  it("once stepped up, searches exactly that row in that tenant", async () => {
    elevated = true;
    renderPage();
    expect(await screen.findByText(RAW)).toBeInTheDocument();
    expect(searchBodies[0]).toEqual({
      tenants: ["acme-corp"], indicator_ids: [42], limit: 100, offset: 0,
    });
    expect(screen.getByText(/one indicator from the threat-intel pulse/i)).toBeInTheDocument();
  });

  it("'show all indicators' drops the row filter", async () => {
    elevated = true;
    renderPage();
    await screen.findByText(RAW);
    fireEvent.click(screen.getByRole("button", { name: /show all indicators/i }));
    expect(window.location.search).toBe("");
    await waitFor(() => {
      const last = searchBodies[searchBodies.length - 1]!;
      expect(last.indicator_ids).toBeUndefined();
      expect(last.tenants).toEqual(["acme-corp", "globex"]);
    });
    expect(screen.queryByText(/one indicator from the threat-intel pulse/i)).toBeNull();
  });

  it("ignores a malformed ref and runs the normal search", async () => {
    elevated = true;
    window.history.pushState({}, "", "/search/indicators?indicator=not-a-ref");
    renderPage();
    await waitFor(() => expect(searchBodies.length).toBeGreaterThan(0));
    expect(searchBodies.every((b) => b.indicator_ids === undefined)).toBe(true);
  });
});
