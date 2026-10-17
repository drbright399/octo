import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import SettingsPage from "@/pages/settings";
import { navigateTo } from "@/lib/router";
import type { Tenant } from "@/contracts/tenant";

/**
 * The "confirmed tenants vanish" bug, end to end through the real router:
 * SettingsPage stays mounted across tab clicks, so the Tenants tab must
 * FOLLOW the URL's ?filter= — the dashboard notice's deep link applies it,
 * any navigation to plain /settings/tenants clears it, and a tenant
 * confirmed under it stays on screen. Only fetch is stubbed.
 */

const TENANTS = "/api/v1/admin/tenants";

function tenant(over: Partial<Tenant> & { slug: string; display_name: string }): Tenant {
  return {
    status: "active", origin: "auto", kind: "unclassified", review_state: "pending",
    compliance_flags: [], ai_policy: "none", created_by_instance: null,
    onboarded_at: "2026-09-01T00:00:00.000Z", offboarded_at: null, archived_at: null, notes: null,
    event_count: 0, last_event_at: null, mapped_sources: [], pending_request: null, duplicate_hints: [],
    ...over,
  };
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stub(): { tenants: Tenant[] } {
  const state = {
    tenants: [
      tenant({ slug: "lab-box", display_name: "Lab Box", kind: "dev" }),
      tenant({ slug: "widget-co", display_name: "Widget Co" }),
      tenant({ slug: "acme-corp", display_name: "Acme Corp", kind: "client", review_state: "confirmed" }),
    ],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, opts?: RequestInit) => {
      const method = opts?.method ?? "GET";
      if (url === "/api/v1/auth/me") {
        return jsonResponse(200, { operator_id: 1, username: "alice", email: "alice@example.test", role: ["admin"] });
      }
      if (url.startsWith(`${TENANTS}?`)) {
        return jsonResponse(200, {
          tenants: state.tenants.map((t) => ({ ...t })),
          pending_review: state.tenants.filter((t) => t.review_state === "pending" && t.status === "active").length,
          quarantined: 0, kinds: [], compliance_tags: [], ai_policies: [],
        });
      }
      if (url.startsWith(`${TENANTS}/requests?`)) return jsonResponse(200, { requests: [] });
      const m = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)$`));
      if (m && method === "PATCH") {
        const body = JSON.parse(String(opts?.body)) as Partial<Tenant>;
        state.tenants = state.tenants.map((t) => (t.slug === m[1] ? { ...t, ...body } : t));
        return jsonResponse(200, state.tenants.find((t) => t.slug === m[1]));
      }
      return jsonResponse(404, { code: "NOT_FOUND", message: `unexpected ${method} ${url}` });
    }),
  );
  return state;
}

const rows = () => screen.queryAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid"));

beforeEach(() => {
  window.history.replaceState({}, "", "/settings/tenants?filter=needs-review");
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState({}, "", "/");
});

describe("Settings → Tenants deep link", () => {
  it("?filter=needs-review → Confirm → row stays; the Tenants tab link then clears the filter", async () => {
    stub();
    render(<SettingsPage />);
    await waitFor(() => expect(rows().sort()).toEqual(["tenant-row-lab-box", "tenant-row-widget-co"]));
    expect(screen.getByLabelText("filter by review state")).toHaveValue("needs-review");

    fireEvent.click(screen.getByTestId("confirm-lab-box"));
    await waitFor(() => expect(within(screen.getByTestId("tenant-row-lab-box")).getByText("confirmed")).toBeInTheDocument());
    expect(within(screen.getByTestId("tenant-row-lab-box")).getByTestId("edit-lab-box")).toBeInTheDocument();

    // The settings nav's "Tenants" tab → /settings/tenants: filter gone, every tenant listed.
    fireEvent.click(screen.getByRole("tab", { name: "Tenants" }));
    expect(window.location.search).toBe("");
    await waitFor(() => expect(rows()).toHaveLength(3));
    expect(screen.getByLabelText("filter by review state")).toHaveValue("all");
  });

  it("the dashboard notice's link applies the filter even while the page is already open", async () => {
    window.history.replaceState({}, "", "/settings/tenants");
    stub();
    render(<SettingsPage />);
    await waitFor(() => expect(rows()).toHaveLength(3));
    act(() => navigateTo("/settings/tenants?filter=needs-review"));
    await waitFor(() => expect(rows()).toHaveLength(2));
    // Back to the plain tab via the view switch inside the page.
    fireEvent.click(screen.getByTestId("view-tenants"));
    await waitFor(() => expect(rows()).toHaveLength(3));
  });

  it("the review select writes the URL (the filter's one home)", async () => {
    window.history.replaceState({}, "", "/settings/tenants");
    stub();
    render(<SettingsPage />);
    await waitFor(() => expect(rows()).toHaveLength(3));
    fireEvent.change(screen.getByLabelText("filter by review state"), { target: { value: "confirmed" } });
    expect(window.location.search).toBe("?filter=confirmed");
    expect(rows()).toEqual(["tenant-row-acme-corp"]);
  });
});

describe("Settings → Tenants → Links to review deep link (?client=)", () => {
  it("opens on the notice's client, and the operator's own pick then sticks", async () => {
    window.history.replaceState({}, "", "/settings/tenants/links?client=acme-corp");
    stub();
    render(<SettingsPage />);
    const select = (await screen.findByLabelText("client")) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe("acme-corp"));
    fireEvent.change(select, { target: { value: "widget-co" } });
    await new Promise((r) => setTimeout(r, 30));
    expect((screen.getByLabelText("client") as HTMLSelectElement).value).toBe("widget-co");
  });
});
