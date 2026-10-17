import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { EntityResolutionPanel } from "@/components/entity-resolution-panel";
import { EntityLinksPanel } from "@/components/entity-links-panel";
import { KnownBenignPanel } from "@/components/known-benign-panel";
import type { Resolution, ReviewQueue } from "@/contracts/entity";

/**
 * Entity resolution in the console: the alert panel ("Where / Device /
 * Why?"), the per-client "Links to review" and the known-benign list. The
 * real `@/lib/entity` runs against a stubbed fetch; vendor / server text is
 * rendered as TEXT (an HTML-looking device name stays characters).
 */

function json(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const RESOLVED: Resolution = {
  slug: "acme-corp",
  event_id: 42,
  mode: "on",
  visible: true,
  resolved: true,
  status: "final",
  at: "2026-10-01T14:17:05.412Z",
  where: { site_id: "st_A", label: "Site A", basis: "both", score: 99, tier: "strong", tier_word: "STRONG" },
  device: { ref: null, tier: "candidate", tier_word: "CANDIDATES", score: 21, n_candidates: 9 },
  why: [
    "The alert's nextdns scope belongs to Site A (confirmed link) (score 95).",
    "The public address was Site A's internet connection at that moment.",
  ],
  flags: ["Later hits in the same hour were counted on this alert — they may come from other devices."],
  candidates: Array.from({ length: 9 }, (_, i) => ({
    label: i === 0 ? '<img src=x onerror="document.body.dataset.pwned=1"> (192.0.2.11, wired)' : `PC-${i} (192.0.2.${11 + i}, wired)`,
    score: i < 4 ? 21 : 11,
    features: i < 4 ? ["F2"] : [],
    conn: "wired",
    match: "in_core",
    lease_id: i + 1,
    mac_kind: "global",
  })),
  candidates_aged_out: false,
  review: [{ kind: "site", id: 7, vendor: "nextdns", scope: "abc123", state: "suggested", rule: "L-EGRESS", score: 85 }],
};

afterEach(() => {
  vi.unstubAllGlobals();
  delete document.body.dataset.pwned;
});

describe("EntityResolutionPanel", () => {
  it("shows where, the candidate set (never a pick), and why — as text", async () => {
    const calls: Array<{ url: string; method: string; body: unknown }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET", body: opts?.body ? JSON.parse(String(opts.body)) : null });
      if (url.endsWith("/resolution")) return json(200, RESOLVED);
      return json(200, { ok: true });
    }));
    render(<EntityResolutionPanel slug="acme-corp" eventId={42} />);
    expect(await screen.findByTestId("entity-where")).toHaveTextContent("Site A");
    expect(screen.getByTestId("entity-where-tier")).toHaveTextContent("STRONG 99");
    expect(screen.getByTestId("entity-device-tier")).toHaveTextContent("CANDIDATES");
    expect(screen.getByTestId("entity-candidate-count")).toHaveTextContent("9 device(s)");
    // five shown, the HTML-looking name as plain characters
    const list = screen.getByTestId("entity-candidates");
    expect(list.querySelectorAll("li")).toHaveLength(5);
    expect(list.textContent).toContain('<img src=x onerror="document.body.dataset.pwned=1">');
    expect(list.querySelector("img")).toBeNull();
    expect(document.body.dataset.pwned).toBeUndefined();
    fireEvent.click(screen.getByText("Show all 9"));
    expect(screen.getByTestId("entity-candidates").querySelectorAll("li")).toHaveLength(9);
    fireEvent.click(screen.getByTestId("entity-why-toggle"));
    expect(screen.getByTestId("entity-why")).toHaveTextContent("internet connection at that moment");
    expect(screen.getByTestId("entity-why")).toHaveTextContent("Later hits");
    // Confirm the suggested profile → site link (one click, audited server-side).
    fireEvent.click(screen.getByTestId("entity-confirm-7"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/links/site/7/confirm"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/confirm"))?.method).toBe("POST");
  });

  it("a rejection needs a reason", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      calls.push(url);
      return url.endsWith("/resolution") ? json(200, RESOLVED) : json(200, { ok: true });
    }));
    render(<EntityResolutionPanel slug="acme-corp" eventId={42} />);
    fireEvent.click(await screen.findByTestId("entity-reject-7"));
    const send = screen.getByTestId("entity-reject-send-7");
    expect(send).toBeDisabled();
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "not this site" } });
    fireEvent.click(send);
    await waitFor(() => expect(calls.some((u) => u.endsWith("/links/site/7/reject"))).toBe(true));
  });

  it("renders nothing in shadow mode and offers Resolve now when not resolved", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(200, { ...RESOLVED, mode: "shadow", visible: false })));
    const { container } = render(<EntityResolutionPanel slug="acme-corp" eventId={42} />);
    await waitFor(() => expect(container.querySelector("[data-testid='entity-panel']")).toBeNull());
    vi.stubGlobal("fetch", vi.fn(async () => json(200, {
      ...RESOLVED, resolved: false, where: null, device: null, candidates: [], why: [], flags: [], review: [],
    })));
    render(<EntityResolutionPanel slug="acme-corp" eventId={43} />);
    expect(await screen.findByTestId("entity-resolve-now")).toBeInTheDocument();
  });
});

describe("EntityResolutionPanel — alerts it never reads", () => {
  it("renders nothing (never 'resolved within a minute', no Resolve now) for not_applicable", async () => {
    const fetchMock = vi.fn(async () => json(200, {
      ...RESOLVED, resolved: false, visible: false, reason: "not_applicable", where: null,
      device: null, candidates: [], why: [], flags: [], review: [],
    }));
    vi.stubGlobal("fetch", fetchMock);
    const { container } = render(<EntityResolutionPanel slug="acme-corp" eventId={77} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 10));
    expect(container.querySelector("[data-testid='entity-panel']")).toBeNull();
    expect(screen.queryByTestId("entity-resolve-now")).toBeNull();
  });
});

const QUEUE: ReviewQueue = {
  slug: "acme-corp",
  resolved: true,
  sites: [{ id: 3, site_id: "st_A", site_label: "Site A", vendor: "nextdns", vendor_scope_id: "abc123", state: "suggested", score: 85, rule_id: "L-SOLE",
             vendor_label: "Site A office", site_location: "100 Example St",
             evidence: { match_source: "manual", rules: ["L-SOLE", "N-SITE"], as_of: "2026-10-01",
                         also: { "N-SITE": { same_name: true } },
                         coverage: { share: 0.93, queries: 1214, days_from_site: 6, days_with_data: 7 } } }],
  names: [{ id: 4, site_id: "st_B", site_label: "Warehouse", vendor: "nextdns", vendor_scope_id: "abc124", state: "suggested", score: 45, rule_id: "N-SITE", evidence: {} }],
  devices: [{ id: 9, state: "suggested", rule: "N-DEV", score: 45, evidence: { same_lan_ip: false },
              nextdns: { name: "DESKTOP-0A1", model: null, client: "nextdns-windows", last_seen: null },
              datto: { hostname: "DESKTOP-0A1", online: 1, last_seen: null, os: null }, watch: null }],
  conflicts: [],
};

describe("EntityLinksPanel + KnownBenignPanel", () => {
  it("lists the queue by tab, warns on name matches, switches the mode with a reason", async () => {
    const calls: Array<{ url: string; method: string; body: unknown }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET", body: opts?.body ? JSON.parse(String(opts.body)) : null });
      if (url.endsWith("/status")) {
        return json(200, { slug: "acme-corp", mode: "shadow", resolved: true, sites: 1, open_leases: 14, resolutions: 3, to_review: 3, conflicts: 0 });
      }
      if (url.endsWith("/review")) return json(200, QUEUE);
      return json(200, { ok: true, mode: "on" });
    }));
    render(<EntityLinksPanel slug="acme-corp" canAdmin />);
    expect(await screen.findByTestId("links-mode")).toHaveTextContent("shadow");
    expect(screen.getByTestId("links-sites")).toHaveTextContent("abc123");
    // Each card names the profile and the site's place, with the traffic
    // evidence as counts — never just an id and a label.
    expect(screen.getByTestId("links-sites")).toHaveTextContent("Site A office");
    expect(screen.getByTestId("links-sites")).toHaveTextContent("100 Example St");
    expect(screen.getByTestId("links-evidence-3")).toHaveTextContent(
      "93% of 1,214 queries came from the site's own internet address; on 6 of 7 day(s) with data");
    // ONE combined suggestion: the agreeing name rule is provenance, not a second card.
    expect(screen.getByTestId("links-evidence-3")).toHaveTextContent("the names match too");
    fireEvent.click(screen.getByTestId("links-tab-names"));
    expect(screen.getByTestId("links-names")).toHaveTextContent("The same name is not proof");
    fireEvent.click(screen.getByTestId("links-tab-devices"));
    expect(screen.getByTestId("links-devices")).toHaveTextContent("name only");
    fireEvent.click(screen.getByTestId("links-confirm-device-9"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/links/device/9/confirm"))).toBe(true));
    fireEvent.change(screen.getByLabelText("entity resolution mode"), { target: { value: "on" } });
    expect(screen.getByTestId("links-mode-save")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("mode reason"), { target: { value: "shadow week done" } });
    fireEvent.click(screen.getByTestId("links-mode-save"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/mode") && c.method === "PUT")).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/mode"))?.body).toEqual({ mode: "on", reason: "shadow week done" });
  });

  it("resolves a conflict, accepts a routing one as expected and reopens an accepted one", async () => {
    const calls: Array<{ url: string; method: string; body: unknown }> = [];
    const routing = { id: 5, kind: "routing", subject: "nextdns:abc124", detail: {}, first_seen: "2026-10-01T14:00:00.000Z",
                      last_seen: "2026-10-01T14:00:00.000Z", hits: 1, resolution: null };
    const siteConflict = { ...routing, id: 6, kind: "site_conflict", subject: "event:nextdns:9" };
    const accepted = { ...routing, id: 7, subject: "nextdns:abc125", resolution: "accepted" as const,
                       resolved_by: "operator:3", resolved_at: "2026-09-30T10:00:00.000Z" };
    vi.stubGlobal("fetch", vi.fn(async (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET", body: opts?.body ? JSON.parse(String(opts.body)) : null });
      if (url.endsWith("/status")) {
        return json(200, { slug: "acme-corp", mode: "on", resolved: true, sites: 1, open_leases: 2, resolutions: 0, to_review: 0, conflicts: 2 });
      }
      if (url.endsWith("/review")) return json(200, { ...QUEUE, conflicts: [routing, siteConflict], accepted: [accepted] });
      return json(200, { ok: true });
    }));
    render(<EntityLinksPanel slug="acme-corp" canAdmin={false} />);
    fireEvent.click(await screen.findByTestId("links-tab-conflicts"));
    // Only a routing card can be accepted as expected.
    expect(screen.getByTestId("links-reject-accept-5")).toHaveTextContent("Accept as expected");
    expect(screen.queryByTestId("links-reject-accept-6")).toBeNull();
    fireEvent.click(screen.getByTestId("links-reject-accept-5"));
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "branch office, no UniFi" } });
    fireEvent.click(screen.getByTestId("links-send-accept-5"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/conflicts/5/accept"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/conflicts/5/accept"))?.body).toEqual({ reason: "branch office, no UniFi" });
    expect(await screen.findByTestId("links-accepted-7")).toHaveTextContent("accepted as expected");
    fireEvent.click(screen.getByTestId("links-reject-reopen-7"));
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "the branch got UniFi" } });
    fireEvent.click(screen.getByTestId("links-send-reopen-7"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/conflicts/7/reopen"))).toBe(true));
    fireEvent.click(screen.getByTestId("links-reject-conflict-6"));
    fireEvent.change(screen.getByLabelText("reason"), { target: { value: "checked" } });
    fireEvent.click(screen.getByTestId("links-send-conflict-6"));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/conflicts/6/resolve"))).toBe(true));
  });

  it("lists the known-benign rules and adds one with a reason", async () => {
    const rule = { id: 1, vendor: "nextdns", match_kind: "regex", pattern: "www\\.go{3,}gle\\.com",
                   reasons: ["threat-intelligence-feeds"], level: "low",
                   label: "Samsung connectivity probe (google typosquat)", note: "", enabled: true };
    const calls: Array<{ url: string; method: string }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET" });
      return json(200, opts?.method === "POST" ? [rule, { ...rule, id: 2, label: "Printer probe" }] : [rule]);
    }));
    render(<KnownBenignPanel canEdit />);
    expect(await screen.findByTestId("kb-rule-1")).toHaveTextContent("Samsung connectivity probe");
    expect(screen.getByTestId("kb-add")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("pattern"), { target: { value: "probe.example" } });
    fireEvent.change(screen.getByLabelText("label"), { target: { value: "Printer probe" } });
    fireEvent.change(screen.getByLabelText("why"), { target: { value: "known printer check" } });
    fireEvent.click(screen.getByTestId("kb-add"));
    expect(await screen.findByTestId("kb-rule-2")).toHaveTextContent("Printer probe");
    expect(calls.some((c) => c.method === "POST")).toBe(true);
  });
});
