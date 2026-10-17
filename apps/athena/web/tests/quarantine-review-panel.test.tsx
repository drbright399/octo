import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QuarantineReviewPanel, groupHeld } from "@/components/quarantine-review-panel";
import type { QuarantineRow } from "@/contracts/tenant";

/**
 * Quarantine review: held events grouped by integration + vendor site +
 * reason, each reason explained in plain language; a group routes to an
 * existing tenant OR a new one created inline (bulk-route), or is discarded
 * with a reason (bulk-discard); the payload is rendered as TEXT — a payload
 * that is HTML/script appears as literal characters and never becomes DOM.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const Q = "/api/v1/admin/quarantine";

function row(over: Partial<QuarantineRow> & { id: number }): QuarantineRow {
  return {
    received_at: `2026-09-22T0${over.id % 10}:00:00.000Z`,
    instance_id: 7,
    vendor: "datto",
    source: "poll",
    vendor_tenant_id: "site-uid-0007",
    vendor_tenant_label: "Seven Sisters Bakery",
    reason: "autocreate-limit",
    event_summary: `Disk — disk full on WS-${over.id}`,
    payload_sha256: "a".repeat(64),
    payload_truncated: false,
    state: "held",
    routed_to_slug: null,
    routed_at: null,
    discarded_at: null,
    discard_reason: null,
    ...over,
  };
}

const HTML_PAYLOAD =
  '{"alertContext":{"message":"<script>document.body.dataset.pwned=\\"1\\"</script><img src=x onerror=\\"document.body.dataset.pwned=\'2\'\\">"},"siteUid":"site-uid-0007"}';

const ROWS: QuarantineRow[] = [
  row({ id: 1 }),
  row({ id: 2, source: "webhook" }),
  row({ id: 3, vendor_tenant_id: "site-uid-0009", vendor_tenant_label: null, reason: "name-unknown" }),
  row({ id: 4, vendor_tenant_id: "site-uid-0003", vendor_tenant_label: "Old Client", reason: "offboarded-tenant" }),
  row({ id: 5, vendor_tenant_id: null, vendor_tenant_label: null, reason: "no-tenant-id", event_summary: "(no site)" }),
];

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

interface Backend {
  rows: QuarantineRow[];
  calls: Array<{ url: string; method: string; body: unknown }>;
}

function stubBackend(rows: QuarantineRow[] = ROWS): Backend {
  const backend: Backend = { rows: [...rows], calls: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, opts?: RequestInit) => {
      const method = opts?.method ?? "GET";
      const body = typeof opts?.body === "string" ? JSON.parse(opts.body) : undefined;
      backend.calls.push({ url, method, body });
      if (url.startsWith(`${Q}?`)) {
        const params = new URLSearchParams(url.slice(url.indexOf("?") + 1));
        const offset = Number(params.get("offset") ?? "0");
        const limit = Number(params.get("limit") ?? "50");
        const held = backend.rows.filter((r) => r.state === "held");
        return jsonResponse(200, {
          rows: held.slice(offset, offset + limit),
          total: held.length,
          limit,
          offset,
          reasons: ["no-tenant-id", "name-unknown", "ambiguous-name", "offboarded-tenant", "autocreate-limit", "instance-disabled", "store-failed"],
        });
      }
      const detail = url.match(new RegExp(`^${Q}/(\\d+)$`));
      if (detail && method === "GET") {
        const r = backend.rows.find((x) => x.id === Number(detail[1]));
        return r ? jsonResponse(200, { ...r, payload: HTML_PAYLOAD }) : jsonResponse(404, { code: "NOT_FOUND", message: "no" });
      }
      if (url === `${Q}/bulk-route` && method === "POST") {
        const hit = backend.rows.filter(
          (r) => r.state === "held" && r.instance_id === body.instance_id && r.vendor_tenant_id === body.vendor_tenant_id &&
            (!body.quarantine_reason || r.reason === body.quarantine_reason),
        );
        if (!hit.length) return jsonResponse(404, { code: "NOT_FOUND", message: "no held events for that vendor tenant on that instance" });
        // Like the server: a truncated payload is skipped (stays held), the rest is routed.
        const replayable = hit.filter((r) => !r.payload_truncated);
        backend.rows = backend.rows.map((r) => (replayable.includes(r) ? { ...r, state: "routed" as const } : r));
        const slug = body.slug ?? body.new.display_name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        return jsonResponse(200, {
          slug, created_tenant: !body.slug, routed: replayable.length, duplicates: 0,
          skipped: hit.length - replayable.length, mapping_written: true,
        });
      }
      if (url === `${Q}/bulk-discard` && method === "POST") {
        const hit = backend.rows.filter(
          (r) => r.state === "held" && r.instance_id === body.instance_id && r.vendor_tenant_id === body.vendor_tenant_id &&
            (!body.quarantine_reason || r.reason === body.quarantine_reason),
        );
        backend.rows = backend.rows.map((r) => (hit.includes(r) ? { ...r, state: "discarded" as const } : r));
        return jsonResponse(200, { discarded: hit.length });
      }
      const one = url.match(new RegExp(`^${Q}/(\\d+)/(route|discard)$`));
      if (one && method === "POST") {
        const id = Number(one[1]);
        backend.rows = backend.rows.map((r) => (r.id === id ? { ...r, state: one[2] === "route" ? "routed" : "discarded" } : r));
        return one[2] === "route"
          ? jsonResponse(200, { slug: body.slug ?? "new-co", created_tenant: false, routed: 1, duplicates: 0, mapping_written: true })
          : jsonResponse(200, { id, discarded: true });
      }
      if (url === "/api/v1/integrations") {
        return jsonResponse(200, {
          definitions: [{ slug: "datto", name: "Datto RMM", category: "rmm", description: "" }],
          instances: {},
        });
      }
      if (url.startsWith("/api/v1/admin/tenants?")) {
        return jsonResponse(200, {
          tenants: [
            { slug: "acme-corp", display_name: "Acme Corp", status: "active", origin: "manual", kind: "client", review_state: "confirmed", compliance_flags: [], ai_policy: "none", created_by_instance: null, onboarded_at: "x", offboarded_at: null, archived_at: null, notes: null, event_count: 0, last_event_at: null, mapped_sources: [], pending_request: null },
            { slug: "gone-co", display_name: "Gone Co", status: "offboarded", origin: "manual", kind: "client", review_state: "confirmed", compliance_flags: [], ai_policy: "none", created_by_instance: null, onboarded_at: "x", offboarded_at: "y", archived_at: null, notes: null, event_count: 0, last_event_at: null, mapped_sources: [], pending_request: null },
          ],
          pending_review: 0,
          quarantined: backend.rows.filter((r) => r.state === "held").length,
          kinds: ["unclassified", "client", "internal", "dev", "vendor", "other"],
          compliance_tags: ["hipaa", "cjis", "pci", "bipa", "glba", "ferpa", "none"],
          ai_policies: ["none", "local", "cloud"],
        });
      }
      return jsonResponse(404, { code: "NOT_FOUND", message: `unexpected ${method} ${url}` });
    }),
  );
  return backend;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("groupHeld", () => {
  it("groups by instance + site + reason, newest first, and carries a label when any row has one", () => {
    const groups = groupHeld(ROWS);
    expect(groups.map((g) => [g.vendor_tenant_id, g.reason, g.rows.length])).toEqual([
      [null, "no-tenant-id", 1],
      ["site-uid-0003", "offboarded-tenant", 1],
      ["site-uid-0009", "name-unknown", 1],
      ["site-uid-0007", "autocreate-limit", 2],
    ]);
    expect(groups[3]?.newest_at).toBe("2026-09-22T02:00:00.000Z");
    expect(groups[3]?.rows.map((r) => r.id)).toEqual([2, 1]);
    // Same site, different reason = different group.
    const mixed = groupHeld([row({ id: 1 }), row({ id: 2, reason: "name-unknown" })]);
    expect(mixed).toHaveLength(2);
  });
});

describe("QuarantineReviewPanel", () => {
  it("renders groups with counts, newest time, plain-language reasons, and no bulk actions without a site id", async () => {
    stubBackend();
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    expect(screen.getByTestId("quarantine-held-total")).toHaveTextContent("5 held events in 4 groups");
    const groups = screen.getAllByTestId("quarantine-group");
    expect(groups).toHaveLength(4);
    const bakery = groups.find((g) => g.textContent?.includes("Seven Sisters Bakery"));
    expect(bakery).toBeTruthy();
    const b = within(bakery as HTMLElement);
    expect(b.getByText(/Datto RMM/)).toBeInTheDocument();
    expect(b.getByText(/site site-uid-0007/)).toBeInTheDocument();
    expect(b.getByTestId("quarantine-group-reason")).toHaveTextContent("auto-create paused — 2 events, newest");
    expect(b.getByText(/bound on new tenants per hour/)).toBeInTheDocument();
    expect(b.getByTestId("group-route-all")).toBeInTheDocument();
    expect(b.getByTestId("group-discard-all")).toBeInTheDocument();

    const offboarded = groups.find((g) => g.textContent?.includes("Old Client")) as HTMLElement;
    expect(within(offboarded).getByText(/will NOT resurrect that tenant/)).toBeInTheDocument();
    const ambiguousLike = groups.find((g) => g.textContent?.includes("site name unknown")) as HTMLElement;
    expect(within(ambiguousLike).getByText(/\(site name unknown\)/)).toBeInTheDocument();

    const noSite = groups.find((g) => g.textContent?.includes("(no site id)")) as HTMLElement;
    expect(within(noSite).queryByTestId("group-route-all")).toBeNull();
    expect(within(noSite).queryByTestId("group-discard-all")).toBeNull();
    expect(within(noSite).getByText(/route or discard each event on its own/)).toBeInTheDocument();
  });

  it("a missing integration default is explained as a misconfiguration, not an offboarding", async () => {
    stubBackend([
      row({ id: 9, vendor_tenant_id: null, vendor_tenant_label: null, reason: "default-tenant-missing", event_summary: "(no site)" }),
    ]);
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const [group] = screen.getAllByTestId("quarantine-group");
    const g = within(group as HTMLElement);
    expect(g.getByTestId("quarantine-group-reason")).toHaveTextContent(
      "integration default names a tenant that does not exist — 1 event",
    );
    expect(g.getByText(/nothing was offboarded/)).toBeInTheDocument();
    expect(g.getByText(/default is misconfigured/)).toBeInTheDocument();
    expect(g.queryByText(/resurrect/)).toBeNull();
  });

  it("filters by reason and by integration", async () => {
    stubBackend();
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    fireEvent.change(screen.getByLabelText("filter by reason"), { target: { value: "name-unknown" } });
    expect(screen.getAllByTestId("quarantine-group")).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("filter by reason"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("filter by integration"), { target: { value: "7" } });
    expect(screen.getAllByTestId("quarantine-group")).toHaveLength(4);
  });

  it("honours the ?instance= pre-filter (a foreign instance shows nothing)", async () => {
    stubBackend();
    render(<QuarantineReviewPanel initialInstanceId={99} />);
    await waitFor(() => screen.getByTestId("quarantine-empty"));
    expect(screen.getByTestId("quarantine-empty")).toHaveTextContent("No held events match these filters.");
  });

  it("expands a group and renders an HTML/script payload as literal text — never as DOM", async () => {
    stubBackend();
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const bakery = screen.getAllByTestId("quarantine-group").find((g) => g.textContent?.includes("Seven Sisters Bakery")) as HTMLElement;
    fireEvent.click(within(bakery).getByRole("button", { name: /Show 2 events/ }));
    const events = within(bakery).getAllByTestId("held-event");
    expect(events).toHaveLength(2);
    expect(events[0]).toHaveTextContent("Disk — disk full on WS-2");
    expect(events[0]).toHaveTextContent("webhook");
    fireEvent.click(within(events[0] as HTMLElement).getByTestId("held-event-payload"));
    const pre = await waitFor(() => within(events[0] as HTMLElement).getByTestId("payload-text"));
    expect(pre.tagName).toBe("PRE");
    expect(pre.textContent).toBe(HTML_PAYLOAD);
    // Literal characters, not markup: no element was created from the payload.
    expect(document.querySelector("script")).toBeNull();
    expect(document.querySelector("img")).toBeNull();
    expect(document.body.dataset.pwned).toBeUndefined();
    expect(within(events[0] as HTMLElement).getByTestId("payload-copy")).toHaveTextContent("Copy");
  });

  it("routes a whole group into a NEW tenant created inline (bulk-route) and reports the outcome", async () => {
    const backend = stubBackend();
    const onChanged = vi.fn();
    render(<QuarantineReviewPanel onChanged={onChanged} />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const bakery = screen.getAllByTestId("quarantine-group").find((g) => g.textContent?.includes("Seven Sisters Bakery")) as HTMLElement;
    fireEvent.click(within(bakery).getByTestId("group-route-all"));
    const dialog = within(screen.getByTestId("route-dialog"));
    expect(dialog.getByText(/Route 2 events from Seven Sisters Bakery/)).toBeInTheDocument();
    expect(dialog.getByText(/auto-create paused/)).toBeInTheDocument();
    // Existing-tenant picker offers only ACTIVE tenants.
    const opts = Array.from((dialog.getByLabelText("target tenant") as HTMLSelectElement).options).map((o) => o.value);
    expect(opts).toContain("acme-corp");
    expect(opts).not.toContain("gone-co");
    expect(dialog.getByTestId("route-submit")).toBeDisabled();

    fireEvent.click(dialog.getByLabelText("create new tenant"));
    // The vendor's site name is the suggested name.
    expect(dialog.getByLabelText("new tenant display name")).toHaveValue("Seven Sisters Bakery");
    fireEvent.click(dialog.getByLabelText("compliance HIPAA"));
    expect((dialog.getByLabelText("kind") as HTMLSelectElement).value).toBe("client");
    expect(Array.from((dialog.getByLabelText("kind") as HTMLSelectElement).options).map((o) => o.value)).not.toContain("unclassified");
    expect(dialog.getByTestId("route-submit")).toHaveTextContent("Create tenant & route");
    fireEvent.click(dialog.getByTestId("route-submit"));
    await waitFor(() => expect(screen.queryByTestId("route-dialog")).toBeNull());
    const call = backend.calls.find((c) => c.url === `${Q}/bulk-route`);
    expect(call?.body).toEqual({
      instance_id: 7,
      vendor_tenant_id: "site-uid-0007",
      quarantine_reason: "autocreate-limit",
      new: { display_name: "Seven Sisters Bakery", kind: "client", compliance_flags: ["hipaa"] },
    });
    expect(screen.getByTestId("quarantine-notice")).toHaveTextContent(
      "Routed 2 events to seven-sisters-bakery — tenant created; the vendor site is now mapped there.",
    );
    expect(onChanged).toHaveBeenCalled();
    await waitFor(() => expect(screen.getByTestId("quarantine-held-total")).toHaveTextContent("3 held events in 3 groups"));
  });

  it("routes a group to an existing tenant", async () => {
    const backend = stubBackend();
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const old = screen.getAllByTestId("quarantine-group").find((g) => g.textContent?.includes("Old Client")) as HTMLElement;
    fireEvent.click(within(old).getByTestId("group-route-all"));
    const dialog = within(screen.getByTestId("route-dialog"));
    fireEvent.change(dialog.getByLabelText("target tenant"), { target: { value: "acme-corp" } });
    fireEvent.click(dialog.getByTestId("route-submit"));
    await waitFor(() => expect(screen.queryByTestId("route-dialog")).toBeNull());
    expect(backend.calls.find((c) => c.url === `${Q}/bulk-route`)?.body).toEqual({
      instance_id: 7, vendor_tenant_id: "site-uid-0003", quarantine_reason: "offboarded-tenant", slug: "acme-corp",
    });
  });

  it("discards a whole group with a required reason (bulk-discard)", async () => {
    const backend = stubBackend();
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const bakery = screen.getAllByTestId("quarantine-group").find((g) => g.textContent?.includes("Seven Sisters Bakery")) as HTMLElement;
    fireEvent.click(within(bakery).getByTestId("group-discard-all"));
    const dialog = within(screen.getByTestId("discard-dialog"));
    expect(dialog.getByText("Discard 2 events?")).toBeInTheDocument();
    expect(dialog.getByTestId("discard-submit")).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("discard reason"), { target: { value: "ab" } });
    expect(dialog.getByTestId("discard-submit")).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("discard reason"), { target: { value: "vendor demo site" } });
    fireEvent.click(dialog.getByTestId("discard-submit"));
    await waitFor(() => expect(screen.queryByTestId("discard-dialog")).toBeNull());
    expect(backend.calls.find((c) => c.url === `${Q}/bulk-discard`)?.body).toEqual({
      instance_id: 7, vendor_tenant_id: "site-uid-0007", quarantine_reason: "autocreate-limit", reason: "vendor demo site",
    });
    expect(screen.getByTestId("quarantine-notice")).toHaveTextContent("Discarded 2 events.");
  });

  it("routes and discards a single event (no-site-id group)", async () => {
    const backend = stubBackend();
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const noSite = screen.getAllByTestId("quarantine-group").find((g) => g.textContent?.includes("(no site id)")) as HTMLElement;
    fireEvent.click(within(noSite).getByRole("button", { name: /Show 1 event/ }));
    const ev = within(noSite).getByTestId("held-event");
    fireEvent.click(within(ev).getByTestId("held-event-route"));
    const dialog = within(screen.getByTestId("route-dialog"));
    fireEvent.change(dialog.getByLabelText("target tenant"), { target: { value: "acme-corp" } });
    fireEvent.click(dialog.getByTestId("route-submit"));
    await waitFor(() => expect(screen.queryByTestId("route-dialog")).toBeNull());
    expect(backend.calls.find((c) => c.url === `${Q}/5/route`)?.body).toEqual({ slug: "acme-corp" });
    expect(backend.calls.find((c) => c.url === `${Q}/bulk-route`)).toBeUndefined();
  });

  it("shows the server's refusal inside the dialog", async () => {
    stubBackend();
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const original = fetch;
    vi.stubGlobal("fetch", async (url: string, opts?: RequestInit) => {
      if (url === `${Q}/bulk-route`) {
        return jsonResponse(409, { code: "CONFLICT", message: "tenant 'acme-corp' has no events store" });
      }
      return original(url, opts);
    });
    const bakery = screen.getAllByTestId("quarantine-group").find((g) => g.textContent?.includes("Seven Sisters Bakery")) as HTMLElement;
    fireEvent.click(within(bakery).getByTestId("group-route-all"));
    const dialog = within(screen.getByTestId("route-dialog"));
    fireEvent.change(dialog.getByLabelText("target tenant"), { target: { value: "acme-corp" } });
    fireEvent.click(dialog.getByTestId("route-submit"));
    await waitFor(() => expect(dialog.getByRole("alert")).toHaveTextContent("tenant 'acme-corp' has no events store"));
    expect(screen.getByTestId("route-dialog")).toBeInTheDocument();
  });

  it("warns about truncated payloads in a group and disables their per-event Route", async () => {
    stubBackend([row({ id: 1 }), row({ id: 2, payload_truncated: true })]);
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const g = screen.getByTestId("quarantine-group");
    const hint = within(g).getByTestId("group-truncated-hint");
    expect(hint).toHaveTextContent("1 of these payloads was truncated on arrival");
    // "Route all" is not blocked by it: the server skips the row and routes the rest.
    expect(hint).toHaveTextContent("“Route all” skips it and routes the rest");
    expect(hint).not.toHaveTextContent("discard it first");
    fireEvent.click(within(g).getByRole("button", { name: /Show 2 events/ }));
    const events = within(g).getAllByTestId("held-event");
    const truncatedRow = events.find((e) => e.textContent?.includes("payload truncated")) as HTMLElement;
    expect(within(truncatedRow).getByTestId("held-event-route")).toBeDisabled();
    expect(within(truncatedRow).getByTestId("held-event-discard")).toBeEnabled();
  });

  it("'Route all' on a group with a truncated payload routes the rest and says what stayed held", async () => {
    const backend = stubBackend([row({ id: 1 }), row({ id: 2, payload_truncated: true }), row({ id: 3 })]);
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    fireEvent.click(within(screen.getByTestId("quarantine-group")).getByTestId("group-route-all"));
    const dialog = within(screen.getByTestId("route-dialog"));
    fireEvent.change(dialog.getByLabelText("target tenant"), { target: { value: "acme-corp" } });
    fireEvent.click(dialog.getByTestId("route-submit"));
    await waitFor(() => expect(screen.queryByTestId("route-dialog")).toBeNull());
    expect(backend.calls.filter((c) => c.url === `${Q}/bulk-route`)).toHaveLength(1);
    expect(screen.getByTestId("quarantine-notice")).toHaveTextContent(
      "Routed 2 events to acme-corp; the vendor site is now mapped there. " +
        "1 could not be replayed (payload truncated on arrival) and stay held — discard them.",
    );
    // The truncated row is still there for a discard.
    await waitFor(() => expect(screen.getByTestId("quarantine-held-total")).toHaveTextContent("1 held event in 1 group"));
  });

  it("pages through everything held and says when the view is partial", async () => {
    const many = Array.from({ length: 450 }, (_, i) => row({ id: i + 1, vendor_tenant_id: `site-${i % 3}` }));
    const backend = stubBackend(many);
    render(<QuarantineReviewPanel />);
    await waitFor(() => screen.getAllByTestId("quarantine-group"));
    const listCalls = backend.calls.filter((c) => c.url.startsWith(`${Q}?`));
    expect(listCalls.map((c) => new URLSearchParams(c.url.split("?")[1]).get("offset"))).toEqual(["0", "200", "400"]);
    expect(screen.getByTestId("quarantine-held-total")).toHaveTextContent("450 held events in 3 groups");
    expect(screen.queryByText(/Showing the newest/)).toBeNull();
  });
});

describe("same-name suggestion (the same-name rule)", () => {
  it("offers ONE click to map the site to the suggested client — never applied by itself", async () => {
    const backend = stubBackend([
      row({ id: 21, vendor_tenant_id: "site-uid-0021", vendor_tenant_label: "ACME CORP.",
            reason: "name-match-suggested", suggested_slug: "acme-corp", suggested_name: "Acme Corp" }),
      row({ id: 22, vendor_tenant_id: "site-uid-0021", vendor_tenant_label: "ACME CORP.",
            reason: "name-match-suggested", suggested_slug: "acme-corp", suggested_name: "Acme Corp" }),
    ]);
    render(<QuarantineReviewPanel />);
    const group = await screen.findByTestId("quarantine-group");
    expect(within(group).getByTestId("quarantine-group-reason")).toHaveTextContent(
      /same name as an existing tenant — confirm it/);
    expect(group).toHaveTextContent(/two different businesses can share one/);
    // Nothing was routed while the panel only showed the suggestion.
    expect(backend.calls.filter((c) => c.method === "POST")).toEqual([]);
    const map = within(group).getByTestId("group-map-suggested");
    expect(map).toHaveTextContent("Map to Acme Corp");
    fireEvent.click(map);
    await waitFor(() => expect(screen.getByTestId("quarantine-notice")).toHaveTextContent(
      "Mapped ACME CORP. to Acme Corp and routed 2 events."));
    const post = backend.calls.find((c) => c.url === `${Q}/bulk-route`);
    expect(post?.body).toEqual({
      instance_id: 7, vendor_tenant_id: "site-uid-0021",
      quarantine_reason: "name-match-suggested", slug: "acme-corp",
    });
  });

  it("a group without a suggestion has no one-click map", async () => {
    stubBackend([row({ id: 31, reason: "ambiguous-name" })]);
    render(<QuarantineReviewPanel />);
    const group = await screen.findByTestId("quarantine-group");
    expect(within(group).queryByTestId("group-map-suggested")).toBeNull();
  });
});
