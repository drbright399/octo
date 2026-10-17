import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import TenantsTab from "@/pages/settings/tenants";
import type { MeResponse } from "@/contracts/operator";
import type { ChangeRequest, Tenant } from "@/contracts/tenant";

/**
 * Settings → Tenants: the table renders every lifecycle state, the filters
 * narrow it, Confirm never lets 'unclassified' through, Offboard demands the
 * slug typed back and words itself by role, the request queue keeps the
 * two-person rule (the requester cannot approve their own), and a viewer /
 * analyst gets nothing — no fetch, no data.
 *
 * The real `@/lib/api` runs against a stubbed fetch that keeps state.
 */

const TENANTS = "/api/v1/admin/tenants";

function me(role: MeResponse["role"], operator_id = 1): MeResponse {
  return { operator_id, username: "alice", email: "alice@example.test", role } as MeResponse;
}

function tenant(over: Partial<Tenant> & { slug: string; display_name: string }): Tenant {
  return {
    status: "active",
    origin: "manual",
    kind: "unclassified",
    review_state: "pending",
    compliance_flags: [],
    ai_policy: "none",
    created_by_instance: null,
    onboarded_at: "2026-09-01T00:00:00.000Z",
    offboarded_at: null,
    archived_at: null,
    notes: null,
    event_count: 0,
    last_event_at: null,
    mapped_sources: [],
    pending_request: null,
    ...over,
  };
}

const WIDGET = tenant({
  slug: "widget-co",
  display_name: "Widget Co",
  origin: "auto",
  created_by_instance: { instance_id: 7, vendor: "datto", label: "Datto RMM" },
  event_count: 42,
  last_event_at: "2026-09-22T10:00:00.000Z",
  mapped_sources: [
    { vendor: "datto", instance_id: 7, vendor_tenant_id: "site-uid-0001", label: "Widget Co", match_source: "auto" },
  ],
});
const ACME = tenant({
  slug: "acme-corp",
  display_name: "Acme Corp",
  kind: "client",
  review_state: "confirmed",
  compliance_flags: ["hipaa", "pci"],
  ai_policy: "local",
  event_count: 7,
});
const LAB = tenant({
  slug: "lab-box",
  display_name: "Lab Box",
  origin: "bootstrap",
  kind: "dev",
  review_state: "pending",
});
const GONE = tenant({
  slug: "gone-co",
  display_name: "Gone Co",
  status: "offboarded",
  kind: "client",
  review_state: "confirmed",
  offboarded_at: "2026-09-10T00:00:00.000Z",
});

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

interface Backend {
  tenants: Tenant[];
  requests: ChangeRequest[];
  calls: Array<{ url: string; method: string; body: unknown }>;
}

interface BulkItem {
  slug: string;
  patch: Record<string, unknown>;
}

/** The server's bulk rules, small: PATCH's refusals per row, the diff of
 *  what actually changes, all-or-nothing on apply. */
function bulkAnswer(backend: Backend, items: BulkItem[], superAdmin: boolean) {
  const rows = items.map((item) => {
    const t = backend.tenants.find((x) => x.slug === item.slug);
    if (!t) {
      return { slug: item.slug, display_name: null, status: null, changes: [], error: { code: "CLIENT_NOT_FOUND", message: `no tenant '${item.slug}'` } };
    }
    const p = item.patch;
    const error =
      p.ai_policy === "cloud" && !superAdmin
        ? { code: "ISOLATION_VIOLATION", message: "ai_policy 'cloud' (data may leave this deployment) requires super_admin" }
        : p.review_state === "confirmed" && (p.kind ?? t.kind) === "unclassified"
          ? { code: "VALIDATION_FAILED", message: "set a kind (client / internal / dev / vendor / other) before confirming" }
          : null;
    const current = t as unknown as Record<string, unknown>;
    const changes = error
      ? []
      : Object.entries(p)
          .filter(([f, v]) => JSON.stringify(current[f]) !== JSON.stringify(v))
          .map(([field, after]) => ({ field, before: current[field], after }));
    return { slug: t.slug, display_name: t.display_name, status: t.status, changes, error };
  });
  const errors = rows.filter((r) => r.error).length;
  const changed = rows.filter((r) => !r.error && r.changes.length > 0).length;
  const cloud = rows.some((r) => r.error?.code === "ISOLATION_VIOLATION");
  const refusal = errors
    ? cloud
      ? { code: "ISOLATION_VIOLATION", message: "ai_policy 'cloud' requires super_admin — nothing was changed" }
      : { code: "VALIDATION_FAILED", message: `${errors} of ${rows.length} row(s) cannot be applied. Nothing was changed.` }
    : null;
  return { rows, errors, changed, unchanged: rows.length - errors - changed, refusal, cloud };
}

function stubBackend(
  init: { tenants?: Tenant[]; requests?: ChangeRequest[]; superAdmin?: boolean } = {},
): Backend {
  const backend: Backend = {
    tenants: init.tenants ?? [WIDGET, ACME, LAB, GONE],
    requests: init.requests ?? [],
    calls: [],
  };
  const access = { tokens_revoked: 0, sessions_revoked: 0, scoped_operators: 0, instance_defaults_cleared: 0 };
  const fetchMock = vi.fn(async (url: string, opts?: RequestInit) => {
    const method = opts?.method ?? "GET";
    const body = typeof opts?.body === "string" ? JSON.parse(opts.body) : undefined;
    backend.calls.push({ url, method, body });
    if (url.startsWith(`${TENANTS}?`) && method === "GET") {
      return jsonResponse(200, {
        // A fresh array, as a parsed JSON body always is.
        tenants: backend.tenants.map((t) => ({ ...t })),
        pending_review: backend.tenants.filter((t) => t.review_state === "pending" && t.status === "active").length,
        quarantined: 3,
        kinds: ["unclassified", "client", "internal", "dev", "vendor", "other"],
        compliance_tags: ["hipaa", "cjis", "pci", "bipa", "glba", "ferpa", "none"],
        ai_policies: ["none", "local", "cloud"],
      });
    }
    if (url.startsWith(`${TENANTS}/requests?`) && method === "GET") {
      if (url.includes("approval_mode=single_attested")) {
        return jsonResponse(200, { requests: backend.requests.filter((r) => r.approval_mode === "single_attested") });
      }
      return jsonResponse(200, { requests: backend.requests.filter((r) => r.state === "pending") });
    }
    const preview = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)/merge-into/([a-z0-9-]+)/preview$`));
    if (preview && method === "GET") {
      return jsonResponse(200, {
        slug: preview[1], target: preview[2], subject_status: "active", events_to_copy: 42,
        left_behind: { incidents: 2, agent_notes: 5, indicators: 0, tickets: 1 },
        mappings_to_repoint: 1, tokens_to_revoke: 1, scoped_operators: 0,
        target_flags_added: [], target_signoffs_to_revoke: [],
        single_person: {
          eligible: true, reasons: [], subject_effective_ai_policy: "none",
          target_effective_ai_policy: "none", subject_flags_not_on_target: [],
        },
        caller_may_apply_alone: init.superAdmin === true,
        caveats: [
          { code: "irreversible", text: "Irreversible: the source tenant is archived." },
          { code: "events_only", text: "Only events are copied." },
        ],
        attestation_min_chars: 40, attestation_max_chars: 2000,
      });
    }
    if (url === TENANTS && method === "POST") {
      const created = tenant({
        slug: body.slug,
        display_name: body.display_name,
        kind: body.kind,
        compliance_flags: body.compliance_flags,
        review_state: body.kind === "unclassified" ? "pending" : "confirmed",
      });
      backend.tenants.push(created);
      return jsonResponse(201, created);
    }
    if (url === `${TENANTS}/bulk-update` && method === "POST") {
      const a = bulkAnswer(backend, body.items as BulkItem[], init.superAdmin === true);
      const result = {
        dry_run: body.dry_run === true, applied: false, request_id: null, rows: a.rows,
        changed: a.changed, unchanged: a.unchanged, errors: a.errors, refusal: a.refusal,
      };
      if (body.dry_run) return jsonResponse(200, result);
      if (a.refusal) return jsonResponse(a.cloud ? 403 : 422, { ...result, ...a.refusal, request_id: "req-refused" });
      for (const item of body.items as BulkItem[]) {
        backend.tenants = backend.tenants.map((x) => (x.slug === item.slug ? ({ ...x, ...item.patch } as Tenant) : x));
      }
      return jsonResponse(200, { ...result, applied: true, request_id: "req-1" });
    }
    const patch = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)$`));
    if (patch && method === "PATCH") {
      const t = backend.tenants.find((x) => x.slug === patch[1]);
      if (!t) return jsonResponse(404, { code: "CLIENT_NOT_FOUND", message: "no tenant" });
      if (body.review_state === "confirmed" && (body.kind ?? t.kind) === "unclassified") {
        return jsonResponse(422, {
          code: "VALIDATION_FAILED",
          message: "set a kind (client / internal / dev / vendor / other) before confirming",
        });
      }
      const next = { ...t, ...body };
      backend.tenants = backend.tenants.map((x) => (x.slug === t.slug ? next : x));
      return jsonResponse(200, next);
    }
    const off = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)/offboard$`));
    if (off && method === "POST") {
      if (body.approval_mode === "single_attested") {
        // The super admin's attested exception: applied now.
        return jsonResponse(200, {
          slug: off[1], applied: true, status: "offboarded", request: null, mappings_frozen: 1,
          access: { ...access, tokens_revoked: 2, sessions_revoked: 1, scoped_operators: 1, instance_defaults_cleared: 1 },
          approval_mode: "single_attested", change_request_id: 12, post_review_state: "pending",
          notifications: { recipients: 2, in_app_error: null, email: "queued" },
        });
      }
      const req: ChangeRequest = {
        id: 11, kind: "offboard", subject_slug: off[1] ?? "", target_slug: null, requested_by: 1,
        requested_at: "2026-09-22T11:00:00.000Z", reason: body.reason, state: "pending",
        decided_by: null, decided_at: null, decision_note: null, approval_mode: "two_person",
      };
      backend.requests.push(req);
      return jsonResponse(202, {
        slug: off[1], applied: false, status: "active", request: req, mappings_frozen: 0, access,
      });
    }
    const merge = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)/merge-into/([a-z0-9-]+)$`));
    if (merge && method === "POST") {
      const subject = merge[1] ?? "";
      const target = merge[2] ?? "";
      if (body.approval_mode === "single_attested") {
        // The super admin's attested exception: applied now.
        return jsonResponse(200, {
          slug: subject, target, applied: true, status: "archived", request: null,
          mappings_repointed: 1, events_copied: 40, events_skipped: 2,
          access: { ...access, tokens_revoked: 1, instance_defaults_cleared: 1 },
          approval_mode: "single_attested", change_request_id: 13, post_review_state: "pending",
          notifications: { recipients: 1, in_app_error: null, email: "queued" },
        });
      }
      const req: ChangeRequest = {
        id: 9, kind: "merge", subject_slug: subject, target_slug: target, requested_by: 1,
        requested_at: "2026-09-22T11:00:00.000Z", reason: body.reason, state: "pending",
        decided_by: null, decided_at: null, decision_note: null,
      };
      backend.requests.push(req);
      return jsonResponse(202, {
        slug: subject, target, applied: false, status: "active", request: req,
        mappings_repointed: 0, events_copied: 0, events_skipped: 0, access,
      });
    }
    const decide = url.match(new RegExp(`^${TENANTS}/requests/(\\d+)/(approve|reject|cancel)$`));
    if (decide && method === "POST") {
      const r = backend.requests.find((x) => x.id === Number(decide[1]));
      if (!r) return jsonResponse(404, { code: "NOT_FOUND", message: "no change request" });
      const state = decide[2] === "approve" ? "applied" : decide[2] === "reject" ? "rejected" : "cancelled";
      const next = { ...r, state } as ChangeRequest;
      backend.requests = backend.requests.map((x) => (x.id === r.id ? next : x));
      return jsonResponse(200, next);
    }
    return jsonResponse(404, { code: "NOT_FOUND", message: `unexpected ${method} ${url}` });
  });
  vi.stubGlobal("fetch", fetchMock);
  return backend;
}

function renderTab(who: MeResponse, view: "tenants" | "quarantine" = "tenants", extra: Record<string, unknown> = {}) {
  const onNavigate = vi.fn();
  render(<TenantsTab me={who} view={view} onNavigate={onNavigate} {...extra} />);
  return onNavigate;
}

async function rowFor(slug: string) {
  return waitFor(() => screen.getByTestId(`tenant-row-${slug}`));
}

beforeEach(() => {
  vi.useRealTimers();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("TenantsTab — table", () => {
  it("renders every lifecycle state: kind, compliance, origin, review chip, events, sources, AI, status", async () => {
    stubBackend();
    renderTab(me(["admin"]));
    const widget = within(await rowFor("widget-co"));
    expect(widget.getByText("Widget Co", { selector: "div" })).toBeInTheDocument();
    expect(widget.getByTestId("needs-review-chip")).toHaveTextContent("Needs review");
    expect(widget.getByTestId("kind-badge")).toHaveTextContent("Unclassified");
    expect(widget.getByText("auto-created")).toBeInTheDocument();
    expect(widget.getByText("by Datto RMM")).toBeInTheDocument();
    expect(widget.getByText("42")).toBeInTheDocument();
    expect(widget.getByText(/^last /)).toBeInTheDocument();
    expect(widget.getByText("datto")).toBeInTheDocument();
    expect(widget.getByText(/· auto/)).toBeInTheDocument();
    expect(widget.getByText("none")).toBeInTheDocument();

    const acme = within(screen.getByTestId("tenant-row-acme-corp"));
    expect(acme.getAllByTestId("compliance-badge").map((b) => b.textContent)).toEqual(["HIPAA", "PCI"]);
    expect(acme.getByText("confirmed")).toBeInTheDocument();
    expect(acme.queryByTestId("confirm-acme-corp")).toBeNull();
    expect(acme.getByText("local")).toBeInTheDocument();

    const gone = within(screen.getByTestId("tenant-row-gone-co"));
    expect(gone.getByText("offboarded")).toBeInTheDocument();
    expect(gone.queryByTestId("offboard-gone-co")).toBeNull();
    expect(gone.queryByTestId("merge-gone-co")).toBeNull();

    // Needs-review rows first by default.
    const rows = screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid"));
    expect(rows.slice(0, 2).sort()).toEqual(["tenant-row-lab-box", "tenant-row-widget-co"]);
    // Header counts: 2 need review, 3 held.
    expect(screen.getByTestId("view-tenants")).toHaveTextContent("2");
    expect(screen.getByTestId("view-quarantine")).toHaveTextContent("3");
  });

  it("filters: review state (in the URL), by kind, by compliance, by origin", async () => {
    stubBackend();
    const onNavigate = renderTab(me(["admin"]));
    await rowFor("widget-co");
    expect(screen.getByTestId("tenants-count")).toHaveTextContent("4 of 4");

    fireEvent.change(screen.getByLabelText("filter by review state"), { target: { value: "needs-review" } });
    expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(2);
    expect(screen.queryByTestId("tenant-row-acme-corp")).toBeNull();
    expect(onNavigate).toHaveBeenLastCalledWith("/settings/tenants?filter=needs-review");
    fireEvent.change(screen.getByLabelText("filter by review state"), { target: { value: "confirmed" } });
    expect(screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid")).sort()).toEqual([
      "tenant-row-acme-corp", "tenant-row-gone-co",
    ]);
    expect(onNavigate).toHaveBeenLastCalledWith("/settings/tenants?filter=confirmed");
    fireEvent.change(screen.getByLabelText("filter by review state"), { target: { value: "all" } });
    expect(onNavigate).toHaveBeenLastCalledWith("/settings/tenants");

    fireEvent.change(screen.getByLabelText("filter by kind"), { target: { value: "client" } });
    expect(screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid")).sort()).toEqual([
      "tenant-row-acme-corp", "tenant-row-gone-co",
    ]);
    fireEvent.change(screen.getByLabelText("filter by kind"), { target: { value: "all" } });

    fireEvent.change(screen.getByLabelText("filter by compliance"), { target: { value: "pci" } });
    expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(1);
    expect(screen.getByTestId("tenant-row-acme-corp")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("filter by compliance"), { target: { value: "all" } });

    fireEvent.change(screen.getByLabelText("filter by origin"), { target: { value: "bootstrap" } });
    expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(1);
    expect(screen.getByTestId("tenant-row-lab-box")).toBeInTheDocument();
  });

  it("honours the ?filter=needs-review deep link", async () => {
    stubBackend();
    renderTab(me(["admin"]), "tenants", { reviewFilter: "needs-review" });
    await rowFor("widget-co");
    expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(2);
    expect(screen.getByLabelText("filter by review state")).toHaveValue("needs-review");
  });

  it("the review filter follows the URL: a later navigation to plain /settings/tenants clears it", async () => {
    stubBackend();
    const onNavigate = vi.fn();
    const { rerender } = render(
      <TenantsTab me={me(["admin"])} view="tenants" onNavigate={onNavigate} reviewFilter="needs-review" />,
    );
    await rowFor("widget-co");
    expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(2);
    // The Tenants tab link / the view tab navigates to /settings/tenants:
    // SettingsPage stays mounted and passes the URL's (absent) filter down.
    rerender(<TenantsTab me={me(["admin"])} view="tenants" onNavigate={onNavigate} reviewFilter="all" />);
    await waitFor(() => expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(4));
    expect(screen.getByLabelText("filter by review state")).toHaveValue("all");
    expect(screen.queryByTestId("hidden-by-filters")).toBeNull();
  });

  it("search matches name or slug; 'N hidden by filters — Clear filters' resets every filter", async () => {
    stubBackend();
    const onNavigate = renderTab(me(["admin"]), "tenants", { reviewFilter: "needs-review" });
    await rowFor("widget-co");
    expect(screen.getByTestId("hidden-by-filters")).toHaveTextContent("2 hidden by filters");

    fireEvent.change(screen.getByLabelText("search tenants"), { target: { value: "LAB" } });
    expect(screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid"))).toEqual(["tenant-row-lab-box"]);
    expect(screen.getByTestId("hidden-by-filters")).toHaveTextContent("3 hidden by filters");

    fireEvent.click(screen.getByTestId("clear-filters"));
    expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(4);
    expect(screen.getByLabelText("search tenants")).toHaveValue("");
    expect(screen.getByLabelText("filter by review state")).toHaveValue("all");
    expect(onNavigate).toHaveBeenLastCalledWith("/settings/tenants");
    expect(screen.queryByTestId("hidden-by-filters")).toBeNull();

    // Slug search, too.
    fireEvent.change(screen.getByLabelText("search tenants"), { target: { value: "acme-c" } });
    expect(screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid"))).toEqual(["tenant-row-acme-corp"]);
  });

  it("sorts by events when the header is clicked", async () => {
    stubBackend();
    renderTab(me(["admin"]));
    await rowFor("widget-co");
    fireEvent.click(screen.getByRole("button", { name: /Events/ }));
    const asc = screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid"));
    expect(asc[asc.length - 1]).toBe("tenant-row-widget-co");
    fireEvent.click(screen.getByRole("button", { name: /Events/ }));
    const desc = screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid"));
    expect(desc[0]).toBe("tenant-row-widget-co");
  });
});

describe("TenantsTab — confirm", () => {
  it("does not confirm an unclassified tenant: the dialog demands a kind first", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("widget-co");
    fireEvent.click(screen.getByTestId("confirm-widget-co"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    expect(dialog.getByTestId("confirm-needs-kind")).toBeInTheDocument();
    expect(dialog.getByTestId("confirm-blocked")).toHaveTextContent("Pick a kind to confirm.");
    expect(dialog.getByTestId("tenant-form-save")).toBeDisabled();
    // Nothing was sent.
    expect(backend.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);

    fireEvent.change(dialog.getByLabelText("kind"), { target: { value: "client" } });
    expect(dialog.queryByTestId("confirm-blocked")).toBeNull();
    expect(dialog.getByTestId("tenant-form-save")).toBeEnabled();
    fireEvent.click(dialog.getByTestId("tenant-form-save"));
    await waitFor(() => expect(screen.queryByTestId("tenant-form-dialog")).toBeNull());
    const patch = backend.calls.find((c) => c.method === "PATCH");
    expect(patch?.url).toBe(`${TENANTS}/widget-co`);
    expect(patch?.body).toEqual({ kind: "client", review_state: "confirmed" });
    await waitFor(() => expect(screen.getByTestId("tenants-notice")).toHaveTextContent("confirmed as Client"));
  });

  it("deep link ?filter=needs-review → Confirm → the row stays reachable, with its actions", async () => {
    // The reported bug: under the dashboard's deep link, a confirmed tenant
    // failed the filter and vanished — Edit / Offboard / Merge with it.
    const backend = stubBackend();
    const onNavigate = renderTab(me(["admin"]), "tenants", { reviewFilter: "needs-review" });
    await rowFor("lab-box");
    fireEvent.click(screen.getByTestId("confirm-lab-box"));
    await waitFor(() => expect(backend.calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    await waitFor(() => expect(within(screen.getByTestId("tenant-row-lab-box")).getByText("confirmed")).toBeInTheDocument());
    const lab = within(screen.getByTestId("tenant-row-lab-box"));
    expect(lab.getByTestId("kept-visible-chip")).toBeInTheDocument();
    expect(lab.queryByTestId("confirm-lab-box")).toBeNull();
    expect(lab.getByTestId("edit-lab-box")).toBeEnabled();
    expect(lab.getByTestId("offboard-lab-box")).toBeEnabled();
    expect(lab.getByTestId("merge-lab-box")).toBeEnabled();
    expect(screen.getByTestId("kept-visible-note")).toHaveTextContent("1 row(s) you just changed");

    // The unclassified one goes through the kind dialog — and stays too.
    fireEvent.click(screen.getByTestId("confirm-widget-co"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    fireEvent.change(dialog.getByLabelText("kind"), { target: { value: "client" } });
    fireEvent.click(dialog.getByTestId("tenant-form-save"));
    await waitFor(() => expect(screen.queryByTestId("tenant-form-dialog")).toBeNull());
    await waitFor(() => expect(within(screen.getByTestId("tenant-row-widget-co")).getByText("confirmed")).toBeInTheDocument());
    expect(screen.getByTestId("kept-visible-note")).toHaveTextContent("2 row(s)");

    // "Show all tenants" drops the filter (and the URL's) — everything is there.
    fireEvent.click(screen.getByTestId("show-all-tenants"));
    expect(onNavigate).toHaveBeenLastCalledWith("/settings/tenants");
    expect(screen.getAllByTestId(/^tenant-row-/)).toHaveLength(4);
    expect(screen.queryByTestId("kept-visible-chip")).toBeNull();
  });

  it("a kept row is released as soon as the filters change", async () => {
    stubBackend();
    renderTab(me(["admin"]), "tenants", { reviewFilter: "needs-review" });
    await rowFor("lab-box");
    fireEvent.click(screen.getByTestId("confirm-lab-box"));
    await waitFor(() => expect(screen.getByTestId("kept-visible-note")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("filter by kind"), { target: { value: "dev" } });
    expect(screen.queryByTestId("tenant-row-lab-box")).toBeNull();     // confirmed: fails needs-review now
    expect(screen.queryByTestId("kept-visible-note")).toBeNull();
  });

  it("a disabled or offboarded tenant can be confirmed but is never counted as needing review", async () => {
    const PAUSED = tenant({ slug: "paused-co", display_name: "Paused Co", status: "disabled", kind: "client" });
    const LEFT = tenant({ slug: "left-co", display_name: "Left Co", status: "offboarded", kind: "vendor" });
    const backend = stubBackend({ tenants: [WIDGET, PAUSED, LEFT] });
    renderTab(me(["admin"]));
    await rowFor("paused-co");
    // Only the ACTIVE pending tenant counts (the dashboard notice's number).
    expect(screen.getByTestId("view-tenants")).toHaveTextContent("1");
    const paused = within(screen.getByTestId("tenant-row-paused-co"));
    expect(paused.getByTestId("pending-inactive-chip")).toHaveTextContent("pending · disabled");
    expect(paused.queryByTestId("needs-review-chip")).toBeNull();
    // Offboard and Merge are offered for a disabled tenant (the server allows both).
    expect(paused.getByTestId("offboard-paused-co")).toBeEnabled();
    expect(paused.getByTestId("merge-paused-co")).toBeEnabled();
    // An offboarded tenant: confirmable, but no offboard / merge from here.
    const left = within(screen.getByTestId("tenant-row-left-co"));
    expect(left.queryByTestId("offboard-left-co")).toBeNull();
    expect(left.queryByTestId("merge-left-co")).toBeNull();
    fireEvent.click(left.getByTestId("confirm-left-co"));
    await waitFor(() =>
      expect(backend.calls.find((c) => c.method === "PATCH")).toMatchObject({
        url: `${TENANTS}/left-co`, body: { review_state: "confirmed" },
      }),
    );
    // Needs review = active only: the non-active rows never show under it.
    fireEvent.change(screen.getByLabelText("filter by review state"), { target: { value: "needs-review" } });
    expect(screen.getAllByTestId(/^tenant-row-/).map((r) => r.getAttribute("data-testid"))).toContain("tenant-row-widget-co");
    expect(screen.queryByTestId("tenant-row-paused-co")).toBeNull();
  });

  it("confirms in one click once a kind is set", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("lab-box");
    fireEvent.click(screen.getByTestId("confirm-lab-box"));
    await waitFor(() =>
      expect(backend.calls.find((c) => c.method === "PATCH")?.body).toEqual({ review_state: "confirmed" }),
    );
    await waitFor(() => expect(screen.queryByTestId("confirm-lab-box")).toBeNull());
  });
});

describe("TenantsTab — edit / add", () => {
  it("edit sends only the changed fields and disables 'cloud' for an admin with the reason", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("acme-corp");
    fireEvent.click(screen.getByTestId("edit-acme-corp"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    const cloud = dialog.getByRole("option", { name: /cloud/ }) as HTMLOptionElement;
    expect(cloud.disabled).toBe(true);
    expect(cloud.textContent).toMatch(/super admin only/);
    expect(dialog.getByTestId("ai-policy-help")).toHaveTextContent(/Only a super admin can choose 'cloud'/);
    fireEvent.click(dialog.getByLabelText("compliance CJIS"));
    fireEvent.change(dialog.getByLabelText("display name"), { target: { value: "  Acme   Corporation " } });
    fireEvent.click(dialog.getByTestId("tenant-form-save"));
    await waitFor(() => expect(screen.queryByTestId("tenant-form-dialog")).toBeNull());
    const patch = backend.calls.find((c) => c.method === "PATCH");
    expect(patch?.body).toEqual({ display_name: "Acme Corporation", compliance_flags: ["hipaa", "pci", "cjis"] });
  });

  it("a confirmed tenant's Edit never offers 'unclassified'; a pending one's does", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("acme-corp");
    fireEvent.click(screen.getByTestId("edit-acme-corp"));
    let dialog = within(screen.getByTestId("tenant-form-dialog"));
    const kinds = Array.from((dialog.getByLabelText("kind") as HTMLSelectElement).options).map((o) => o.value);
    expect(kinds).not.toContain("unclassified");
    expect(kinds).toContain("internal");
    fireEvent.change(dialog.getByLabelText("kind"), { target: { value: "internal" } });
    fireEvent.click(dialog.getByTestId("tenant-form-save"));
    await waitFor(() => expect(screen.queryByTestId("tenant-form-dialog")).toBeNull());
    expect(backend.calls.find((c) => c.method === "PATCH")?.body).toEqual({ kind: "internal" });

    fireEvent.click(screen.getByTestId("edit-lab-box"));                   // pending
    dialog = within(screen.getByTestId("tenant-form-dialog"));
    expect(Array.from((dialog.getByLabelText("kind") as HTMLSelectElement).options).map((o) => o.value)).toContain(
      "unclassified",
    );
  });

  it("a legacy confirmed + unclassified row shows its value honestly and still saves other fields", async () => {
    const LEGACY = tenant({ slug: "legacy-co", display_name: "Legacy Co", review_state: "confirmed" });
    const backend = stubBackend({ tenants: [LEGACY] });
    renderTab(me(["admin"]));
    await rowFor("legacy-co");
    fireEvent.click(screen.getByTestId("edit-legacy-co"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    expect(dialog.getByLabelText("kind")).toHaveValue("unclassified");
    expect(dialog.getByTestId("legacy-unclassified-note")).toHaveTextContent("pick one");
    fireEvent.change(dialog.getByLabelText("display name"), { target: { value: "Legacy Company" } });
    fireEvent.click(dialog.getByTestId("tenant-form-save"));
    await waitFor(() => expect(screen.queryByTestId("tenant-form-dialog")).toBeNull());
    expect(backend.calls.find((c) => c.method === "PATCH")?.body).toEqual({ display_name: "Legacy Company" });
  });

  it("a super_admin may pick 'cloud'", async () => {
    stubBackend();
    renderTab(me(["super_admin"]));
    await rowFor("acme-corp");
    fireEvent.click(screen.getByTestId("edit-acme-corp"));
    const cloud = within(screen.getByTestId("tenant-form-dialog")).getByRole("option", { name: "cloud" }) as HTMLOptionElement;
    expect(cloud.disabled).toBe(false);
  });

  it("+ Add tenant suggests a slug from the name, keeps an edited slug, and creates via the API", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("acme-corp");
    fireEvent.click(screen.getByTestId("add-tenant"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    fireEvent.change(dialog.getByLabelText("display name"), { target: { value: "Café Nürnberg & Sons, Inc." } });
    expect(dialog.getByLabelText("slug")).toHaveValue("cafe-nurnberg-sons-inc");
    fireEvent.change(dialog.getByLabelText("slug"), { target: { value: "cafe-ns" } });
    fireEvent.change(dialog.getByLabelText("display name"), { target: { value: "Café Nürnberg" } });
    expect(dialog.getByLabelText("slug")).toHaveValue("cafe-ns");
    fireEvent.change(dialog.getByLabelText("kind"), { target: { value: "client" } });
    fireEvent.click(dialog.getByLabelText("compliance PCI"));
    fireEvent.click(dialog.getByLabelText("compliance none"));   // 'none' clears the rest
    fireEvent.click(dialog.getByTestId("tenant-form-save"));
    await waitFor(() => expect(screen.queryByTestId("tenant-form-dialog")).toBeNull());
    const post = backend.calls.find((c) => c.method === "POST" && c.url === TENANTS);
    expect(post?.body).toEqual({ slug: "cafe-ns", display_name: "Café Nürnberg", kind: "client", compliance_flags: ["none"] });
    await rowFor("cafe-ns");
  });

  it("refuses an invalid slug before calling the API", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("acme-corp");
    fireEvent.click(screen.getByTestId("add-tenant"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    fireEvent.change(dialog.getByLabelText("display name"), { target: { value: "X" } });
    fireEvent.change(dialog.getByLabelText("slug"), { target: { value: "Bad Slug" } });
    expect(dialog.getByTestId("tenant-form-save")).toBeDisabled();
    expect(backend.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });
});

describe("TenantsTab — offboard", () => {
  it("super_admin: a two-person request by default; alone only with a 40-char attestation and the slug typed back", async () => {
    const backend = stubBackend();
    renderTab(me(["super_admin"]));
    await rowFor("acme-corp");
    expect(screen.getByTestId("offboard-acme-corp")).toHaveTextContent("Offboard");
    fireEvent.click(screen.getByTestId("offboard-acme-corp"));
    const dialog = within(screen.getByTestId("offboard-dialog"));
    expect(dialog.getByTestId("offboard-role-note")).toHaveTextContent("Two-person approval is the default");
    const confirm = dialog.getByTestId("offboard-confirm");
    expect(confirm).toHaveTextContent("Request offboard — a second super admin must approve");
    expect(dialog.getByLabelText("two-person request")).toBeChecked();
    expect(dialog.queryByLabelText("attestation")).toBeNull();
    expect(confirm).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("reason"), { target: { value: "contract ended" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "acme-corp" } });
    expect(confirm).toBeEnabled();
    // Alone: the attestation box appears, counted live; 39 typed characters are not enough.
    fireEvent.click(dialog.getByLabelText("apply alone (attested exception)"));
    expect(confirm).toHaveTextContent("Offboard alone (step-up)");
    expect(confirm).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: `  ${"x".repeat(39)}  ` } });
    expect(dialog.getByTestId("attestation-count")).toHaveTextContent("39 / 40 characters minimum");
    expect(confirm).toBeDisabled();
    const typed = "Contract ended today; the client's access must be cut now.";
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: typed } });
    expect(dialog.getByTestId("attestation-count")).toHaveTextContent(`${typed.length} / 40 characters minimum`);
    expect(confirm).toBeEnabled();
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "acme-corpp" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "acme-corp" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(screen.queryByTestId("offboard-dialog")).toBeNull());
    const post = backend.calls.find((c) => c.url === `${TENANTS}/acme-corp/offboard`);
    expect(post?.body).toEqual({
      reason: "contract ended", approval_mode: "single_attested", attestation: typed, confirm_subject: "acme-corp",
    });
    // The notice says exactly what the server severed — and the loose end.
    const notice = screen.getByTestId("tenants-notice");
    expect(notice).toHaveTextContent("acme-corp offboarded alone (attested single-person exception, change #12)");
    expect(notice).toHaveTextContent("1 site mapping(s) frozen");
    expect(notice).toHaveTextContent("2 other admin(s) notified in-app");
    expect(notice).toHaveTextContent("2 buoy/API token(s) revoked, 1 client user session(s) ended, ");
    // The server CLEARS an offboarded tenant's integration defaults (sets NULL);
    // the notice must not claim they were re-pointed anywhere.
    expect(notice).toHaveTextContent(
      "1 integration default(s) cleared — id-less events from that integration will now be held in quarantine.",
    );
    expect(notice).not.toHaveTextContent("re-pointed");
    expect(notice).toHaveTextContent("1 client user account(s) are still scoped to it");
    expect(notice).toHaveTextContent("remove them under Operators");
    expect(notice).toHaveTextContent("Its data is kept.");
  });

  it("the dialog says mappings are frozen (not removed) and what happens to client users", async () => {
    stubBackend();
    renderTab(me(["super_admin"]));
    await rowFor("acme-corp");
    fireEvent.click(screen.getByTestId("offboard-acme-corp"));
    const dialog = within(screen.getByTestId("offboard-dialog"));
    expect(dialog.getByText(/mappings are frozen/)).toBeInTheDocument();
    expect(dialog.getByText(/creating a look-alike tenant/)).toBeInTheDocument();
    expect(dialog.getByText(/client users' sessions are ended/)).toBeInTheDocument();
    expect(dialog.getByText(/remove them under Operators/)).toBeInTheDocument();
    expect(dialog.queryByText(/mappings are removed/)).toBeNull();
  });

  it("admin: 'Request offboard — a super admin must approve'", async () => {
    stubBackend();
    renderTab(me(["admin"]));
    await rowFor("acme-corp");
    expect(screen.getByTestId("offboard-acme-corp")).toHaveTextContent("Request offboard");
    fireEvent.click(screen.getByTestId("offboard-acme-corp"));
    const dialog = within(screen.getByTestId("offboard-dialog"));
    expect(dialog.getByTestId("offboard-role-note")).toHaveTextContent("a super admin must approve it");
    expect(dialog.getByTestId("offboard-confirm")).toHaveTextContent("Request offboard — a super admin must approve");
  });

  it("a tenant with a pending request cannot be offboarded or merged again", async () => {
    const req: ChangeRequest = {
      id: 3, kind: "offboard", subject_slug: "acme-corp", target_slug: null, requested_by: 2,
      requested_at: "2026-09-22T09:00:00.000Z", reason: "contract ended", state: "pending",
      decided_by: null, decided_at: null, decision_note: null,
    };
    stubBackend({ tenants: [{ ...ACME, pending_request: req }, WIDGET], requests: [req] });
    renderTab(me(["super_admin"]));
    const acme = within(await rowFor("acme-corp"));
    expect(acme.getByTestId("pending-request-badge")).toHaveTextContent("offboard request #3");
    expect(acme.getByTestId("offboard-acme-corp")).toBeDisabled();
    expect(acme.getByTestId("merge-acme-corp")).toBeDisabled();
  });
});

describe("TenantsTab — merge", () => {
  it("super_admin: picker, caveats, then alone (attested) — applied at once and the other admins told", async () => {
    const backend = stubBackend({ superAdmin: true });
    renderTab(me(["super_admin"]));
    await rowFor("widget-co");
    fireEvent.click(screen.getByTestId("merge-widget-co"));
    const dialog = within(screen.getByTestId("merge-dialog"));
    expect(dialog.queryByText(/always a request/)).toBeNull();
    expect(dialog.getByTestId("merge-role-note")).toHaveTextContent("Two-person approval is the default");
    expect(dialog.getByText(/every event of widget-co is copied into the target/i)).toBeInTheDocument();
    expect(dialog.getByText(/buoy\/API tokens stop working/)).toBeInTheDocument();
    expect(dialog.getByText(/the tenant that will be archived/)).toBeInTheDocument();
    const options = (dialog.getByLabelText("merge target") as HTMLSelectElement).options;
    const values = Array.from(options).map((o) => o.value);
    expect(values).toContain("acme-corp");
    expect(values).toContain("lab-box");
    expect(values).not.toContain("widget-co");   // not itself
    expect(values).not.toContain("gone-co");     // not offboarded
    // Nothing to apply alone until a target is picked and checked.
    expect(dialog.getByLabelText("apply alone (attested exception)")).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("merge target"), { target: { value: "acme-corp" } });
    await waitFor(() => expect(dialog.getByTestId("merge-caveats")).toBeInTheDocument());
    expect(dialog.getByTestId("merge-caveat-irreversible")).toHaveTextContent("Irreversible");
    expect(dialog.getByTestId("merge-left-behind")).toHaveTextContent(
      "Moves: 42 event(s). Stays with the archived widget-co: 2 incident(s), 5 agent note(s), 0 indicator(s), 1 ticket(s).",
    );
    expect(dialog.getByTestId("merge-eligibility")).toHaveTextContent("Single-person merge allowed");
    fireEvent.change(dialog.getByLabelText("reason"), { target: { value: "same customer twice" } });
    expect(dialog.getByTestId("merge-submit")).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "widget-co" } });
    expect(dialog.getByTestId("merge-submit")).toHaveTextContent("Request merge — a second super admin must approve");
    fireEvent.click(dialog.getByLabelText("apply alone (attested exception)"));
    expect(dialog.getByTestId("merge-submit")).toHaveTextContent("Merge alone (step-up)");
    expect(dialog.getByTestId("merge-submit")).toBeDisabled();
    const typed = "Auto-created duplicate; I compared both tenants' tags today.";
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: typed } });
    fireEvent.click(dialog.getByTestId("merge-submit"));
    await waitFor(() => expect(screen.queryByTestId("merge-dialog")).toBeNull());
    expect(
      backend.calls.find((c) => c.url === `${TENANTS}/widget-co/merge-into/acme-corp` && c.method === "POST")?.body,
    ).toEqual({
      reason: "same customer twice", approval_mode: "single_attested", attestation: typed, confirm_subject: "widget-co",
    });
    const notice = screen.getByTestId("tenants-notice");
    expect(notice).toHaveTextContent("widget-co merged into acme-corp alone (attested single-person exception, change #13)");
    expect(notice).toHaveTextContent("40 event(s) copied (2 already there)");
    expect(notice).toHaveTextContent("1 other admin(s) notified in-app");
    expect(notice).toHaveTextContent("1 site mapping(s) re-pointed, 1 buoy/API token(s) revoked");
    // A merge re-points the defaults at the target (what `_apply_merge` does).
    expect(notice).toHaveTextContent("1 integration default(s) re-pointed to acme-corp.");
    expect(notice).not.toHaveTextContent("cleared");
    expect(notice).toHaveTextContent("widget-co is archived.");
    expect(screen.queryByTestId("request-9")).toBeNull();
  });

  it("admin: 'Request merge — a super admin must approve' creates a request", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("widget-co");
    fireEvent.click(screen.getByTestId("merge-widget-co"));
    const dialog = within(screen.getByTestId("merge-dialog"));
    expect(dialog.getByTestId("merge-role-note")).toHaveTextContent("a super admin other than you must approve");
    fireEvent.change(dialog.getByLabelText("merge target"), { target: { value: "acme-corp" } });
    fireEvent.change(dialog.getByLabelText("reason"), { target: { value: "same customer twice" } });
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "widget-co" } });
    expect(dialog.getByTestId("merge-submit")).toHaveTextContent("Request merge — a super admin must approve");
    fireEvent.click(dialog.getByTestId("merge-submit"));
    await waitFor(() => expect(screen.queryByTestId("merge-dialog")).toBeNull());
    expect(backend.calls.find((c) => c.url === `${TENANTS}/widget-co/merge-into/acme-corp`)?.body).toEqual({
      reason: "same customer twice",
    });
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent("Merge of widget-co into acme-corp requested");
    await waitFor(() => expect(screen.getByTestId("request-9")).toBeInTheDocument());
  });
});

describe("TenantsTab — background poll", () => {
  it("keeps an unread action error on screen across the 30 s reload", async () => {
    const backend = stubBackend();
    // Capture the poll so it can be fired on demand (real timers stay real).
    const polls: Array<() => void> = [];
    const realSetInterval = window.setInterval;
    vi.spyOn(window, "setInterval").mockImplementation(((fn: () => void, ms?: number) => {
      polls.push(fn);
      return realSetInterval(() => undefined, ms ?? 60_000);
    }) as typeof window.setInterval);
    renderTab(me(["admin"]));
    await rowFor("lab-box");
    const original = fetch;
    vi.stubGlobal("fetch", async (url: string, opts?: RequestInit) => {
      if (url === `${TENANTS}/lab-box` && opts?.method === "PATCH") {
        return jsonResponse(409, { code: "CONFLICT", message: "tenant 'lab-box' is archived" });
      }
      return original(url, opts);
    });
    fireEvent.click(screen.getByTestId("confirm-lab-box"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("tenant 'lab-box' is archived"));
    // The 30 s poll refreshes the data …
    const listCalls = backend.calls.filter((c) => c.url.startsWith(`${TENANTS}?`)).length;
    expect(polls.length).toBeGreaterThan(0);
    polls.forEach((p) => p());
    await waitFor(() =>
      expect(backend.calls.filter((c) => c.url.startsWith(`${TENANTS}?`)).length).toBeGreaterThan(listCalls),
    );
    // … but the error the operator has not acted on is still there.
    expect(screen.getByRole("alert")).toHaveTextContent("tenant 'lab-box' is archived");
  });
});

describe("TenantsTab — requests panel (two-person rule)", () => {
  const MINE: ChangeRequest = {
    id: 11, kind: "merge", subject_slug: "lab-box", target_slug: "acme-corp", requested_by: 1,
    requested_at: "2026-09-22T09:00:00.000Z", reason: "dupe", state: "pending",
    decided_by: null, decided_at: null, decision_note: null,
  };
  const THEIRS: ChangeRequest = {
    id: 12, kind: "offboard", subject_slug: "widget-co", target_slug: null, requested_by: 2,
    requested_at: "2026-09-22T09:30:00.000Z", reason: "left us", state: "pending",
    decided_by: null, decided_at: null, decision_note: null,
  };

  it("super_admin: Approve/Reject disabled with the reason on their own request, enabled on another's; Cancel only on their own", async () => {
    const backend = stubBackend({ requests: [MINE, THEIRS] });
    renderTab(me(["super_admin"], 1));
    await waitFor(() => screen.getByTestId("request-11"));
    const mine = within(screen.getByTestId("request-11"));
    expect(mine.getByText(/by you/)).toBeInTheDocument();
    expect(mine.getByTestId("approve-11")).toBeDisabled();
    expect(mine.getByTestId("reject-11")).toBeDisabled();
    expect(mine.getByTestId("decide-blocked-11")).toHaveTextContent("two-person rule");
    expect(mine.getByTestId("cancel-11")).toBeEnabled();

    const theirs = within(screen.getByTestId("request-12"));
    expect(theirs.getByText(/operator #2/)).toBeInTheDocument();
    expect(theirs.getByTestId("approve-12")).toBeEnabled();
    expect(theirs.queryByTestId("cancel-12")).toBeNull();
    fireEvent.change(theirs.getByLabelText("decision note for request 12"), { target: { value: "ok by me" } });
    fireEvent.click(theirs.getByTestId("approve-12"));
    await waitFor(() => expect(screen.queryByTestId("request-12")).toBeNull());
    expect(backend.calls.find((c) => c.url === `${TENANTS}/requests/12/approve`)?.body).toEqual({ note: "ok by me" });
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent("Request #12 approved and applied: offboard of widget-co");
  });

  it("admin: no Approve/Reject at all, Cancel on their own request", async () => {
    const backend = stubBackend({ requests: [MINE, THEIRS] });
    renderTab(me(["admin"], 1));
    await waitFor(() => screen.getByTestId("request-11"));
    expect(screen.queryByTestId("approve-11")).toBeNull();
    expect(screen.queryByTestId("approve-12")).toBeNull();
    expect(screen.getByTestId("decide-blocked-12")).toHaveTextContent("Only a super admin can decide");
    fireEvent.click(screen.getByTestId("cancel-11"));
    await waitFor(() => expect(screen.queryByTestId("request-11")).toBeNull());
    expect(backend.calls.find((c) => c.url === `${TENANTS}/requests/11/cancel`)).toBeTruthy();
  });

  it("shows the server's refusal when a decision is rejected", async () => {
    const backend = stubBackend({ requests: [THEIRS] });
    renderTab(me(["super_admin"], 1));
    await waitFor(() => screen.getByTestId("request-12"));
    // The backend now says no (e.g. someone else already applied it).
    const original = fetch;
    vi.stubGlobal("fetch", async (url: string, opts?: RequestInit) => {
      if (url === `${TENANTS}/requests/12/approve`) {
        return jsonResponse(409, { code: "CONFLICT", message: "change request 12 is applied" });
      }
      return original(url, opts);
    });
    fireEvent.click(screen.getByTestId("approve-12"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("change request 12 is applied"));
    expect(backend.calls.filter((c) => c.url.endsWith("/approve"))).toHaveLength(0);
  });
});

describe("TenantsTab — role gate", () => {
  it.each([["viewer"], ["analyst"]])("%s: refuses to render and fetches nothing", async (role) => {
    const backend = stubBackend();
    renderTab(me([role as MeResponse["role"][number]]));
    expect(screen.getByTestId("tenants-forbidden")).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 20));
    expect(backend.calls).toHaveLength(0);
    expect(screen.queryByTestId("tenants-table")).toBeNull();
    expect(screen.queryByText("Widget Co")).toBeNull();
  });
});

describe("TenantsTab — quarantine view", () => {
  it("renders the quarantine panel with the instance pre-filter and switches views via the nav", async () => {
    const backend = stubBackend();
    const original = fetch;
    vi.stubGlobal("fetch", async (url: string, opts?: RequestInit) => {
      if (url.startsWith("/api/v1/admin/quarantine?")) {
        return jsonResponse(200, { rows: [], total: 0, limit: 200, offset: 0, reasons: [] });
      }
      if (url === "/api/v1/integrations") {
        return jsonResponse(200, { definitions: [], instances: {} });
      }
      return original(url, opts);
    });
    const onNavigate = renderTab(me(["admin"]), "quarantine", { initialInstanceId: 7 });
    await waitFor(() => screen.getByTestId("quarantine-review"));
    expect(screen.getByTestId("quarantine-empty")).toHaveTextContent("Nothing is held in quarantine.");
    expect(screen.queryByTestId("add-tenant")).toBeNull();
    fireEvent.click(screen.getByTestId("view-tenants"));
    expect(onNavigate).toHaveBeenCalledWith("/settings/tenants");
    expect(backend.calls.length).toBeGreaterThan(0);
  });
});

describe("TenantsTab — bulk review", () => {
  const bulkCalls = (b: Backend) => b.calls.filter((c) => c.url === `${TENANTS}/bulk-update`);

  it("select → Bulk edit → per-row diff preview (nothing written) → apply the same rows", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("widget-co");
    expect(screen.queryByTestId("bulk-bar")).toBeNull();
    fireEvent.click(screen.getByTestId("select-widget-co"));
    fireEvent.click(screen.getByTestId("select-lab-box"));
    fireEvent.click(screen.getByTestId("select-acme-corp"));
    expect(screen.getByTestId("bulk-bar")).toHaveTextContent("3 selected");
    fireEvent.click(screen.getByTestId("bulk-edit"));

    const dialog = within(screen.getByTestId("bulk-edit-dialog"));
    expect(dialog.getByTestId("bulk-preview-btn")).toBeDisabled();        // nothing chosen yet
    // 'unclassified' is never a bulk kind; 'cloud' is a super admin's choice.
    expect(Array.from((dialog.getByLabelText("bulk kind") as HTMLSelectElement).options).map((o) => o.value)).not.toContain(
      "unclassified",
    );
    expect((dialog.getByRole("option", { name: /cloud/ }) as HTMLOptionElement).disabled).toBe(true);
    fireEvent.change(dialog.getByLabelText("bulk kind"), { target: { value: "client" } });
    fireEvent.change(dialog.getByLabelText("bulk compliance mode"), { target: { value: "add" } });
    fireEvent.click(dialog.getByLabelText("compliance HIPAA"));
    fireEvent.click(dialog.getByLabelText("confirm review"));
    fireEvent.click(dialog.getByTestId("bulk-preview-btn"));

    await waitFor(() => expect(dialog.getByTestId("bulk-preview")).toBeInTheDocument());
    const preview = bulkCalls(backend)[0];
    expect(preview?.body).toEqual({
      dry_run: true,
      // In the table's order (needs-review first, then by name).
      items: [
        // "add" merges onto each tenant's own tags.
        { slug: "lab-box", patch: { kind: "client", compliance_flags: ["hipaa"], review_state: "confirmed" } },
        { slug: "widget-co", patch: { kind: "client", compliance_flags: ["hipaa"], review_state: "confirmed" } },
        { slug: "acme-corp", patch: { kind: "client", compliance_flags: ["hipaa", "pci"], review_state: "confirmed" } },
      ],
    });
    expect(backend.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
    expect(dialog.getByTestId("bulk-summary")).toHaveTextContent("2 will change · 1 already set · 0 refused");
    const widget = within(dialog.getByTestId("bulk-row-widget-co"));
    expect(widget.getByText("Unclassified")).toBeInTheDocument();
    expect(widget.getByText("Client")).toBeInTheDocument();
    expect(widget.getByText(/review:/)).toBeInTheDocument();
    expect(within(dialog.getByTestId("bulk-row-acme-corp")).getByTestId("bulk-row-unchanged")).toBeInTheDocument();

    fireEvent.click(dialog.getByTestId("bulk-apply"));
    await waitFor(() => expect(screen.queryByTestId("bulk-edit-dialog")).toBeNull());
    const applied = bulkCalls(backend)[1];
    expect(applied?.body).toEqual({ ...(preview?.body as object), dry_run: false });
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent("Bulk review applied: 2 tenant(s) updated, one audit entry each");
    expect(screen.queryByTestId("bulk-bar")).toBeNull();                   // selection cleared
    await waitFor(() => expect(within(screen.getByTestId("tenant-row-widget-co")).getByText("confirmed")).toBeInTheDocument());
  });

  it("refused rows block the apply; dropping them re-previews the rest", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("widget-co");
    fireEvent.click(screen.getByTestId("select-widget-co"));   // unclassified
    fireEvent.click(screen.getByTestId("select-lab-box"));     // dev
    fireEvent.click(screen.getByTestId("bulk-edit"));
    const dialog = within(screen.getByTestId("bulk-edit-dialog"));
    fireEvent.click(dialog.getByLabelText("confirm review"));
    expect(dialog.getByTestId("bulk-needs-kind")).toHaveTextContent("1 selected tenant(s) are still unclassified");
    fireEvent.click(dialog.getByTestId("bulk-preview-btn"));
    await waitFor(() => expect(dialog.getByTestId("bulk-summary")).toHaveTextContent("1 refused"));
    expect(within(dialog.getByTestId("bulk-row-widget-co")).getByTestId("bulk-row-error")).toHaveTextContent(
      "set a kind",
    );
    expect(dialog.getByTestId("bulk-refusal")).toHaveTextContent("Nothing was changed");
    expect(dialog.getByTestId("bulk-apply")).toBeDisabled();

    fireEvent.click(dialog.getByTestId("bulk-drop-refused"));
    await waitFor(() => expect(dialog.getByTestId("bulk-summary")).toHaveTextContent("1 will change · 0 already set · 0 refused"));
    expect(dialog.queryByTestId("bulk-row-widget-co")).toBeNull();
    expect(bulkCalls(backend)[1]?.body).toEqual({
      dry_run: true, items: [{ slug: "lab-box", patch: { review_state: "confirmed" } }],
    });
    fireEvent.click(dialog.getByTestId("bulk-apply"));
    await waitFor(() => expect(screen.queryByTestId("bulk-edit-dialog")).toBeNull());
    expect(backend.tenants.find((t) => t.slug === "widget-co")?.review_state).toBe("pending");
    expect(backend.tenants.find((t) => t.slug === "lab-box")?.review_state).toBe("confirmed");
  });

  it("an apply refused by the server (state changed since the preview) writes nothing and shows every row", async () => {
    const backend = stubBackend();
    renderTab(me(["admin"]));
    await rowFor("lab-box");
    fireEvent.click(screen.getByTestId("select-lab-box"));
    fireEvent.click(screen.getByTestId("bulk-edit"));
    const dialog = within(screen.getByTestId("bulk-edit-dialog"));
    fireEvent.change(dialog.getByLabelText("bulk kind"), { target: { value: "vendor" } });
    fireEvent.click(dialog.getByTestId("bulk-preview-btn"));
    await waitFor(() => expect(dialog.getByTestId("bulk-apply")).toBeEnabled());
    // Someone archived it in the meantime: the server refuses the batch.
    const original = fetch;
    vi.stubGlobal("fetch", async (url: string, opts?: RequestInit) => {
      if (url === `${TENANTS}/bulk-update`) {
        return jsonResponse(422, {
          code: "VALIDATION_FAILED", message: "1 of 1 row(s) cannot be applied (see each row's error). Nothing was changed.",
          request_id: "r", dry_run: false, applied: false,
          rows: [{ slug: "lab-box", display_name: "Lab Box", status: "archived", changes: [],
                   error: { code: "CONFLICT", message: "tenant 'lab-box' is archived" } }],
          changed: 0, unchanged: 0, errors: 1, refusal: null,
        });
      }
      return original(url, opts);
    });
    fireEvent.click(dialog.getByTestId("bulk-apply"));
    await waitFor(() =>
      expect(within(dialog.getByTestId("bulk-row-lab-box")).getByTestId("bulk-row-error")).toHaveTextContent("is archived"),
    );
    expect(dialog.getAllByRole("alert").map((a) => a.textContent).join(" ")).toContain("Nothing was changed");
    expect(dialog.getByTestId("bulk-apply")).toBeDisabled();
    expect(screen.getByTestId("bulk-edit-dialog")).toBeInTheDocument();
    expect(backend.tenants.find((t) => t.slug === "lab-box")?.kind).toBe("dev");
  });

  it("super_admin may choose 'cloud' in bulk; select-all takes only the rows shown", async () => {
    const backend = stubBackend({ superAdmin: true });
    renderTab(me(["super_admin"]), "tenants", { reviewFilter: "needs-review" });
    await rowFor("widget-co");
    fireEvent.click(screen.getByTestId("select-all"));
    expect(screen.getByTestId("bulk-bar")).toHaveTextContent("2 selected");   // not the hidden rows
    fireEvent.click(screen.getByTestId("bulk-edit"));
    const dialog = within(screen.getByTestId("bulk-edit-dialog"));
    expect((dialog.getByRole("option", { name: "cloud" }) as HTMLOptionElement).disabled).toBe(false);
    fireEvent.change(dialog.getByLabelText("bulk AI policy"), { target: { value: "cloud" } });
    fireEvent.click(dialog.getByTestId("bulk-preview-btn"));
    await waitFor(() => expect(dialog.getByTestId("bulk-apply")).toBeEnabled());
    const items = (bulkCalls(backend)[0]?.body as { items: BulkItem[] }).items;
    expect(items.map((i) => i.slug).sort()).toEqual(["lab-box", "widget-co"]);
    expect(items.every((i) => i.patch.ai_policy === "cloud")).toBe(true);
  });
});

describe("TenantsTab — duplicate hints", () => {
  const DUP_A = tenant({
    slug: "acme-holdings-tax", display_name: "Acme Holdings Tax",
    duplicate_hints: [{ slug: "acme-holdings-llc", display_name: "Acme Holdings LLC", status: "active", rule: "name-prefix" }],
  });
  const DUP_B = tenant({
    slug: "acme-holdings-llc", display_name: "Acme Holdings LLC", kind: "client", review_state: "confirmed",
    duplicate_hints: [{ slug: "acme-holdings-tax", display_name: "Acme Holdings Tax", status: "active", rule: "name-prefix" }],
  });
  const RETURNING = tenant({
    slug: "widget-company", display_name: "Widget Company",
    duplicate_hints: [{ slug: "widget-old", display_name: "Widget Co", status: "offboarded", rule: "same-name" }],
  });
  const OLD = tenant({
    slug: "widget-old", display_name: "Widget Co", status: "offboarded", kind: "client", review_state: "confirmed",
    duplicate_hints: [{ slug: "widget-company", display_name: "Widget Company", status: "active", rule: "same-name" }],
  });

  it("shows the hint and opens the ordinary merge dialog pre-filled — never merges by itself", async () => {
    const backend = stubBackend({ tenants: [DUP_A, DUP_B, RETURNING, OLD] });
    renderTab(me(["super_admin"]));
    await rowFor("acme-holdings-tax");
    const hint = within(screen.getByTestId("duplicate-hint-acme-holdings-tax-acme-holdings-llc"));
    expect(hint.getByText(/possible duplicate of Acme Holdings LLC/)).toHaveAttribute(
      "title", expect.stringContaining("leading part"),
    );
    fireEvent.click(hint.getByTestId("duplicate-merge-acme-holdings-tax-acme-holdings-llc"));
    const dialog = within(screen.getByTestId("merge-dialog"));
    expect(dialog.getByText(/Merge Acme Holdings Tax into/)).toBeInTheDocument();
    expect(dialog.getByLabelText("merge target")).toHaveValue("acme-holdings-llc");
    expect(dialog.getByTestId("merge-submit")).toBeDisabled();          // slug + reason still required
    // The pre-filled pair is previewed (a read) — never merged.
    await waitFor(() => expect(dialog.getByTestId("merge-caveats")).toBeInTheDocument());
    expect(backend.calls.filter((c) => c.url.includes("/merge-into/") && c.method === "POST")).toHaveLength(0);
  });

  it("an offboarded look-alike is hinted but offers no merge from either row", async () => {
    stubBackend({ tenants: [RETURNING, OLD] });
    renderTab(me(["super_admin"]));
    await rowFor("widget-company");
    const hint = within(screen.getByTestId("duplicate-hint-widget-company-widget-old"));
    expect(hint.getByText(/possible duplicate of Widget Co \(offboarded\)/)).toBeInTheDocument();
    expect(hint.queryByRole("button")).toBeNull();
    expect(within(screen.getByTestId("duplicate-hint-widget-old-widget-company")).queryByRole("button")).toBeNull();
  });
});

describe("TenantsTab — placeholder names", () => {
  // Auto-created with no vendor name: "<vendor> site <id>", and the slug made
  // from it. Client users must never see a vendor name, so the server refuses
  // to invite a viewer to either — the chips say why before anyone tries.
  const UNNAMED = tenant({
    slug: "datto-site-1a2b3c4d", display_name: "datto site 1a2b3c4d", origin: "auto",
    placeholder_name: true, placeholder_slug: true,
  });
  const RENAMED = tenant({
    slug: "datto-site-9f8e7d6c", display_name: "Widget West", origin: "auto",
    placeholder_name: false, placeholder_slug: true,
  });

  it("flags a placeholder name and a placeholder slug; a named tenant gets neither", async () => {
    stubBackend({ tenants: [UNNAMED, RENAMED, ACME] });
    renderTab(me(["admin"]));
    const unnamed = within(await rowFor("datto-site-1a2b3c4d"));
    expect(unnamed.getByTestId("placeholder-name-datto-site-1a2b3c4d")).toHaveTextContent(
      "placeholder name — rename before inviting client users",
    );
    expect(unnamed.getByTestId("placeholder-slug-datto-site-1a2b3c4d")).toBeInTheDocument();

    const renamed = within(await rowFor("datto-site-9f8e7d6c"));
    expect(renamed.queryByTestId("placeholder-name-datto-site-9f8e7d6c")).toBeNull();
    expect(renamed.getByTestId("placeholder-slug-datto-site-9f8e7d6c")).toHaveTextContent(
      /placeholder slug — merge into a properly named tenant/,
    );
    expect(renamed.getByTestId("placeholder-slug-datto-site-9f8e7d6c")).toHaveAttribute(
      "title", expect.stringContaining("can't be renamed"),
    );

    const acme = within(await rowFor("acme-corp"));
    expect(acme.queryByTestId(/placeholder-/)).toBeNull();
  });
});
