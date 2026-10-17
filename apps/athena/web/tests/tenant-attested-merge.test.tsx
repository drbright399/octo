import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import TenantsTab from "@/pages/settings/tenants";
import AdminNotices from "@/components/admin-notices";
import type { MeResponse } from "@/contracts/operator";
import type { OperatorNotice } from "@/contracts/notice";
import {
  attestationLength,
  notificationNote,
  type ChangeRequest,
  type MergePreview,
  type Tenant,
} from "@/contracts/tenant";

/**
 * v0.10 item 7 — the attested single-person merge / offboard, in the console:
 *   - two-person approval is the default; a super admin may choose "apply
 *     alone", an admin never sees that choice;
 *   - the merge dialog shows, from the server's preview, the caveats, what
 *     stays with the archived source, and whether the single-person guards
 *     allow it (and why not) — "apply alone" is disabled when they do not;
 *   - the attestation is counted live (trimmed, as the server counts), the
 *     slug is typed back, then the server's STEP_UP_REQUIRED opens re-auth
 *     and the SAME request is retried;
 *   - a server refusal (SINGLE_PERSON_INELIGIBLE) offers the two-person
 *     request in one click;
 *   - the requests panel badges single-person changes, shows the attestation
 *     and lets a SECOND admin record the post-review;
 *   - every other admin sees the notice until they acknowledge it.
 *
 * The real `@/lib/api` runs against a stubbed fetch that keeps state.
 */

const TENANTS = "/api/v1/admin/tenants";
const NOTICES = "/api/v1/admin/notices";
const TYPED = "Auto-created duplicate of the same customer; I compared both tenants today.";

function me(role: MeResponse["role"], operator_id = 1): MeResponse {
  return { operator_id, username: "alice", email: "alice@example.test", role } as MeResponse;
}

function tenant(over: Partial<Tenant> & { slug: string; display_name: string }): Tenant {
  return {
    status: "active", origin: "manual", kind: "client", review_state: "confirmed", compliance_flags: [],
    ai_policy: "none", effective_ai_policy: "none", created_by_instance: null,
    onboarded_at: "2026-09-01T00:00:00.000Z", offboarded_at: null, archived_at: null, notes: null,
    event_count: 3, last_event_at: null, mapped_sources: [], pending_request: null, ...over,
  };
}

const ACME = tenant({ slug: "acme-corp", display_name: "Acme Corp", ai_policy: "local", effective_ai_policy: "local" });
const DUP = tenant({ slug: "acme-dup", display_name: "Acme Corp (dup)", origin: "auto" });

function preview(eligible: boolean): MergePreview {
  return {
    slug: "acme-dup", target: "acme-corp", subject_status: "active", events_to_copy: 3,
    left_behind: { incidents: 1, agent_notes: 0, indicators: 0, tickets: 0 },
    mappings_to_repoint: 1, tokens_to_revoke: 0, scoped_operators: 0,
    target_flags_added: [], target_signoffs_to_revoke: [],
    single_person: eligible
      ? { eligible, reasons: [], subject_effective_ai_policy: "local", target_effective_ai_policy: "local", subject_flags_not_on_target: [] }
      : {
          eligible,
          reasons: [{
            code: "target_ai_more_permissive",
            message: "acme-corp runs AI as 'local', more permissive than acme-dup's 'none' — acme-dup's events would be reasoned over by a model its own policy does not allow",
          }],
          subject_effective_ai_policy: "none", target_effective_ai_policy: "local", subject_flags_not_on_target: [],
        },
    caller_may_apply_alone: true,
    caveats: [
      { code: "irreversible", text: "Irreversible: the source tenant is archived and nothing in Athena brings an archived tenant back." },
      { code: "events_only", text: "Only events are copied." },
      { code: "retriage", text: "Copied events are re-triaged under the TARGET's AI policy." },
      { code: "write_lock", text: "The registry write lock is held for the whole copy. Merge in a quiet window." },
      { code: "scoped_users", text: "Client users scoped to the source are signed out." },
    ],
    attestation_min_chars: 40, attestation_max_chars: 2000,
  };
}

function attestedChange(over: Partial<ChangeRequest> = {}): ChangeRequest {
  return {
    id: 21, kind: "merge", subject_slug: "acme-dup", target_slug: "acme-corp", requested_by: 1,
    requested_at: "2026-09-28T10:00:00.000Z", reason: "same customer", state: "applied",
    decided_by: 1, decided_at: "2026-09-28T10:00:00.000Z", decision_note: "applied alone — attested single-person exception",
    approval_mode: "single_attested", attestation: TYPED, subject_confirmation: "acme-dup",
    post_review_state: "pending", post_reviewed_by: null, post_reviewed_at: null, post_review_note: null,
    ...over,
  };
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

interface Backend {
  calls: Array<{ url: string; method: string; body: unknown }>;
  stepUp: boolean;
  attested: ChangeRequest[];
  notices: OperatorNotice[];
}

function stubBackend(init: {
  eligible?: boolean;
  refuseAlone?: boolean;
  attested?: ChangeRequest[];
  notices?: OperatorNotice[];
  /** A lone super admin: the preview counts no other super admin. */
  alone?: boolean;
} = {}): Backend {
  const backend: Backend = { calls: [], stepUp: false, attested: init.attested ?? [], notices: init.notices ?? [] };
  const access = { tokens_revoked: 0, sessions_revoked: 0, scoped_operators: 0, instance_defaults_cleared: 0 };
  vi.stubGlobal("fetch", vi.fn(async (url: string, opts?: RequestInit) => {
    const method = opts?.method ?? "GET";
    const body = typeof opts?.body === "string" ? JSON.parse(opts.body) : undefined;
    backend.calls.push({ url, method, body });
    if (url.startsWith(`${TENANTS}?`)) {
      return jsonResponse(200, {
        tenants: [ACME, DUP], pending_review: 0, quarantined: 0,
        kinds: ["client"], compliance_tags: ["hipaa", "none"], ai_policies: ["none", "local", "cloud"],
      });
    }
    if (url.startsWith(`${TENANTS}/requests?`)) {
      return jsonResponse(200, { requests: url.includes("approval_mode=single_attested") ? backend.attested : [] });
    }
    if (url === "/api/v1/search/elevate" && method === "POST") {
      backend.stepUp = true;
      return jsonResponse(200, { elevated: true });
    }
    if (url === `${TENANTS}/acme-dup/merge-into/acme-corp/preview`) {
      const p = preview(init.eligible !== false);
      if (!init.alone) return jsonResponse(200, p);
      return jsonResponse(200, {
        ...p,
        single_person: {
          ...p.single_person,
          other_super_admins: 0,
          reasons: p.single_person.reasons.map((r) => ({
            ...r,
            remedy: "set acme-dup's AI policy to 'local' first, if its data may be processed that way — or merge acme-corp into acme-dup instead (keeps acme-dup)",
          })),
        },
      });
    }
    if (url === `${TENANTS}/acme-dup/merge-into/acme-corp` && method === "POST") {
      if (body.approval_mode === "single_attested") {
        if (init.refuseAlone) {
          return jsonResponse(409, {
            code: "SINGLE_PERSON_INELIGIBLE",
            message: "single-person merge refused: acme-dup is tagged [pci] and acme-corp is not. File a two-person request instead.",
          });
        }
        if (!backend.stepUp) return jsonResponse(401, { code: "STEP_UP_REQUIRED", message: "step-up required" });
        return jsonResponse(200, {
          slug: "acme-dup", target: "acme-corp", applied: true, status: "archived", request: null,
          mappings_repointed: 1, events_copied: 3, events_skipped: 0, access,
          target_flags_added: [], signoffs_invalidated: [],
          approval_mode: "single_attested", change_request_id: 21, post_review_state: "pending",
          notifications: { recipients: 2, in_app_error: null, email: "queued" },
        });
      }
      const req: ChangeRequest = {
        id: 22, kind: "merge", subject_slug: "acme-dup", target_slug: "acme-corp", requested_by: 1,
        requested_at: "2026-09-28T10:00:00.000Z", reason: body.reason, state: "pending",
        decided_by: null, decided_at: null, decision_note: null, approval_mode: "two_person",
      };
      return jsonResponse(202, {
        slug: "acme-dup", target: "acme-corp", applied: false, status: "active", request: req,
        mappings_repointed: 0, events_copied: 0, events_skipped: 0, access,
      });
    }
    const review = url.match(new RegExp(`^${TENANTS}/requests/(\\d+)/post-review$`));
    if (review && method === "POST") {
      const next = {
        ...backend.attested.find((c) => c.id === Number(review[1]))!,
        post_review_state: body.verdict === "ok" ? "reviewed_ok" : "reviewed_concern",
        post_reviewed_by: 2, post_reviewed_at: "2026-09-28T11:00:00.000Z", post_review_note: body.note,
      };
      backend.attested = backend.attested.map((c) => (c.id === next.id ? next : c));
      return jsonResponse(200, next);
    }
    if (url === NOTICES) {
      return jsonResponse(200, { notices: backend.notices.filter((n) => !n.acknowledged_at), open: backend.notices.length });
    }
    const ack = url.match(new RegExp(`^${NOTICES}/(\\d+)/acknowledge$`));
    if (ack && method === "POST") {
      backend.notices = backend.notices.map((n) =>
        n.id === Number(ack[1]) ? { ...n, acknowledged_at: "2026-09-28T12:00:00.000Z" } : n);
      return jsonResponse(200, backend.notices.find((n) => n.id === Number(ack[1])));
    }
    return jsonResponse(404, { code: "NOT_FOUND", message: `unexpected ${method} ${url}` });
  }));
  return backend;
}

function renderTab(who: MeResponse) {
  render(<TenantsTab me={who} view="tenants" onNavigate={vi.fn()} />);
}

async function openMerge() {
  fireEvent.click(within(await waitFor(() => screen.getByTestId("tenant-row-acme-dup"))).getByTestId("merge-acme-dup"));
  const dialog = within(screen.getByTestId("merge-dialog"));
  fireEvent.change(dialog.getByLabelText("merge target"), { target: { value: "acme-corp" } });
  await waitFor(() => expect(dialog.getByTestId("merge-caveats")).toBeInTheDocument());
  return dialog;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("contract helpers", () => {
  it("counts the attestation as the server does, and words who was told", () => {
    expect(attestationLength("   abc  \n")).toBe(3);
    expect(notificationNote({ recipients: 2, in_app_error: null, email: "queued" })).toBe(
      " 2 other admin(s) notified in-app; an e-mail copy goes out if a Resend integration is configured.");
    expect(notificationNote({ recipients: 0, in_app_error: null, email: "none" })).toBe(
      " There is no other admin to notify.");
    expect(notificationNote({ recipients: 0, in_app_error: "IntegrityError", email: "none" })).toContain(
      "could NOT be notified in-app (IntegrityError)");
    expect(notificationNote(null)).toBe("");
  });
});

describe("merge dialog — the attested single-person exception", () => {
  it("caveats, eligibility, live count, typed slug, then step-up and the SAME request retried", async () => {
    const backend = stubBackend();
    renderTab(me(["super_admin"]));
    const dialog = await openMerge();
    // The caveats, as the server states them, before anything else.
    for (const code of ["irreversible", "events_only", "retriage", "write_lock", "scoped_users"]) {
      expect(dialog.getByTestId(`merge-caveat-${code}`)).toBeInTheDocument();
    }
    expect(dialog.getByTestId("merge-left-behind")).toHaveTextContent("Stays with the archived acme-dup: 1 incident(s)");
    expect(dialog.getByTestId("merge-eligibility")).toHaveTextContent(
      "Single-person merge allowed: acme-corp runs AI as local, no more permissively than acme-dup (local)");
    fireEvent.click(dialog.getByLabelText("apply alone (attested exception)"));
    fireEvent.change(dialog.getByLabelText("reason"), { target: { value: "same customer" } });
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "acme-dup" } });
    const submit = dialog.getByTestId("merge-submit");
    expect(submit).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: "short" } });
    expect(dialog.getByTestId("attestation-count")).toHaveTextContent("5 / 40 characters minimum");
    expect(submit).toBeDisabled();
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: TYPED } });
    expect(dialog.getByTestId("attestation-count")).toHaveTextContent(`${TYPED.length} / 40`);
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    // The server wants step-up: re-auth opens, then the SAME merge is retried.
    await screen.findByText("Re-authentication required");
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw-example-1" } });
    fireEvent.change(screen.getByLabelText(/TOTP code/i), { target: { value: "123456" } });
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() => expect(screen.queryByTestId("merge-dialog")).toBeNull());
    const posts = backend.calls.filter((c) => c.url === `${TENANTS}/acme-dup/merge-into/acme-corp` && c.method === "POST");
    expect(posts).toHaveLength(2);
    const expected = { reason: "same customer", approval_mode: "single_attested", attestation: TYPED, confirm_subject: "acme-dup" };
    expect(posts[0]!.body).toEqual(expected);
    expect(posts[1]!.body).toEqual(expected);
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent(
      "acme-dup merged into acme-corp alone (attested single-person exception, change #21)");
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent("2 other admin(s) notified in-app");
  });

  it("not eligible: 'apply alone' is disabled with the reasons, and the request still goes through", async () => {
    const backend = stubBackend({ eligible: false });
    renderTab(me(["super_admin"]));
    const dialog = await openMerge();
    expect(dialog.getByTestId("merge-eligibility")).toHaveTextContent("Single-person merge not allowed — two people must decide");
    expect(dialog.getByTestId("merge-ineligible-target_ai_more_permissive")).toHaveTextContent(
      "acme-corp runs AI as 'local', more permissive than acme-dup's 'none'");
    expect(dialog.getByLabelText("apply alone (attested exception)")).toBeDisabled();
    expect(dialog.getByTestId("alone-blocked")).toHaveTextContent("two people must decide");
    expect(dialog.queryByLabelText("attestation")).toBeNull();
    fireEvent.change(dialog.getByLabelText("reason"), { target: { value: "same customer" } });
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "acme-dup" } });
    expect(dialog.getByTestId("merge-submit")).toHaveTextContent("Request merge — a second super admin must approve");
    fireEvent.click(dialog.getByTestId("merge-submit"));
    await waitFor(() => expect(screen.queryByTestId("merge-dialog")).toBeNull());
    const post = backend.calls.find((c) => c.method === "POST" && c.url.endsWith("/merge-into/acme-corp"));
    expect(post?.body).toEqual({ reason: "same customer" });
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent("Merge of acme-dup into acme-corp requested");
  });

  it("a server refusal offers the two-person request in one click", async () => {
    const backend = stubBackend({ refuseAlone: true });
    renderTab(me(["super_admin"]));
    const dialog = await openMerge();
    fireEvent.click(dialog.getByLabelText("apply alone (attested exception)"));
    fireEvent.change(dialog.getByLabelText("reason"), { target: { value: "same customer" } });
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: TYPED } });
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "acme-dup" } });
    fireEvent.click(dialog.getByTestId("merge-submit"));
    await waitFor(() => expect(dialog.getByTestId("single-person-refused")).toHaveTextContent(
      "acme-dup is tagged [pci] and acme-corp is not"));
    expect(screen.queryByText("Re-authentication required")).toBeNull();     // refused before re-auth
    fireEvent.click(dialog.getByTestId("file-request-instead"));
    await waitFor(() => expect(screen.queryByTestId("merge-dialog")).toBeNull());
    const posts = backend.calls.filter((c) => c.method === "POST" && c.url.endsWith("/merge-into/acme-corp"));
    expect(posts.map((p) => p.body)).toEqual([
      { reason: "same customer", approval_mode: "single_attested", attestation: TYPED, confirm_subject: "acme-dup" },
      { reason: "same customer" },
    ]);
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent("requested — a super admin other than you must approve it");
  });

  it("a lone super admin sees what would make it eligible, and no dead-end request offer", async () => {
    stubBackend({ eligible: false, refuseAlone: true, alone: true });
    renderTab(me(["super_admin"]));
    const dialog = await openMerge();
    expect(dialog.getByTestId("merge-remedy-target_ai_more_permissive")).toHaveTextContent(
      "To merge alone: set acme-dup's AI policy to 'local' first");
    expect(dialog.getByTestId("merge-remedy-target_ai_more_permissive")).toHaveTextContent(
      "merge acme-corp into acme-dup instead");
    expect(dialog.getByTestId("merge-no-approver")).toHaveTextContent(
      "A two-person request needs a super admin other than you to approve it, and there is none");
  });

  it("a refusal under the lock does not offer a request nobody could approve", async () => {
    stubBackend({ refuseAlone: true, alone: true });                  // eligible in the preview
    renderTab(me(["super_admin"]));
    const dialog = await openMerge();
    fireEvent.click(dialog.getByLabelText("apply alone (attested exception)"));
    fireEvent.change(dialog.getByLabelText("reason"), { target: { value: "same customer" } });
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: TYPED } });
    fireEvent.change(dialog.getByLabelText("type the slug to confirm"), { target: { value: "acme-dup" } });
    fireEvent.click(dialog.getByTestId("merge-submit"));
    await waitFor(() => expect(dialog.getByTestId("single-person-refused")).toBeInTheDocument());
    expect(dialog.queryByTestId("file-request-instead")).toBeNull();
  });

  it("an admin sees the caveats but never the single-person choice", async () => {
    stubBackend();
    renderTab(me(["admin"]));
    const dialog = await openMerge();
    expect(dialog.getByTestId("merge-caveat-write_lock")).toBeInTheDocument();
    expect(dialog.queryByTestId("approval-choice")).toBeNull();
    expect(dialog.queryByTestId("merge-eligibility")).toBeNull();
    expect(dialog.queryByLabelText("attestation")).toBeNull();
    expect(dialog.getByTestId("merge-submit")).toHaveTextContent("Request merge — a super admin must approve");
  });
});

describe("requests panel — single-person changes and their post-review", () => {
  it("badges them, shows the attestation, and lets a SECOND admin record the post-review", async () => {
    const backend = stubBackend({ attested: [attestedChange()] });
    renderTab(me(["admin"], 2));
    const row = within(await waitFor(() => screen.getByTestId("attested-21")));
    expect(row.getByTestId("attested-badge-21")).toHaveTextContent("applied alone");
    expect(row.getByTestId("post-review-state-21")).toHaveTextContent("post-review pending");
    expect(row.getByTestId("attestation-21")).toHaveTextContent(TYPED);
    expect(row.getByText(/slug typed: acme-dup/)).toBeInTheDocument();
    const submit = row.getByTestId("post-review-submit-21");
    expect(submit).toBeDisabled();                                  // a note is required
    fireEvent.change(row.getByLabelText("post-review verdict for change 21"), { target: { value: "concern" } });
    fireEvent.change(row.getByLabelText("post-review note for change 21"), { target: { value: "no ticket references it" } });
    fireEvent.click(submit);
    await waitFor(() => expect(screen.getByTestId("tenants-notice")).toHaveTextContent(
      "Post-review of change #21 recorded: reviewed — concern raised."));
    expect(backend.calls.find((c) => c.url.endsWith("/requests/21/post-review"))?.body).toEqual({
      verdict: "concern", note: "no ticket references it",
    });
    await waitFor(() => expect(screen.getByTestId("post-review-21")).toHaveTextContent(
      "Reviewed by you"));
  });

  it("the one who applied it cannot review it", async () => {
    stubBackend({ attested: [attestedChange()] });
    renderTab(me(["super_admin"], 1));
    const row = within(await waitFor(() => screen.getByTestId("attested-21")));
    expect(row.getByTestId("post-review-blocked-21")).toHaveTextContent("an admin other than you reviews it");
    expect(row.queryByTestId("post-review-submit-21")).toBeNull();
  });
});

describe("AdminNotices — every other admin is told until they acknowledge", () => {
  const NOTICE: OperatorNotice = {
    id: 5, kind: "single_attested_merge", actor_id: 1, subject_slug: "acme-dup", target_slug: "acme-corp",
    change_request_id: 21, title: "Single-person merge: acme-dup → acme-corp",
    body: "alice (operator #1) merged acme-dup into acme-corp alone, on a typed attestation.",
    created_at: "2026-09-28T10:00:00.000Z", acknowledged_at: null, email_state: "not_configured",
  };

  it("shows the notice to an admin; acknowledging clears it; 'Review it' leads to Tenants", async () => {
    const backend = stubBackend({ notices: [NOTICE] });
    const onNavigate = vi.fn();
    render(<AdminNotices me={me(["admin"], 2)} onNavigate={onNavigate} />);
    const strip = within(await screen.findByTestId("admin-notices"));
    expect(strip.getByText("Single-person merge: acme-dup → acme-corp")).toBeInTheDocument();
    fireEvent.click(strip.getByTestId("admin-notice-review-5"));
    expect(onNavigate).toHaveBeenCalledWith("/settings/tenants");
    fireEvent.click(strip.getByTestId("admin-notice-ack-5"));
    await waitFor(() => expect(screen.queryByTestId("admin-notices")).toBeNull());
    expect(backend.calls.some((c) => c.url === `${NOTICES}/5/acknowledge` && c.method === "POST")).toBe(true);
  });

  it("a mapping-review notice (same-name rule) says so and leads to Integrations", async () => {
    const review: OperatorNotice = {
      id: 6, kind: "mapping_review", actor_id: 0, subject_slug: "global", target_slug: null,
      change_request_id: null, title: "2 tenant mappings made from a name match — please re-review",
      body: "These vendor sites were mapped to a client by NAME alone…",
      created_at: "2026-10-01T10:00:00.000Z", acknowledged_at: null, email_state: "not_configured",
    };
    stubBackend({ notices: [review] });
    const onNavigate = vi.fn();
    render(<AdminNotices me={me(["admin"], 2)} onNavigate={onNavigate} />);
    const strip = await screen.findByTestId("admin-notices");
    expect(strip).toHaveTextContent("tenant mappings to re-review — 1 notice");
    expect(strip).not.toHaveTextContent("applied without a second approver");
    fireEvent.click(within(strip).getByTestId("admin-notice-review-6"));
    expect(onNavigate).toHaveBeenCalledWith("/settings/integrations");
  });

  it("an entity-review notice is its own kind: own heading, line breaks kept, leads to Links with the client", async () => {
    const entity: OperatorNotice = {
      id: 7, kind: "entity_review", actor_id: 0, subject_slug: "acme-corp", target_slug: null,
      change_request_id: null, title: "Entity links to review — acme-corp",
      body: "Entity resolution for acme-corp needs a look (2 item(s)).\n- two sites claimed one alert: event:nextdns:4\n- a rule disagreed with an operator decision: nextdns:2:abc123",
      created_at: "2026-10-01T10:00:00.000Z", acknowledged_at: null, email_state: "not_configured",
    };
    stubBackend({ notices: [entity] });
    const onNavigate = vi.fn();
    render(<AdminNotices me={me(["admin"], 2)} onNavigate={onNavigate} />);
    const strip = await screen.findByTestId("admin-notices");
    expect(strip).toHaveTextContent("entity links to review — 1 notice");
    expect(strip).not.toHaveTextContent("applied without a second approver");
    expect(strip).toHaveAttribute("aria-label", "entity links to review");
    const body = within(strip).getByText(/needs a look/);
    expect(body.className).toContain("whitespace-pre-line");
    fireEvent.click(within(strip).getByTestId("admin-notice-review-7"));
    expect(onNavigate).toHaveBeenCalledWith("/settings/tenants/links?client=acme-corp");
  });

  it("a viewer (client user) fetches nothing and sees nothing", async () => {
    const backend = stubBackend({ notices: [NOTICE] });
    const { unmount } = render(<AdminNotices me={me(["viewer"], 3)} onNavigate={vi.fn()} />);
    expect(screen.queryByTestId("admin-notices")).toBeNull();
    unmount();
    await new Promise((r) => setTimeout(r, 0));
    expect(backend.calls.filter((c) => c.url.startsWith(NOTICES))).toHaveLength(0);
  });

  it("an analyst is paged: a threat notice shows and leads to the fleet map", async () => {
    const page: OperatorNotice = {
      id: 9, kind: "threat_black", actor_id: 0, subject_slug: "acme-corp", target_slug: null,
      change_request_id: null, title: "BLACK: analyst-declared Black — Acme Corp",
      body: "Open the incident in the console.",
      created_at: "2026-10-01T10:00:00.000Z", acknowledged_at: null, email_state: "not_configured",
    };
    const registry: OperatorNotice = { ...page, id: 10, kind: "threat_registry",
                                       title: "Life-safety tag added" };
    const backend = stubBackend({ notices: [page, registry] });
    const onNavigate = vi.fn();
    render(<AdminNotices me={me(["analyst"], 3)} onNavigate={onNavigate} />);
    const strip = await screen.findByTestId("admin-notices");
    expect(strip).toHaveTextContent("security incidents — 2 notices");
    expect(strip).not.toHaveTextContent("applied without a second approver");
    expect(strip).toHaveAttribute("aria-label", "security incidents");
    fireEvent.click(within(strip).getByTestId("admin-notice-review-9"));
    expect(onNavigate).toHaveBeenCalledWith("/fleet");
    fireEvent.click(within(strip).getByTestId("admin-notice-review-10"));
    expect(onNavigate).toHaveBeenCalledWith("/settings/threats");
    expect(backend.calls.filter((c) => c.url.startsWith(NOTICES)).length).toBeGreaterThan(0);
  });
});
