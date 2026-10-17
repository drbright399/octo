import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  BulkUpdateRefused,
  acknowledgeNotice,
  bulkDiscardQuarantined,
  bulkRouteQuarantined,
  bulkUpdateTenants,
  decideChangeRequest,
  fetchReviewSummary,
  getQuarantined,
  listChangeRequests,
  listNotices,
  listQuarantine,
  listTenants,
  mergeTenant,
  offboardTenant,
  patchTenant,
  postReviewChangeRequest,
  previewMerge,
  routeQuarantined,
} from "@/lib/api";
import {
  KIND_HELP,
  addComplianceTags,
  bulkEditIsEmpty,
  bulkPatchFor,
  canBeMergeTarget,
  canConfirm,
  canMergeFrom,
  canOffboard,
  explainQuarantineReason,
  needsReview,
  reviewFilterFromParam,
  reviewFilterPath,
  suggestSlug,
  toggleComplianceTag,
  type BulkEdit,
  type Tenant,
} from "@/contracts/tenant";

/** The tenant/quarantine client: URLs, bodies, defaults for a sparse body,
 *  and the server's own message + code on refusal. */

const calls: Array<{ url: string; init: RequestInit | undefined }> = [];

function stub(status: number, body: unknown) {
  calls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      return { ok: status < 300, status, json: async () => body };
    }),
  );
}

const body = (i = 0): unknown => JSON.parse(String(calls[i]?.init?.body));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("tenant API client", () => {
  it("listTenants: include_archived, no-store, and safe defaults", async () => {
    stub(200, { tenants: [{ slug: "a" }] });
    const r = await listTenants();
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants?include_archived=1");
    expect(calls[0]?.init).toMatchObject({ credentials: "include", cache: "no-store" });
    expect(r.tenants).toHaveLength(1);
    expect(r.pending_review).toBe(0);
    expect(r.kinds).toEqual([]);
  });

  it("fetchReviewSummary hits the cheap count endpoint", async () => {
    stub(200, { pending_review: 1, quarantined: 2, pending_requests: 3 });
    expect(await fetchReviewSummary()).toEqual({ pending_review: 1, quarantined: 2, pending_requests: 3 });
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/review-summary");
  });

  it("patchTenant / offboardTenant / decideChangeRequest send the documented bodies", async () => {
    stub(200, {});
    await patchTenant("acme-corp", { kind: "client", review_state: "confirmed" });
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/acme-corp");
    expect(calls[0]?.init?.method).toBe("PATCH");
    expect(body()).toEqual({ kind: "client", review_state: "confirmed" });

    stub(202, { slug: "acme-corp", applied: false });
    await offboardTenant("acme-corp", "contract ended");
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/acme-corp/offboard");
    expect(body()).toEqual({ reason: "contract ended" });

    // Merge has the same shape as offboard: {reason} alone is the two-person request (v0.10).
    stub(200, { slug: "acme-dup", target: "acme-corp", applied: true, status: "archived", request: null });
    const merged = await mergeTenant("acme-dup", "acme-corp", "same customer");
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/acme-dup/merge-into/acme-corp");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(body()).toEqual({ reason: "same customer" });
    expect(merged.applied).toBe(true);

    stub(200, { id: 4, state: "applied" });
    await decideChangeRequest(4, "approve", "  looks right ");
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/requests/4/approve");
    expect(body()).toEqual({ note: "looks right" });
    stub(200, { id: 4, state: "cancelled" });
    await decideChangeRequest(4, "cancel");
    expect(body()).toEqual({});

    stub(200, { requests: [] });
    await listChangeRequests("all");
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/requests?state=all");
  });

  it("v0.10: the attested single-person bodies, the preview, post-review and notices", async () => {
    const attested = { attestation: "x".repeat(40), confirm_subject: "acme-dup" };
    stub(200, { slug: "acme-dup", applied: true });
    await offboardTenant("acme-dup", "contract ended", attested);
    expect(body()).toEqual({
      reason: "contract ended", approval_mode: "single_attested", attestation: "x".repeat(40), confirm_subject: "acme-dup",
    });
    stub(200, { slug: "acme-dup", target: "acme-corp", applied: true });
    await mergeTenant("acme-dup", "acme-corp", "same customer", attested);
    expect(body()).toEqual({
      reason: "same customer", approval_mode: "single_attested", attestation: "x".repeat(40), confirm_subject: "acme-dup",
    });
    // The server's refusal keeps its code — the dialog offers the two-person request on it.
    stub(409, { code: "SINGLE_PERSON_INELIGIBLE", message: "single-person merge refused: …" });
    const err = await mergeTenant("acme-dup", "acme-corp", "same customer", attested).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("SINGLE_PERSON_INELIGIBLE");

    stub(200, { slug: "acme-dup", target: "acme-corp" });
    await previewMerge("acme-dup", "acme-corp");
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/acme-dup/merge-into/acme-corp/preview");
    expect(calls[0]?.init).toMatchObject({ credentials: "include", cache: "no-store" });

    stub(200, { id: 5, post_review_state: "reviewed_ok" });
    await postReviewChangeRequest(5, "ok", "  checked the ticket ");
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/requests/5/post-review");
    expect(body()).toEqual({ verdict: "ok", note: "checked the ticket" });

    stub(200, { requests: [] });
    await listChangeRequests("all", "single_attested");
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/requests?state=all&approval_mode=single_attested");

    stub(200, {});
    expect(await listNotices()).toEqual({ notices: [], open: 0 });
    expect(calls[0]?.url).toBe("/api/v1/admin/notices");
    await listNotices(true);
    expect(calls[1]?.url).toBe("/api/v1/admin/notices?include_acknowledged=1");
    stub(200, { id: 3, acknowledged_at: "2026-09-28T12:00:00.000Z" });
    await acknowledgeNotice(3);
    expect(calls[0]?.url).toBe("/api/v1/admin/notices/3/acknowledge");
    expect(calls[0]?.init?.method).toBe("POST");
  });

  it("quarantine list query + detail payload as text + route/discard bodies", async () => {
    stub(200, { rows: [], total: 0 });
    await listQuarantine({ instance_id: 7, reason: "name-unknown", state: "held", limit: 200, offset: 400 });
    expect(calls[0]?.url).toBe("/api/v1/admin/quarantine?instance_id=7&reason=name-unknown&state=held&limit=200&offset=400");

    stub(200, { id: 3, payload: 42 });
    expect((await getQuarantined(3)).payload).toBe("");   // never anything but a string
    expect(calls[0]?.url).toBe("/api/v1/admin/quarantine/3");

    stub(200, { slug: "acme-corp", routed: 1 });
    await routeQuarantined(3, { slug: "acme-corp" });
    expect(calls[0]?.url).toBe("/api/v1/admin/quarantine/3/route");
    expect(body()).toEqual({ slug: "acme-corp" });

    stub(200, { slug: "new-co", routed: 30 });
    await bulkRouteQuarantined({
      instance_id: 7, vendor_tenant_id: "site-uid-0007", quarantine_reason: "autocreate-limit",
      target: { new: { display_name: "New Co", kind: "client", compliance_flags: [] } },
    });
    expect(calls[0]?.url).toBe("/api/v1/admin/quarantine/bulk-route");
    expect(body()).toEqual({
      instance_id: 7, vendor_tenant_id: "site-uid-0007", quarantine_reason: "autocreate-limit",
      new: { display_name: "New Co", kind: "client", compliance_flags: [] },
    });

    stub(200, { discarded: 2 });
    await bulkDiscardQuarantined({ instance_id: 7, vendor_tenant_id: "site-uid-0007", reason: "demo noise" });
    expect(calls[0]?.url).toBe("/api/v1/admin/quarantine/bulk-discard");
    expect(body()).toEqual({ instance_id: 7, vendor_tenant_id: "site-uid-0007", reason: "demo noise" });
  });

  it("surfaces the server's message and code on refusal", async () => {
    stub(409, { code: "CONFLICT", message: "two-person rule: a change request must be approved by a different super_admin", request_id: "r" });
    const err = await decideChangeRequest(1, "approve").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toMatch(/two-person rule/);
    expect((err as ApiError).code).toBe("CONFLICT");
    expect((err as ApiError).status).toBe(409);
  });
});

describe("tenant contract helpers", () => {
  it("suggestSlug mirrors the server's slug_from_name shape", () => {
    expect(suggestSlug("Acme Corp")).toBe("acme-corp");
    expect(suggestSlug("  Café Nürnberg & Sons, Inc. ")).toBe("cafe-nurnberg-sons-inc");
    expect(suggestSlug("---")).toBe("");
    expect(suggestSlug("x".repeat(80))).toHaveLength(48);
  });

  it("toggleComplianceTag keeps 'none' exclusive", () => {
    expect(toggleComplianceTag([], "hipaa")).toEqual(["hipaa"]);
    expect(toggleComplianceTag(["hipaa", "pci"], "none")).toEqual(["none"]);
    expect(toggleComplianceTag(["none"], "cjis")).toEqual(["cjis"]);
    expect(toggleComplianceTag(["hipaa", "pci"], "pci")).toEqual(["hipaa"]);
  });

  it("explainQuarantineReason has plain words for every known reason and a fallback", () => {
    expect(explainQuarantineReason("ambiguous-name").body).toMatch(/matched more than one existing tenant by name/);
    expect(explainQuarantineReason("offboarded-tenant").body).toMatch(/will NOT resurrect/);
    // A default pointing at NO client is a misconfiguration, not an offboarding —
    // its own reason, and its text says so, so nobody hunts for a departed tenant.
    const missing = explainQuarantineReason("default-tenant-missing");
    expect(missing.title).toMatch(/does not exist/);
    expect(missing.body).toMatch(/nothing was offboarded/);
    expect(missing.body).toMatch(/default is misconfigured/);
    expect(missing.body).not.toMatch(/resurrect/);
    expect(explainQuarantineReason("name-already-mapped").body).toMatch(/already mapped to it/);
    // The 'other' kind's help must not send the operator to a notes field that does not exist.
    expect(KIND_HELP.other).not.toMatch(/notes/);
    expect(explainQuarantineReason("something-new").title).toBe("something-new");
  });

  it("review filter ↔ URL, and 'needs review' is the server's predicate (pending AND active)", () => {
    expect(reviewFilterFromParam("needs-review")).toBe("needs-review");
    expect(reviewFilterFromParam("confirmed")).toBe("confirmed");
    expect(reviewFilterFromParam("anything-else")).toBe("all");
    expect(reviewFilterFromParam(null)).toBe("all");
    expect(reviewFilterPath("all")).toBe("/settings/tenants");
    expect(reviewFilterPath("needs-review")).toBe("/settings/tenants?filter=needs-review");
    const t = (status: Tenant["status"], review_state: Tenant["review_state"]) =>
      ({ status, review_state }) as Tenant;
    expect(needsReview(t("active", "pending"))).toBe(true);
    expect(needsReview(t("disabled", "pending"))).toBe(false);
    expect(needsReview(t("offboarded", "pending"))).toBe(false);
    expect(canConfirm(t("offboarded", "pending"))).toBe(true);
    expect(canConfirm(t("archived", "pending"))).toBe(false);
    expect(canOffboard(t("disabled", "confirmed"))).toBe(true);
    expect(canMergeFrom(t("disabled", "confirmed"))).toBe(true);
    expect(canMergeFrom(t("offboarded", "confirmed"))).toBe(false);
    expect(canBeMergeTarget(t("disabled", "confirmed"))).toBe(false);
  });

  it("bulkPatchFor: leave / add / replace, confirm, and an empty edit", () => {
    const acme = { compliance_flags: ["pci"] } as unknown as Tenant;
    const none = { compliance_flags: ["none"] } as unknown as Tenant;
    const base: BulkEdit = { kind: null, complianceMode: "leave", compliance: [], aiPolicy: null, confirm: false };
    expect(bulkEditIsEmpty(base)).toBe(true);
    expect(bulkEditIsEmpty({ ...base, complianceMode: "add" })).toBe(true);        // nothing to add
    expect(bulkEditIsEmpty({ ...base, complianceMode: "replace" })).toBe(false);   // replace with [] clears
    expect(bulkPatchFor(acme, { ...base, kind: "client", confirm: true })).toEqual({ kind: "client", review_state: "confirmed" });
    expect(bulkPatchFor(acme, { ...base, complianceMode: "add", compliance: ["hipaa"] })).toEqual({ compliance_flags: ["hipaa", "pci"] });
    expect(bulkPatchFor(none, { ...base, complianceMode: "add", compliance: ["hipaa"] })).toEqual({ compliance_flags: ["hipaa"] });
    expect(bulkPatchFor(acme, { ...base, complianceMode: "add", compliance: ["none"] })).toEqual({ compliance_flags: ["none"] });
    expect(bulkPatchFor(acme, { ...base, complianceMode: "replace", compliance: ["glba", "cjis"] })).toEqual({
      compliance_flags: ["cjis", "glba"],
    });
    expect(bulkPatchFor(acme, { ...base, aiPolicy: "local" })).toEqual({ ai_policy: "local" });
    expect(addComplianceTags(["pci"], [])).toEqual(["pci"]);
  });
});

describe("bulk update client", () => {
  it("posts {items, dry_run} and returns the per-row answer", async () => {
    stub(200, { dry_run: true, applied: false, request_id: null, rows: [], changed: 0, unchanged: 0, errors: 0, refusal: null });
    await bulkUpdateTenants([{ slug: "acme-corp", patch: { kind: "client" } }], true);
    expect(calls[0]?.url).toBe("/api/v1/admin/tenants/bulk-update");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(body()).toEqual({ items: [{ slug: "acme-corp", patch: { kind: "client" } }], dry_run: true });
  });

  it("a refused batch throws BulkUpdateRefused carrying every row's answer", async () => {
    stub(403, {
      code: "ISOLATION_VIOLATION", message: "ai_policy 'cloud' requires super_admin — nothing was changed", request_id: "r",
      rows: [{ slug: "acme-corp", display_name: "Acme Corp", status: "active", changes: [],
               error: { code: "ISOLATION_VIOLATION", message: "requires super_admin" } }],
      changed: 0, unchanged: 0, errors: 1, refusal: { code: "ISOLATION_VIOLATION", message: "requires super_admin" },
    });
    const err = await bulkUpdateTenants([{ slug: "acme-corp", patch: { ai_policy: "cloud" } }], false).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BulkUpdateRefused);
    expect(err).toBeInstanceOf(ApiError);
    const refused = err as BulkUpdateRefused;
    expect(refused.status).toBe(403);
    expect(refused.code).toBe("ISOLATION_VIOLATION");
    expect(refused.message).toMatch(/nothing was changed/);
    expect(refused.result?.rows[0]?.error?.code).toBe("ISOLATION_VIOLATION");
    expect(refused.result?.errors).toBe(1);

    stub(500, {});
    const bare = await bulkUpdateTenants([{ slug: "acme-corp", patch: { kind: "client" } }], false).catch((e: unknown) => e);
    expect((bare as BulkUpdateRefused).result).toBeNull();
    expect((bare as BulkUpdateRefused).message).toBe("Bulk update failed");
  });
});
