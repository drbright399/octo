import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import TenantsTab from "@/pages/settings/tenants";
import type { MeResponse } from "@/contracts/operator";
import {
  AI_POLICY_HELP,
  NO_CLOUD_MODEL_NOTE,
  aiPolicyView,
  canSignOff,
  effectiveAiPolicy,
  regimesNotCovered,
  signoffRequired,
  type ComplianceSignoff,
  type SignoffHistoryResponse,
  type Tenant,
} from "@/contracts/tenant";
import { clearsCloudWithoutSignoff, cloudSignoffNote } from "@/components/tenant-dialogs";

/**
 * v0.10 — compliance sign-off before cloud AI, in the console:
 *   - the AI column shows what RUNS: "cloud → local" (with why) for a tenant
 *     that asked for cloud without a live sign-off — never plain "cloud";
 *   - a super admin signs from that cell: the dialog shows the tenant's
 *     current flags (sent back as acknowledge_flags), the attestation
 *     template + version, one agreement reference per regime (labelled with
 *     that regime's instrument) and a typed attestation, and the server's
 *     STEP_UP_REQUIRED opens re-auth then retries the same sign;
 *   - "cloud" reads as CLEARED for cloud, with the note that no cloud model
 *     is connected yet;
 *   - an edit that would clear a tenant for cloud with no sign-off (tagged
 *     'none' while asking for cloud) cannot be saved by an admin, and a
 *     super admin's save re-authenticates then retries;
 *   - an admin sees the history read-only; revoke is super admin + step-up;
 *   - the Edit dialog, bulk preview and merge dialog say when cloud will run
 *     as local, and which sign-off a tag change / merge revokes.
 *
 * The real `@/lib/api` runs against a stubbed fetch that keeps state.
 */

const TENANTS = "/api/v1/admin/tenants";
const TEXT = "I have checked Acme's tags today and our BAA with them covers cloud processing of alerts.";

function me(role: MeResponse["role"], operator_id = 1): MeResponse {
  return { operator_id, username: "alice", email: "alice@example.test", role } as MeResponse;
}

function tenant(over: Partial<Tenant> & { slug: string; display_name: string }): Tenant {
  return {
    status: "active",
    origin: "manual",
    kind: "client",
    review_state: "confirmed",
    compliance_flags: [],
    ai_policy: "none",
    effective_ai_policy: "none",
    ai_policy_reason: null,
    signoff: { state: "required", signoff_id: null, signed_by: null, signed_at: null, expires_at: null, flags_covered: null },
    created_by_instance: null,
    onboarded_at: "2026-09-01T00:00:00.000Z",
    offboarded_at: null,
    archived_at: null,
    notes: null,
    event_count: 3,
    last_event_at: null,
    mapped_sources: [],
    pending_request: null,
    ...over,
  };
}

const ACME = tenant({
  slug: "acme-corp",
  display_name: "Acme Corp",
  compliance_flags: ["hipaa"],
  ai_policy: "cloud",
  effective_ai_policy: "local",
  ai_policy_reason: "cloud requested — degraded to local: sign-off required for [hipaa]",
});
const GLOBEX = tenant({
  slug: "globex-inc",
  display_name: "Globex Inc",
  compliance_flags: ["pci"],
  ai_policy: "cloud",
  effective_ai_policy: "cloud",
  ai_policy_reason: "cloud permitted — sign-off #4 covers [pci] until 2027-09-28",
  signoff: {
    state: "live", signoff_id: 4, signed_by: 1, signed_at: "2026-09-28T10:00:00.000Z",
    expires_at: "2027-09-28T10:00:00.000Z", flags_covered: ["pci"],
  },
});
const PLAIN = tenant({
  slug: "plain-co",
  display_name: "Plain Co",
  compliance_flags: ["none"],
  ai_policy: "local",
  effective_ai_policy: "local",
  signoff: { state: "not_required", signoff_id: null, signed_by: null, signed_at: null, expires_at: null, flags_covered: null },
});

const INSTRUMENT: Readonly<Record<string, string>> = {
  hipaa: "HIPAA business associate agreement (BAA)",
  cjis: "CJIS Security Addendum",
  pci: "PCI DSS service-provider responsibility agreement",
  untagged: "data-processing agreement",
};

function signoffRow(over: Partial<ComplianceSignoff> & { id: number }): ComplianceSignoff {
  return {
    slug: "acme-corp", policy: "cloud", flags_covered: ["hipaa"], agreement_references: { hipaa: "BAA-2026-001" },
    attestation_text: TEXT, attestation_sha256: "c".repeat(64), attestation_version: "2026-09-28.v2",
    signed_by: 1, signed_at: "2026-09-01T10:00:00.000Z", expires_at: "2027-09-01T10:00:00.000Z",
    revoked_at: null, revoked_by: null, revoked_kind: null, revoke_reason: null, state: "live",
    ...over,
  };
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

interface Backend {
  tenants: Tenant[];
  calls: Array<{ url: string; method: string; body: unknown }>;
  stepUp: boolean;
}

function history(t: Tenant, signoffs: ComplianceSignoff[]): SignoffHistoryResponse {
  return {
    slug: t.slug, display_name: t.display_name, status: t.status,
    ai_policy: {
      requested: t.ai_policy, effective: t.effective_ai_policy ?? "none",
      degraded: t.ai_policy !== t.effective_ai_policy, reason: t.ai_policy_reason ?? null,
      flags: t.compliance_flags, signoff: t.signoff!,
    },
    signoffs,
    attestation: { version: "2026-09-28.v2", text: "I am an Athena Admin for this MSP…", min_chars: 40, max_chars: 2000 },
    agreements_required: (t.compliance_flags.filter((f) => f !== "none").length
      ? t.compliance_flags.filter((f) => f !== "none").sort()
      : ["untagged"]
    ).map((key) => ({ key, instrument: INSTRUMENT[key] ?? key })),
    term_months_default: 12, term_months_max: 12, agreement_reference_max_chars: 120,
  };
}

function stubBackend(init: {
  tenants?: Tenant[];
  signoffs?: Record<string, ComplianceSignoff[]>;
  signStatus?: number;
  bulkRows?: unknown[];
  /** Applying the bulk batch clears a tenant for cloud: step-up first. */
  bulkStepUp?: boolean;
} = {}): Backend {
  const backend: Backend = { tenants: init.tenants ?? [ACME, GLOBEX, PLAIN], calls: [], stepUp: false };
  const signoffs = init.signoffs ?? {};
  const fetchMock = vi.fn(async (url: string, opts?: RequestInit) => {
    const method = opts?.method ?? "GET";
    const body = typeof opts?.body === "string" ? JSON.parse(opts.body) : undefined;
    backend.calls.push({ url, method, body });
    if (url.startsWith(`${TENANTS}?`) && method === "GET") {
      return jsonResponse(200, {
        tenants: backend.tenants.map((t) => ({ ...t })),
        pending_review: 0, quarantined: 0,
        kinds: ["unclassified", "client", "internal", "dev", "vendor", "other"],
        compliance_tags: ["hipaa", "cjis", "pci", "bipa", "glba", "ferpa", "none"],
        ai_policies: ["none", "local", "cloud"],
      });
    }
    if (url.startsWith(`${TENANTS}/requests?`)) return jsonResponse(200, { requests: [] });
    if (url === "/api/v1/search/elevate" && method === "POST") {
      backend.stepUp = true;
      return jsonResponse(200, { elevated: true });
    }
    const hist = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)/compliance-signoffs$`));
    if (hist && method === "GET") {
      const t = backend.tenants.find((x) => x.slug === hist[1])!;
      return jsonResponse(200, history(t, signoffs[t.slug] ?? []));
    }
    const sign = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)/compliance-signoff$`));
    if (sign && method === "POST") {
      if (!backend.stepUp) return jsonResponse(401, { code: "STEP_UP_REQUIRED", message: "step-up required" });
      if (init.signStatus === 409) {
        return jsonResponse(409, {
          code: "CONFLICT",
          message: "tenant 'acme-corp' is tagged [hipaa, pci], not [hipaa] — its flags changed since the dialog opened",
        });
      }
      const t = backend.tenants.find((x) => x.slug === sign[1])!;
      const row = signoffRow({ id: 9, slug: t.slug, flags_covered: body.acknowledge_flags, expires_at: "2027-09-28T10:00:00.000Z" });
      const next: Tenant = { ...t, effective_ai_policy: t.ai_policy, signoff: { ...t.signoff!, state: "live", signoff_id: 9 } };
      backend.tenants = backend.tenants.map((x) => (x.slug === t.slug ? next : x));
      return jsonResponse(201, {
        slug: t.slug, signoff: row, superseded: [],
        ai_policy: { requested: t.ai_policy, effective: t.ai_policy, degraded: false, reason: null, flags: t.compliance_flags, signoff: next.signoff },
      });
    }
    const revoke = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)/compliance-signoff/(\\d+)/revoke$`));
    if (revoke && method === "POST") {
      if (!backend.stepUp) return jsonResponse(401, { code: "STEP_UP_REQUIRED", message: "step-up required" });
      const t = backend.tenants.find((x) => x.slug === revoke[1])!;
      return jsonResponse(200, {
        slug: t.slug, signoff: signoffRow({ id: Number(revoke[2]), state: "revoked" }), superseded: [],
        ai_policy: { requested: "cloud", effective: "local", degraded: true, reason: "revoked", flags: t.compliance_flags, signoff: t.signoff },
      });
    }
    if (url === `${TENANTS}/bulk-update` && method === "POST") {
      const dry = (body as { dry_run?: boolean }).dry_run === true;
      if (!dry && init.bulkStepUp && !backend.stepUp) {
        return jsonResponse(401, { code: "STEP_UP_REQUIRED", message: "step-up required" });
      }
      return jsonResponse(200, {
        dry_run: dry, applied: !dry, request_id: dry ? null : "req-1", rows: init.bulkRows ?? [],
        changed: (init.bulkRows ?? []).length, unchanged: 0, errors: 0, refusal: null,
        step_up_required: init.bulkStepUp ?? false,
      });
    }
    const patch = url.match(new RegExp(`^${TENANTS}/([a-z0-9-]+)$`));
    if (patch && method === "PATCH") {
      const t = backend.tenants.find((x) => x.slug === patch[1])!;
      const next: Tenant = { ...t, ...(body as Partial<Tenant>) };
      const clears = next.ai_policy === "cloud" && !signoffRequired(next.compliance_flags);
      if (clears && !backend.stepUp) return jsonResponse(401, { code: "STEP_UP_REQUIRED", message: "step-up required" });
      const saved: Tenant = { ...next, effective_ai_policy: clears ? "cloud" : next.effective_ai_policy };
      backend.tenants = backend.tenants.map((x) => (x.slug === t.slug ? saved : x));
      return jsonResponse(200, saved);
    }
    return jsonResponse(404, { code: "NOT_FOUND", message: `unexpected ${method} ${url}` });
  });
  vi.stubGlobal("fetch", fetchMock);
  return backend;
}

function renderTab(who: MeResponse) {
  render(<TenantsTab me={who} view="tenants" onNavigate={vi.fn()} />);
}

async function rowFor(slug: string) {
  return waitFor(() => screen.getByTestId(`tenant-row-${slug}`));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("AI policy contract helpers", () => {
  it("effective policy, the badge, who can sign, the merge algebra", () => {
    expect(effectiveAiPolicy({ ai_policy: "cloud", effective_ai_policy: "local" })).toBe("local");
    // An older backend sends no effective policy: cloud is never implied.
    expect(effectiveAiPolicy({ ai_policy: "cloud" })).toBe("local");
    expect(effectiveAiPolicy({ ai_policy: "local" })).toBe("local");
    expect(aiPolicyView(ACME)).toMatchObject({ label: "cloud → local", degraded: true, tone: "high" });
    expect(aiPolicyView(ACME).title).toContain("sign-off required for [hipaa]");
    // "cloud" is a clearance: no cloud model is connected yet, and the badge
    // and its tooltip say so.
    expect(aiPolicyView(GLOBEX)).toMatchObject({ label: "cloud (cleared)", degraded: false });
    expect(aiPolicyView(GLOBEX).title).toBe(
      `cloud permitted — sign-off #4 covers [pci] until 2027-09-28 ${NO_CLOUD_MODEL_NOTE}`);
    expect(AI_POLICY_HELP.cloud).toContain(NO_CLOUD_MODEL_NOTE);
    expect(signoffRequired([])).toBe(true);
    expect(signoffRequired(["none"])).toBe(false);
    expect(signoffRequired(["hipaa"])).toBe(true);
    expect(canSignOff(ACME)).toBe(true);
    expect(canSignOff(GLOBEX)).toBe(false);                     // already live
    expect(canSignOff(PLAIN)).toBe(false);                      // tagged none
    expect(canSignOff({ ...ACME, status: "offboarded" })).toBe(false);
    expect(regimesNotCovered(["pci"], ["hipaa"])).toEqual(["pci"]);
    expect(regimesNotCovered([], ["hipaa"])).toEqual([]);
    expect(regimesNotCovered(["none"], ["hipaa"])).toEqual([]);
    expect(regimesNotCovered(["hipaa"], ["hipaa", "pci"])).toEqual([]);
  });

  it("the Edit dialog's note: local until signed, or which sign-off a tag change revokes", () => {
    expect(cloudSignoffNote(ACME, "cloud", ["hipaa"])).toMatch(/^Runs as local until a super admin signs off for cloud AI covering \[hipaa\]/);
    expect(cloudSignoffNote(null, "cloud", [])).toMatch(/no compliance tags yet/);
    expect(cloudSignoffNote(ACME, "cloud", ["none"])).toBeNull();
    expect(cloudSignoffNote(ACME, "local", ["hipaa"])).toBeNull();
    expect(cloudSignoffNote(GLOBEX, "cloud", ["pci"])).toBeNull();          // live and unchanged
    expect(cloudSignoffNote(GLOBEX, "cloud", ["hipaa", "pci"])).toBe(
      "Changing the compliance tags revokes sign-off #4 — this tenant will run as local until a super admin signs off for [hipaa, pci].",
    );
  });
});

describe("TenantsTab — AI column", () => {
  it("shows what runs: 'cloud → local' with why, 'cloud' only when signed; Sign off… only for a super admin", async () => {
    stubBackend();
    renderTab(me(["super_admin"]));
    const acme = within(await rowFor("acme-corp"));
    expect(acme.getByTestId("ai-policy-acme-corp")).toHaveTextContent("cloud → local");
    expect(acme.getByTestId("ai-policy-acme-corp")).toHaveAttribute(
      "title", "cloud requested — degraded to local: sign-off required for [hipaa]");
    expect(acme.getByTestId("ai-policy-why-acme-corp")).toHaveTextContent("sign-off required");
    expect(acme.getByTestId("sign-off-acme-corp")).toBeInTheDocument();
    const globex = within(screen.getByTestId("tenant-row-globex-inc"));
    expect(globex.getByTestId("ai-policy-globex-inc")).toHaveTextContent(/^cloud \(cleared\)$/);
    expect(globex.getByText("signed until 2027-09-28")).toBeInTheDocument();
    expect(globex.queryByTestId("sign-off-globex-inc")).toBeNull();
    expect(globex.getByTestId("signoffs-globex-inc")).toBeInTheDocument();
    const plain = within(screen.getByTestId("tenant-row-plain-co"));
    expect(plain.getByTestId("ai-policy-plain-co")).toHaveTextContent(/^local$/);
    expect(plain.queryByTestId("signoffs-plain-co")).toBeNull();
  });

  it("an admin never gets Sign off…; the history opens read-only", async () => {
    stubBackend({ signoffs: { "globex-inc": [signoffRow({ id: 4, slug: "globex-inc", flags_covered: ["pci"] })] } });
    renderTab(me(["admin"]));
    const acme = within(await rowFor("acme-corp"));
    expect(acme.queryByTestId("sign-off-acme-corp")).toBeNull();
    fireEvent.click(acme.getByTestId("signoffs-acme-corp"));
    let dialog = within(await screen.findByTestId("compliance-signoff-dialog"));
    await waitFor(() => expect(dialog.getByTestId("signoff-readonly")).toBeInTheDocument());
    expect(dialog.queryByTestId("signoff-form")).toBeNull();
    expect(dialog.getByTestId("signoff-history-empty")).toBeInTheDocument();
    fireEvent.click(dialog.getByText("Close"));

    fireEvent.click(screen.getByTestId("signoffs-globex-inc"));
    dialog = within(await screen.findByTestId("compliance-signoff-dialog"));
    await waitFor(() => expect(dialog.getByTestId("signoff-row-4")).toBeInTheDocument());
    expect(dialog.getByTestId("signoff-row-state-4")).toHaveTextContent("signed");
    expect(dialog.getByTestId("signoff-row-agreements-4")).toHaveTextContent("hipaa: BAA-2026-001");
    expect(dialog.queryByTestId("signoff-revoke-4")).toBeNull();
    expect(dialog.getByTestId("signoff-effective")).toHaveTextContent("cleared for cloud");
    expect(dialog.getByTestId("signoff-no-cloud-model")).toHaveTextContent(NO_CLOUD_MODEL_NOTE);
  });
});

describe("Sign off for cloud AI", () => {
  it("shows the flags, template and version; needs an agreement per regime + typed attestation; re-auths then signs exactly those flags", async () => {
    const backend = stubBackend();
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("acme-corp")).getByTestId("sign-off-acme-corp"));
    const dialog = within(await screen.findByTestId("compliance-signoff-dialog"));
    await waitFor(() => expect(dialog.getByTestId("signoff-form")).toBeInTheDocument());
    expect(dialog.getByTestId("signoff-effective")).toHaveTextContent("cloud requested → runs as local");
    expect(dialog.getByTestId("signoff-reason")).toHaveTextContent("sign-off required for [hipaa]");
    expect(dialog.getByTestId("signoff-flags")).toHaveTextContent("HIPAA");
    expect(dialog.getByTestId("signoff-template")).toHaveTextContent("I am an Athena Admin for this MSP");
    expect(dialog.getByText(/version 2026-09-28\.v2/)).toBeInTheDocument();

    const submit = dialog.getByTestId("signoff-submit");
    expect(submit).toBeDisabled();
    expect(submit).toHaveTextContent("Sign off for [hipaa] (step-up)");
    fireEvent.change(dialog.getByLabelText("HIPAA business associate agreement (BAA) reference"),
      { target: { value: "BAA-2026-014" } });
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: "too short" } });
    expect(submit).toBeDisabled();
    expect(dialog.getByTestId("signoff-count")).toHaveTextContent("9 / 40");
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: TEXT } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    // The server wants step-up: re-auth opens, then the SAME sign is retried.
    await screen.findByText("Re-authentication required");
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw-example-1" } });
    fireEvent.change(screen.getByLabelText(/TOTP code/i), { target: { value: "123456" } });
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() => expect(screen.queryByTestId("compliance-signoff-dialog")).toBeNull());

    const signs = backend.calls.filter((c) => c.url.endsWith("/compliance-signoff") && c.method === "POST");
    expect(signs).toHaveLength(2);
    expect(signs[1]!.body).toEqual({
      agreement_references: { hipaa: "BAA-2026-014" },
      attestation_text: TEXT,
      attestation_version: "2026-09-28.v2",
      acknowledge_flags: ["hipaa"],
      term_months: 12,
    });
    // Cleared — not "runs as cloud": nothing cloud-hosted is connected yet.
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent(
      "acme-corp signed off for cloud AI (sign-off #9, until 2027-09-28) — it is now cleared for cloud AI. " +
        NO_CLOUD_MODEL_NOTE);
    await waitFor(() =>
      expect(screen.getByTestId("ai-policy-acme-corp")).toHaveTextContent(/^cloud \(cleared\)$/));
  });

  it("a stale acknowledgement is refused with the server's words and the dialog reloads the truth", async () => {
    const backend = stubBackend({ signStatus: 409 });
    backend.stepUp = true;
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("acme-corp")).getByTestId("sign-off-acme-corp"));
    const dialog = within(await screen.findByTestId("compliance-signoff-dialog"));
    await waitFor(() => expect(dialog.getByTestId("signoff-form")).toBeInTheDocument());
    fireEvent.change(dialog.getByLabelText("HIPAA business associate agreement (BAA) reference"),
      { target: { value: "BAA-2026-014" } });
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: TEXT } });
    fireEvent.click(dialog.getByTestId("signoff-submit"));
    await waitFor(() => expect(dialog.getByRole("alert")).toHaveTextContent("flags changed since the dialog opened"));
    const loads = backend.calls.filter((c) => c.url.endsWith("/compliance-signoffs"));
    await waitFor(() => expect(loads.length).toBeGreaterThanOrEqual(1));
    expect(screen.getByTestId("compliance-signoff-dialog")).toBeInTheDocument();
  });

  it("a never-tagged tenant says so: its sign-off covers exactly []", async () => {
    const UNTAGGED = { ...ACME, slug: "untagged-co", display_name: "Untagged Co", compliance_flags: [] as string[] };
    stubBackend({ tenants: [UNTAGGED] });
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("untagged-co")).getByTestId("sign-off-untagged-co"));
    const dialog = within(await screen.findByTestId("compliance-signoff-dialog"));
    await waitFor(() => expect(dialog.getByTestId("signoff-flags")).toHaveTextContent("never been tagged"));
    expect(dialog.getByTestId("signoff-submit")).toHaveTextContent("Sign off for []");
    expect(dialog.getByLabelText("data-processing agreement reference")).toBeInTheDocument();
  });

  it("a tenant with several regimes needs one agreement for EACH before it can be signed", async () => {
    const MULTI = { ...ACME, slug: "multi-co", display_name: "Multi Co", compliance_flags: ["cjis", "hipaa"] };
    const backend = stubBackend({ tenants: [MULTI] });
    backend.stepUp = true;
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("multi-co")).getByTestId("sign-off-multi-co"));
    const dialog = within(await screen.findByTestId("compliance-signoff-dialog"));
    await waitFor(() => expect(dialog.getByTestId("signoff-agreements")).toBeInTheDocument());
    const submit = dialog.getByTestId("signoff-submit");
    fireEvent.change(dialog.getByLabelText("attestation"), { target: { value: TEXT } });
    fireEvent.change(dialog.getByLabelText("HIPAA business associate agreement (BAA) reference"),
      { target: { value: "BAA-2026-014" } });
    expect(submit).toBeDisabled();                    // the BAA does not cover CJIS
    fireEvent.change(dialog.getByLabelText("CJIS Security Addendum reference"), { target: { value: "CSA-7" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() => expect(screen.queryByTestId("compliance-signoff-dialog")).toBeNull());
    const sign = backend.calls.find((c) => c.url.endsWith("/compliance-signoff") && c.method === "POST")!;
    expect((sign.body as { agreement_references: unknown }).agreement_references).toEqual({
      cjis: "CSA-7", hipaa: "BAA-2026-014" });
  });

  it("revoke: super admin, a reason, step-up, then the table reloads", async () => {
    const backend = stubBackend({
      signoffs: { "globex-inc": [signoffRow({ id: 4, slug: "globex-inc", flags_covered: ["pci"] })] },
    });
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("globex-inc")).getByTestId("signoffs-globex-inc"));
    const dialog = within(await screen.findByTestId("compliance-signoff-dialog"));
    fireEvent.click(await dialog.findByTestId("signoff-revoke-4"));
    const confirm = dialog.getByTestId("signoff-revoke-confirm-4");
    expect(confirm).toBeDisabled();
    expect(confirm).toHaveTextContent("Revoke (step-up)");
    fireEvent.change(dialog.getByLabelText("reason to revoke sign-off 4"), { target: { value: "BAA not renewed" } });
    fireEvent.click(confirm);
    await screen.findByText("Re-authentication required");
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw-example-1" } });
    fireEvent.change(screen.getByLabelText(/TOTP code/i), { target: { value: "123456" } });
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() => expect(screen.queryByTestId("compliance-signoff-dialog")).toBeNull());
    const revokes = backend.calls.filter((c) => c.url.endsWith("/compliance-signoff/4/revoke"));
    expect(revokes.map((c) => c.body)).toEqual([{ reason: "BAA not renewed" }, { reason: "BAA not renewed" }]);
    expect(screen.getByTestId("tenants-notice")).toHaveTextContent(
      "Sign-off #4 for globex-inc revoked — it runs as local until signed again.");
  });
});

describe("Edit, bulk and merge say what will run", () => {
  it("Edit: choosing cloud on a tagged tenant says it runs as local until signed", async () => {
    stubBackend({ tenants: [{ ...ACME, ai_policy: "local", effective_ai_policy: "local", ai_policy_reason: null }] });
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("acme-corp")).getByTestId("edit-acme-corp"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    expect(dialog.queryByTestId("ai-policy-signoff-note")).toBeNull();
    fireEvent.change(dialog.getByLabelText("AI policy"), { target: { value: "cloud" } });
    expect(dialog.getByTestId("ai-policy-signoff-note")).toHaveTextContent(
      "Runs as local until a super admin signs off for cloud AI covering [hipaa]");
  });

  it("Edit: tagging a waiting cloud tenant 'none' clears it for cloud — an admin cannot save it", async () => {
    stubBackend();
    renderTab(me(["admin"]));
    fireEvent.click(within(await rowFor("acme-corp")).getByTestId("edit-acme-corp"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    fireEvent.click(dialog.getByLabelText("compliance none"));        // replaces [hipaa]
    expect(dialog.getByTestId("ai-policy-signoff-note")).toHaveTextContent(
      "would be cleared for cloud AI with no sign-off — only a super admin may do that");
    expect(dialog.getByTestId("tenant-form-save")).toBeDisabled();
  });

  it("Edit: a super admin's save that clears cloud re-authenticates, then saves", async () => {
    const backend = stubBackend();
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("acme-corp")).getByTestId("edit-acme-corp"));
    const dialog = within(screen.getByTestId("tenant-form-dialog"));
    fireEvent.click(dialog.getByLabelText("compliance none"));
    expect(dialog.getByTestId("ai-policy-signoff-note")).toHaveTextContent(
      "you will be asked to re-authenticate (step-up)");
    fireEvent.click(dialog.getByTestId("tenant-form-save"));
    await screen.findByText("Re-authentication required");
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw-example-1" } });
    fireEvent.change(screen.getByLabelText(/TOTP code/i), { target: { value: "123456" } });
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() => expect(screen.queryByTestId("tenant-form-dialog")).toBeNull());
    const patches = backend.calls.filter((c) => c.method === "PATCH");
    expect(patches.map((c) => c.body)).toEqual([{ compliance_flags: ["none"] }, { compliance_flags: ["none"] }]);
  });

  it("the clearance rule the Edit dialog applies", () => {
    expect(clearsCloudWithoutSignoff(ACME, "cloud", ["none"])).toBe(true);     // local → cleared
    expect(clearsCloudWithoutSignoff(GLOBEX, "cloud", ["none"])).toBe(true);   // signed → on the tag alone
    expect(clearsCloudWithoutSignoff(ACME, "cloud", ["hipaa"])).toBe(false);   // runs as local
    expect(clearsCloudWithoutSignoff(ACME, "local", ["none"])).toBe(false);
    expect(clearsCloudWithoutSignoff({ ...PLAIN, ai_policy: "cloud", effective_ai_policy: "cloud" }, "cloud", ["none"]))
      .toBe(false);                                                            // already so
    expect(clearsCloudWithoutSignoff(null, "cloud", ["none"])).toBe(true);     // created that way
  });

  it("bulk: a batch that clears a tenant for cloud re-authenticates on apply, then applies", async () => {
    const backend = stubBackend({
      bulkStepUp: true,
      bulkRows: [
        {
          slug: "acme-corp", display_name: "Acme Corp", status: "active", error: null,
          changes: [{ field: "compliance_flags", before: ["hipaa"], after: ["none"] }],
          effective_ai_policy: "cloud", signoff: null, signoffs_invalidated: [], step_up_required: true,
          ai_policy_note: "will be cleared for cloud AI — tagged 'none', no sign-off needed; applying needs a super admin with step-up re-authentication",
        },
      ],
    });
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("acme-corp")).getByTestId("select-acme-corp"));
    fireEvent.click(screen.getByTestId("bulk-edit"));
    const dialog = within(screen.getByTestId("bulk-edit-dialog"));
    fireEvent.change(dialog.getByLabelText("bulk kind"), { target: { value: "client" } });
    fireEvent.click(dialog.getByTestId("bulk-preview-btn"));
    await dialog.findByTestId("bulk-row-acme-corp");
    const apply = dialog.getByTestId("bulk-apply");
    expect(apply).toHaveTextContent("Apply to 1 tenant(s) (step-up)");
    fireEvent.click(apply);
    await screen.findByText("Re-authentication required");
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw-example-1" } });
    fireEvent.change(screen.getByLabelText(/TOTP code/i), { target: { value: "123456" } });
    fireEvent.click(screen.getByText("Confirm"));
    await waitFor(() => expect(screen.queryByTestId("bulk-edit-dialog")).toBeNull());
    const applies = backend.calls.filter(
      (c) => c.url.endsWith("/bulk-update") && (c.body as { dry_run?: boolean }).dry_run === false);
    expect(applies).toHaveLength(2);                                            // refused, then retried
  });

  it("bulk preview rows carry the server's AI note", async () => {
    stubBackend({
      bulkRows: [
        {
          slug: "acme-corp", display_name: "Acme Corp", status: "active", error: null,
          changes: [{ field: "ai_policy", before: "local", after: "cloud" }],
          effective_ai_policy: "local", signoff: null, signoffs_invalidated: [],
          ai_policy_note: "will run as local until signed — sign-off required for [hipaa]",
        },
      ],
    });
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("acme-corp")).getByTestId("select-acme-corp"));
    fireEvent.click(screen.getByTestId("bulk-edit"));
    const dialog = within(screen.getByTestId("bulk-edit-dialog"));
    fireEvent.change(dialog.getByLabelText("bulk AI policy"), { target: { value: "cloud" } });
    expect(dialog.getByTestId("bulk-cloud-signoff-help")).toHaveTextContent("keeps running as local until you sign off");
    fireEvent.click(dialog.getByTestId("bulk-preview-btn"));
    const row = within(await dialog.findByTestId("bulk-row-acme-corp"));
    expect(row.getByTestId("bulk-row-ai-note")).toHaveTextContent(
      "will run as local until signed — sign-off required for [hipaa]");
  });

  it("merge: a subject carrying a regime the target lacks is flagged before the click", async () => {
    stubBackend();
    renderTab(me(["super_admin"]));
    fireEvent.click(within(await rowFor("globex-inc")).getByTestId("merge-globex-inc"));
    const dialog = within(screen.getByTestId("merge-dialog"));
    fireEvent.change(dialog.getByLabelText("merge target"), { target: { value: "acme-corp" } });
    expect(dialog.getByTestId("merge-flags-note")).toHaveTextContent(
      "globex-inc is tagged [pci] and acme-corp is not: the merge adds [pci] to acme-corp's compliance tags");
    fireEvent.change(dialog.getByLabelText("merge target"), { target: { value: "plain-co" } });
    expect(dialog.getByTestId("merge-flags-note")).toBeInTheDocument();       // ["none"] target
    // This stub serves no preview: the dialog says so, and the note stands.
    await waitFor(() => expect(dialog.getByTestId("merge-preview-error")).toBeInTheDocument());
    expect(dialog.getByTestId("merge-flags-note")).toBeInTheDocument();
  });
});
