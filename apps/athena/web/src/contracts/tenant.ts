/**
 * Tenant lifecycle contract — Settings → Tenants and the quarantine review.
 *
 * Mirrors `apps/octo/api/routers/admin_tenants.py` (TenantOut,
 * ChangeRequestOut, QuarantineRowOut, …) and the vocabularies in
 * `apps/octo/instances/tenant_lifecycle.py`. The server's list response
 * carries the live vocabularies (`kinds`, `compliance_tags`, `ai_policies`):
 * the pickers offer THOSE, and the label maps here only prettify what the
 * server sent (an unknown value renders as its raw slug, never breaks).
 *
 * Product rulings this surface must keep (see the router's docstring):
 *   - a tenant is "reviewed" only once a human has said what it is: the
 *     console never lets 'unclassified' be confirmed, and a confirmed
 *     tenant's kind never goes back to 'unclassified';
 *   - bulk review is all-or-nothing under PATCH's own rules, previewed
 *     row by row before anything is written;
 *   - offboard AND merge are a two-person request by default, for every
 *     role; the approver is never the requester. A super_admin may apply
 *     one ALONE only as the attested exception (typed attestation, the
 *     slug typed back and checked server-side, step-up; a merge only when
 *     the eligibility guards allow) — the other admins are notified and a
 *     second person may post-review it;
 *   - 'cloud' AI policy needs a super_admin (data may leave the deployment),
 *     and runs as local until a super_admin signs a compliance sign-off for
 *     the tenant's exact flags — the table shows what RUNS, never implies
 *     cloud is on when it is not;
 *   - quarantined payloads are UNTRUSTED vendor text: rendered as text only.
 */

export type TenantKind = "unclassified" | "client" | "internal" | "dev" | "vendor" | "other";
export type TenantOrigin = "bootstrap" | "manual" | "auto";
export type TenantReviewState = "confirmed" | "pending";
export type TenantStatus = "active" | "disabled" | "offboarded" | "archived";
export type AiPolicy = "none" | "local" | "cloud";
export type ComplianceTag = "hipaa" | "cjis" | "pci" | "bipa" | "glba" | "ferpa" | "none";

/** Fallbacks for a backend that predates the vocabularies in the list body. */
export const TENANT_KINDS: readonly TenantKind[] = [
  "unclassified", "client", "internal", "dev", "vendor", "other",
];
export const COMPLIANCE_TAGS: readonly ComplianceTag[] = [
  "hipaa", "cjis", "pci", "bipa", "glba", "ferpa", "none",
];
export const AI_POLICIES: readonly AiPolicy[] = ["none", "local", "cloud"];

export const KIND_LABEL: Readonly<Record<string, string>> = {
  unclassified: "Unclassified",
  client: "Client",
  internal: "Internal",
  dev: "Dev / lab",
  vendor: "Vendor",
  other: "Other",
};

export const KIND_HELP: Readonly<Record<string, string>> = {
  unclassified: "Nobody has said what this is yet. Pick a kind to confirm it.",
  client: "A customer whose data this console protects.",
  internal: "The MSP's own systems, offices or staff devices.",
  dev: "A lab, test or development environment.",
  vendor: "A vendor's or partner's own site that shows up in the feed.",
  other: "Something else — none of the kinds above fits; the name should say what it is.",
};

export const COMPLIANCE_LABEL: Readonly<Record<string, string>> = {
  hipaa: "HIPAA",
  cjis: "CJIS",
  pci: "PCI",
  bipa: "BIPA",
  glba: "GLBA",
  ferpa: "FERPA",
  none: "none",
};

export const ORIGIN_LABEL: Readonly<Record<string, string>> = {
  bootstrap: "bootstrap",
  manual: "manual",
  auto: "auto-created",
};

export const AI_POLICY_LABEL: Readonly<Record<string, string>> = {
  none: "none",
  local: "local",
  cloud: "cloud",
};

/** No cloud model is wired into OCTO yet (v0.10): a tenant cleared for
 *  cloud AI is still reasoned over by the bundle's local model. Every place
 *  that says "cloud" says this with it. */
export const NO_CLOUD_MODEL_NOTE = "No cloud model is connected yet — Ask-Octo and triage use the local model.";

export const AI_POLICY_HELP: Readonly<Record<string, string>> = {
  none: "No LLM escalation for this tenant. The default for every new tenant.",
  local: "The bundle's own local model may reason over this tenant's events. Nothing leaves the deployment.",
  cloud:
    "Cleared for cloud AI: a cloud model may see this tenant's data, outside the deployment. Only a super admin " +
    "can choose this, and unless the tenant is tagged 'none' it runs as local until a super admin signs a " +
    `compliance sign-off. ${NO_CLOUD_MODEL_NOTE}`,
};

// ---------------------------------------------------------------------------
// Compliance sign-off before cloud AI (v0.10) — mirrors
// `apps/octo/instances/ai_policy.py` and `routers/tenant_compliance.py`.
//
// `ai_policy` is the STORED intent; `effective_ai_policy` is what runs.
// 'cloud' is honoured only while a live sign-off covers EXACTLY the tenant's
// current compliance flags (or the tenant is tagged exactly ["none"]);
// otherwise it runs as 'local'. [] (never tagged) needs a sign-off too. The
// console never shows "cloud" for a tenant that is not running as cloud.
// ---------------------------------------------------------------------------

export type SignoffState = "not_required" | "required" | "live" | "expired" | "revoked" | "flags_changed";

export interface SignoffStatus {
  readonly state: SignoffState | string;
  readonly signoff_id: number | null;
  readonly signed_by: number | null;
  readonly signed_at: string | null;
  readonly expires_at: string | null;
  readonly flags_covered: readonly string[] | null;
}

export const SIGNOFF_STATE_LABEL: Readonly<Record<string, string>> = {
  not_required: "no sign-off needed",
  required: "sign-off required",
  live: "signed",
  expired: "sign-off expired",
  revoked: "sign-off revoked",
  flags_changed: "flags changed since sign-off",
  superseded: "superseded",
};

/** Cloud needs a sign-off unless the tenant is tagged exactly ["none"]. */
export function signoffRequired(flags: readonly string[]): boolean {
  return !(flags.length === 1 && flags[0] === "none");
}

/** What actually runs. A backend that predates v0.10 sends no effective
 *  policy: 'cloud' is then shown as local (never implied active). */
export function effectiveAiPolicy(t: Pick<Tenant, "ai_policy" | "effective_ai_policy">): string {
  if (t.effective_ai_policy) return t.effective_ai_policy;
  return t.ai_policy === "cloud" ? "local" : t.ai_policy;
}

export interface AiPolicyView {
  /** The badge text: "none" | "local" | "cloud (cleared)" | "cloud → local". */
  readonly label: string;
  readonly tone: "dim" | "accent" | "high";
  readonly degraded: boolean;
  /** One sentence for the tooltip / note. */
  readonly title: string;
}

export function aiPolicyView(t: Pick<Tenant, "ai_policy" | "effective_ai_policy" | "ai_policy_reason">): AiPolicyView {
  const effective = effectiveAiPolicy(t);
  const degraded = effective !== t.ai_policy;
  if (degraded) {
    return {
      label: `${t.ai_policy} → ${effective}`,
      tone: "high",
      degraded,
      title: t.ai_policy_reason ?? `${t.ai_policy} requested — runs as ${effective}`,
    };
  }
  return {
    // "cloud" is a clearance, not a model: nothing cloud-hosted runs yet.
    label: effective === "cloud" ? "cloud (cleared)" : labelFor(AI_POLICY_LABEL, effective),
    tone: effective === "none" ? "dim" : effective === "cloud" ? "high" : "accent",
    degraded,
    title:
      effective === "cloud"
        ? `${t.ai_policy_reason ?? AI_POLICY_HELP.cloud}${t.ai_policy_reason ? ` ${NO_CLOUD_MODEL_NOTE}` : ""}`
        : (t.ai_policy_reason ?? AI_POLICY_HELP[effective] ?? ""),
  };
}

/** A super admin can sign for a tenant that still receives traffic and
 *  whose cloud policy is not already honoured. */
export function canSignOff(t: Pick<Tenant, "status" | "compliance_flags" | "signoff">): boolean {
  if (t.status !== "active" && t.status !== "disabled") return false;
  if (!signoffRequired(t.compliance_flags)) return false;
  return t.signoff?.state !== "live";
}

/** The regimes a merge subject carries that the target lacks ('none' and
 *  an untagged subject add nothing) — the server unions them onto the
 *  target and revokes its sign-off. */
export function regimesNotCovered(subject: readonly string[], target: readonly string[]): string[] {
  const t = new Set(target.filter((f) => f !== "none"));
  return [...new Set(subject.filter((f) => f !== "none" && !t.has(f)))].sort();
}

export function flagsLabel(flags: readonly string[]): string {
  return `[${flags.join(", ")}]`;
}

export interface ComplianceSignoff {
  readonly id: number;
  readonly slug: string;
  readonly policy: string;
  readonly flags_covered: readonly string[];
  /** One agreement per regime covered ({"hipaa": "<BAA ref>", …});
   *  'untagged' for a never-tagged tenant, 'reference' for a pre-v2 row. */
  readonly agreement_references: Readonly<Record<string, string>>;
  readonly attestation_text: string;
  readonly attestation_sha256: string;
  readonly attestation_version: string;
  readonly signed_by: number;
  readonly signed_at: string;
  readonly expires_at: string | null;
  readonly revoked_at: string | null;
  readonly revoked_by: number | null;
  readonly revoked_kind: string | null;
  readonly revoke_reason: string | null;
  /** live | expired | revoked | superseded | flags_changed — against the tenant now. */
  readonly state: string;
}

export interface AiPolicyStatus {
  readonly requested: string;
  readonly effective: string;
  readonly degraded: boolean;
  readonly reason: string | null;
  /** The tenant's current flags, canonical — what a sign-off must acknowledge. */
  readonly flags: readonly string[];
  readonly signoff: SignoffStatus;
}

export interface AttestationTemplate {
  readonly version: string;
  readonly text: string;
  readonly min_chars: number;
  readonly max_chars: number;
}

/** An agreement a sign-off must name: a regime (or 'untagged') and the
 *  instrument that regime requires (a BAA is HIPAA's, not CJIS's). */
export interface AgreementRequired {
  readonly key: string;
  readonly instrument: string;
}

export interface SignoffHistoryResponse {
  readonly slug: string;
  readonly display_name: string;
  readonly status: string;
  readonly ai_policy: AiPolicyStatus;
  readonly signoffs: readonly ComplianceSignoff[];
  readonly attestation: AttestationTemplate;
  /** For the tenant's CURRENT flags — one reference each. */
  readonly agreements_required: readonly AgreementRequired[];
  readonly term_months_default: number;
  readonly term_months_max: number;
  readonly agreement_reference_max_chars: number;
}

export interface SignoffPayload {
  /** One reference per `agreements_required` key — no more, no fewer. */
  readonly agreement_references: Readonly<Record<string, string>>;
  readonly attestation_text: string;
  readonly attestation_version: string;
  /** Must equal the tenant's current flags (the server refuses stale ones). */
  readonly acknowledge_flags: readonly string[];
  readonly term_months: number;
}

export interface SignoffResult {
  readonly slug: string;
  readonly signoff: ComplianceSignoff;
  readonly ai_policy: AiPolicyStatus;
  readonly superseded: readonly number[];
}

export const STATUS_LABEL: Readonly<Record<string, string>> = {
  active: "active",
  disabled: "disabled",
  offboarded: "offboarded",
  archived: "archived",
};

export function labelFor(map: Readonly<Record<string, string>>, value: string): string {
  return map[value] ?? value;
}

export interface MappedSource {
  readonly vendor: string;
  readonly instance_id: number;
  readonly vendor_tenant_id: string;
  readonly label: string | null;
  readonly match_source: string;
}

export interface CreatedByInstance {
  readonly instance_id: number;
  readonly vendor: string;
  readonly label: string;
}

export type ChangeRequestKind = "offboard" | "merge";
export type ChangeRequestState = "pending" | "approved" | "rejected" | "applied" | "cancelled";
/** v0.10: 'two_person' (the default — a second super admin decided) or
 *  'single_attested' (one super admin applied it alone, on a typed
 *  attestation — the explicit exception). */
export type ApprovalMode = "two_person" | "single_attested";
export type PostReviewState = "not_requested" | "pending" | "reviewed_ok" | "reviewed_concern";

export interface ChangeRequest {
  readonly id: number;
  readonly kind: ChangeRequestKind;
  readonly subject_slug: string;
  readonly target_slug: string | null;
  readonly requested_by: number;
  readonly requested_at: string;
  readonly reason: string;
  readonly state: ChangeRequestState;
  readonly decided_by: number | null;
  readonly decided_at: string | null;
  readonly decision_note: string | null;
  /** Absent from a backend that predates v0.10 (read as two_person). */
  readonly approval_mode?: ApprovalMode | string;
  /** single_attested: the typed attestation, verbatim, and the slug as typed. */
  readonly attestation?: string | null;
  readonly subject_confirmation?: string | null;
  /** The optional after-the-fact review of a single-person change, by a
   *  SECOND admin+ (never the one who applied it). */
  readonly post_review_state?: PostReviewState | string;
  readonly post_reviewed_by?: number | null;
  readonly post_reviewed_at?: string | null;
  readonly post_review_note?: string | null;
}

/** The attested single-person exception (super admin only): at least this
 *  many typed characters, and the subject slug typed back exactly. */
export const ATTESTATION_MIN_CHARS = 40;
export const ATTESTATION_MAX_CHARS = 2000;

/** What the server counts: the typed attestation, trimmed. */
export function attestationLength(text: string): number {
  return text.trim().length;
}

export interface AttestedAction {
  readonly attestation: string;
  /** The subject slug as the operator typed it — checked server-side. */
  readonly confirm_subject: string;
}

export type PostReviewVerdict = "ok" | "concern";

export const POST_REVIEW_LABEL: Readonly<Record<string, string>> = {
  not_requested: "no post-review",
  pending: "post-review pending",
  reviewed_ok: "reviewed — OK",
  reviewed_concern: "reviewed — concern raised",
};

/** Who was told of a single-person change. */
export interface NotificationSummary {
  /** Other admins given an in-app notice. */
  readonly recipients: number;
  /** The failure class when the in-app notices could not be created (the
   *  change stood; it is in the audit log). */
  readonly in_app_error: string | null;
  /** 'queued' — e-mailed after the response when a Resend integration is
   *  configured (recorded either way); 'none' — nobody to e-mail. */
  readonly email: string;
}

export interface EligibilityReason {
  /** 'target_ai_more_permissive' | 'subject_flags_not_on_target' | 'subject_not_active'. */
  readonly code: string;
  readonly message: string;
  /** What would make the single-person path apply (sign the subject off,
   *  tag the target, merge the other way …) — null when nothing would. */
  readonly remedy?: string | null;
}

export interface SinglePersonEligibility {
  readonly eligible: boolean;
  readonly reasons: readonly EligibilityReason[];
  readonly subject_effective_ai_policy: string;
  readonly target_effective_ai_policy: string;
  readonly subject_flags_not_on_target: readonly string[];
  /** Active super admins other than the caller — 0: nobody could approve a
   *  two-person request. Absent from a pre-v0.10 backend. */
  readonly other_super_admins?: number;
}

export interface Caveat {
  readonly code: string;
  readonly text: string;
}

/** GET …/merge-into/{target}/preview — what the merge would do, what it
 *  leaves behind, its caveats, and whether one person may apply it. */
export interface MergePreview {
  readonly slug: string;
  readonly target: string;
  readonly subject_status: string;
  readonly events_to_copy: number;
  /** Stays with the archived subject: incidents, agent_notes, indicators, tickets. */
  readonly left_behind: Readonly<Record<string, number>>;
  readonly mappings_to_repoint: number;
  readonly tokens_to_revoke: number;
  readonly scoped_operators: number;
  readonly target_flags_added: readonly string[];
  /** The target's flags once merged — differs from today's when regimes are
   *  added, or when an untagged subject takes a 'none' target back to []. */
  readonly target_flags_after?: readonly string[];
  readonly target_signoffs_to_revoke: readonly number[];
  readonly subject_signoffs_to_revoke?: readonly number[];
  readonly single_person: SinglePersonEligibility;
  readonly caller_may_apply_alone: boolean;
  readonly caveats: readonly Caveat[];
  readonly attestation_min_chars: number;
  readonly attestation_max_chars: number;
}

export const LEFT_BEHIND_LABEL: Readonly<Record<string, string>> = {
  incidents: "incident(s)",
  agent_notes: "agent note(s)",
  indicators: "indicator(s)",
  tickets: "ticket(s)",
};

/** One sentence on who was told of a single-person change. */
export function notificationNote(n: NotificationSummary | null | undefined): string {
  if (!n) return "";
  if (n.in_app_error) {
    return ` The other admins could NOT be notified in-app (${n.in_app_error}) — recorded in the audit log; tell them yourself.`;
  }
  if (n.recipients === 0) return " There is no other admin to notify.";
  return ` ${n.recipients} other admin(s) notified in-app${n.email === "queued" ? "; an e-mail copy goes out if a Resend integration is configured" : ""}.`;
}

/** Another tenant whose name looks like the same business
 *  (`tenant_lifecycle.duplicate_rule`): a HINT for a human — merging stays
 *  the ordinary, confirmed merge flow. */
export interface DuplicateHint {
  readonly slug: string;
  readonly display_name: string;
  readonly status: TenantStatus;
  /** 'same-name' (identical once normalised) | 'name-prefix' (one name is
   *  the leading part of the other). */
  readonly rule: string;
}

export const DUPLICATE_RULE_HELP: Readonly<Record<string, string>> = {
  "same-name": "Same name once punctuation, case and legal suffixes (Inc, LLC, PLLC…) are ignored.",
  "name-prefix": "One name is the leading part of the other once legal suffixes are ignored.",
};

export interface Tenant {
  readonly slug: string;
  readonly display_name: string;
  readonly status: TenantStatus;
  readonly origin: TenantOrigin;
  readonly kind: TenantKind;
  readonly review_state: TenantReviewState;
  readonly compliance_flags: readonly string[];
  /** The STORED intent ('cloud' may be set before any sign-off). */
  readonly ai_policy: AiPolicy;
  /** What actually runs (v0.10; absent from older backends — see
   *  `effectiveAiPolicy`), why, and the cloud sign-off standing. */
  readonly effective_ai_policy?: AiPolicy;
  readonly ai_policy_reason?: string | null;
  readonly signoff?: SignoffStatus;
  readonly created_by_instance: CreatedByInstance | null;
  readonly onboarded_at: string;
  readonly offboarded_at: string | null;
  readonly archived_at: string | null;
  readonly notes: string | null;
  readonly event_count: number;
  readonly last_event_at: string | null;
  readonly mapped_sources: readonly MappedSource[];
  readonly pending_request: ChangeRequest | null;
  /** Absent from a backend that predates the hints. */
  readonly duplicate_hints?: readonly DuplicateHint[];
  /** Auto-created and still named "<vendor> site …" — rename it. No client
   *  user (viewer) can be invited to it meanwhile. Absent = false. */
  readonly placeholder_name?: boolean;
  /** Auto-created with a slug made from that placeholder ("<vendor>-site-…"),
   *  which never changes: merge it into a properly named tenant before
   *  inviting client users. Absent = false. */
  readonly placeholder_slug?: boolean;
}

export interface TenantListResponse {
  readonly tenants: readonly Tenant[];
  readonly pending_review: number;
  readonly quarantined: number;
  readonly kinds: readonly string[];
  readonly compliance_tags: readonly string[];
  readonly ai_policies: readonly string[];
}

export interface CreateTenantPayload {
  readonly slug: string;
  readonly display_name: string;
  readonly kind: string;
  readonly compliance_flags: readonly string[];
  readonly ai_policy?: string;
}

export interface PatchTenantPayload {
  readonly display_name?: string;
  readonly kind?: string;
  readonly compliance_flags?: readonly string[];
  readonly ai_policy?: string;
  readonly review_state?: "confirmed";
}

// ---------------------------------------------------------------------------
// Bulk review — POST /admin/tenants/bulk-update
// ---------------------------------------------------------------------------

/** At most this many tenants per bulk request (the server's bound). */
export const BULK_UPDATE_MAX = 200;

export interface BulkUpdateItem {
  readonly slug: string;
  /** Exactly PATCH /admin/tenants/{slug}'s body and rules. */
  readonly patch: PatchTenantPayload;
}

export interface FieldChange {
  readonly field: string;
  readonly before: string | readonly string[];
  readonly after: string | readonly string[];
}

export interface BulkRowError {
  readonly code: string;
  readonly message: string;
}

export interface BulkRow {
  readonly slug: string;
  readonly display_name: string | null;
  readonly status: string | null;
  /** Empty with no error = the tenant already says all that (not written). */
  readonly changes: readonly FieldChange[];
  readonly error: BulkRowError | null;
  /** Rows touching AI policy / flags (v0.10): what the tenant will RUN with
   *  once applied, its sign-off standing then, one line about it ("will run
   *  as local until signed …"), and the sign-offs its flag change revokes. */
  readonly effective_ai_policy?: string | null;
  readonly signoff?: SignoffStatus | null;
  readonly ai_policy_note?: string | null;
  readonly signoffs_invalidated?: readonly number[];
  /** The row would make the tenant run as cloud AI: a super admin with
   *  step-up applies it (an admin's row is refused instead). */
  readonly step_up_required?: boolean;
}

/**
 * The per-row answer — the preview (`dry_run`, 200) and the applied result
 * (200). A refused apply (422, or 403 when a non-super_admin asked for
 * 'cloud' anywhere in the batch) carries the same shape plus the error
 * envelope, and NOTHING was written: the batch is all-or-nothing.
 */
export interface BulkUpdateResponse {
  readonly dry_run: boolean;
  readonly applied: boolean;
  /** The batch's id — each per-tenant audit row carries it. */
  readonly request_id: string | null;
  readonly rows: readonly BulkRow[];
  readonly changed: number;
  readonly unchanged: number;
  readonly errors: number;
  /** Why the batch is (or, on a dry run, would be) refused as a whole. */
  readonly refusal: BulkRowError | null;
  /** Applying needs step-up re-authentication (a row sets step_up_required). */
  readonly step_up_required?: boolean;
}

/** One edit applied to every selected tenant; null / "leave" = untouched. */
export interface BulkEdit {
  readonly kind: string | null;
  readonly complianceMode: "leave" | "add" | "replace";
  readonly compliance: readonly string[];
  readonly aiPolicy: string | null;
  readonly confirm: boolean;
}

/** `add` onto an existing tag list with the picker's own rule: 'none' is
 *  exclusive ("we checked, none applies"), a real tag displaces it. */
export function addComplianceTags(current: readonly string[], add: readonly string[]): string[] {
  if (add.length === 0) return [...current].sort();
  if (add.includes("none")) return ["none"];
  const out = new Set(current.filter((t) => t !== "none"));
  add.forEach((t) => out.add(t));
  return [...out].sort();
}

/** True when the edit changes nothing at all (nothing to preview). */
export function bulkEditIsEmpty(edit: BulkEdit): boolean {
  const compliance =
    edit.complianceMode === "replace" || (edit.complianceMode === "add" && edit.compliance.length > 0);
  return edit.kind === null && !compliance && edit.aiPolicy === null && !edit.confirm;
}

/** The PATCH body one tenant gets from a bulk edit. Confirming is sent to
 *  every selected tenant (a confirmed one reports "unchanged"); the server
 *  refuses to confirm one that would still be unclassified. */
export function bulkPatchFor(t: Tenant, edit: BulkEdit): PatchTenantPayload {
  const flags =
    edit.complianceMode === "replace"
      ? [...edit.compliance].sort()
      : edit.complianceMode === "add" && edit.compliance.length > 0
        ? addComplianceTags(t.compliance_flags, edit.compliance)
        : null;
  return {
    ...(edit.kind !== null ? { kind: edit.kind } : {}),
    ...(flags !== null ? { compliance_flags: flags } : {}),
    ...(edit.aiPolicy !== null ? { ai_policy: edit.aiPolicy } : {}),
    ...(edit.confirm ? { review_state: "confirmed" as const } : {}),
  };
}

// ---------------------------------------------------------------------------
// Review state + row actions (the rules the table and the server share)
// ---------------------------------------------------------------------------

/** The Tenants table's review-state filter, carried in the URL
 *  (`?filter=needs-review` | `?filter=confirmed`; absent = all). */
export type ReviewFilter = "all" | "needs-review" | "confirmed";

export function reviewFilterFromParam(param: string | null | undefined): ReviewFilter {
  return param === "needs-review" || param === "confirmed" ? param : "all";
}

export function reviewFilterPath(filter: ReviewFilter): string {
  return filter === "all" ? "/settings/tenants" : `/settings/tenants?filter=${filter}`;
}

/**
 * "Needs review" — the SAME predicate as the server's counts (the dashboard
 * notice, the tab badge): pending AND active. A disabled or offboarded
 * tenant receives no traffic and blocks nothing, so it is never counted —
 * but it can still be confirmed (`canConfirm`), so none stays pending for
 * ever.
 */
export function needsReview(t: Tenant): boolean {
  return t.review_state === "pending" && t.status === "active";
}

export function canConfirm(t: Tenant): boolean {
  return t.review_state === "pending" && t.status !== "archived";
}

/** Offboard: the server refuses only offboarded / archived tenants. */
export function canOffboard(t: Tenant): boolean {
  return t.status === "active" || t.status === "disabled";
}

/** Merge FROM (the tenant that gets archived): active or disabled. An
 *  offboarded tenant's frozen site mappings would be re-pointed by a merge
 *  and its traffic flow again — that is not a row-button decision. */
export function canMergeFrom(t: Pick<Tenant, "status">): boolean {
  return t.status === "active" || t.status === "disabled";
}

/** Merge INTO: the server takes an active target only. */
export function canBeMergeTarget(t: Pick<Tenant, "status">): boolean {
  return t.status === "active";
}

/** What an operator types to find a tenant: name or slug, any case. */
export function matchesSearch(t: Tenant, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return t.display_name.toLowerCase().includes(q) || t.slug.includes(q);
}

/** What stopped working for the tenant's own side when it left. */
export interface AccessSevered {
  /** Buoy / API bearer tokens revoked. */
  readonly tokens_revoked: number;
  /** Live console sessions of client users scoped to the tenant, ended. */
  readonly sessions_revoked: number;
  /** Client user accounts still scoped to it — remove them under Operators. */
  readonly scoped_operators: number;
  /** Integration defaults that pointed at it (cleared, or re-pointed on a merge). */
  readonly instance_defaults_cleared: number;
}

export interface OffboardResponse {
  readonly slug: string;
  /** true = applied now (a super admin, alone, attested); false = a
   *  two-person request awaits approval. */
  readonly applied: boolean;
  readonly status: string;
  readonly request: ChangeRequest | null;
  /** Kept, pointing at the offboarded slug, so the site's traffic holds
   *  as 'offboarded-tenant' instead of creating a look-alike tenant. */
  readonly mappings_frozen: number;
  readonly access: AccessSevered;
  /** v0.10 — how it was approved; applied alone: the change record, its
   *  post-review state and who was told. */
  readonly approval_mode?: ApprovalMode | string;
  readonly change_request_id?: number | null;
  readonly post_review_state?: string | null;
  readonly notifications?: NotificationSummary | null;
}

export interface MergeResponse {
  readonly slug: string;
  readonly target: string;
  /** true = applied now (a super admin, alone, attested); false = a
   *  two-person request awaits approval. */
  readonly applied: boolean;
  readonly approval_mode?: ApprovalMode | string;
  readonly change_request_id?: number | null;
  readonly post_review_state?: string | null;
  readonly notifications?: NotificationSummary | null;
  readonly status: string;
  readonly request: ChangeRequest | null;
  readonly mappings_repointed: number;
  readonly events_copied: number;
  readonly events_skipped: number;
  readonly access: AccessSevered;
  /** Regimes the subject carried that the target lacked — unioned onto the
   *  target, whose sign-off(s) were revoked (v0.10). */
  readonly target_flags_added?: readonly string[];
  /** The target's flags after the merge (an untagged subject takes a
   *  'none' target back to []). */
  readonly target_flags_after?: readonly string[];
  readonly signoffs_invalidated?: readonly number[];
  /** The archived subject's own cloud-AI sign-offs, revoked. */
  readonly subject_signoffs_revoked?: readonly number[];
}

/** The dashboard's "needs review" counts (admin+, cheap, unaudited). */
export interface ReviewSummary {
  readonly pending_review: number;
  readonly quarantined: number;
  readonly pending_requests: number;
  /** Live cloud-AI sign-offs expiring within 30 days / lapsed (the tenant
   *  runs as local until signed again). Absent from a pre-v0.10 backend. */
  readonly signoffs_expiring?: number;
  readonly signoffs_expired?: number;
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

export type QuarantineReason =
  | "no-tenant-id"
  | "name-unknown"
  | "ambiguous-name"
  | "name-already-mapped"
  | "name-match-suggested"
  | "offboarded-tenant"
  | "default-tenant-missing"
  | "autocreate-limit"
  | "instance-disabled"
  | "store-failed";

export type QuarantineState = "held" | "routed" | "discarded";

export interface QuarantineRow {
  readonly id: number;
  readonly received_at: string;
  readonly instance_id: number;
  readonly vendor: string;
  readonly source: string;
  readonly vendor_tenant_id: string | null;
  readonly vendor_tenant_label: string | null;
  readonly reason: string;
  readonly event_summary: string | null;
  readonly payload_sha256: string;
  readonly payload_truncated: boolean;
  readonly state: QuarantineState;
  readonly routed_to_slug: string | null;
  readonly routed_at: string | null;
  readonly discarded_at: string | null;
  readonly discard_reason: string | null;
  /** A held name-match row: the ONE active client with the same name,
   *  offered as a one-click "map to <client>" — a suggestion for a human,
   *  never applied by itself (the same-name rule). */
  readonly suggested_slug?: string | null;
  readonly suggested_name?: string | null;
}

/** One held event with its payload — opaque TEXT, never markup. */
export interface QuarantineDetail extends QuarantineRow {
  readonly payload: string;
}

export interface QuarantineListResponse {
  readonly rows: readonly QuarantineRow[];
  readonly total: number;
  readonly limit: number;
  readonly offset: number;
  readonly reasons: readonly string[];
}

export interface NewTenantSpec {
  readonly display_name: string;
  readonly kind: string;
  readonly compliance_flags: readonly string[];
}

/** Exactly one of the two: an existing active tenant, or a new one. */
export type RouteTarget =
  | { readonly slug: string; readonly new?: undefined }
  | { readonly slug?: undefined; readonly new: NewTenantSpec };

export interface RouteResponse {
  readonly slug: string;
  readonly created_tenant: boolean;
  readonly routed: number;
  readonly duplicates: number;
  /** Held rows whose payload was truncated on arrival: left held (discard them). */
  readonly skipped: number;
  readonly mapping_written: boolean;
}

export interface BulkDiscardResponse {
  readonly discarded: number;
}

interface ReasonExplanation {
  /** Short, for the group header. */
  readonly title: string;
  /** Plain language: what happened and what routing will (not) do. */
  readonly body: string;
}

const REASON_HELP: Readonly<Record<QuarantineReason, ReasonExplanation>> = {
  "no-tenant-id": {
    title: "no site id on the event",
    body:
      "Nothing on the payload says which vendor site it came from, so it cannot be " +
      "matched to a tenant. Route each event by hand, or discard it.",
  },
  "name-unknown": {
    title: "site name unknown",
    body:
      "The vendor sent a site id but no name, and the site list has not been loaded " +
      "yet. Reload the site list under the integration's Tenant mapping and new " +
      "events will resolve by themselves; route the ones already held here.",
  },
  "ambiguous-name": {
    title: "name matches more than one tenant",
    body:
      "The site's name matched more than one existing tenant by name — pick which " +
      "one it belongs to. Routing maps the site so future events go straight there.",
  },
  "name-already-mapped": {
    title: "name matches a tenant that already has a site here",
    body:
      "The site's name matches one existing tenant, but a different site of this " +
      "integration is already mapped to it — a second site of the same client, or " +
      "a look-alike name. Confirm where it belongs; routing maps the site.",
  },
  "name-match-suggested": {
    title: "same name as an existing tenant — confirm it",
    body:
      "The site's name is the same as one existing tenant's. A name is only a " +
      "suggestion: two different businesses can share one. If it is " +
      "that client, map it in one click; otherwise route it elsewhere or create a " +
      "new tenant. Nothing was linked by itself.",
  },
  "offboarded-tenant": {
    title: "site belongs to an offboarded tenant",
    body:
      "This site is mapped to a tenant that was offboarded (or archived / disabled). " +
      "Routing it here will NOT resurrect that tenant — choose another tenant or " +
      "create a new one.",
  },
  "default-tenant-missing": {
    title: "integration default names a tenant that does not exist",
    body:
      "The event carries no site id, and the integration's default tenant points at " +
      "a client slug that does not exist — nothing was offboarded; the integration's " +
      "default is misconfigured. Fix or clear the default under Integrations, then " +
      "route these events by hand or discard them.",
  },
  "autocreate-limit": {
    title: "auto-create paused",
    body:
      "The bound on new tenants per hour / awaiting review was reached, so this new " +
      "site was held instead of creating a tenant. Review the pending tenants, then " +
      "route these events to an existing tenant or create one here.",
  },
  "instance-disabled": {
    title: "integration was disabled",
    body:
      "The event arrived while its integration was switched off. Route it to a " +
      "tenant or discard it.",
  },
  "store-failed": {
    title: "tenant store refused the write",
    body:
      "The tenant is known but its event store could not take the write at the " +
      "time. Routing replays the event into the tenant's store.",
  },
};

export function explainQuarantineReason(reason: string): ReasonExplanation {
  return (
    REASON_HELP[reason as QuarantineReason] ?? {
      title: reason,
      body: "Held for a reason this console does not know how to explain. Route or discard it.",
    }
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const MAX_SLUG_CHARS = 48;
export const MAX_DISPLAY_NAME = 200;
export const REASON_MIN = 3;
export const REASON_MAX = 500;

/**
 * A slug suggestion from a display name — the same shape the server's
 * `slug_from_name` produces (accents stripped, lowercased, every
 * non-alphanumeric run one hyphen, bounded). The operator can edit it; the
 * server validates the final value.
 */
export function suggestSlug(displayName: string): string {
  const flat = displayName
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return flat.slice(0, MAX_SLUG_CHARS).replace(/-+$/g, "");
}

export function isValidSlug(slug: string): boolean {
  return slug.length <= 64 && SLUG_RE.test(slug);
}

/** 'none' is an explicit "no regime applies" and cannot be combined. */
export function toggleComplianceTag(current: readonly string[], tag: string): string[] {
  if (current.includes(tag)) return current.filter((t) => t !== tag);
  if (tag === "none") return ["none"];
  return [...current.filter((t) => t !== "none"), tag];
}
