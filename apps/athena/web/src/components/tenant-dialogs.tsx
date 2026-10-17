/**
 * Tenant manager dialogs — add / edit, offboard, merge.
 *
 * The rules the backend enforces are stated HERE too, before the click,
 * so an operator is never refused by surprise:
 *   - 'unclassified' cannot be confirmed: the Confirm button is inert until
 *     a kind is picked (the server would answer 422 with the same words),
 *     and a confirmed tenant's Edit never offers 'unclassified' again;
 *   - 'cloud' AI policy is a super_admin choice (data may leave the
 *     deployment) — the option is disabled for an admin, with the reason —
 *     and the dialog says when it will run as local until a compliance
 *     sign-off covers the tenant's tags (or that changing the tags revokes
 *     the sign-off on record); an edit that would CLEAR a tenant for cloud
 *     with no sign-off (tagged 'none' while asking for cloud) is the
 *     sign-off's call: a super admin saves it after step-up (the re-auth
 *     prompt opens and the save is retried), an admin cannot save it;
 *   - offboarding AND merging are a two-person REQUEST by default (a
 *     different super_admin approves) — for an admin, the only path. A super
 *     admin may apply one ALONE as the attested exception (v0.10): the
 *     dialog asks for the typed attestation (live character count), the
 *     slug typed back (checked by the server too) and then step-up
 *     re-authentication; the server's STEP_UP_REQUIRED opens the re-auth
 *     prompt and the same action is retried. The merge dialog first shows
 *     the server's preview — the caveats, what stays with the archived
 *     source, and whether the single-person guards allow it (and why not);
 *     a refusal offers the two-person request in one click.
 * Destructive actions require the slug typed back, and the dialogs say
 * exactly what stops working for the tenant's own side (buoy tokens, client
 * user sessions) — nothing more, nothing less than the server does.
 */
import { type FC, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  AI_POLICIES,
  AI_POLICY_HELP,
  AI_POLICY_LABEL,
  ATTESTATION_MAX_CHARS,
  ATTESTATION_MIN_CHARS,
  COMPLIANCE_LABEL,
  COMPLIANCE_TAGS,
  KIND_HELP,
  KIND_LABEL,
  LEFT_BEHIND_LABEL,
  MAX_DISPLAY_NAME,
  REASON_MAX,
  REASON_MIN,
  TENANT_KINDS,
  attestationLength,
  flagsLabel,
  isValidSlug,
  labelFor,
  notificationNote,
  regimesNotCovered,
  signoffRequired,
  suggestSlug,
  toggleComplianceTag,
  type AccessSevered,
  type ApprovalMode,
  type MergePreview,
  type MergeResponse,
  type OffboardResponse,
  type Tenant,
} from "@/contracts/tenant";
import { ApiError, createTenant, mergeTenant, offboardTenant, patchTenant, previewMerge } from "@/lib/api";
import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";

export const inputCls =
  "rounded border border-border bg-bg-input px-2 py-1.5 text-xs text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none";
const labelCls = "flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim";
const primaryBtn =
  "rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50";
const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";
const dangerBtn =
  "rounded-sm border border-critical bg-critical px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50";

const isStepUp = (e: unknown): e is ApiError =>
  e instanceof ApiError && (e.code === "STEP_UP_REQUIRED" || e.code === "STEP_UP_NETWORK_CHANGED");

/** A modal frame portalled to <body> (same reason as the integrations
 *  drawers: the App root's stacking context would let the footer paint
 *  over the buttons).
 *
 *  `keyboard`: Escape closes it (never while busy), focus moves into it on
 *  open (unless something inside already took it) and back to where it
 *  was on close. Opt-in — a dialog that stacks a step-up prompt over
 *  itself handles Escape its own way. */
export const ModalFrame: FC<{
  readonly label: string;
  readonly testId: string;
  readonly busy: boolean;
  readonly onClose: () => void;
  readonly children: ReactNode;
  readonly wide?: boolean;
  readonly keyboard?: boolean;
}> = ({ label, testId, busy, onClose, children, wide = false, keyboard = false }) => {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!keyboard) return undefined;
    const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (ref.current && !ref.current.contains(document.activeElement)) ref.current.focus();
    return () => { if (before?.isConnected) before.focus(); };
  }, [keyboard]);
  useEffect(() => {
    if (!keyboard) return undefined;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [keyboard, busy, onClose]);
  return createPortal(
    <>
      <div onClick={busy ? undefined : onClose} aria-hidden="true" className="fixed inset-0 z-40 bg-black/50" />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        data-testid={testId}
        tabIndex={keyboard ? -1 : undefined}
        className={[
          "fixed left-1/2 top-1/2 z-50 max-h-[92vh] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-border-bright bg-bg-elevated p-5 shadow-xl focus:outline-none",
          wide ? "w-[min(680px,94vw)]" : "w-[min(560px,94vw)]",
        ].join(" ")}
      >
        {children}
      </div>
    </>,
    document.body,
  );
};

export const ErrorLine: FC<{ readonly message: string | null }> = ({ message }) =>
  message ? (
    <div role="alert" className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
      {message}
    </div>
  ) : null;

// ---------------------------------------------------------------------------
// Kind / compliance / AI pickers (shared with the quarantine route dialog)
// ---------------------------------------------------------------------------

export const KindSelect: FC<{
  readonly value: string;
  readonly kinds: readonly string[];
  readonly onChange: (kind: string) => void;
  readonly allowUnclassified?: boolean;
  readonly id?: string;
}> = ({ value, kinds, onChange, allowUnclassified = true, id }) => {
  const options = (kinds.length ? kinds : TENANT_KINDS).filter(
    (k) => allowUnclassified || k !== "unclassified",
  );
  return (
    <label className={labelCls}>
      kind
      <select
        id={id}
        aria-label="kind"
        className={inputCls}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        title={KIND_HELP[value] ?? ""}
      >
        {options.map((k) => (
          <option key={k} value={k}>
            {labelFor(KIND_LABEL, k)}
          </option>
        ))}
      </select>
      <span className="normal-case tracking-normal text-text-dim">{KIND_HELP[value] ?? ""}</span>
    </label>
  );
};

export const ComplianceTagPicker: FC<{
  readonly value: readonly string[];
  readonly tags: readonly string[];
  readonly onChange: (next: string[]) => void;
}> = ({ value, tags, onChange }) => (
  <fieldset className="flex flex-col gap-1">
    <legend className="text-[10px] uppercase tracking-wider text-text-dim">
      compliance tags
      <span className="ml-1 normal-case tracking-normal">
        — which regimes apply; “none” means “we checked, none applies”
      </span>
    </legend>
    <div className="flex flex-wrap gap-1.5" role="group" aria-label="compliance tags">
      {(tags.length ? tags : COMPLIANCE_TAGS).map((t) => {
        const on = value.includes(t);
        return (
          <label
            key={t}
            className={[
              "inline-flex cursor-pointer items-center gap-1 rounded-sm border px-2 py-0.5 font-mono text-[11px]",
              on ? "border-accent bg-accent/15 text-accent" : "border-border text-text-secondary",
            ].join(" ")}
          >
            <input
              type="checkbox"
              className="sr-only"
              checked={on}
              onChange={() => onChange(toggleComplianceTag(value, t))}
              aria-label={`compliance ${labelFor(COMPLIANCE_LABEL, t)}`}
            />
            {labelFor(COMPLIANCE_LABEL, t)}
          </label>
        );
      })}
    </div>
  </fieldset>
);

export const AiPolicySelect: FC<{
  readonly value: string;
  readonly policies: readonly string[];
  readonly isSuperAdmin: boolean;
  readonly onChange: (policy: string) => void;
  /** What will actually run, when it differs from the choice (the sign-off rule). */
  readonly note?: string | null;
}> = ({ value, policies, isSuperAdmin, onChange, note = null }) => {
  const cloudLocked = !isSuperAdmin;
  const cloudTitle = cloudLocked
    ? "Only a super admin can choose 'cloud': with it, this tenant's data may leave the deployment."
    : AI_POLICY_HELP.cloud ?? "";
  return (
    <label className={labelCls}>
      AI policy
      <select
        aria-label="AI policy"
        className={inputCls}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        title={value === "cloud" ? cloudTitle : AI_POLICY_HELP[value] ?? ""}
      >
        {(policies.length ? policies : AI_POLICIES).map((p) => (
          <option
            key={p}
            value={p}
            disabled={p === "cloud" && cloudLocked}
            title={p === "cloud" ? cloudTitle : AI_POLICY_HELP[p] ?? ""}
          >
            {labelFor(AI_POLICY_LABEL, p)}
            {p === "cloud" && cloudLocked ? " — super admin only" : ""}
          </option>
        ))}
      </select>
      <span className="normal-case tracking-normal text-text-dim" data-testid="ai-policy-help">
        {value === "cloud" ? cloudTitle : AI_POLICY_HELP[value] ?? ""}
        {cloudLocked && value !== "cloud" ? ` ${cloudTitle}` : ""}
      </span>
      {note ? (
        <span className="normal-case tracking-normal text-high" data-testid="ai-policy-signoff-note">
          {note}
        </span>
      ) : null}
    </label>
  );
};

/** What the Edit / Add dialog says about cloud once saved: runs as local
 *  until signed, or which sign-off a tag change revokes. null = nothing to
 *  add (the choice is what runs). */
export function cloudSignoffNote(
  tenant: Pick<Tenant, "compliance_flags" | "signoff"> | null,
  policy: string,
  flags: readonly string[],
): string | null {
  const sorted = [...flags].sort();
  const same = (a: readonly string[] | null | undefined): boolean =>
    !!a && a.length === sorted.length && [...a].sort().every((f, i) => f === sorted[i]);
  const live = tenant?.signoff?.state === "live" ? tenant.signoff : null;
  const tagsChange = tenant !== null && !same(tenant.compliance_flags);
  if (live && tagsChange && signoffRequired(tenant?.compliance_flags ?? [])) {
    const revoke = `Changing the compliance tags revokes sign-off #${live.signoff_id ?? "?"}`;
    return policy === "cloud" && signoffRequired(sorted)
      ? `${revoke} — this tenant will run as local until a super admin signs off for ${flagsLabel(sorted)}.`
      : `${revoke}.`;
  }
  if (policy !== "cloud" || !signoffRequired(sorted)) return null;
  if (live && same(live.flags_covered)) return null;
  return sorted.length === 0
    ? "Runs as local until a super admin signs off for cloud AI — this tenant has no compliance tags yet, which needs a sign-off too."
    : `Runs as local until a super admin signs off for cloud AI covering ${flagsLabel(sorted)} (AI column → Sign off…).`;
}

/** Would saving make the tenant run as cloud with NO sign-off — asking for
 *  cloud and tagged exactly 'none' — where it did not before? That is the
 *  sign-off's decision (super admin + step-up), whoever makes it. */
export function clearsCloudWithoutSignoff(
  tenant: Pick<Tenant, "ai_policy" | "effective_ai_policy" | "compliance_flags"> | null,
  policy: string,
  flags: readonly string[],
): boolean {
  if (policy !== "cloud" || signoffRequired(flags)) return false;
  if (tenant === null) return true;
  return !(tenant.effective_ai_policy === "cloud" && !signoffRequired(tenant.compliance_flags));
}

// ---------------------------------------------------------------------------
// Add / edit
// ---------------------------------------------------------------------------

interface Vocab {
  readonly kinds: readonly string[];
  readonly compliance_tags: readonly string[];
  readonly ai_policies: readonly string[];
}

interface TenantFormDialogProps {
  /** null = create a new tenant; a tenant = edit it. */
  readonly tenant: Tenant | null;
  readonly vocab: Vocab;
  readonly isSuperAdmin: boolean;
  /** Edit mode: Save also confirms the review (needs a kind). Opened from
   *  the row's Confirm button when the tenant is still unclassified. */
  readonly confirmOnSave?: boolean;
  readonly onClose: () => void;
  readonly onSaved: (t: Tenant, note: string) => void;
}

export const TenantFormDialog: FC<TenantFormDialogProps> = ({
  tenant,
  vocab,
  isSuperAdmin,
  confirmOnSave = false,
  onClose,
  onSaved,
}) => {
  const creating = tenant === null;
  const [displayName, setDisplayName] = useState(tenant?.display_name ?? "");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  // Plain strings: the pickers offer whatever vocabulary the server sent.
  const [kind, setKind] = useState<string>(tenant?.kind ?? "unclassified");
  const [flags, setFlags] = useState<string[]>([...(tenant?.compliance_flags ?? [])]);
  const [aiPolicy, setAiPolicy] = useState<string>(tenant?.ai_policy ?? "none");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<StepUpReason | null>(null);

  // The slug follows the name until the operator touches it.
  useEffect(() => {
    if (creating && !slugEdited) setSlug(suggestSlug(displayName));
  }, [creating, slugEdited, displayName]);

  const name = displayName.replace(/\s+/g, " ").trim();
  const nameOk = name.length > 0 && name.length <= MAX_DISPLAY_NAME;
  const slugOk = !creating || isValidSlug(slug);
  const mustPickKind = confirmOnSave && kind === "unclassified";
  // A confirmed tenant keeps a real kind (the server answers 422 otherwise).
  // A legacy row that is already confirmed + unclassified (bare-SQL seeds on
  // a pre-034 registry — migration 034 moved those back to pending and now
  // refuses the combination) still shows its value honestly and can be
  // saved without touching the kind; picking a kind fixes it.
  const confirmed = !creating && tenant.review_state === "confirmed";
  const legacyUnclassified = confirmed && tenant.kind === "unclassified";
  const backToUnclassified = confirmed && !legacyUnclassified && kind === "unclassified";
  // Clearing a tenant for cloud with no sign-off is the sign-off's bar.
  const clearsCloud = clearsCloudWithoutSignoff(tenant, aiPolicy, flags);
  const clearanceNote = clearsCloud
    ? isSuperAdmin
      ? "Saving clears this tenant for cloud AI with no sign-off (tagged “none”) — you will be asked to re-authenticate (step-up)."
      : "Tagged “none” while asking for cloud, this tenant would be cleared for cloud AI with no sign-off — only a super admin may do that."
    : null;
  const canSave =
    nameOk && slugOk && !mustPickKind && !backToUnclassified && !busy && !(clearsCloud && !isSuperAdmin);

  const onSave = async (): Promise<void> => {
    if (!canSave) return;
    setBusy(true);
    setError(null);
    try {
      if (creating) {
        const t = await createTenant({
          slug,
          display_name: name,
          kind,
          compliance_flags: flags,
          ...(aiPolicy !== "none" ? { ai_policy: aiPolicy } : {}),
        });
        onSaved(
          t,
          t.review_state === "pending"
            ? `Tenant ${t.slug} created — it stays “needs review” until a kind is set.`
            : `Tenant ${t.slug} created.`,
        );
        return;
      }
      const patch = {
        ...(name !== tenant.display_name ? { display_name: name } : {}),
        ...(kind !== tenant.kind ? { kind } : {}),
        ...(flags.slice().sort().join(",") !== tenant.compliance_flags.slice().sort().join(",")
          ? { compliance_flags: flags }
          : {}),
        ...(aiPolicy !== tenant.ai_policy ? { ai_policy: aiPolicy } : {}),
        ...(confirmOnSave && tenant.review_state === "pending" ? { review_state: "confirmed" as const } : {}),
      };
      if (Object.keys(patch).length === 0) {
        onClose();
        return;
      }
      const t = await patchTenant(tenant.slug, patch);
      onSaved(t, confirmOnSave ? `Tenant ${t.slug} confirmed as ${labelFor(KIND_LABEL, t.kind)}.` : `Tenant ${t.slug} updated.`);
    } catch (e) {
      // Clearing for cloud needs step-up: re-authenticate, then save again.
      if (isStepUp(e)) setStepUp(e.code === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
      else setError(e instanceof Error ? e.message : "Save failed");
      setBusy(false);
    }
  };

  return (
    <>
      <ModalFrame
        label={creating ? "Add tenant" : `Edit ${tenant.display_name}`}
        testId="tenant-form-dialog"
        busy={busy}
        onClose={onClose}
      >
        <h2 className="text-base font-semibold text-text-primary">
          {creating ? "Add tenant" : confirmOnSave ? `Confirm ${tenant.display_name}` : `Edit ${tenant.display_name}`}
        </h2>
        {confirmOnSave ? (
          <p className="mt-1 text-xs leading-relaxed text-text-secondary" data-testid="confirm-needs-kind">
            Confirming means saying what this tenant is. Pick a kind — “unclassified” cannot be confirmed.
          </p>
        ) : creating ? (
          <p className="mt-1 text-xs leading-relaxed text-text-secondary">
            Creates the tenant and its event store now. With a kind chosen it is confirmed at once;
            left unclassified it appears under “needs review”. AI policy starts at “none” unless you
            say otherwise.
          </p>
        ) : null}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void onSave();
          }}
          className="mt-3 flex flex-col gap-3"
        >
          <label className={labelCls}>
            display name
            <input
              aria-label="display name"
              className={inputCls}
              value={displayName}
              maxLength={MAX_DISPLAY_NAME}
              placeholder="Acme Corp"
              onChange={(e) => setDisplayName(e.target.value)}
              autoFocus
            />
          </label>
          {creating ? (
            <label className={labelCls}>
              slug
              <input
                aria-label="slug"
                className={`${inputCls} font-mono ${slug && !slugOk ? "border-critical" : ""}`}
                value={slug}
                placeholder="acme-corp"
                onChange={(e) => {
                  setSlugEdited(true);
                  setSlug(e.target.value.trim());
                }}
              />
              <span className="normal-case tracking-normal text-text-dim">
                Suggested from the name; lowercase words joined by single hyphens. It cannot be
                changed later.
              </span>
            </label>
          ) : (
            <p className="font-mono text-[11px] text-text-dim">slug: {tenant.slug}</p>
          )}
          <KindSelect
            value={kind}
            kinds={vocab.kinds}
            onChange={setKind}
            allowUnclassified={!confirmed || legacyUnclassified}
          />
          {legacyUnclassified ? (
            <p className="text-[11px] text-high" data-testid="legacy-unclassified-note">
              This tenant is marked confirmed but has no kind yet — pick one. Other changes save
              without it.
            </p>
          ) : null}
          <ComplianceTagPicker value={flags} tags={vocab.compliance_tags} onChange={setFlags} />
          <AiPolicySelect
            value={aiPolicy}
            policies={vocab.ai_policies}
            isSuperAdmin={isSuperAdmin}
            onChange={setAiPolicy}
            note={clearanceNote ?? cloudSignoffNote(tenant, aiPolicy, flags)}
          />
          <ErrorLine message={error} />
          <div className="mt-1 flex items-center justify-end gap-2">
            {mustPickKind ? (
              <span className="mr-auto text-[11px] text-high" data-testid="confirm-blocked">
                Pick a kind to confirm.
              </span>
            ) : null}
            <button type="button" disabled={busy} onClick={onClose} className={secondaryBtn}>
              Cancel
            </button>
            <button type="submit" disabled={!canSave} className={primaryBtn} data-testid="tenant-form-save">
              {busy ? "Saving…" : creating ? "Create tenant" : confirmOnSave ? "Save & confirm" : "Save"}
            </button>
          </div>
        </form>
      </ModalFrame>
      {createPortal(
        <StepUpModal
          open={stepUp !== null}
          reason={stepUp ?? "required"}
          onClose={() => setStepUp(null)}
          onSuccess={() => {
            setStepUp(null);
            void onSave();
          }}
        />,
        document.body,
      )}
    </>
  );
};

// ---------------------------------------------------------------------------
// What an offboard / merge severed
// ---------------------------------------------------------------------------

/** What became of the integration defaults that pointed at the tenant. The
 *  server does two different things and the notice must say which: an
 *  OFFBOARD clears them (sets NULL — `_sever_client_access`), so an id-less
 *  event from that integration is held in quarantine from now on; a MERGE
 *  re-points them at the target first (`_apply_merge`), and the count it
 *  reports under the same field is that re-point. */
export type DefaultsFate = { readonly kind: "offboard" } | { readonly kind: "merge"; readonly target: string };

/** One honest sentence about what the server severed for the tenant's own
 *  side — with the loose end the operator still owns (accounts to remove). */
export function accessNote(a: AccessSevered, fate: DefaultsFate): string {
  const parts = [`${a.tokens_revoked} buoy/API token(s) revoked`, `${a.sessions_revoked} client user session(s) ended`];
  if (a.instance_defaults_cleared) {
    parts.push(
      fate.kind === "merge"
        ? `${a.instance_defaults_cleared} integration default(s) re-pointed to ${fate.target}`
        : `${a.instance_defaults_cleared} integration default(s) cleared — id-less events from that integration will now be held in quarantine`,
    );
  }
  const tail =
    a.scoped_operators > 0
      ? ` ${a.scoped_operators} client user account(s) are still scoped to it and can sign in (they see nothing) — remove them under Operators.`
      : "";
  return `${parts.join(", ")}.${tail}`;
}

// ---------------------------------------------------------------------------
// Approval: the two-person request (default) or the attested exception
// ---------------------------------------------------------------------------

/** How an offboard / merge is approved. A super admin chooses; an admin
 *  only ever files the request (and never sees this). */
export const ApprovalChoice: FC<{
  readonly verb: "offboard" | "merge";
  readonly value: ApprovalMode;
  readonly onChange: (mode: ApprovalMode) => void;
  /** Why applying alone is not available right now (null = it is). */
  readonly aloneBlocked: string | null;
}> = ({ verb, value, onChange, aloneBlocked }) => (
  <fieldset className="mt-3 flex flex-col gap-1.5 text-xs text-text-primary" data-testid="approval-choice">
    <legend className="mb-1 text-[10px] uppercase tracking-wider text-text-dim">approval</legend>
    <label className="flex items-start gap-2">
      <input
        type="radio"
        name={`${verb}-approval`}
        aria-label="two-person request"
        checked={value === "two_person"}
        onChange={() => onChange("two_person")}
      />
      <span>
        <span className="font-semibold">Two-person request</span> (the default) — a second super admin approves it
        before anything changes.
      </span>
    </label>
    <label className={`flex items-start gap-2 ${aloneBlocked ? "opacity-60" : ""}`}>
      <input
        type="radio"
        name={`${verb}-approval`}
        aria-label="apply alone (attested exception)"
        checked={value === "single_attested"}
        disabled={aloneBlocked !== null}
        onChange={() => onChange("single_attested")}
      />
      <span>
        <span className="font-semibold text-critical">Apply alone</span> — an attested exception: you type why it
        cannot wait, type the slug back, and re-authenticate. The other admins are notified, and one of them can
        review it afterwards.
      </span>
    </label>
    {aloneBlocked ? (
      <span className="ml-6 text-[11px] text-text-dim" data-testid="alone-blocked">
        {aloneBlocked}
      </span>
    ) : null}
  </fieldset>
);

/** The typed attestation, with the count the server applies (trimmed). */
export const AttestationField: FC<{
  readonly value: string;
  readonly onChange: (v: string) => void;
  readonly verb: "offboard" | "merge";
}> = ({ value, onChange, verb }) => {
  const n = attestationLength(value);
  return (
    <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
      <span>
        Attestation <span className="text-critical">*</span>{" "}
        <span className="text-text-dim">
          — why this {verb} cannot wait for a second approver, and that you checked what it does. Stored verbatim on
          the change record (the audit log keeps its hash). Never paste a credential here.
        </span>
      </span>
      <textarea
        aria-label="attestation"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        maxLength={ATTESTATION_MAX_CHARS}
        rows={3}
        className={`${inputCls} font-mono`}
      />
      <span
        className={`text-[11px] ${n >= ATTESTATION_MIN_CHARS ? "text-text-dim" : "text-high"}`}
        data-testid="attestation-count"
      >
        {n} / {ATTESTATION_MIN_CHARS} characters minimum
      </span>
    </label>
  );
};

/** The server's "two people must decide" — with the offer it makes. A
 *  two-person request is offered only when someone could approve it: with
 *  no other super admin, the message's own remedies are the way. */
const IneligibleBox: FC<{
  readonly message: string;
  readonly busy: boolean;
  readonly canRequest: boolean;
  readonly onFileRequest: () => void;
}> = ({ message, busy, canRequest, onFileRequest }) => (
  <div role="alert" className="mt-3 rounded border border-high bg-high/10 px-3 py-2 text-xs text-high" data-testid="single-person-refused">
    <p>{message}</p>
    {canRequest ? (
      <button type="button" className={`${secondaryBtn} mt-2`} disabled={busy} onClick={onFileRequest} data-testid="file-request-instead">
        File a two-person request instead
      </button>
    ) : null}
  </div>
);

// ---------------------------------------------------------------------------
// Offboard
// ---------------------------------------------------------------------------

interface OffboardDialogProps {
  readonly tenant: Tenant;
  readonly isSuperAdmin: boolean;
  readonly onClose: () => void;
  readonly onDone: (r: OffboardResponse, note: string) => void;
}

export const OffboardDialog: FC<OffboardDialogProps> = ({ tenant, isSuperAdmin, onClose, onDone }) => {
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [mode, setMode] = useState<ApprovalMode>("two_person");
  const [attestation, setAttestation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<StepUpReason | null>(null);
  const typedOk = typed.trim() === tenant.slug;
  const reasonOk = reason.trim().length >= REASON_MIN;
  const alone = isSuperAdmin && mode === "single_attested";
  const canSubmit = typedOk && reasonOk && !busy && (!alone || attestationLength(attestation) >= ATTESTATION_MIN_CHARS);

  const perform = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const r = alone
        ? await offboardTenant(tenant.slug, reason.trim(), { attestation, confirm_subject: typed.trim() })
        : await offboardTenant(tenant.slug, reason.trim());
      onDone(
        r,
        r.applied
          ? `${tenant.slug} offboarded alone (attested single-person exception, change #${r.change_request_id ?? "?"}): ${r.mappings_frozen} site mapping(s) frozen, ${accessNote(r.access, { kind: "offboard" })} Its data is kept.${notificationNote(r.notifications)}`
          : `Offboard of ${tenant.slug} requested — a super admin other than you must approve it.`,
      );
    } catch (e) {
      if (isStepUp(e)) setStepUp(e.code === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
      else setError(e instanceof Error ? e.message : "Offboard failed");
      setBusy(false);
    }
  };

  return (
    <>
      <ModalFrame label={`Offboard ${tenant.display_name}`} testId="offboard-dialog" busy={busy} onClose={onClose}>
        <h2 className="text-base font-semibold text-text-primary">Offboard {tenant.display_name}?</h2>
        <p className="mt-2 text-xs leading-relaxed text-text-secondary">
          Its status becomes <span className="text-text-primary">offboarded</span>: its vendor site
          mappings are frozen (the sites stay known as this tenant's, so their future traffic is held in
          quarantine instead of landing here or creating a look-alike tenant), its buoy/API tokens are
          revoked, its client users' sessions are ended and they can no longer read its data, and its
          data is <strong>kept</strong>. An offboarded tenant is never brought back by incoming traffic.
          Client user accounts scoped to it are not deleted — remove them under Operators.
        </p>
        <p className="mt-2 text-xs leading-relaxed text-text-secondary" data-testid="offboard-role-note">
          {isSuperAdmin
            ? "Two-person approval is the default: this files a request that a second super admin approves. Applying it alone is an attested exception."
            : "As an admin this creates a request — a super admin must approve it before anything changes."}
        </p>
        {isSuperAdmin ? <ApprovalChoice verb="offboard" value={mode} onChange={setMode} aloneBlocked={null} /> : null}
        <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
          <span>
            Reason <span className="text-critical">*</span>{" "}
            <span className="text-text-dim">— recorded in the audit log. Never paste a credential here.</span>
          </span>
          <textarea
            aria-label="reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={REASON_MAX}
            rows={3}
            placeholder="e.g. contract ended 2026-09"
            className={`${inputCls} font-mono`}
          />
        </label>
        {alone ? <AttestationField value={attestation} onChange={setAttestation} verb="offboard" /> : null}
        <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
          <span>
            Type <span className="font-mono text-critical">{tenant.slug}</span> to confirm
            {alone ? <span className="text-text-dim"> — checked by the server too</span> : null}
          </span>
          <input
            aria-label="type the slug to confirm"
            className={`${inputCls} font-mono`}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
          />
        </label>
        <ErrorLine message={error} />
        <div className="mt-4 flex items-center justify-end gap-2">
          <button type="button" disabled={busy} onClick={onClose} className={secondaryBtn}>
            Cancel
          </button>
          <button
            type="button"
            disabled={!canSubmit}
            onClick={() => void perform()}
            className={alone ? dangerBtn : primaryBtn}
            data-testid="offboard-confirm"
          >
            {busy
              ? "Working…"
              : alone
                ? "Offboard alone (step-up)"
                : isSuperAdmin
                  ? "Request offboard — a second super admin must approve"
                  : "Request offboard — a super admin must approve"}
          </button>
        </div>
      </ModalFrame>
      {createPortal(
        <StepUpModal
          open={stepUp !== null}
          reason={stepUp ?? "required"}
          onClose={() => setStepUp(null)}
          onSuccess={() => {
            setStepUp(null);
            void perform();
          }}
        />,
        document.body,
      )}
    </>
  );
};

// ---------------------------------------------------------------------------
// Merge into…
// ---------------------------------------------------------------------------

interface MergeDialogProps {
  readonly tenant: Tenant;
  readonly candidates: readonly Tenant[];
  readonly isSuperAdmin: boolean;
  /** Pre-selected surviving tenant (a duplicate hint's "Merge…"). The
   *  operator still types the slug and a reason — a hint never merges. */
  readonly initialTarget?: string | undefined;
  readonly onClose: () => void;
  readonly onDone: (r: MergeResponse, note: string) => void;
}

/** One line on what the single-person guards answered for this pair. */
function eligibilityLine(subject: string, target: string, p: MergePreview): string {
  const e = p.single_person;
  if (e.eligible) {
    return `Single-person merge allowed: ${target} runs AI as ${e.target_effective_ai_policy}, no more permissively than ${subject} (${e.subject_effective_ai_policy}), and ${subject} carries no compliance regime ${target} lacks.`;
  }
  return "Single-person merge not allowed — two people must decide:";
}

export const MergeDialog: FC<MergeDialogProps> = ({
  tenant,
  candidates,
  isSuperAdmin,
  initialTarget,
  onClose,
  onDone,
}) => {
  const [target, setTarget] = useState(() =>
    initialTarget &&
    candidates.some((t) => t.slug === initialTarget && t.slug !== tenant.slug && t.status === "active" && !t.pending_request)
      ? initialTarget
      : "",
  );
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [mode, setMode] = useState<ApprovalMode>("two_person");
  const [attestation, setAttestation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<StepUpReason | null>(null);
  const [preview, setPreview] = useState<MergePreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const targets = useMemo(
    () =>
      candidates
        .filter((t) => t.slug !== tenant.slug && t.status === "active" && !t.pending_request)
        .sort((a, b) => a.display_name.localeCompare(b.display_name)),
    [candidates, tenant.slug],
  );

  // The server's preview for the chosen pair: caveats, what stays behind,
  // and the single-person guards' answer — before anyone confirms.
  useEffect(() => {
    setPreview(null);
    setPreviewError(null);
    setRefused(null);
    if (!target) return undefined;
    let cancelled = false;
    previewMerge(tenant.slug, target).then(
      (p) => {
        if (!cancelled) setPreview(p);
      },
      (e: unknown) => {
        if (!cancelled) setPreviewError(e instanceof Error ? e.message : "preview failed");
      },
    );
    return () => {
      cancelled = true;
    };
  }, [tenant.slug, target]);

  const aloneBlocked = !target
    ? "Pick the surviving tenant first."
    : preview === null
      ? previewError
        ? "Eligibility could not be checked — file a two-person request."
        : "Checking whether one person may apply it…"
      : preview.single_person.eligible
        ? null
        : "Not for this pair — two people must decide (see above).";
  // A blocked choice never stays selected.
  useEffect(() => {
    if (aloneBlocked !== null) setMode("two_person");
  }, [aloneBlocked]);

  const alone = isSuperAdmin && mode === "single_attested" && aloneBlocked === null;
  const typedOk = typed.trim() === tenant.slug;
  const reasonOk = reason.trim().length >= REASON_MIN;
  const canSubmit =
    target !== "" && typedOk && reasonOk && !busy && (!alone || attestationLength(attestation) >= ATTESTATION_MIN_CHARS);
  const targetTenant = candidates.find((t) => t.slug === target) ?? null;
  const flagsAdded = targetTenant ? regimesNotCovered(tenant.compliance_flags, targetTenant.compliance_flags) : [];
  // An untagged subject takes a 'none' target back to [] (the server's
  // preview says so; no regime is ADDED, but "no regime applies" goes).
  const noneDropped =
    flagsAdded.length === 0 &&
    targetTenant !== null &&
    (preview?.target_flags_after ?? null) !== null &&
    flagsLabel(preview?.target_flags_after ?? []) !== flagsLabel(targetTenant.compliance_flags);
  // Nobody else could approve a two-person request (0 other super admins).
  const nobodyToApprove = isSuperAdmin && preview?.single_person.other_super_admins === 0;

  const perform = async (asMode: ApprovalMode): Promise<void> => {
    setBusy(true);
    setError(null);
    setRefused(null);
    try {
      const r =
        asMode === "single_attested"
          ? await mergeTenant(tenant.slug, target, reason.trim(), { attestation, confirm_subject: typed.trim() })
          : await mergeTenant(tenant.slug, target, reason.trim());
      const added = r.target_flags_added ?? [];
      const after = r.target_flags_after ?? null;
      const revoked = r.signoffs_invalidated ?? [];
      const revokedNote = revoked.length ? `; its cloud sign-off ${revoked.map((i) => `#${i}`).join(", ")} was revoked.` : ".";
      const flagsNote = added.length
        ? ` ${target} is now also tagged ${flagsLabel(added)}${revokedNote}`
        : after !== null && after.length === 0 && targetTenant !== null && targetTenant.compliance_flags.includes("none")
          ? ` ${target} is no longer tagged 'none' (it took in never-tagged data) — cloud AI needs a sign-off${revokedNote}`
          : "";
      onDone(
        r,
        r.applied
          ? `${tenant.slug} merged into ${target} alone (attested single-person exception, change #${r.change_request_id ?? "?"}): ${r.events_copied} event(s) copied (${r.events_skipped} already there), ${r.mappings_repointed} site mapping(s) re-pointed, ${accessNote(r.access, { kind: "merge", target })} ${tenant.slug} is archived.${flagsNote}${notificationNote(r.notifications)}`
          : `Merge of ${tenant.slug} into ${target} requested — a super admin other than you must approve it.`,
      );
    } catch (e) {
      if (isStepUp(e)) setStepUp(e.code === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
      else if (e instanceof ApiError && e.code === "SINGLE_PERSON_INELIGIBLE") setRefused(e.message);
      else setError(e instanceof Error ? e.message : "Merge failed");
      setBusy(false);
    }
  };

  const behind = preview
    ? Object.entries(preview.left_behind)
        .map(([k, n]) => `${n} ${LEFT_BEHIND_LABEL[k] ?? k}`)
        .join(", ")
    : "";

  return (
    <>
      <ModalFrame label={`Merge ${tenant.display_name} into another tenant`} testId="merge-dialog" busy={busy} onClose={onClose} wide>
        <h2 className="text-base font-semibold text-text-primary">Merge {tenant.display_name} into…</h2>
        <p className="mt-2 text-xs leading-relaxed text-text-secondary">
          Every event of {tenant.slug} is copied into the target (duplicates skipped), its vendor site
          mappings and any integration default are re-pointed there, and {tenant.slug} itself is{" "}
          <span className="text-text-primary">archived</span>: its buoy/API tokens stop working (issue
          new ones for the target), and its client users' sessions are ended — re-scope those accounts
          to the target under Operators. Pick the tenant that should survive.
        </p>
        <p className="mt-2 text-xs leading-relaxed text-text-secondary" data-testid="merge-role-note">
          {isSuperAdmin
            ? "Two-person approval is the default: this files a request that a second super admin approves. Merging alone is an attested exception, allowed only when the guards below say so."
            : "As an admin this creates a request — a super admin other than you must approve it before anything changes."}
        </p>
        <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
          <span>Merge into</span>
          <select aria-label="merge target" className={inputCls} value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">— select the surviving tenant —</option>
            {targets.map((t) => (
              <option key={t.slug} value={t.slug}>
                {t.display_name} ({t.slug}) — {t.event_count} events
              </option>
            ))}
          </select>
          {targets.length === 0 ? (
            <span className="text-text-dim">No other active tenant without a pending request.</span>
          ) : null}
        </label>
        {preview ? (
          <section className="mt-3 rounded border border-border bg-bg-card px-3 py-2 text-xs" data-testid="merge-caveats">
            <h3 className="mb-1 text-[10px] uppercase tracking-wider text-text-dim">before you merge</h3>
            <ul className="list-disc space-y-1 pl-4 text-text-secondary">
              {preview.caveats.map((c) => (
                <li key={c.code} data-testid={`merge-caveat-${c.code}`}>
                  {c.text}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-text-secondary" data-testid="merge-left-behind">
              Moves: {preview.events_to_copy} event(s). Stays with the archived {tenant.slug}: {behind}.
            </p>
          </section>
        ) : previewError ? (
          <p className="mt-3 text-[11px] text-high" data-testid="merge-preview-error">
            The merge preview could not be loaded ({previewError}).
          </p>
        ) : null}
        {flagsAdded.length > 0 ? (
          <p className="mt-2 rounded border border-high/50 bg-high/10 px-3 py-2 text-xs text-high" data-testid="merge-flags-note">
            {tenant.slug} is tagged {flagsLabel(flagsAdded)} and {target} is not: the merge adds{" "}
            {flagsLabel(flagsAdded)} to {target}'s compliance tags, and revokes {target}'s cloud AI sign-off if it has
            one — cloud waits for a new sign-off covering them.
          </p>
        ) : noneDropped ? (
          <p className="mt-2 rounded border border-high/50 bg-high/10 px-3 py-2 text-xs text-high" data-testid="merge-flags-note">
            {tenant.slug} has never been tagged and {target} is tagged “none”: the merge takes {target} back to no
            tags (nobody has said no regime applies to {tenant.slug}'s data), so cloud AI for {target} then needs a
            sign-off.
          </p>
        ) : null}
        {isSuperAdmin && preview ? (
          <div
            className={`mt-3 rounded border px-3 py-2 text-xs ${preview.single_person.eligible ? "border-border text-text-secondary" : "border-high/50 bg-high/10 text-high"}`}
            data-testid="merge-eligibility"
          >
            <p>{eligibilityLine(tenant.slug, target, preview)}</p>
            {preview.single_person.reasons.length ? (
              <ul className="mt-1 list-disc pl-4">
                {preview.single_person.reasons.map((r) => (
                  <li key={r.code} data-testid={`merge-ineligible-${r.code}`}>
                    {r.message}
                    {r.remedy ? (
                      <span className="block text-text-secondary" data-testid={`merge-remedy-${r.code}`}>
                        To merge alone: {r.remedy}.
                      </span>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : null}
            {!preview.single_person.eligible && nobodyToApprove ? (
              <p className="mt-1 text-text-secondary" data-testid="merge-no-approver">
                A two-person request needs a super admin other than you to approve it, and there is none — use a way
                above instead.
              </p>
            ) : null}
          </div>
        ) : null}
        {isSuperAdmin ? <ApprovalChoice verb="merge" value={mode} onChange={setMode} aloneBlocked={aloneBlocked} /> : null}
        <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
          <span>
            Reason <span className="text-critical">*</span>{" "}
            <span className="text-text-dim">— shown to the approver and recorded in the audit log.</span>
          </span>
          <textarea
            aria-label="reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={REASON_MAX}
            rows={3}
            placeholder="e.g. same customer created twice from two vendor sites"
            className={`${inputCls} font-mono`}
          />
        </label>
        {alone ? <AttestationField value={attestation} onChange={setAttestation} verb="merge" /> : null}
        <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
          <span>
            Type <span className="font-mono text-critical">{tenant.slug}</span> (the tenant that will be archived) to confirm
            {alone ? <span className="text-text-dim"> — checked by the server too</span> : null}
          </span>
          <input
            aria-label="type the slug to confirm"
            className={`${inputCls} font-mono`}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
          />
        </label>
        {refused ? (
          <IneligibleBox
            message={refused}
            busy={busy}
            canRequest={!nobodyToApprove}
            onFileRequest={() => void perform("two_person")}
          />
        ) : null}
        <ErrorLine message={error} />
        <div className="mt-4 flex items-center justify-end gap-2">
          <button type="button" disabled={busy} onClick={onClose} className={secondaryBtn}>
            Cancel
          </button>
          <button
            type="button"
            disabled={!canSubmit}
            onClick={() => void perform(alone ? "single_attested" : "two_person")}
            className={alone ? dangerBtn : primaryBtn}
            data-testid="merge-submit"
          >
            {busy
              ? "Working…"
              : alone
                ? "Merge alone (step-up)"
                : isSuperAdmin
                  ? "Request merge — a second super admin must approve"
                  : "Request merge — a super admin must approve"}
          </button>
        </div>
      </ModalFrame>
      {createPortal(
        <StepUpModal
          open={stepUp !== null}
          reason={stepUp ?? "required"}
          onClose={() => setStepUp(null)}
          onSuccess={() => {
            setStepUp(null);
            void perform("single_attested");
          }}
        />,
        document.body,
      )}
    </>
  );
};
