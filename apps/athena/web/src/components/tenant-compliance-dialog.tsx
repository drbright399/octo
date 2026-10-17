/**
 * ComplianceSignoffDialog — "Sign off for cloud AI" + the sign-off history
 * (Settings → Tenants, v0.10).
 *
 * A tenant may ASK for AI policy 'cloud', but it RUNS as local until an
 * Athena Admin (super admin) records a sign-off for EXACTLY the tenant's
 * current compliance flags, naming the agreement each of those regimes
 * requires (a BAA is HIPAA's instrument — not CJIS's, PCI's, GLBA's, BIPA's
 * or FERPA's). This dialog is where that happens, and it says so plainly:
 *   - the flags the sign-off will cover are the server's current ones (sent
 *     back as `acknowledge_flags` — a dialog opened before someone changed
 *     them is refused, never signs a stale set); '[]' (never tagged) needs a
 *     sign-off too, and is shown as such;
 *   - the attestation template (and its version) is shown above a typed
 *     attestation, one agreement reference per regime (each labelled with
 *     the instrument that regime needs) and a term (≤ 12 months);
 *   - signing and revoking need step-up re-authentication: the server
 *     answers STEP_UP_REQUIRED, the re-auth modal opens, and the action is
 *     retried once it succeeds;
 *   - admins see the history read-only; only a super admin signs or revokes.
 * The status line shows what RUNS (requested vs effective, and why) — never
 * "cloud" for a tenant that is running as local, and "cleared for cloud"
 * rather than "runs as cloud": no cloud model is connected yet.
 */
import { type FC, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  COMPLIANCE_LABEL,
  NO_CLOUD_MODEL_NOTE,
  SIGNOFF_STATE_LABEL,
  flagsLabel,
  labelFor,
  signoffRequired,
  type ComplianceSignoff,
  type SignoffHistoryResponse,
  type Tenant,
} from "@/contracts/tenant";
import {
  ApiError,
  listComplianceSignoffs,
  revokeComplianceSignoff,
  signComplianceSignoff,
} from "@/lib/api";
import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";
import { ErrorLine, ModalFrame, inputCls } from "@/components/tenant-dialogs";

const labelCls = "flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim";
const primaryBtn =
  "rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50";
const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";
const dangerBtn =
  "rounded-sm border border-critical bg-critical px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50";
const chip = (tone: "accent" | "high" | "dim" | "success" | "critical"): string =>
  [
    "inline-flex items-center rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
    tone === "accent"
      ? "border-accent/50 bg-accent/10 text-accent"
      : tone === "high"
        ? "border-high/60 bg-high/10 text-high"
        : tone === "success"
          ? "border-success/60 bg-success/10 text-success"
          : tone === "critical"
            ? "border-critical/60 bg-critical/10 text-critical"
            : "border-border text-text-dim",
  ].join(" ");

const REVOKE_MIN = 3;
const REVOKE_MAX = 500;

type PendingAction = { readonly kind: "sign" } | { readonly kind: "revoke"; readonly id: number; readonly reason: string };

function stateTone(state: string): "success" | "high" | "dim" | "critical" {
  if (state === "live") return "success";
  if (state === "superseded") return "dim";
  if (state === "revoked") return "critical";
  return "high";
}

function day(iso: string | null): string {
  return iso ? iso.slice(0, 10) : "—";
}

interface ComplianceSignoffDialogProps {
  readonly tenant: Tenant;
  readonly isSuperAdmin: boolean;
  readonly onClose: () => void;
  /** A sign-off was recorded or revoked: the parent reloads and shows `note`. */
  readonly onDone: (note: string) => void;
}

export const ComplianceSignoffDialog: FC<ComplianceSignoffDialogProps> = ({ tenant, isSuperAdmin, onClose, onDone }) => {
  const [history, setHistory] = useState<SignoffHistoryResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // One reference per agreement the tenant's flags need (keyed by regime).
  const [refs, setRefs] = useState<Readonly<Record<string, string>>>({});
  const [attestation, setAttestation] = useState("");
  const [term, setTerm] = useState<number | null>(null);
  const [renewing, setRenewing] = useState(false);
  const [revoking, setRevoking] = useState<number | null>(null);
  const [revokeReason, setRevokeReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<StepUpReason | null>(null);
  const pending = useRef<PendingAction | null>(null);

  const load = useCallback(async (): Promise<void> => {
    setLoadError(null);
    try {
      setHistory(await listComplianceSignoffs(tenant.slug));
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : "Failed to load compliance sign-offs");
    }
  }, [tenant.slug]);

  useEffect(() => {
    void load();
  }, [load]);

  const policy = history?.ai_policy ?? null;
  const flags = policy?.flags ?? tenant.compliance_flags;
  const needsSignoff = signoffRequired(flags);
  const live = policy?.signoff.state === "live";
  const departed = tenant.status !== "active" && tenant.status !== "disabled";
  const canSign = isSuperAdmin && needsSignoff && !departed && history !== null && (!live || renewing);
  const minChars = history?.attestation.min_chars ?? 40;
  const maxChars = history?.attestation.max_chars ?? 2000;
  const termMax = history?.term_months_max ?? 12;
  const termValue = term ?? history?.term_months_default ?? 12;
  const typed = attestation.trim().length;
  const agreements = history?.agreements_required ?? [];
  const refsOk = agreements.length > 0 && agreements.every((a) => (refs[a.key] ?? "").trim().length > 0);
  const formOk = refsOk && typed >= minChars && !busy;

  const perform = async (action: PendingAction): Promise<void> => {
    if (!history) return;
    setBusy(true);
    setError(null);
    try {
      if (action.kind === "sign") {
        const r = await signComplianceSignoff(tenant.slug, {
          agreement_references: Object.fromEntries(agreements.map((a) => [a.key, (refs[a.key] ?? "").trim()])),
          attestation_text: attestation,
          attestation_version: history.attestation.version,
          acknowledge_flags: history.ai_policy.flags,
          term_months: termValue,
        });
        onDone(
          r.ai_policy.effective === "cloud"
            ? `${tenant.slug} signed off for cloud AI (sign-off #${r.signoff.id}, until ${day(r.signoff.expires_at)}) — it is now cleared for cloud AI. ${NO_CLOUD_MODEL_NOTE}`
            : `Sign-off #${r.signoff.id} recorded for ${tenant.slug} (until ${day(r.signoff.expires_at)}). Its AI policy is ${r.ai_policy.requested}, so nothing leaves the deployment until someone sets it to cloud.`,
        );
      } else {
        const r = await revokeComplianceSignoff(tenant.slug, action.id, action.reason);
        onDone(
          `Sign-off #${action.id} for ${tenant.slug} revoked — it runs as ${r.ai_policy.effective}` +
            (r.ai_policy.requested === "cloud" && r.ai_policy.effective !== "cloud" ? " until signed again." : "."),
        );
      }
    } catch (e) {
      if (e instanceof ApiError && (e.code === "STEP_UP_REQUIRED" || e.code === "STEP_UP_NETWORK_CHANGED")) {
        pending.current = action;
        setStepUp(e.code === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
      } else {
        setError(e instanceof Error ? e.message : "The sign-off request failed");
        // A 409 (flags or wording changed under the dialog): show the truth.
        if (e instanceof ApiError && e.status === 409) void load();
      }
    } finally {
      setBusy(false);
    }
  };

  const onStepUpSuccess = (): void => {
    setStepUp(null);
    const action = pending.current;
    pending.current = null;
    if (action) void perform(action);
  };

  return (
    <>
      <ModalFrame
        label={isSuperAdmin ? `Sign off ${tenant.display_name} for cloud AI` : `Cloud AI sign-offs for ${tenant.display_name}`}
        testId="compliance-signoff-dialog"
        busy={busy}
        onClose={onClose}
        wide
      >
        <h2 className="text-base font-semibold text-text-primary">
          {isSuperAdmin ? "Sign off for cloud AI" : "Cloud AI sign-offs"} — {tenant.display_name}
        </h2>
        <p className="mt-1 text-xs leading-relaxed text-text-secondary">
          A tenant asking for AI policy “cloud” runs as <span className="text-text-primary">local</span> until a
          super admin records a sign-off covering exactly its current compliance tags, naming the agreement each
          regime requires. Any change to the tags — an edit, a bulk review, a merge — revokes the sign-off; so does
          its expiry.
        </p>

        {loadError ? <ErrorLine message={loadError} /> : null}
        {history === null && !loadError ? <p className="mt-3 text-xs text-text-dim">Loading…</p> : null}

        {policy ? (
          <div className="mt-3 rounded border border-border bg-bg-card px-3 py-2 text-xs" data-testid="signoff-status">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-text-dim">AI policy</span>
              <span className={chip(policy.degraded ? "high" : policy.effective === "cloud" ? "high" : "accent")} data-testid="signoff-effective">
                {policy.degraded
                  ? `${policy.requested} requested → runs as ${policy.effective}`
                  : policy.effective === "cloud"
                    ? "cleared for cloud"
                    : `runs as ${policy.effective}`}
              </span>
              <span className={chip(stateTone(policy.signoff.state))} data-testid="signoff-state">
                {labelFor(SIGNOFF_STATE_LABEL, policy.signoff.state)}
              </span>
            </div>
            {policy.reason ? (
              <p className="mt-1 text-[11px] text-text-secondary" data-testid="signoff-reason">
                {policy.reason}
              </p>
            ) : null}
            {policy.effective === "cloud" ? (
              <p className="mt-1 text-[11px] text-text-dim" data-testid="signoff-no-cloud-model">
                {NO_CLOUD_MODEL_NOTE}
              </p>
            ) : null}
          </div>
        ) : null}

        {history && !needsSignoff ? (
          <p className="mt-3 text-xs text-text-secondary" data-testid="signoff-not-required">
            Tagged “none” — no compliance regime applies, so cloud AI needs no sign-off.
          </p>
        ) : null}
        {history && isSuperAdmin && needsSignoff && departed ? (
          <p className="mt-3 text-xs text-text-secondary">This tenant is {tenant.status}: nothing to sign.</p>
        ) : null}
        {history && isSuperAdmin && needsSignoff && !departed && live && !renewing ? (
          <div className="mt-3 flex items-center gap-2 text-xs text-text-secondary">
            Signed until {day(policy?.signoff.expires_at ?? null)}.
            <button type="button" className={secondaryBtn} onClick={() => setRenewing(true)} data-testid="signoff-renew">
              Renew…
            </button>
          </div>
        ) : null}
        {history && !isSuperAdmin ? (
          <p className="mt-3 text-[11px] text-text-dim" data-testid="signoff-readonly">
            Only a super admin can sign off or revoke. Admins see the history.
          </p>
        ) : null}

        {canSign && history ? (
          <form
            className="mt-3 flex flex-col gap-3"
            data-testid="signoff-form"
            onSubmit={(e) => {
              e.preventDefault();
              if (formOk) void perform({ kind: "sign" });
            }}
          >
            <div className={labelCls}>
              compliance tags this sign-off covers
              <div className="flex flex-wrap items-center gap-1 normal-case tracking-normal" data-testid="signoff-flags">
                {flags.length === 0 ? (
                  <span className="text-[11px] text-high">
                    none set — this tenant has never been tagged. The sign-off covers exactly that; if a regime
                    applies, tag the tenant first (tagging later revokes this sign-off).
                  </span>
                ) : (
                  flags.map((f) => (
                    <span key={f} className={chip("accent")}>
                      {labelFor(COMPLIANCE_LABEL, f)}
                    </span>
                  ))
                )}
              </div>
            </div>
            <div className="rounded border border-border bg-bg-input px-3 py-2">
              <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-text-dim">
                attestation · version {history.attestation.version}
              </div>
              <p className="text-xs leading-relaxed text-text-primary" data-testid="signoff-template">
                {history.attestation.text}
              </p>
            </div>
            <fieldset className="flex flex-col gap-2" data-testid="signoff-agreements">
              <legend className="mb-1 text-[10px] uppercase tracking-wider text-text-dim">
                agreement references — one per regime (a BAA covers HIPAA only)
              </legend>
              {agreements.map((a) => (
                <label key={a.key} className={labelCls}>
                  {a.key === "untagged" ? "never tagged" : labelFor(COMPLIANCE_LABEL, a.key)} — {a.instrument}
                  <input
                    aria-label={`${a.instrument} reference`}
                    className={inputCls}
                    value={refs[a.key] ?? ""}
                    maxLength={history.agreement_reference_max_chars}
                    placeholder="where it lives, e.g. contract id or document reference"
                    onChange={(e) => setRefs((prev) => ({ ...prev, [a.key]: e.target.value }))}
                    autoComplete="off"
                  />
                </label>
              ))}
            </fieldset>
            <label className={labelCls}>
              your attestation
              <textarea
                aria-label="attestation"
                className={`${inputCls} font-mono`}
                rows={4}
                value={attestation}
                maxLength={maxChars}
                placeholder="In your own words: which agreement covers this tenant's data in a cloud model, and that you checked the tags above today. Never paste a credential here."
                onChange={(e) => setAttestation(e.target.value)}
              />
              <span className={`normal-case tracking-normal ${typed >= minChars ? "text-text-dim" : "text-high"}`} data-testid="signoff-count">
                {typed} / {minChars} characters minimum — stored exactly as typed, with its SHA-256, and audit-logged.
              </span>
            </label>
            <label className={labelCls}>
              expires after
              <select
                aria-label="sign-off term"
                className={inputCls}
                value={termValue}
                onChange={(e) => setTerm(Number(e.target.value))}
              >
                {Array.from({ length: termMax }, (_, i) => termMax - i).map((m) => (
                  <option key={m} value={m}>
                    {m} month{m === 1 ? "" : "s"}
                  </option>
                ))}
              </select>
            </label>
            <ErrorLine message={error} />
            <div className="flex items-center justify-end gap-2">
              <button type="button" className={secondaryBtn} disabled={busy} onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className={primaryBtn} disabled={!formOk} data-testid="signoff-submit">
                {busy ? "Signing…" : `Sign off for ${flagsLabel(flags)} (step-up)`}
              </button>
            </div>
          </form>
        ) : (
          <ErrorLine message={error} />
        )}

        {history ? (
          <section className="mt-4" data-testid="signoff-history">
            <h3 className="mb-1 text-sm font-semibold text-text-primary">History</h3>
            {history.signoffs.length === 0 ? (
              <p className="rounded border border-border bg-bg-card px-3 py-2 text-xs text-text-dim" data-testid="signoff-history-empty">
                No sign-off has ever been recorded for this tenant.
              </p>
            ) : (
              <ul role="list" className="flex flex-col gap-2">
                {history.signoffs.map((s) => (
                  <HistoryRow
                    key={s.id}
                    s={s}
                    canRevoke={isSuperAdmin && s.revoked_at === null}
                    revoking={revoking === s.id}
                    reason={revokeReason}
                    busy={busy}
                    onStart={() => {
                      setRevoking(s.id);
                      setRevokeReason("");
                    }}
                    onCancel={() => setRevoking(null)}
                    onReason={setRevokeReason}
                    onConfirm={() => void perform({ kind: "revoke", id: s.id, reason: revokeReason.trim() })}
                  />
                ))}
              </ul>
            )}
          </section>
        ) : null}

        {!canSign ? (
          <div className="mt-4 flex justify-end">
            <button type="button" className={secondaryBtn} disabled={busy} onClick={onClose}>
              Close
            </button>
          </div>
        ) : null}
      </ModalFrame>
      {createPortal(
        <StepUpModal
          open={stepUp !== null}
          reason={stepUp ?? "required"}
          onClose={() => {
            setStepUp(null);
            pending.current = null;
          }}
          onSuccess={onStepUpSuccess}
        />,
        document.body,
      )}
    </>
  );
};

const HistoryRow: FC<{
  readonly s: ComplianceSignoff;
  readonly canRevoke: boolean;
  readonly revoking: boolean;
  readonly reason: string;
  readonly busy: boolean;
  readonly onStart: () => void;
  readonly onCancel: () => void;
  readonly onReason: (v: string) => void;
  readonly onConfirm: () => void;
}> = ({ s, canRevoke, revoking, reason, busy, onStart, onCancel, onReason, onConfirm }) => (
  <li className="rounded border border-border bg-bg-card p-2 text-xs" data-testid={`signoff-row-${s.id}`}>
    <div className="flex flex-wrap items-center gap-2">
      <span className="font-mono text-text-primary">#{s.id}</span>
      <span className={chip(stateTone(s.state))} data-testid={`signoff-row-state-${s.id}`}>
        {labelFor(SIGNOFF_STATE_LABEL, s.state)}
      </span>
      <span className="text-text-secondary">covers {flagsLabel(s.flags_covered)}</span>
      <span className="text-text-dim">
        signed {day(s.signed_at)} by operator #{s.signed_by} · expires {day(s.expires_at)}
      </span>
      {canRevoke && !revoking ? (
        <button
          type="button"
          className="ml-auto rounded-sm border border-border bg-bg-input px-2 py-1 text-[11px] text-critical"
          onClick={onStart}
          data-testid={`signoff-revoke-${s.id}`}
        >
          Revoke…
        </button>
      ) : null}
    </div>
    <div className="mt-1 text-[11px] text-text-secondary">
      agreements:{" "}
      <span className="font-mono" data-testid={`signoff-row-agreements-${s.id}`}>
        {Object.entries(s.agreement_references ?? {})
          .map(([k, v]) => `${k}: ${v}`)
          .join("; ") || "—"}
      </span>{" "}
      · attestation v{s.attestation_version} ·{" "}
      <span className="font-mono text-text-dim" title={s.attestation_sha256}>
        sha256 {s.attestation_sha256.slice(0, 12)}…
      </span>
    </div>
    <details className="mt-1 text-[11px] text-text-secondary">
      <summary className="cursor-pointer text-text-dim">attestation as typed</summary>
      <p className="mt-1 whitespace-pre-wrap">{s.attestation_text}</p>
    </details>
    {s.revoked_at ? (
      <div className="mt-1 text-[11px] text-text-dim">
        revoked {day(s.revoked_at)} by operator #{s.revoked_by} — {s.revoke_reason}
      </div>
    ) : null}
    {revoking ? (
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input
          aria-label={`reason to revoke sign-off ${s.id}`}
          className={`${inputCls} min-w-[240px] flex-1`}
          placeholder="why (audit-logged)"
          value={reason}
          maxLength={REVOKE_MAX}
          onChange={(e) => onReason(e.target.value)}
        />
        <button type="button" className={secondaryBtn} disabled={busy} onClick={onCancel}>
          Keep it
        </button>
        <button
          type="button"
          className={dangerBtn}
          disabled={busy || reason.trim().length < REVOKE_MIN}
          onClick={onConfirm}
          data-testid={`signoff-revoke-confirm-${s.id}`}
        >
          Revoke (step-up)
        </button>
      </div>
    ) : null}
  </li>
);
