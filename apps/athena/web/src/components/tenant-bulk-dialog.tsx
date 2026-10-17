/**
 * BulkEditDialog — tenant review at scale (Settings → Tenants, admin+).
 *
 * One edit (kind / compliance tags / AI policy / confirm) for every selected
 * tenant, in two steps that never skip each other:
 *   1. Preview — the server runs PATCH's own rules on every row WITHOUT
 *      writing (`dry_run`) and answers a per-row diff: what changes, what is
 *      already so, what is refused and why;
 *   2. Apply — the same rows, all-or-nothing: if any row is refused nothing
 *      is written (the answer lists every row's error again), otherwise one
 *      transaction and one audit entry per changed tenant.
 *
 * Role rules are the server's, stated before the click: 'cloud' AI policy is
 * a super_admin choice (disabled for an admin, with the reason); a batch an
 * admin sends with 'cloud' in it is refused as a whole.
 *
 * AI rows say what will RUN (v0.10): 'cloud' on a tenant with compliance tags
 * (or none set yet) is stored but runs as local until a super admin signs
 * off — each preview row says so ("will run as local until signed …"), and a
 * tag change names the sign-off it revokes. A row that would CLEAR a tenant
 * for cloud with no sign-off (tagged 'none' while asking for cloud) is the
 * sign-off's call: refused in an admin's batch, and for a super admin the
 * apply asks for step-up re-authentication, then is retried.
 */
import { type FC, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AI_POLICIES,
  AI_POLICY_HELP,
  AI_POLICY_LABEL,
  BULK_UPDATE_MAX,
  COMPLIANCE_LABEL,
  KIND_LABEL,
  TENANT_KINDS,
  bulkEditIsEmpty,
  bulkPatchFor,
  labelFor,
  type BulkEdit,
  type BulkUpdateItem,
  type BulkUpdateResponse,
  type FieldChange,
  type Tenant,
} from "@/contracts/tenant";
import { BulkUpdateRefused, bulkUpdateTenants } from "@/lib/api";
import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";
import { ComplianceTagPicker, ErrorLine, ModalFrame, inputCls } from "@/components/tenant-dialogs";

interface Vocab {
  readonly kinds: readonly string[];
  readonly compliance_tags: readonly string[];
  readonly ai_policies: readonly string[];
}

interface BulkEditDialogProps {
  /** The selected rows (≤ BULK_UPDATE_MAX). */
  readonly tenants: readonly Tenant[];
  readonly vocab: Vocab;
  readonly isSuperAdmin: boolean;
  readonly onClose: () => void;
  readonly onApplied: (r: BulkUpdateResponse, note: string) => void;
}

const labelCls = "flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim";
const primaryBtn =
  "rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50";
const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";

const FIELD_LABEL: Readonly<Record<string, string>> = {
  display_name: "name",
  kind: "kind",
  compliance_flags: "compliance",
  ai_policy: "AI policy",
  review_state: "review",
};

function formatValue(field: string, value: string | readonly string[]): string {
  if (Array.isArray(value)) {
    return value.length ? value.map((v) => labelFor(COMPLIANCE_LABEL, v)).join(", ") : "—";
  }
  const v = value as string;
  if (field === "kind") return labelFor(KIND_LABEL, v);
  if (field === "ai_policy") return labelFor(AI_POLICY_LABEL, v);
  return v;
}

const ChangeLine: FC<{ readonly c: FieldChange }> = ({ c }) => (
  <li className="text-[11px] text-text-secondary">
    <span className="text-text-dim">{FIELD_LABEL[c.field] ?? c.field}:</span>{" "}
    <span className="line-through decoration-text-dim/60">{formatValue(c.field, c.before)}</span>
    {" → "}
    <span className="text-text-primary">{formatValue(c.field, c.after)}</span>
  </li>
);

const EMPTY_EDIT: BulkEdit = { kind: null, complianceMode: "leave", compliance: [], aiPolicy: null, confirm: false };

export const BulkEditDialog: FC<BulkEditDialogProps> = ({ tenants, vocab, isSuperAdmin, onClose, onApplied }) => {
  const [working, setWorking] = useState<readonly Tenant[]>(tenants);
  const [edit, setEdit] = useState<BulkEdit>(EMPTY_EDIT);
  const [preview, setPreview] = useState<{ items: readonly BulkUpdateItem[]; result: BulkUpdateResponse } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<StepUpReason | null>(null);

  const kinds = (vocab.kinds.length ? vocab.kinds : TENANT_KINDS).filter((k) => k !== "unclassified");
  const policies = vocab.ai_policies.length ? vocab.ai_policies : AI_POLICIES;
  const cloudTitle = "Only a super admin can choose 'cloud': with it, the tenants' data may leave the deployment.";
  const tooMany = working.length > BULK_UPDATE_MAX;
  const empty = bulkEditIsEmpty(edit);
  const unclassifiedToConfirm = useMemo(
    () => (edit.confirm && edit.kind === null ? working.filter((t) => t.kind === "unclassified" && t.review_state === "pending").length : 0),
    [edit.confirm, edit.kind, working],
  );

  const set = (patch: Partial<BulkEdit>): void => {
    setEdit((e) => ({ ...e, ...patch }));
    setPreview(null);
  };

  const runPreview = async (rows: readonly Tenant[]): Promise<void> => {
    if (rows.length === 0 || bulkEditIsEmpty(edit)) return;
    const items = rows.map((t) => ({ slug: t.slug, patch: bulkPatchFor(t, edit) }));
    setBusy(true);
    setError(null);
    try {
      setPreview({ items, result: await bulkUpdateTenants(items, true) });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Preview failed");
    } finally {
      setBusy(false);
    }
  };

  const apply = async (): Promise<void> => {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const r = await bulkUpdateTenants(preview.items, false);
      onApplied(
        r,
        `Bulk review applied: ${r.changed} tenant(s) updated, one audit entry each` +
          (r.unchanged ? `; ${r.unchanged} already said that and were left alone.` : "."),
      );
    } catch (e) {
      if (e instanceof BulkUpdateRefused && (e.code === "STEP_UP_REQUIRED" || e.code === "STEP_UP_NETWORK_CHANGED")) {
        // A row clears a tenant for cloud: re-authenticate, then apply again.
        setStepUp(e.code === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
        setBusy(false);
        return;
      }
      // All-or-nothing: nothing was written. Show every row's answer again
      // (something changed since the preview) so the batch can be fixed.
      if (e instanceof BulkUpdateRefused && e.result) setPreview({ items: preview.items, result: e.result });
      setError(e instanceof Error ? e.message : "Apply failed");
      setBusy(false);
    }
  };

  const dropRefused = (): void => {
    if (!preview) return;
    const refused = new Set(preview.result.rows.filter((r) => r.error).map((r) => r.slug));
    const next = working.filter((t) => !refused.has(t.slug));
    setWorking(next);
    setPreview(null);
    void runPreview(next);
  };

  const result = preview?.result ?? null;
  const canApply = result !== null && result.errors === 0 && result.changed > 0 && !busy;

  return (
    <>
      <ModalFrame label={`Bulk edit ${working.length} tenants`} testId="bulk-edit-dialog" busy={busy} onClose={onClose} wide>
        <h2 className="text-base font-semibold text-text-primary">Bulk edit {working.length} tenant(s)</h2>
        <p className="mt-1 text-xs leading-relaxed text-text-secondary">
          One change for every selected tenant. Preview first: each row shows exactly what would change.
          Applying is all-or-nothing — if any row is refused, nothing is written — and every changed
          tenant gets its own audit entry.
        </p>
        {tooMany ? (
          <p role="alert" className="mt-2 text-xs text-critical" data-testid="bulk-too-many">
            At most {BULK_UPDATE_MAX} tenants at once — narrow the selection.
          </p>
        ) : null}

        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className={labelCls}>
            kind
            <select
              aria-label="bulk kind"
              className={inputCls}
              value={edit.kind ?? ""}
              onChange={(e) => set({ kind: e.target.value || null })}
            >
              <option value="">— leave unchanged —</option>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {labelFor(KIND_LABEL, k)}
                </option>
              ))}
            </select>
          </label>
          <label className={labelCls}>
            AI policy
            <select
              aria-label="bulk AI policy"
              className={inputCls}
              value={edit.aiPolicy ?? ""}
              onChange={(e) => set({ aiPolicy: e.target.value || null })}
            >
              <option value="">— leave unchanged —</option>
              {policies.map((p) => (
                <option
                  key={p}
                  value={p}
                  disabled={p === "cloud" && !isSuperAdmin}
                  title={p === "cloud" && !isSuperAdmin ? cloudTitle : AI_POLICY_HELP[p] ?? ""}
                >
                  {labelFor(AI_POLICY_LABEL, p)}
                  {p === "cloud" && !isSuperAdmin ? " — super admin only" : ""}
                </option>
              ))}
            </select>
            {!isSuperAdmin ? (
              <span className="normal-case tracking-normal text-text-dim" data-testid="bulk-ai-help">
                {cloudTitle}
              </span>
            ) : edit.aiPolicy === "cloud" ? (
              <span className="normal-case tracking-normal text-high" data-testid="bulk-cloud-signoff-help">
                Stored as cloud for every row; a tenant with compliance tags — or none set yet — keeps running as
                local until you sign off for it. The preview says which.
              </span>
            ) : null}
          </label>
        </div>

        <div className="mt-3 flex flex-col gap-2">
          <label className={labelCls}>
            compliance tags
            <select
              aria-label="bulk compliance mode"
              className={inputCls}
              value={edit.complianceMode}
              onChange={(e) => set({ complianceMode: e.target.value as BulkEdit["complianceMode"] })}
            >
              <option value="leave">— leave unchanged —</option>
              <option value="add">add these tags to each tenant's own</option>
              <option value="replace">replace each tenant's tags with these</option>
            </select>
          </label>
          {edit.complianceMode !== "leave" ? (
            <ComplianceTagPicker
              value={edit.compliance}
              tags={vocab.compliance_tags}
              onChange={(next) => set({ compliance: next })}
            />
          ) : null}
        </div>

        <label className="mt-3 inline-flex items-center gap-2 text-xs text-text-primary">
          <input
            type="checkbox"
            checked={edit.confirm}
            onChange={(e) => set({ confirm: e.target.checked })}
            aria-label="confirm review"
          />
          Confirm review
          <span className="text-text-dim">— a tenant is confirmed only with a kind other than unclassified.</span>
        </label>
        {unclassifiedToConfirm > 0 ? (
          <p className="mt-1 text-[11px] text-high" data-testid="bulk-needs-kind">
            {unclassifiedToConfirm} selected tenant(s) are still unclassified — set a kind above or they
            will be refused.
          </p>
        ) : null}

        <ErrorLine message={error} />

        {result ? (
          <section className="mt-4" data-testid="bulk-preview">
            <p className="mb-2 text-xs text-text-secondary" data-testid="bulk-summary">
              {result.changed} will change · {result.unchanged} already set · {result.errors} refused
            </p>
            {result.refusal ? (
              <p role="alert" className="mb-2 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical" data-testid="bulk-refusal">
                {result.refusal.message}
              </p>
            ) : null}
            <div className="max-h-[40vh] overflow-y-auto rounded border border-border">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-border text-text-dim">
                  <tr>
                    <th className="px-3 py-1.5 font-normal">Tenant</th>
                    <th className="px-3 py-1.5 font-normal">Change</th>
                  </tr>
                </thead>
                <tbody>
                  {result.rows.map((row) => (
                    <tr key={row.slug} data-testid={`bulk-row-${row.slug}`} className="border-b border-border/40 align-top last:border-b-0">
                      <td className="px-3 py-1.5">
                        <div className="text-text-primary">{row.display_name ?? row.slug}</div>
                        <div className="font-mono text-[10px] text-text-dim">{row.slug}</div>
                      </td>
                      <td className="px-3 py-1.5">
                        {row.error ? (
                          <span className="text-[11px] text-critical" data-testid="bulk-row-error">
                            refused — {row.error.message}
                          </span>
                        ) : row.changes.length === 0 ? (
                          <span className="text-[11px] text-text-dim" data-testid="bulk-row-unchanged">
                            already set — left alone
                          </span>
                        ) : (
                          <ul className="flex flex-col gap-0.5">
                            {row.changes.map((c) => (
                              <ChangeLine key={c.field} c={c} />
                            ))}
                          </ul>
                        )}
                        {!row.error && row.ai_policy_note ? (
                          <p className="mt-0.5 text-[11px] text-high" data-testid="bulk-row-ai-note">
                            {row.ai_policy_note}
                          </p>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ) : null}

        <div className="mt-4 flex flex-wrap items-center justify-end gap-2">
          {result && result.errors > 0 ? (
            <button
              type="button"
              className={secondaryBtn}
              disabled={busy}
              onClick={dropRefused}
              data-testid="bulk-drop-refused"
            >
              Drop the {result.errors} refused row(s) and preview again
            </button>
          ) : null}
          <button type="button" disabled={busy} onClick={onClose} className={secondaryBtn}>
            Cancel
          </button>
          {result === null ? (
            <button
              type="button"
              className={primaryBtn}
              disabled={busy || empty || tooMany || working.length === 0}
              onClick={() => void runPreview(working)}
              data-testid="bulk-preview-btn"
            >
              {busy ? "Checking…" : "Preview changes"}
            </button>
          ) : (
            <button
              type="button"
              className={primaryBtn}
              disabled={!canApply}
              onClick={() => void apply()}
              data-testid="bulk-apply"
            >
              {busy
                ? "Applying…"
                : `Apply to ${result.changed} tenant(s)${result.step_up_required ? " (step-up)" : ""}`}
            </button>
          )}
        </div>
      </ModalFrame>
      {createPortal(
        <StepUpModal
          open={stepUp !== null}
          reason={stepUp ?? "required"}
          onClose={() => setStepUp(null)}
          onSuccess={() => {
            setStepUp(null);
            void apply();
          }}
        />,
        document.body,
      )}
    </>
  );
};
