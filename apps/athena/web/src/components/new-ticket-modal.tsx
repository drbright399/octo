/**
 * NewTicketModal — manual ticket creation form.
 *
 * Slotted into /tickets header. Backend POST /tickets/{slug} already
 * exists (analyst+ create with scope + severity + status validation,
 * optional source_event_id for create-from-alert flows).
 *
 * Manual create is the v1 entry-point — the "create-from-alert"
 * branch (P3.8) flows through the same endpoint but is initiated
 * from the /search drawer. The "Push this ticket to Autotask" option
 * is offered ONLY while the PSA writes kill switch is on
 * (GET /tickets/_meta → psa_writes_enabled; default off, flipped by a
 * super_admin with step-up). While it is off the option is hidden and
 * the form never asks for a push.
 */
import { type FC, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";

import {
  type TicketChargeInput,
  type TicketCreateBody,
  type TicketDetail,
  createTicket,
  fetchTicketsMeta,
  requestAutotaskPush,
} from "@/lib/tickets";

/** Shape consumed by alert-drawer.tsx + (future) other cross-link
 *  surfaces that hand off into the ticket-create flow with context
 *  carried over. Every field is optional — modal renders normally
 *  when none are provided. */
export interface NewTicketPrefill {
  tenant?: string | undefined;
  source_event_id?: number | null | undefined;
  title?: string | undefined;
  description?: string | undefined;
  severity?: TicketCreateBody["severity"] | undefined;
}

interface Props {
  /** In-scope tenant slugs the operator may create tickets in. */
  tenants: string[];
  /** Pre-select this tenant when opening (e.g., when launched from
   *  a tenant-scoped surface). When unset, the first tenant wins. */
  defaultTenant?: string;
  /** Optional pre-population for cross-link flows (e.g. "create ticket
   *  from this alert" on the dashboard). The user reviews + edits
   *  before submission — this is a draft, not an auto-post. */
  prefill?: NewTicketPrefill | undefined;
  onClose: () => void;
  /** Called with the freshly-created ticket so the caller can open
   *  it in a window / drawer and refresh the list. */
  onCreated: (ticket: TicketDetail) => void;
}

const SEVERITIES: TicketCreateBody["severity"][] = [
  "info", "low", "medium", "high", "critical",
];

const NewTicketModal: FC<Props> = ({
  tenants, defaultTenant, prefill, onClose, onCreated,
}) => {
  // Resolve initial tenant — prefill > defaultTenant > first available.
  // When prefill.tenant is set, we trust it even if the in-flight
  // `tenants` prop hasn't loaded yet (the parent gates open-modal on
  // list-loaded, so this is belt-and-suspenders for cross-link flows).
  const initialTenant = (() => {
    if (prefill?.tenant) return prefill.tenant;
    if (defaultTenant && tenants.includes(defaultTenant)) return defaultTenant;
    return tenants[0] ?? "";
  })();
  // The select needs to render an option for the initial tenant even
  // if the operator's scope list (`tenants`) didn't include it. Merge
  // it in for the dropdown so the value matches a renderable option.
  const tenantOptions = useMemo(() => {
    const seen = new Set<string>();
    const merged: string[] = [];
    if (initialTenant) { seen.add(initialTenant); merged.push(initialTenant); }
    for (const t of tenants) { if (!seen.has(t)) { seen.add(t); merged.push(t); } }
    return merged;
  }, [initialTenant, tenants]);
  const [tenant, setTenant] = useState<string>(initialTenant);
  const [title, setTitle] = useState(prefill?.title ?? "");
  const [description, setDescription] = useState(prefill?.description ?? "");
  const [severity, setSeverity] = useState<TicketCreateBody["severity"]>(
    prefill?.severity ?? "medium",
  );
  const [queue, setQueue] = useState("");
  // Source event id (read-only — the operator can't edit which event
  // a ticket is opened against, only the surrounding metadata).
  const sourceEventId = prefill?.source_event_id ?? null;
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Autotask write-back options (P4-c2). Collapsed by default — most
  // tickets are Athena-side only. Operators opt in per ticket.
  const [autotaskOpen, setAutotaskOpen] = useState(false);
  const [pushToAutotask, setPushToAutotask] = useState(false);
  // The PSA writes kill switch (GET /tickets/_meta). Fails CLOSED: until the
  // server says writes are on — and if it cannot be asked — the push option
  // is not offered and nothing is ever sent for this ticket.
  const [psaWritesEnabled, setPsaWritesEnabled] = useState(false);
  useEffect(() => {
    let live = true;
    fetchTicketsMeta()
      .then((meta) => { if (live) setPsaWritesEnabled(meta.psa_writes_enabled); })
      .catch(() => { if (live) setPsaWritesEnabled(false); });
    return () => { live = false; };
  }, []);
  const pushRequested = psaWritesEnabled && pushToAutotask;
  const [isBillable, setIsBillable] = useState(true);
  const [billingCodeId, setBillingCodeId] = useState("");
  const [contractId, setContractId] = useState("");
  const [charges, setCharges] = useState<TicketChargeInput[]>([]);

  const titleRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    titleRef.current?.focus();
  }, []);

  // Close on Escape — matches the rest of the V3 modal pattern.
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape" && !submitting) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, submitting]);

  const canSubmit = tenant && title.trim().length > 0 && !submitting;

  const onSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const cleanCharges: TicketChargeInput[] = charges
        .filter((c) => c.name.trim().length > 0)
        .map((c) => ({
          ...c,
          name: c.name.trim(),
          description: (c.description ?? "").trim() || undefined,
          billing_code_id: c.billing_code_id?.trim() || null,
        }));
      const body: TicketCreateBody = {
        title: title.trim(),
        description: description.trim() || undefined,
        severity,
        queue: queue.trim() || undefined,
        push_to_autotask: pushRequested,
        is_billable: isBillable,
        billing_code_id: billingCodeId.trim() || null,
        contract_id: contractId.trim() || null,
        charges: cleanCharges,
      };
      // Carry the source event reference through to the server so the
      // ticket links back to the originating alert in /search drill-downs.
      if (sourceEventId !== null && sourceEventId !== undefined) {
        body.source_event_id = sourceEventId;
      }
      const created = await createTicket(tenant, body);
      // If the operator both opted in AND clicked the inline push
      // checkbox, fire the push enqueue now so they don't have to
      // re-open the ticket to do it. Best-effort — if the enqueue
      // fails the ticket is still created. Never while writes are off.
      if (pushRequested) {
        try {
          await requestAutotaskPush(tenant, created.id);
        } catch { /* surfaced on the ticket window's push-state badge */ }
      }
      onCreated(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  };

  const addCharge = (): void => {
    setCharges((prev) => [
      ...prev,
      {
        name: "", description: "",
        unit_cost: 0, unit_price: 0, quantity: 1,
        is_billable: true, billing_code_id: null,
      },
    ]);
  };
  const updateCharge = (idx: number, patch: Partial<TicketChargeInput>): void => {
    setCharges((prev) => prev.map((c, i) => i === idx ? { ...c, ...patch } : c));
  };
  const removeCharge = (idx: number): void => {
    setCharges((prev) => prev.filter((_, i) => i !== idx));
  };

  if (tenants.length === 0) {
    return createPortal(
      <Backdrop onClose={onClose}>
        <div className="rounded-sm border border-border bg-bg-surface p-6 text-[12px] text-text-secondary">
          You have no tenants in scope — ask an admin to grant tenant access
          before creating tickets.
        </div>
      </Backdrop>,
      document.body,
    );
  }

  return createPortal(
    <Backdrop onClose={submitting ? () => { /* lock during submit */ } : onClose}>
      <form
        onSubmit={(e) => void onSubmit(e)}
        onClick={(e) => e.stopPropagation()}
        className="flex w-[min(560px,95vw)] flex-col gap-4 rounded-sm border border-border bg-bg-surface p-5 shadow-xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-ticket-title"
      >
        <header className="flex items-baseline justify-between border-b border-border pb-2">
          <h2 id="new-ticket-title" className="font-mono text-[11px] uppercase tracking-widest text-accent">
            ·· new ticket ··
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="close"
            disabled={submitting}
            className="text-text-dim hover:text-text-primary disabled:opacity-50"
          >
            ✕
          </button>
        </header>

        {sourceEventId !== null && (
          <div
            role="status"
            className="flex items-center gap-2 rounded-sm border border-accent/40 bg-accent/5 px-2 py-1.5 font-mono text-[10px] text-text-secondary"
          >
            <span aria-hidden="true" className="text-accent">▸</span>
            <span className="uppercase tracking-wider text-accent">opened from alert</span>
            <span className="text-text-dim">
              event #{sourceEventId} · tenant <code className="text-text-secondary">{tenant}</code>
            </span>
          </div>
        )}

        <Field label="tenant">
          <select
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
            disabled={submitting}
            className="w-full rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[12px] text-text-primary focus:border-accent focus:outline-none"
          >
            {tenantOptions.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </Field>

        <Field label="title">
          <input
            ref={titleRef}
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            disabled={submitting}
            maxLength={500}
            placeholder="Short summary of the issue"
            className="w-full rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[12px] text-text-primary focus:border-accent focus:outline-none"
            required
          />
        </Field>

        <Field label="description">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={submitting}
            maxLength={8000}
            rows={5}
            placeholder="What's happening, what's been tried, what should the on-call know"
            className="w-full resize-y rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[12px] text-text-primary focus:border-accent focus:outline-none"
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="severity">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as TicketCreateBody["severity"])}
              disabled={submitting}
              className="w-full rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[12px] text-text-primary focus:border-accent focus:outline-none"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="queue (optional)">
            <input
              type="text"
              value={queue}
              onChange={(e) => setQueue(e.target.value)}
              disabled={submitting}
              maxLength={120}
              placeholder="e.g. Triage, EDR, Network"
              className="w-full rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[12px] text-text-primary focus:border-accent focus:outline-none"
            />
          </Field>
        </div>

        {/* ---- Autotask write-back (P4-c2) ----
            Collapsed by default. Operator opts in here to push the
            ticket up to Autotask on create. Billing semantics + add-on
            charges follow Autotask's TicketCharge entity. */}
        <details
          open={autotaskOpen}
          onToggle={(e) => setAutotaskOpen((e.target as HTMLDetailsElement).open)}
          className="rounded-sm border border-border bg-bg-card"
        >
          <summary className="cursor-pointer select-none border-b border-border px-3 py-2 font-mono text-[10px] uppercase tracking-widest text-text-secondary hover:text-accent">
            ·· autotask options ·· {pushRequested && "(push on)"}
          </summary>

          <div className="flex flex-col gap-3 p-3">
            {psaWritesEnabled ? (
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  checked={pushToAutotask}
                  onChange={(e) => setPushToAutotask(e.target.checked)}
                  disabled={submitting}
                  className="mt-0.5 h-3 w-3 accent-accent"
                />
                <div className="flex flex-col">
                  <span className="text-[11px] text-text-primary">
                    Push this ticket to Autotask
                  </span>
                  <span className="text-[10px] text-text-dim">
                    Tenant must have an Autotask mapping configured. Push
                    happens out-of-band; status shows in the ticket window.
                  </span>
                </div>
              </label>
            ) : (
              <p data-testid="psa-writes-off" className="text-[10px] text-text-dim">
                Writing to Autotask is switched off. This ticket stays in
                Athena; billing details below are kept here only.
              </p>
            )}

            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                checked={isBillable}
                onChange={(e) => setIsBillable(e.target.checked)}
                disabled={submitting}
                className="mt-0.5 h-3 w-3 accent-accent"
              />
              <div className="flex flex-col">
                <span className="text-[11px] text-text-primary">
                  Billable to client
                </span>
                <span className="text-[10px] text-text-dim">
                  Uncheck for goodwill / contract-included work.
                </span>
              </div>
            </label>

            <div className="grid grid-cols-2 gap-3">
              <Field label="billing code (autotask)">
                <input
                  type="text"
                  value={billingCodeId}
                  onChange={(e) => setBillingCodeId(e.target.value)}
                  disabled={submitting}
                  placeholder="optional · uses Autotask default if blank"
                  className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1.5 text-[12px] text-text-primary focus:border-accent focus:outline-none"
                />
              </Field>
              <Field label="contract id (autotask)">
                <input
                  type="text"
                  value={contractId}
                  onChange={(e) => setContractId(e.target.value)}
                  disabled={submitting}
                  placeholder="optional"
                  className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1.5 text-[12px] text-text-primary focus:border-accent focus:outline-none"
                />
              </Field>
            </div>

            {/* Add-on charges (TicketCharge entity). v1 = manual entry;
                v2 will pull suggestions from agent + recent ticket
                history. */}
            <div className="rounded-sm border border-border bg-bg-surface">
              <div className="flex items-baseline justify-between border-b border-border px-3 py-1.5">
                <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
                  ·· add-on charges ··
                </span>
                <button
                  type="button"
                  onClick={addCharge}
                  disabled={submitting}
                  className="font-mono text-[10px] uppercase tracking-wider text-accent hover:underline disabled:opacity-50"
                >
                  + line
                </button>
              </div>
              {charges.length === 0 ? (
                <div className="px-3 py-2 text-[10px] text-text-dim">
                  No charges. Use "+ line" for parts, expenses, travel, etc.
                </div>
              ) : (
                <table className="w-full text-[11px]">
                  <thead className="bg-bg-card text-left text-[10px] uppercase tracking-widest text-text-dim">
                    <tr>
                      <th className="px-2 py-1 font-mono">item</th>
                      <th className="px-2 py-1 font-mono">qty</th>
                      <th className="px-2 py-1 font-mono">unit price</th>
                      <th className="px-2 py-1 font-mono"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {charges.map((c, idx) => (
                      <tr key={idx} className="border-t border-border/60">
                        <td className="px-2 py-1 align-top">
                          <input
                            type="text"
                            value={c.name}
                            placeholder="e.g. APC RBC11"
                            onChange={(e) => updateCharge(idx, { name: e.target.value })}
                            disabled={submitting}
                            className="w-full rounded-sm border border-border bg-bg-surface px-1.5 py-1 text-[11px] focus:border-accent focus:outline-none"
                          />
                        </td>
                        <td className="px-2 py-1 align-top w-20">
                          <input
                            type="number"
                            value={c.quantity ?? 1}
                            min={0}
                            step={0.5}
                            onChange={(e) => updateCharge(idx, {
                              quantity: parseFloat(e.target.value) || 0,
                            })}
                            disabled={submitting}
                            className="w-full rounded-sm border border-border bg-bg-surface px-1.5 py-1 text-[11px] focus:border-accent focus:outline-none"
                          />
                        </td>
                        <td className="px-2 py-1 align-top w-28">
                          <input
                            type="number"
                            value={c.unit_price ?? 0}
                            min={0}
                            step={0.01}
                            onChange={(e) => updateCharge(idx, {
                              unit_price: parseFloat(e.target.value) || 0,
                            })}
                            disabled={submitting}
                            className="w-full rounded-sm border border-border bg-bg-surface px-1.5 py-1 text-[11px] focus:border-accent focus:outline-none"
                          />
                        </td>
                        <td className="px-2 py-1 align-top text-right">
                          <button
                            type="button"
                            onClick={() => removeCharge(idx)}
                            aria-label="remove charge"
                            disabled={submitting}
                            className="text-text-dim hover:text-critical disabled:opacity-50"
                          >
                            ✕
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </details>

        {error && (
          <div role="alert" className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 text-[11px] text-critical">
            {error}
          </div>
        )}

        <footer className="flex items-center justify-end gap-2 border-t border-border pt-3">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="rounded-sm border border-border bg-bg-card px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-secondary hover:text-text-primary disabled:opacity-50"
          >
            cancel
          </button>
          <button
            type="submit"
            disabled={!canSubmit}
            className="rounded-sm border border-accent bg-accent px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent hover:bg-accent/80 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? "creating…" : "create ticket"}
          </button>
        </footer>
      </form>
    </Backdrop>,
    document.body,
  );
};

const Backdrop: FC<{ onClose: () => void; children: React.ReactNode }> = ({
  onClose, children,
}) => (
  <div
    onClick={onClose}
    className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm"
  >
    {children}
  </div>
);

const Field: FC<{ label: string; children: React.ReactNode }> = ({
  label, children,
}) => (
  <label className="flex flex-col gap-1">
    <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
      {label}
    </span>
    {children}
  </label>
);

export default NewTicketModal;
