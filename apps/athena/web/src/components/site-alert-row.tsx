/**
 * One row of the Fleet drawer's "needs attention" list (v0.17.2, operators
 * only — a client user never gets the list):
 *
 *   * where it stands — acknowledged (by whom, when, the note), "expected
 *     (rule #N)" until its review date, or RE-SURFACED (new hits after an
 *     acknowledgement); acknowledged / expected rows are greyed; an open
 *     alert whose acknowledgement was RECALLED says by whom and why
 *     (v0.17.5);
 *   * AFTER AN ACKNOWLEDGEMENT (v0.17.5; Rick, 2026-10-08 — context learnt
 *     after acknowledging could not be added): its follow-up notes are
 *     listed under it (newest last), and an acknowledged row offers "add
 *     note" (inline, ≤ 500; the original note stays as it was) and "recall"
 *     (an in-app confirmation — focus on Cancel, Esc cancels — with a
 *     reason of 10+ characters: the alert returns to "needs attention" and
 *     counts towards the site's colour again; the acknowledgement stays in
 *     the history). Either re-reads the list;
 *   * ACKNOWLEDGE — an optional note (≤ 500), optionally "acknowledge
 *     repeats for 24 h": the alert leaves the list and the site's Yellow
 *     until a new occurrence;
 *   * THIS IS EXPECTED — a reason (≥ 10 characters), a review date (≤ 90
 *     days, 90 by default) and, for a network alert, "only from this
 *     remote": matching alerts are labelled expected until the review date.
 *     Not offered where the server says it may not be (a CSAM lookup, an
 *     alert an incident rests on, a decoy, a malware verdict) — the reason
 *     is shown instead;
 *   * the ENRICHMENT — a UniFi IPS alert's direction, remote (owner, PTR,
 *     scanner / vendor labels, "looking up…" while the background lookup
 *     runs), the local device's name and "N× in 24 h"; a Datto alert's one
 *     line, host, open / resolved and "N repeats since …", WHICH device
 *     ("<manufacturer> <model> · SN <serial>" from its Datto audit — v0.17.3
 *     — site, LAN / WAN, uid; the other devices' serials when its name is
 *     shared), the full text behind "details". A RocketCyber alert offers
 *     Acknowledge only (the server says: never expected, never "repeats").
 *
 * The server checks every rule again; nothing here decides a permission.
 */
import { type FC, useRef, useState } from "react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import type { AlertEnrichment, DattoEnrichment, RemoteLabel, SiteAlert } from "@/contracts/fleet";
import { ApiError } from "@/lib/api";
import {
  ACK_NOTE_MAX,
  EXPECTED_REASON_MIN,
  RECALL_REASON_MIN,
  REVIEW_MAX_DAYS,
  ackAlert,
  expectAlert,
  noteAck,
  recallAck,
} from "@/lib/fleet";

const btn = "rounded-sm border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest transition-colors disabled:opacity-50";
const field = "rounded-sm border border-border bg-bg-input px-1 py-0.5 text-[11px]";

function when(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { hour12: false });
}

function day(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 10) : "—";
}

const collapse = (s: string): string => s.trim().replace(/\s+/g, " ");

export function reviewDate(days: number, now: number = Date.now()): string {
  return new Date(now + days * 86_400_000).toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------
// Where it stands
// ---------------------------------------------------------------------------

const VerdictLine: FC<{ alert: SiteAlert }> = ({ alert }) => {
  const a = alert.ack;
  if (alert.status === "expected" && alert.rule) {
    return (
      <div className="font-mono text-[9px] text-text-dim" data-testid={`alert-status-${alert.event_id}`}>
        expected (rule #{alert.rule.id}) · review {day(alert.rule.review_at)}
        {alert.rule.remote ? ` · from ${alert.rule.remote}` : ""}
      </div>
    );
  }
  if (alert.status === "acknowledged" && a) {
    return (
      <div className="font-mono text-[9px] text-text-dim" data-testid={`alert-status-${alert.event_id}`}>
        acknowledged by {a.by_name ?? `#${a.by}`} · {when(a.at)}
        {a.by_repeat ? " · repeats for 24 h" : ""}{a.note ? ` — ${a.note}` : ""}
      </div>
    );
  }
  if (alert.status === "resurfaced" && a) {
    return (
      <div className="font-mono text-[9px] text-medium" data-testid={`alert-status-${alert.event_id}`}>
        re-surfaced{alert.new_since_ack ? `: ${alert.new_since_ack} new` : ""} since acknowledged by{" "}
        {a.by_name ?? `#${a.by}`} · {when(a.at)}
      </div>
    );
  }
  if (alert.status === "open" && a?.recalled) {
    const r = a.recalled;
    const who = r.by_name ?? (r.by !== null ? `#${r.by}` : null);
    return (
      <div className="flex flex-col font-mono text-[9px]" data-testid={`alert-status-${alert.event_id}`}>
        <span className="text-medium" data-testid={`alert-recalled-${alert.event_id}`}>
          acknowledgement recalled{who ? ` by ${who}` : ""} · {when(r.at)}{r.reason ? ` — ${r.reason}` : ""}
        </span>
        <span className="text-text-dim">
          it was acknowledged by {a.by_name ?? `#${a.by}`} · {when(a.at)}{a.note ? ` — ${a.note}` : ""}
        </span>
      </div>
    );
  }
  return null;
};

/** The notes added under an acknowledgement after it was made, oldest
 *  first (newest last) — whatever the alert's state. */
const AckNotes: FC<{ alert: SiteAlert }> = ({ alert }) => {
  const notes = alert.ack?.notes ?? [];
  if (notes.length === 0) return null;
  return (
    <ul className="mt-0.5 flex flex-col gap-0.5 border-l border-border pl-1.5"
        data-testid={`ack-notes-${alert.event_id}`}>
      {notes.map((n, i) => (
        <li key={`${n.at}-${i}`} className="font-mono text-[9px] text-text-dim">
          note by {n.by_name ?? `#${n.by}`} · {when(n.at)} — <span className="text-text-secondary">{n.note}</span>
        </li>
      ))}
    </ul>
  );
};

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

/** A remote's label. One from the registry's OWNER NAME is the holder's own
 *  words — it says so, never "internet scanner" outright. */
export function labelText(l: RemoteLabel): string {
  if (l.basis === "rdap") return `owner name mentions ${l.name}`;
  return `${l.kind === "scanner" ? "internet scanner" : "vendor"}: ${l.name}`;
}

/** "<manufacturer> <model>" from the device's Datto audit ("" when neither
 *  is known); a model that already starts with the maker's name is not
 *  doubled ("HP HP EliteBook"). */
export function hardware(e: DattoEnrichment): string {
  const maker = e.manufacturer?.trim() ?? "";
  const model = e.model?.trim() ?? "";
  const first = maker.split(/\s+/)[0]?.toLowerCase() ?? "";
  if (maker && model && first && model.toLowerCase().startsWith(first)) return model;
  return [maker, model].filter(Boolean).join(" ");
}

/** The shared-hostname warning's serials, when known: " (this one SN X;
 *  the other: SN Y)" — "" when none is known. */
export function sharedSerials(e: DattoEnrichment): string {
  const others = e.shared_serials ?? [];
  const parts = [
    e.serial ? `this one SN ${e.serial}` : null,
    others.length > 0
      ? `the other${(e.shared_hostname ?? 0) > 2 ? "s" : ""}: ${others.map((s) => `SN ${s}`).join(", ")}`
      : null,
  ].filter(Boolean);
  return parts.length > 0 ? ` (${parts.join("; ")})` : "";
}

const Enrichment: FC<{ alert: SiteAlert; e: AlertEnrichment }> = ({ alert, e }) => {
  if (e.kind === "datto") {
    return (
      <div className="mt-0.5 flex flex-col gap-0.5 text-[10px] text-text-secondary"
           data-testid={`alert-enrichment-${alert.event_id}`}>
        <div>
          {e.line}
          {e.host ? ` · ${e.host}` : ""}
          {` · ${e.resolved ? "resolved" : "open"}`}
          {e.repeats > 0 ? ` · ${e.repeats} repeat${e.repeats === 1 ? "" : "s"} since ${day(e.since)}` : ""}
        </div>
        {(hardware(e) || e.serial || e.site || e.lan_ip || e.wan_ip || e.device_uid) && (
          <div className="text-text-dim" data-testid={`alert-device-${alert.event_id}`}>
            {[hardware(e) || null, e.serial ? `SN ${e.serial}` : null,
              e.site ? `site ${e.site}` : null, e.lan_ip ? `LAN ${e.lan_ip}` : null,
              e.wan_ip ? `WAN ${e.wan_ip}` : null,
              e.device_uid ? `device ${e.device_uid.slice(0, 8)}` : null].filter(Boolean).join(" · ")}
          </div>
        )}
        {(e.shared_hostname ?? 0) > 1 && (
          <div className="text-warning" data-testid={`alert-shared-host-${alert.event_id}`}>
            {`${e.shared_hostname} devices in this client are named ${e.host ?? "this"}`}
            {(e.shared_sites ?? 0) > 1 ? ` (at ${e.shared_sites} sites)` : ""}
            {" — they are different machines; this alert and its repeats are this device only"}
            {sharedSerials(e)}
          </div>
        )}
        {e.details.length > 0 && (
          <details data-testid={`alert-details-${alert.event_id}`}>
            <summary className="cursor-pointer font-mono text-[9px] uppercase tracking-widest text-text-dim">details</summary>
            <div className="whitespace-pre-wrap text-[10px] text-text-dim">{e.details.join("\n")}</div>
          </details>
        )}
      </div>
    );
  }
  const r = e.remote;
  const tags = r?.labels ?? [];
  const owner = r && !r.pending && !r.failed
    ? [r.org, r.ptr ? `${r.ptr}${r.ptr_confirmed ? "" : " (PTR not confirmed)"}` : null]
      .filter(Boolean).join(" · ")
    : "";
  return (
    <div className="mt-0.5 flex flex-col gap-0.5 text-[10px] text-text-secondary"
         data-testid={`alert-enrichment-${alert.event_id}`}>
      <div>
        {e.direction ?? "direction unknown"} · {e.action === "detected" ? "NOT blocked" : "blocked"}
        {e.remote_ip ? ` · remote ${e.remote_ip}` : ""}
        {owner ? ` — ${owner}` : ""}
        {r?.pending ? " · looking up…" : ""}
        {r?.failed ? " · owner not found" : ""}
      </div>
      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {tags.map((l) => (
            <span key={`${l.kind}-${l.name}`} title={`from the ${l.basis}`}
                  data-testid={`alert-label-${alert.event_id}`}
                  className="rounded-sm border border-border px-1 font-mono text-[9px] uppercase tracking-wider text-text-dim">
              {labelText(l)}
            </span>
          ))}
        </div>
      )}
      <div>
        local {e.local_ip ?? "?"}
        {e.local_name ? ` (${e.local_name}${e.local_name_source === "datto" ? ", Datto" : ""})` : ""}
        {e.repeats_24h !== null ? ` · ${e.repeats_24h}× in 24 h from this remote${e.repeats_approximate ? " (at least)" : ""}` : ""}
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// The two verdicts
// ---------------------------------------------------------------------------

const AckForm: FC<{ tenantSlug: string; alert: SiteAlert; onDone: () => void; onCancel: () => void }> = ({
  tenantSlug, alert, onDone, onCancel,
}) => {
  const [note, setNote] = useState("");
  const [repeat, setRepeat] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = alert.event_id;
  // Not for an alert that names no device or a CSAM lookup (the server says).
  const canRepeat = alert.can_repeat !== false;
  return (
    <form className="mt-1 flex flex-col gap-1" data-testid={`ack-form-${id}`}
          onSubmit={(e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            const text = collapse(note);
            // What the list SHOWED: the ack covers no more (hits that came in
            // while the form was open re-surface the alert).
            ackAlert(tenantSlug, id, {
              ...(text ? { note: text } : {}),
              ...(repeat && canRepeat ? { repeat_24h: true } : {}),
              ...(typeof alert.hits === "number" && alert.hits > 0 ? { seen_hits: alert.hits } : {}),
              ...(alert.last_seen ? { seen_last: alert.last_seen } : {}),
            })
              .then(() => onDone())
              .catch((err: unknown) => setError(err instanceof ApiError ? err.message
                : "The alert could not be acknowledged"))
              .finally(() => setBusy(false));
          }}>
      <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2}
                maxLength={ACK_NOTE_MAX} data-testid={`ack-note-${id}`}
                placeholder="note (optional) — it leaves the list until a new occurrence"
                className={field} />
      {canRepeat && (
        <label className="flex items-center gap-1 text-[10px] text-text-secondary">
          <input type="checkbox" checked={repeat} onChange={(e) => setRepeat(e.target.checked)}
                 data-testid={`ack-repeat-${id}`} />
          also acknowledge repeats for 24 h (same device and signature)
        </label>
      )}
      <div className="flex gap-1.5">
        <button type="submit" disabled={busy} data-testid={`ack-submit-${id}`}
                className={`${btn} border-accent text-accent`}>acknowledge</button>
        <button type="button" onClick={onCancel} className={`${btn} border-border text-text-dim`}>cancel</button>
      </div>
      {error && <div className="text-[11px] text-critical">{error}</div>}
    </form>
  );
};

const ExpectedForm: FC<{ tenantSlug: string; alert: SiteAlert; onDone: () => void; onCancel: () => void }> = ({
  tenantSlug, alert, onDone, onCancel,
}) => {
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(REVIEW_MAX_DAYS);
  const remoteIp = alert.enrichment?.kind === "unifi_ips" ? alert.enrichment.remote_ip : null;
  const [onlyRemote, setOnlyRemote] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = alert.event_id;
  const validDays = Number.isInteger(days) && days >= 1 && days <= REVIEW_MAX_DAYS;
  const ready = collapse(reason).length >= EXPECTED_REASON_MIN && validDays;
  return (
    <form className="mt-1 flex flex-col gap-1" data-testid={`expected-form-${id}`}
          onSubmit={(e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            expectAlert(tenantSlug, id, {
              reason: collapse(reason), review_days: days,
              ...(onlyRemote && remoteIp ? { remote: remoteIp } : {}),
            })
              .then(() => onDone())
              .catch((err: unknown) => setError(err instanceof ApiError ? err.message
                : "The alert could not be marked expected"))
              .finally(() => setBusy(false));
          }}>
      <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2}
                maxLength={500} data-testid={`expected-reason-${id}`}
                placeholder={`why this is expected (at least ${EXPECTED_REASON_MIN} characters) — matching alerts stop turning the site yellow`}
                className={field} />
      <label className="flex items-center gap-1 text-[10px] text-text-secondary">
        review in
        <input type="number" min={1} max={REVIEW_MAX_DAYS} value={Number.isNaN(days) ? "" : days}
               onChange={(e) => setDays(Number(e.target.value))}
               data-testid={`expected-days-${id}`} className={`${field} w-14`} />
        days {validDays ? `(${reviewDate(days)} — it then stops, no renewal)` : `(1–${REVIEW_MAX_DAYS})`}
      </label>
      {alert.network && remoteIp && (
        <label className="flex items-center gap-1 text-[10px] text-text-secondary">
          <input type="checkbox" checked={onlyRemote} onChange={(e) => setOnlyRemote(e.target.checked)}
                 data-testid={`expected-remote-${id}`} />
          only from {remoteIp}
        </label>
      )}
      <div className="flex gap-1.5">
        <button type="submit" disabled={busy || !ready} data-testid={`expected-submit-${id}`}
                className={`${btn} border-accent text-accent`}>mark expected</button>
        <button type="button" onClick={onCancel} className={`${btn} border-border text-text-dim`}>cancel</button>
      </div>
      {error && <div className="text-[11px] text-critical">{error}</div>}
    </form>
  );
};

// ---------------------------------------------------------------------------
// After an acknowledgement (v0.17.5): a note, the recall
// ---------------------------------------------------------------------------

const NoteForm: FC<{ tenantSlug: string; alert: SiteAlert; verdictId: number; onDone: () => void;
  onCancel: () => void }> = ({ tenantSlug, alert, verdictId, onDone, onCancel }) => {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = alert.event_id;
  const text = collapse(note);
  return (
    <form className="mt-1 flex flex-col gap-1" data-testid={`followup-note-form-${id}`}
          onSubmit={(e) => {
            e.preventDefault();
            if (!text) return;
            setBusy(true);
            setError(null);
            noteAck(tenantSlug, verdictId, text)
              .then(() => onDone())
              .catch((err: unknown) => {
                setError(err instanceof ApiError ? err.message : "The note could not be saved");
                setBusy(false);
              });
          }}>
      <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2}
                maxLength={ACK_NOTE_MAX} data-testid={`followup-note-${id}`} autoFocus
                aria-label="note under this acknowledgement"
                placeholder="what you learnt since — shown under the acknowledgement (its own note stays as it was)"
                className={field} />
      <div className="flex items-center gap-1.5">
        <button type="submit" disabled={busy || !text} data-testid={`followup-note-save-${id}`}
                className={`${btn} border-accent text-accent`}>{busy ? "saving…" : "save"}</button>
        <button type="button" onClick={onCancel} data-testid={`followup-note-cancel-${id}`}
                className={`${btn} border-border text-text-dim`}>cancel</button>
        <span className="font-mono text-[9px] text-text-dim">{note.length}/{ACK_NOTE_MAX}</span>
      </div>
      {error && <div className="text-[11px] text-critical" role="alert">{error}</div>}
    </form>
  );
};

/** The dialog's words (Rick's feature, 2026-10-08). */
export const RECALL_EXPLAINED =
  "The alert returns to 'needs attention' and counts towards the site's colour again. " +
  "The acknowledgement stays in the history.";

const RecallDialog: FC<{ tenantSlug: string; alert: SiteAlert; verdictId: number;
  onDone: () => void; onCancel: () => void; returnFocus: () => HTMLElement | null }> = ({
  tenantSlug, alert, verdictId, onDone, onCancel, returnFocus,
}) => {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const id = alert.event_id;
  const text = collapse(reason);
  const recall = (): void => {
    if (text.length < RECALL_REASON_MIN) {
      setError(`Give a reason of at least ${RECALL_REASON_MIN} characters.`);
      return;
    }
    setBusy("recall");
    setError(null);
    recallAck(tenantSlug, verdictId, text)
      .then(() => onDone())
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "The acknowledgement could not be recalled");
        setBusy(null);
      });
  };
  return (
    <ConfirmDialog
      title="Recall this acknowledgement?"
      actions={[{ id: "recall", label: "Recall", busyLabel: "Recalling…", primary: true, onSelect: recall }]}
      onCancel={onCancel}
      busy={busy}
      error={error}
      returnFocus={returnFocus}
      testId={`recall-dialog-${id}`}
    >
      <p>{RECALL_EXPLAINED}</p>
      {alert.ack?.repeat_until ? (
        <p>It also covered repeats of this alert for 24 h — they return too.</p>
      ) : null}
      <label className="flex flex-col gap-1 text-text-secondary">
        <span>Why? (at least {RECALL_REASON_MIN} characters — kept with the acknowledgement)</span>
        {/* tabIndex: the dialog's focus trap keeps it in the Tab cycle. */}
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3}
                  tabIndex={0} readOnly={busy !== null} maxLength={ACK_NOTE_MAX}
                  data-testid={`recall-reason-${id}`} className={field}
                  placeholder="e.g. the partner removed the agents on purpose — it needs a follow-up" />
      </label>
      <span className="font-mono text-[9px] text-text-dim" data-testid={`recall-reason-count-${id}`}>
        {text.length < RECALL_REASON_MIN
          ? `${RECALL_REASON_MIN - text.length} more character${RECALL_REASON_MIN - text.length === 1 ? "" : "s"} needed`
          : `${reason.length}/${ACK_NOTE_MAX}`}
      </span>
    </ConfirmDialog>
  );
};

// ---------------------------------------------------------------------------
// The row
// ---------------------------------------------------------------------------

export interface SiteAlertRowProps {
  alert: SiteAlert;
  tenantSlug: string | null;
  tenantWideNote: boolean;
  /** After an acknowledge / expected (the list and the fleet refresh). */
  onChanged: () => void;
  /** The R8 "confirm as threat" control. */
  confirm?: React.ReactNode;
}

const SiteAlertRow: FC<SiteAlertRowProps> = ({ alert: a, tenantSlug, tenantWideNote, onChanged, confirm }) => {
  const [open, setOpen] = useState<"ack" | "expected" | "note" | null>(null);
  const [recalling, setRecalling] = useState(false);
  const recallButton = useRef<HTMLButtonElement | null>(null);
  const handled = a.status === "acknowledged" || a.status === "expected";
  const done = (): void => { setOpen(null); onChanged(); };
  // v0.17.5: an acknowledged row's ack may take a note or be recalled (the
  // server checks again: scope, an ack, not recalled yet).
  const ackId = a.ack?.verdict_id;
  const followUp = tenantSlug !== null && a.status === "acknowledged" && !!a.ack
    && typeof ackId === "number" && !a.ack.recalled;
  return (
    <li className={`rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] ${handled ? "opacity-60" : ""}`}
        data-testid={`site-alert-${a.event_id}`} data-status={a.status ?? "open"}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-text-primary" title={a.title}>{a.title}</span>
        <span className="shrink-0 font-mono text-[10px] uppercase text-text-dim">{a.severity}</span>
      </div>
      <div className="font-mono text-[9px] text-text-dim">
        {when(a.occurred_at)} · {a.source}{tenantWideNote ? " · client-wide" : ""}
        {a.hits && a.hits > 1 ? ` · ${a.hits}× (last ${when(a.last_seen)})` : ""}
      </div>
      <VerdictLine alert={a} />
      <AckNotes alert={a} />
      {a.enrichment && <Enrichment alert={a} e={a.enrichment} />}
      {tenantSlug && (
        <div className="mt-1 flex flex-wrap items-center gap-1">
          {!handled && open === null && (
            <button type="button" data-testid={`ack-open-${a.event_id}`} onClick={() => setOpen("ack")}
                    className={`${btn} border-border text-text-secondary hover:border-accent hover:text-accent`}>
              acknowledge
            </button>
          )}
          {a.status !== "expected" && open === null && a.can_expect && (
            <button type="button" data-testid={`expected-open-${a.event_id}`} onClick={() => setOpen("expected")}
                    className={`${btn} border-border text-text-secondary hover:border-accent hover:text-accent`}>
              this is expected
            </button>
          )}
          {a.can_expect === false && a.expected_refusal && open === null && (
            <span className="font-mono text-[9px] text-text-dim" data-testid={`expected-refusal-${a.event_id}`}
                  title={a.expected_refusal}>
              never expected: {a.expected_refusal}
            </span>
          )}
          {followUp && open === null && (
            <>
              <button type="button" data-testid={`followup-note-open-${a.event_id}`}
                      onClick={() => setOpen("note")}
                      className={`${btn} border-border text-text-secondary hover:border-accent hover:text-accent`}>
                add note
              </button>
              <button type="button" ref={recallButton} data-testid={`recall-open-${a.event_id}`}
                      onClick={() => setRecalling(true)}
                      className={`${btn} border-border text-text-secondary hover:border-critical hover:text-critical`}>
                recall
              </button>
            </>
          )}
          {open === null && confirm}
        </div>
      )}
      {tenantSlug && followUp && typeof ackId === "number" && open === "note" && (
        <NoteForm tenantSlug={tenantSlug} alert={a} verdictId={ackId} onDone={done}
                  onCancel={() => setOpen(null)} />
      )}
      {tenantSlug && followUp && typeof ackId === "number" && recalling && (
        <RecallDialog tenantSlug={tenantSlug} alert={a} verdictId={ackId}
                      onDone={() => { setRecalling(false); onChanged(); }}
                      onCancel={() => setRecalling(false)}
                      returnFocus={() => recallButton.current} />
      )}
      {tenantSlug && open === "ack" && (
        <AckForm tenantSlug={tenantSlug} alert={a} onDone={done} onCancel={() => setOpen(null)} />
      )}
      {tenantSlug && open === "expected" && (
        <ExpectedForm tenantSlug={tenantSlug} alert={a} onDone={done} onCancel={() => setOpen(null)} />
      )}
    </li>
  );
};

export default SiteAlertRow;
