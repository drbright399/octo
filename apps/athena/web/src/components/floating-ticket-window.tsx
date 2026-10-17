/**
 * Two ticket open-modes:
 *
 *   FloatingTicketWindow  — Autotask-style draggable pop-out
 *   TicketDrawer          — right-side slide-out (same shape as /search)
 *
 * Both wrap a shared `TicketDetailBody` so the actual ticket UI
 * (metadata, status select, description, history) is identical
 * between modes. Operator picks the shell via the user-pref toggle in
 * Settings → Account (localStorage-backed; matches the appearance
 * preference scheme).
 *
 * Why a draggable window: ops staff often have several tickets in
 * flight simultaneously. Autotask already trains the muscle memory
 * for floating windows — we don't have a reason to reinvent it.
 * Multi-window stacking is a P1b follow-up; v1 holds one open at a
 * time regardless of mode.
 */
import { type FC, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import {
  type TicketDetail,
  type TicketStatus,
  patchTicket,
} from "@/lib/tickets";
import { useClickOutsideClose } from "@/lib/use-click-outside-close";
import { TicketNotesPanel } from "@/components/ticket-notes-panel";
import { AgentNotesPanel } from "@/components/agent-notes-panel";

const STATUS_OPTIONS: TicketStatus[] = [
  "new",
  "in_progress",
  "waiting_customer",
  "waiting_vendor",
  "resolved",
  "closed",
  "reopened",
];

const SEVERITY_STYLE: Record<string, string> = {
  info:     "border-border       text-text-dim",
  low:      "border-border       text-text-secondary",
  medium:   "border-medium/60    text-medium",
  high:     "border-high/60      text-high",
  critical: "border-critical/60  text-critical",
};

interface Props {
  ticket: TicketDetail;
  loading: boolean;
  error: string | null;
  onClose: () => void;
  onUpdated: (updated: TicketDetail) => void;
}

export const FloatingTicketWindow: FC<Props> = ({
  ticket, loading, error, onClose, onUpdated,
}) => {
  const [pos, setPos] = useState<{ x: number; y: number }>(() => ({
    // Initial: roughly centered, biased toward top-left so the user can
    // still see the list behind it.
    x: Math.max(40, Math.round(window.innerWidth / 2 - 320)),
    y: Math.max(40, Math.round(window.innerHeight / 2 - 280)),
  }));
  const dragOffset = useRef<{ dx: number; dy: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const windowRef = useRef<HTMLDivElement | null>(null);

  const [busy, setBusy] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);
  // Status select is auto-save; the dirty bit lives wholly in the
  // notes panel's compose box. The child component flips dirtyRef via
  // setDirty().
  const dirtyRef = useRef(false);
  const setDirty = useCallback((d: boolean) => { dirtyRef.current = d; }, []);
  const isDirty = useCallback(() => dirtyRef.current, []);
  useClickOutsideClose(windowRef, isDirty, onClose);

  // Attach window-level pointer listeners only while dragging. Keyed to
  // `dragging` (a state flag, not the ref) so pointerdown reliably triggers
  // a re-render → this effect runs → listeners attach. Using the ref alone
  // (its mutation doesn't re-render) was the old bug: drag only worked if an
  // unrelated render happened to re-arm the effect. Keying to `dragging` also
  // stops the per-move teardown/re-add churn (setPos no longer re-runs this).
  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: PointerEvent): void => {
      if (!dragOffset.current) return;
      setPos({
        x: Math.max(0, Math.min(window.innerWidth - 100, e.clientX - dragOffset.current.dx)),
        y: Math.max(0, Math.min(window.innerHeight - 60, e.clientY - dragOffset.current.dy)),
      });
    };
    const onUp = (): void => {
      dragOffset.current = null;
      setDragging(false);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
  }, [dragging]);

  const onHeaderPointerDown = (e: React.PointerEvent<HTMLDivElement>): void => {
    // Ignore clicks on interactive header controls (e.g. the ✕ button) so
    // they don't initiate a drag.
    if ((e.target as HTMLElement).closest("button")) return;
    e.preventDefault();
    dragOffset.current = { dx: e.clientX - pos.x, dy: e.clientY - pos.y };
    setDragging(true);
  };

  const onStatusChange = async (status: TicketStatus): Promise<void> => {
    if (status === ticket.status || busy) return;
    setBusy(true);
    setTransitionError(null);
    try {
      const updated = await patchTicket(ticket.client_slug, ticket.id, {
        status,
        reason: `operator transitioned to ${status}`,
      });
      onUpdated(updated);
    } catch (e) {
      setTransitionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onSeverityChange = async (
    severity: TicketDetail["severity"],
  ): Promise<void> => {
    if (severity === ticket.severity || busy) return;
    setBusy(true);
    setTransitionError(null);
    try {
      const updated = await patchTicket(ticket.client_slug, ticket.id, {
        severity,
        reason: `operator changed severity to ${severity}`,
      });
      onUpdated(updated);
    } catch (e) {
      setTransitionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onDueChange = async (iso: string | null): Promise<void> => {
    if (busy) return;
    setBusy(true);
    setTransitionError(null);
    try {
      const updated = await patchTicket(ticket.client_slug, ticket.id, {
        due_at: iso ?? "",
        reason: iso ? `due set to ${iso}` : "due cleared",
      });
      onUpdated(updated);
    } catch (e) {
      setTransitionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const headerNode = (
    <div className="flex min-w-0 items-center gap-2">
      <span className="font-mono text-[10px] uppercase tracking-widest text-accent">
        [ ticket #{ticket.id} ]
      </span>
      <span
        className={[
          "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase",
          SEVERITY_STYLE[ticket.severity] || SEVERITY_STYLE.low,
        ].join(" ")}
      >
        {ticket.severity}
      </span>
      <span className="truncate font-mono text-[11px] text-text-secondary">
        {ticket.client_slug}
      </span>
    </div>
  );

  const bodyNode = (
    <TicketDetailBody
      ticket={ticket}
      loading={loading}
      error={error}
      busy={busy}
      transitionError={transitionError}
      onStatusChange={onStatusChange}
      onSeverityChange={onSeverityChange}
      onDueChange={onDueChange}
      onDirtyChange={setDirty}
    />
  );

  return createPortal(
    <div
      ref={windowRef}
      role="dialog"
      aria-modal="false"
      aria-label={`Ticket ${ticket.id}`}
      className="fixed z-40 flex w-[640px] flex-col rounded-sm border border-border-bright bg-bg-elevated shadow-2xl"
      style={{ left: pos.x, top: pos.y, maxHeight: "calc(100vh - 80px)" }}
    >
      {/* Title bar — drag handle */}
      <div
        onPointerDown={onHeaderPointerDown}
        className="flex cursor-move select-none items-center justify-between gap-3 border-b border-border bg-bg-surface px-3 py-2"
      >
        {headerNode}
        <button
          type="button"
          onClick={onClose}
          className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
        >
          ✕
        </button>
      </div>
      <div className="flex-1 overflow-auto p-4 text-[12px] font-mono">
        {bodyNode}
      </div>
    </div>,
    document.body,
  );
};

/**
 * Right-side slide-out alternative. Identical body content, different
 * shell — matches the /search drawer's visual rhythm.
 */
export const TicketDrawer: FC<Props> = ({
  ticket, loading, error, onClose, onUpdated,
}) => {
  const drawerRef = useRef<HTMLDivElement | null>(null);
  const [busy, setBusy] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);
  // Same wiring as FloatingTicketWindow — the notes panel's compose
  // box is the only dirty source; child flips this via setDirty().
  const dirtyRef = useRef(false);
  const setDirty = useCallback((d: boolean) => { dirtyRef.current = d; }, []);
  const isDirty = useCallback(() => dirtyRef.current, []);
  useClickOutsideClose(drawerRef, isDirty, onClose);

  const onStatusChange = async (status: TicketStatus): Promise<void> => {
    if (status === ticket.status || busy) return;
    setBusy(true);
    setTransitionError(null);
    try {
      const updated = await patchTicket(ticket.client_slug, ticket.id, {
        status,
        reason: `operator transitioned to ${status}`,
      });
      onUpdated(updated);
    } catch (e) {
      setTransitionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onSeverityChange = async (
    severity: TicketDetail["severity"],
  ): Promise<void> => {
    if (severity === ticket.severity || busy) return;
    setBusy(true);
    setTransitionError(null);
    try {
      const updated = await patchTicket(ticket.client_slug, ticket.id, {
        severity,
        reason: `operator changed severity to ${severity}`,
      });
      onUpdated(updated);
    } catch (e) {
      setTransitionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onDueChange = async (iso: string | null): Promise<void> => {
    if (busy) return;
    setBusy(true);
    setTransitionError(null);
    try {
      const updated = await patchTicket(ticket.client_slug, ticket.id, {
        due_at: iso ?? "",
        reason: iso ? `due set to ${iso}` : "due cleared",
      });
      onUpdated(updated);
    } catch (e) {
      setTransitionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return createPortal(
    <div
      ref={drawerRef}
      role="dialog"
      aria-modal="false"
      aria-label={`Ticket ${ticket.id}`}
      className="fixed right-0 top-0 z-40 flex h-full w-[560px] flex-col border-l border-border-bright bg-bg-elevated shadow-2xl"
    >
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex min-w-0 items-center gap-2">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-accent">
              [ ticket #{ticket.id} ]
            </div>
            <div className="truncate text-sm font-semibold text-text-primary">
              {ticket.title}
            </div>
          </div>
          <span
            className={[
              "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase",
              SEVERITY_STYLE[ticket.severity] || SEVERITY_STYLE.low,
            ].join(" ")}
          >
            {ticket.severity}
          </span>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
        >
          ✕ close
        </button>
      </header>
      <div className="flex-1 overflow-auto p-4 text-[12px] font-mono">
        <TicketDetailBody
          ticket={ticket}
          loading={loading}
          error={error}
          busy={busy}
          transitionError={transitionError}
          onStatusChange={onStatusChange}
          onSeverityChange={onSeverityChange}
          onDueChange={onDueChange}
          onDirtyChange={setDirty}
        />
      </div>
    </div>,
    document.body,
  );
};

interface BodyProps {
  ticket: TicketDetail;
  loading: boolean;
  error: string | null;
  busy: boolean;
  transitionError: string | null;
  onStatusChange: (s: TicketStatus) => Promise<void>;
  onSeverityChange: (s: TicketDetail["severity"]) => Promise<void>;
  onDueChange: (iso: string | null) => Promise<void>;
  onDirtyChange?: (dirty: boolean) => void;
}

const SEVERITY_OPTIONS: TicketDetail["severity"][] = [
  "info", "low", "medium", "high", "critical",
];

const TicketDetailBody: FC<BodyProps> = ({
  ticket, loading, error, busy, transitionError, onStatusChange,
  onSeverityChange, onDueChange, onDirtyChange,
}) => {
  if (loading) return <div className="text-text-dim">loading ticket…</div>;
  if (error) return <div className="text-critical">{error}</div>;
  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-[14px] font-semibold leading-tight text-text-primary">
        {ticket.title}
      </h2>

      <div className="grid grid-cols-[auto_1fr] items-center gap-x-3 gap-y-1.5 text-[11px]">
        <span className="text-text-dim">status</span>
        <div className="flex items-center gap-2">
          <select
            aria-label="Ticket status"
            value={ticket.status}
            onChange={(e) => void onStatusChange(e.target.value as TicketStatus)}
            disabled={busy}
            className="cursor-pointer rounded-sm border border-accent/60 bg-bg-surface px-2 py-0.5 text-accent transition-colors hover:border-border-bright focus:outline-none"
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s} className="bg-bg-surface text-text-primary">
                {s.replace(/_/g, " ")}
              </option>
            ))}
          </select>
          {busy && <span className="text-text-dim">applying…</span>}
        </div>

        <span className="text-text-dim">severity</span>
        <div className="flex items-center gap-2">
          <select
            aria-label="Ticket severity"
            value={ticket.severity}
            onChange={(e) => void onSeverityChange(
              e.target.value as TicketDetail["severity"],
            )}
            disabled={busy}
            className="cursor-pointer rounded-sm border border-accent/60 bg-bg-surface px-2 py-0.5 text-accent transition-colors hover:border-border-bright focus:outline-none"
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s} className="bg-bg-surface text-text-primary">
                {s}
              </option>
            ))}
          </select>
        </div>

        <span className="text-text-dim">assignee</span>
        <span className="text-text-secondary">
          {ticket.assignee_operator_id !== null
            ? `operator #${ticket.assignee_operator_id}`
            : (ticket.queue ? `queue: ${ticket.queue}` : "unassigned")}
        </span>

        <span className="text-text-dim">due</span>
        <div className="flex items-center gap-2">
          <input
            type="datetime-local"
            aria-label="Ticket due date"
            // value coerced from ISO Z → local-input form. Backend
            // accepts whatever ISO string we send; we round-trip the
            // string form to keep UX simple.
            value={ticket.due_at ? ticket.due_at.slice(0, 16) : ""}
            disabled={busy}
            onChange={(e) => {
              const v = e.target.value;
              void onDueChange(v ? `${v}:00Z` : null);
            }}
            className="rounded-sm border border-border bg-bg-surface px-2 py-0.5 text-text-primary focus:border-accent focus:outline-none"
          />
          {ticket.due_at && (
            <button
              type="button"
              onClick={() => void onDueChange(null)}
              disabled={busy}
              aria-label="Clear due date"
              className="font-mono text-[10px] text-text-dim hover:text-critical disabled:opacity-50"
            >
              clear
            </button>
          )}
        </div>

        <span className="text-text-dim">opened</span>
        <span className="text-text-secondary">{ticket.opened_at}</span>

        <span className="text-text-dim">updated</span>
        <span className="text-text-secondary">{ticket.updated_at}</span>

        {ticket.autotask_id && (
          <>
            <span className="text-text-dim">autotask</span>
            <span className="text-text-secondary">{ticket.autotask_id}</span>
          </>
        )}

      </div>

      {ticket.source_event_id !== null && (
        <section>
          <div className="mb-1 text-[10px] uppercase tracking-widest text-text-dim">
            source alert
          </div>
          <button
            type="button"
            onClick={() => {
              window.history.pushState(
                {}, "",
                `/search/events?focus=${encodeURIComponent(ticket.client_slug)}:${ticket.source_event_id}`,
              );
              window.dispatchEvent(new CustomEvent("athena:navigate"));
            }}
            className="flex w-full items-baseline justify-between gap-3 rounded-sm border border-high/40 bg-high/5 px-3 py-1.5 text-left transition-colors hover:border-high/60 hover:bg-high/10"
          >
            <span className="font-mono text-[11px] text-text-primary">
              event #{ticket.source_event_id} · {ticket.client_slug}
            </span>
            <span className="font-mono text-[9px] uppercase tracking-widest text-high">
              view in /search →
            </span>
          </button>
        </section>
      )}

      {ticket.agent_pattern_links.length > 0 && (
        <section>
          <div className="mb-1 text-[10px] uppercase tracking-widest text-text-dim">
            pattern links ({ticket.agent_pattern_links.length})
          </div>
          <ol className="flex flex-col gap-1 rounded-sm border border-border bg-bg-card p-2 text-[10px]">
            {ticket.agent_pattern_links.map((p, i) => (
              <li key={i} className="flex items-baseline justify-between gap-2">
                <span className="flex items-baseline gap-2 text-text-secondary">
                  <span className="font-mono uppercase tracking-wider text-text-dim">
                    {p.relation.replace(/_/g, " ")}
                  </span>
                  <span className="font-mono text-text-dim">
                    {p.from_kind} #{p.from_id} → {p.to_kind} #{p.to_id}
                  </span>
                  <span>{p.rationale}</span>
                </span>
                <span
                  className="shrink-0 font-mono text-text-dim"
                  title={`strength ${p.strength.toFixed(2)} · ${p.created_by_agent}`}
                >
                  {Math.round(p.strength * 100)}%
                </span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {transitionError && (
        <div role="alert" className="rounded-sm border border-critical/40 bg-critical/10 px-2 py-1 text-[11px] text-critical">
          {transitionError}
        </div>
      )}

      <section>
        <div className="mb-1 text-[10px] uppercase tracking-widest text-text-dim">
          description
        </div>
        <div className="rounded-sm border border-border bg-bg-card p-2 text-[11px] leading-relaxed text-text-secondary">
          {ticket.description || "—"}
        </div>
      </section>

      {/* Slice 8b — agent enrichment via the shared AgentNotesPanel.
          Replaces the prior inline agent_insights renderer. Panel
          fetches notes per-ref so switching tickets shows only the
          current ticket's history (no cross-ref bleed), AND the
          operator can fire "Ask Octo" canned queries to enrich
          older tickets with new threat-intel context. heuristic_note
          seeds octo with the ticket title + description summary —
          analogous to the alert.summary seed we use on alert
          drawers. */}
      <section>
        <AgentNotesPanel
          notes={[]}
          clientSlug={ticket.client_slug}
          refKind="ticket"
          refId={ticket.id}
          heuristicNote={
            ticket.description?.slice(0, 500) || ticket.title
          }
        />
      </section>

      <TicketNotesPanel
        clientSlug={ticket.client_slug}
        ticketId={ticket.id}
        onDirtyChange={onDirtyChange}
      />

      <section>
        <div className="mb-1 text-[10px] uppercase tracking-widest text-text-dim">
          status history
        </div>
        <ol className="flex flex-col gap-1 rounded-sm border border-border bg-bg-card p-2 text-[10px]">
          {ticket.status_history.map((h, i) => (
            <li key={i} className="flex items-baseline justify-between gap-2">
              <span className="text-text-secondary">
                {h.from_status ? `${h.from_status} →` : "·"} {h.to_status}
                {h.reason && <span className="text-text-dim"> · {h.reason}</span>}
              </span>
              <span className="text-text-dim">{h.changed_at}</span>
            </li>
          ))}
          {ticket.status_history.length === 0 && (
            <li className="text-text-dim">no history</li>
          )}
        </ol>
      </section>
    </div>
  );
};
