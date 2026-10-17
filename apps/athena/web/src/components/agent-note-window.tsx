/**
 * AgentNoteWindow — modal popup showing one agent triage entry.
 *
 * Opens when the operator clicks any row in the agent triage feed.
 * Shows what the agent did: who (octo/athena), what it looked at
 * (event/ticket/indicator + tenant + id), the note text in full,
 * confidence, time, and a status hint.
 *
 * Cross-link: when the entry is ref_kind='ticket', a follow-button
 * opens the linked ticket in the operator's preferred window/drawer.
 * For event/indicator kinds today the follow-link surfaces as a hint
 * for the future event/indicator detail surfaces — wired to navigate
 * via the App-level navigation event once those surfaces are live.
 *
 * Status field is forward-looking — the dev seeder writes "complete"
 * since we don't have a live runtime yet, but the schema is ready for
 * "thinking", "hunting", "loading" etc. once #119 (octo runtime) ships.
 */
import { type FC } from "react";
import { createPortal } from "react-dom";

import type { AgentActivityItem } from "@/lib/tickets";

interface Props {
  item: AgentActivityItem;
  onClose: () => void;
  /** If non-null, called when operator clicks the ticket follow-link.
   * Wired regardless of ref_kind — both "this triage IS a ticket
   * note" and "this triage is an event note with a derived ticket"
   * surface the same affordance. */
  onOpenTicket?: ((slug: string, id: number) => void) | undefined;
  /** Called when operator clicks the event follow-link (navigates to
   * /search with the event slug+id queued for preview). Optional —
   * not all triage entries have an associated event id. */
  onOpenEvent?: ((slug: string, id: number) => void) | undefined;
}

const AGENT_HUE: Record<string, string> = {
  octo:   "border-accent/60 text-accent",
  athena: "border-high/60   text-high",
};

export const AgentNoteWindow: FC<Props> = ({
  item, onClose, onOpenTicket, onOpenEvent,
}) => {
  // Resolve which sibling refs this triage entry can navigate to:
  //   - For ticket-kind: this entry IS a ticket note. The ticket
  //     button opens THIS ticket. If the ticket has a source event,
  //     the event button opens that.
  //   - For event-kind: this entry is an event note. The event
  //     button opens THIS event. If a ticket was derived, the
  //     ticket button opens that derived ticket.
  const linkedTicketId =
    item.ref_kind === "ticket" ? item.ref_id : item.linked_ticket_id;
  const linkedEventId =
    item.ref_kind === "event" ? item.ref_id : item.linked_event_id;
  const ticketTitle =
    item.linked_ticket_title || (linkedTicketId !== null ? `Ticket #${linkedTicketId}` : null);
  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="agent-note-window-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-sm border border-accent/40 bg-bg-elevated p-5 font-mono text-[12px]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-baseline justify-between">
          <h2
            id="agent-note-window-title"
            className="text-[11px] uppercase tracking-widest text-accent"
          >
            ·· agent triage · entry ··
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm border border-border bg-bg-card px-2 py-0.5 text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
          >
            ✕
          </button>
        </div>

        <div className="mb-3 grid grid-cols-2 gap-3 rounded-sm border border-border bg-bg-card p-3 text-[11px]">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">agent</div>
            <span
              className={[
                "mt-1 inline-block rounded-sm border px-1.5 py-0.5 font-mono uppercase tracking-wider",
                AGENT_HUE[item.agent_id] || "border-border text-text-secondary",
              ].join(" ")}
            >
              {item.agent_id}
            </span>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">status</div>
            <div className="mt-1 text-text-primary">
              {/* Once the live runtime ships (#119), this becomes
                 'thinking', 'hunting', 'loading' etc. For now every
                 seeded entry is finished. */}
              complete
            </div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">attached to</div>
            <div className="mt-1 text-text-primary">
              {item.ref_kind} #{item.ref_id} · {item.client_slug}
            </div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">confidence</div>
            <div className="mt-1 text-text-primary">
              {Math.round(item.confidence * 100)}%
              <span className="ml-2 text-text-dim">
                ({item.confidence.toFixed(2)})
              </span>
              {item.agent_id === "octo" && (
                <span
                  className="ml-2 rounded-sm bg-yellow-900/40 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-yellow-400/90"
                  title={
                    "uncalibrated — this is a raw model probability, " +
                    "not a calibrated likelihood. don't gate triage " +
                    "decisions on it. calibration loop is a future " +
                    "workstream."
                  }
                >
                  uncal
                </span>
              )}
            </div>
          </div>
        </div>

        <section className="mb-3">
          <div className="mb-1 text-[10px] uppercase tracking-widest text-text-dim">
            output
          </div>
          <div className="whitespace-pre-wrap rounded-sm border border-border bg-bg-card p-2 text-[11px] leading-relaxed text-text-secondary">
            {item.note_text}
          </div>
        </section>

        <div className="mb-3 text-[10px] text-text-dim">
          recorded {item.created_at}
        </div>

        <div className="mb-3 flex flex-wrap gap-2">
          {linkedTicketId !== null && onOpenTicket && (
            <button
              type="button"
              onClick={() => onOpenTicket(item.client_slug, linkedTicketId)}
              className="flex flex-col items-start rounded-sm border border-accent bg-accent/10 px-3 py-1.5 text-left transition-colors hover:bg-accent/20"
            >
              <span className="font-mono text-[9px] uppercase tracking-widest text-accent">
                open ticket
              </span>
              <span className="text-[11px] text-text-primary">
                #{linkedTicketId}
                {ticketTitle && ticketTitle !== `Ticket #${linkedTicketId}` && (
                  <span className="ml-1 text-text-secondary">· {ticketTitle}</span>
                )}
              </span>
            </button>
          )}
          {linkedEventId !== null && onOpenEvent && (
            <button
              type="button"
              onClick={() => onOpenEvent(item.client_slug, linkedEventId)}
              className="flex flex-col items-start rounded-sm border border-high/60 bg-high/10 px-3 py-1.5 text-left transition-colors hover:bg-high/20"
            >
              <span className="font-mono text-[9px] uppercase tracking-widest text-high">
                open alert
              </span>
              <span className="text-[11px] text-text-primary">
                event #{linkedEventId}
              </span>
            </button>
          )}
          {item.ref_kind === "indicator" && (
            <span
              className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-[11px] uppercase tracking-wider text-text-dim"
              title="indicator detail surface is a follow-on workstream"
            >
              indicator detail · pending
            </span>
          )}
        </div>

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm border border-border bg-bg-card px-3 py-1 text-[11px] uppercase tracking-wider text-text-secondary transition-colors hover:border-border-bright"
          >
            Close
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
};
