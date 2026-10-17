/**
 * TicketNotesPanel — Autotask-style notes section embedded inside the
 * ticket window/drawer. Two sub-regions:
 *
 *   1. Compose box   — collapsible; type a note, pick note-type +
 *                      publish flag, submit. Calls POST /notes which
 *                      audit-logs and (later) round-trips to Autotask.
 *   2. Notes list    — newest-first; each row shows author, timestamp,
 *                      type + publish badges, optional title (bold),
 *                      body. Read-only in P1 (edit/delete is P2.4).
 *
 * Dirty wiring: as long as the operator has any unsent text in the
 * compose box (after expanding it), the parent's `onDirtyChange(true)`
 * fires. The click-outside hook then prompts a confirm before
 * closing the window/drawer. Submit/Cancel/clear-text → false.
 *
 * Aligned to Autotask TicketNote vocabulary so future round-trip is a
 * field-by-field push:
 *   note_type maps to TicketNote.noteType (picklist, per-instance)
 *   publish   maps to TicketNote.publish  (picklist, per-instance)
 *   title     maps to TicketNote.title    (250 char cap)
 *   body      maps to TicketNote.description (32000 char cap, plain text)
 */
import { type FC, useCallback, useEffect, useState } from "react";

import {
  type TicketNote,
  type TicketNoteType,
  type TicketNotePublish,
  createTicketNote,
  listTicketNotes,
} from "@/lib/tickets";

const NOTE_TYPE_LABELS: Record<TicketNoteType, string> = {
  task_detail:     "Task detail",
  workflow:        "Workflow",
  internal:        "Internal",
  detail:          "Detail",
  summary:         "Summary",
  resolution:      "Resolution",
  system_workflow: "System workflow",
};

const PUBLISH_LABELS: Record<TicketNotePublish, string> = {
  internal:           "Internal only",
  all_autotask_users: "All staff",
  client_portal:      "Client portal",
};

// Operator-facing note types — `system_workflow` is reserved for the
// Autotask-side automation channel and shouldn't be authorable from
// our UI.
const SELECTABLE_NOTE_TYPES: TicketNoteType[] = [
  "internal", "detail", "summary", "resolution", "workflow", "task_detail",
];

const TITLE_MAX = 250;
const BODY_MAX = 32000;

interface Props {
  clientSlug: string;
  ticketId: number;
  /** Lets the parent (ticket window) flip its dirty flag while the
   * operator has unsent compose text. */
  onDirtyChange?: ((dirty: boolean) => void) | undefined;
}

export const TicketNotesPanel: FC<Props> = ({
  clientSlug, ticketId, onDirtyChange,
}) => {
  const [notes, setNotes] = useState<TicketNote[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [composing, setComposing] = useState(false);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [noteType, setNoteType] = useState<TicketNoteType>("internal");
  const [publish, setPublish] = useState<TicketNotePublish>("internal");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const ns = await listTicketNotes(clientSlug, ticketId);
      setNotes(ns);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [clientSlug, ticketId]);

  useEffect(() => { void refresh(); }, [refresh]);

  // Dirty whenever the compose drawer is open AND the operator has
  // typed something. Closing the compose drawer or clearing the body
  // flips it back to clean.
  useEffect(() => {
    const dirty = composing && (body.trim().length > 0 || title.trim().length > 0);
    onDirtyChange?.(dirty);
  }, [composing, body, title, onDirtyChange]);

  const resetCompose = (): void => {
    setComposing(false);
    setTitle("");
    setBody("");
    setNoteType("internal");
    setPublish("internal");
    setSubmitError(null);
  };

  const onSubmit = async (): Promise<void> => {
    if (submitting) return;
    if (body.trim().length === 0) {
      setSubmitError("Note body cannot be empty");
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      const created = await createTicketNote(clientSlug, ticketId, {
        body: body.trim(),
        title: title.trim() || undefined,
        note_type: noteType,
        publish,
      });
      setNotes((prev) => [created, ...prev]);
      resetCompose();
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section>
      <div className="mb-1 flex items-baseline justify-between">
        <div className="text-[10px] uppercase tracking-widest text-text-dim">
          notes ({notes.length})
        </div>
        {!composing && (
          <button
            type="button"
            onClick={() => setComposing(true)}
            className="rounded-sm border border-accent/60 bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent transition-colors hover:border-accent"
          >
            + add note
          </button>
        )}
      </div>

      {composing && (
        <div className="mb-3 flex flex-col gap-2 rounded-sm border border-accent/40 bg-bg-card p-2">
          <input
            type="text"
            placeholder="title (optional)"
            value={title}
            onChange={(e) => setTitle(e.target.value.slice(0, TITLE_MAX))}
            className="rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
          />
          <textarea
            placeholder="Write a note…"
            value={body}
            onChange={(e) => setBody(e.target.value.slice(0, BODY_MAX))}
            rows={4}
            className="resize-y rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] leading-relaxed text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
          />
          <div className="flex flex-wrap items-center gap-3 text-[10px]">
            <label className="flex items-center gap-1.5 uppercase tracking-wider text-text-dim">
              type
              <select
                value={noteType}
                onChange={(e) => setNoteType(e.target.value as TicketNoteType)}
                className="cursor-pointer rounded-sm border border-border bg-bg-surface px-1.5 py-0.5 text-[10px] text-accent hover:border-border-bright focus:outline-none"
              >
                {SELECTABLE_NOTE_TYPES.map((t) => (
                  <option key={t} value={t} className="bg-bg-surface text-text-primary">
                    {NOTE_TYPE_LABELS[t]}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-1.5 uppercase tracking-wider text-text-dim">
              publish
              <select
                value={publish}
                onChange={(e) => setPublish(e.target.value as TicketNotePublish)}
                className="cursor-pointer rounded-sm border border-border bg-bg-surface px-1.5 py-0.5 text-[10px] text-accent hover:border-border-bright focus:outline-none"
              >
                {(Object.keys(PUBLISH_LABELS) as TicketNotePublish[]).map((p) => (
                  <option key={p} value={p} className="bg-bg-surface text-text-primary">
                    {PUBLISH_LABELS[p]}
                  </option>
                ))}
              </select>
            </label>
            <span className="ml-auto text-text-dim">
              {body.length} / {BODY_MAX}
            </span>
          </div>
          {submitError && (
            <div role="alert" className="rounded-sm border border-critical/40 bg-critical/10 px-2 py-1 text-[10px] text-critical">
              {submitError}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={resetCompose}
              disabled={submitting}
              className="rounded-sm border border-border bg-bg-surface px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-secondary transition-colors hover:border-border-bright"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void onSubmit()}
              disabled={submitting || body.trim().length === 0}
              className="rounded-sm border border-accent bg-accent px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent transition-colors hover:bg-accent/80 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {submitting ? "saving…" : "Save note"}
            </button>
          </div>
        </div>
      )}

      <ol className="flex flex-col gap-2">
        {loading && <li className="text-text-dim">loading notes…</li>}
        {error && <li className="text-critical">{error}</li>}
        {!loading && !error && notes.length === 0 && (
          <li className="rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[11px] text-text-dim">
            No notes yet.
          </li>
        )}
        {notes.map((n) => (
          <li
            key={n.id}
            className="rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[11px]"
          >
            <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2 text-[10px]">
              <div className="flex items-baseline gap-2">
                <span className="text-text-secondary">
                  {n.author_operator_id !== null
                    ? `operator #${n.author_operator_id}`
                    : "autotask"}
                </span>
                <span className="rounded-sm border border-border px-1 py-0.5 font-mono uppercase tracking-wider text-text-dim">
                  {NOTE_TYPE_LABELS[n.note_type]}
                </span>
                <span className="rounded-sm border border-border px-1 py-0.5 font-mono uppercase tracking-wider text-text-dim">
                  {PUBLISH_LABELS[n.publish]}
                </span>
                {n.autotask_id && (
                  <span className="text-text-dim">· at:{n.autotask_id}</span>
                )}
              </div>
              <span className="text-text-dim">{n.created_at}</span>
            </div>
            {n.title && (
              <div className="mb-0.5 font-semibold text-text-primary">{n.title}</div>
            )}
            <div className="whitespace-pre-wrap leading-relaxed text-text-secondary">
              {n.body}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
};
