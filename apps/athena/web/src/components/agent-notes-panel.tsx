/**
 * AgentNotesPanel — shared renderer for agent_notes attached to any
 * ref (event, ticket, indicator, buoy, etc).
 *
 * Surfaces consistently in:
 *   /search payload drawer
 *   /tickets floating window
 *   dashboard alert drawer
 *   buoy drawer
 *
 * Optionally renders the "ask octo" canned-query button bar below
 * the notes list. Operator clicks fire a POST to /api/v1/agent-query
 * (bridge → octo-llm), and the returned note is appended to the
 * displayed list immediately. Disabled / unavailable / errored states
 * are surfaced inline with a single status line — never block the
 * surrounding UI.
 *
 * Per the octo-llm triage-taxonomy design decision (2026-05-21):
 *   - The button bar is OPERATOR enrichment only. NOT chat. Each
 *     button maps to a closed-enum `query_kind` server-side.
 *   - Athena's interactive chat surface is a separate, future thing.
 */
import { type FC, useEffect, useState } from "react";

import {
  ApiError,
  agentQuery,
  fetchAgentNotesForRef,
  type AgentNote,
  type AgentQueryNoteRow,
  type AskOctoQueryKind,
} from "@/lib/api";


// ---------------------------------------------------------------------------
// Canned-query button vocabulary. Matches the closed enum on the
// backend; adding new buttons requires extending both ends + the
// octo-llm models.QueryKind.
// ---------------------------------------------------------------------------

interface CannedQuery {
  kind: AskOctoQueryKind;
  label: string;
  hint: string;  // tooltip
}

// Compact labels so the button bar fits the 240px alert-drawer
// sidecar without ugly per-button wrapping. The hint tooltip carries
// the longer descriptive copy.
const CANNED_QUERIES: CannedQuery[] = [
  {
    kind: "tell_me_more",
    label: "Tell me more",
    hint: "Octo paraphrases the heuristic note + adds context",
  },
  {
    kind: "recognized_patterns",
    label: "Patterns?",
    hint: "Octo compares against known IOC + TTP patterns",
  },
  {
    kind: "compare_recent",
    label: "Similar recent",
    hint: "Octo summarizes similar recent events on this host",
  },
  {
    kind: "suggest_disposition",
    label: "Disposition",
    hint: "Noise / pattern / escalate explanation",
  },
  {
    kind: "suggest_next_steps",
    label: "Next steps",
    hint: "Concrete next-step investigation or remediation actions",
  },
];


// ---------------------------------------------------------------------------
// Display row — accepts either an existing AgentNote (from a payload
// fetch) or a freshly-returned AgentQueryNoteRow (from /agent-query).
// Both shapes carry the same display fields; the query-result row
// also carries `query_kind` for chip labeling.
// ---------------------------------------------------------------------------

type DisplayNote = AgentNote | AgentQueryNoteRow;


function noteQueryKind(n: DisplayNote): string | null {
  return "query_kind" in n ? n.query_kind : null;
}


// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface Props {
  notes: AgentNote[];
  /** Hide the "ask octo" button bar — used when the surface doesn't
   * have routing context (e.g. metadata-only drawer with no ref). */
  hideAskBar?: boolean;
  /** Required iff hideAskBar is false. The bridge needs these to
   * route the call. */
  clientSlug?: string;
  refKind?: "event" | "ticket" | "indicator";
  refId?: number;
  /** Heuristic note text that octo paraphrases. The first existing
   * agent_note's text is a reasonable default if none is supplied
   * explicitly. */
  heuristicNote?: string;
  /** Whether the "Ask Octo" section starts expanded. Defaults to
   * `false` so the sidecar stays quiet until the operator wants it. */
  askBarStartOpen?: boolean;
}

const AgentNotesPanel: FC<Props> = ({
  notes: initialNotes, hideAskBar = false,
  clientSlug, refKind, refId, heuristicNote,
  askBarStartOpen = false,
}) => {
  // Notes loaded for THE CURRENT ref — fetched on mount + reset on
  // ref change so switching alerts/events/tickets doesn't leak
  // previously-fired enrichments across surfaces. Slice 7h.
  const [fetchedNotes, setFetchedNotes] = useState<AgentQueryNoteRow[]>([]);
  const [extraNotes, setExtraNotes] = useState<AgentQueryNoteRow[]>([]);
  const [pendingKind, setPendingKind] = useState<AskOctoQueryKind | null>(null);
  const [askBarOpen, setAskBarOpen] = useState<boolean>(askBarStartOpen);
  const [status, setStatus] = useState<{
    kind: "idle" | "ok" | "disabled" | "unavailable" | "error";
    text?: string;
  }>({ kind: "idle" });

  // Reset + refetch whenever the displayed ref changes. The
  // dependency array intentionally excludes `initialNotes` — the
  // parent passes those for surfaces that already have them
  // server-rendered (e.g. /search payload drawer); we want the
  // FETCH to be ref-driven, not initialNotes-driven.
  useEffect(() => {
    setExtraNotes([]);
    setStatus({ kind: "idle" });
    if (clientSlug === undefined || refKind === undefined || refId === undefined) {
      setFetchedNotes([]);
      return;
    }
    let cancelled = false;
    fetchAgentNotesForRef(clientSlug, refKind, refId)
      .then((notes) => { if (!cancelled) setFetchedNotes(notes); })
      .catch(() => { if (!cancelled) setFetchedNotes([]); });
    return () => { cancelled = true; };
  }, [clientSlug, refKind, refId]);

  // Display set: server-fetched first (most authoritative), then
  // anything the parent passed in (only used when the fetch hasn't
  // landed yet or for surfaces without a ref), then locally-fired
  // queries that haven't been refetched. Dedup by id.
  const allNotes: DisplayNote[] = (() => {
    const seen = new Set<number>();
    const out: DisplayNote[] = [];
    for (const n of fetchedNotes) {
      if (!seen.has(n.id)) { seen.add(n.id); out.push(n); }
    }
    // initialNotes only used if we haven't yet fetched (the fetch
    // is authoritative; initialNotes may be stale from a parent
    // re-render race).
    if (fetchedNotes.length === 0) {
      for (const n of initialNotes) {
        if (!seen.has(n.id)) { seen.add(n.id); out.push(n); }
      }
    }
    for (const n of extraNotes) {
      if (!seen.has(n.id)) { seen.add(n.id); out.push(n); }
    }
    return out;
  })();

  const canAsk = !hideAskBar
    && clientSlug !== undefined
    && refKind !== undefined
    && refId !== undefined;

  const onAsk = async (kind: AskOctoQueryKind): Promise<void> => {
    if (!canAsk) return;
    // Use the first note's text as the heuristic default if the
    // caller didn't supply one. If the panel renders empty, we can
    // still ask — sending an empty heuristic_note isn't useful, so
    // we bail with a status hint.
    const baseNote = heuristicNote
      ?? initialNotes[0]?.note_text
      ?? "";
    if (!baseNote) {
      setStatus({
        kind: "error",
        text: "no heuristic note to enrich",
      });
      return;
    }
    setPendingKind(kind);
    setStatus({ kind: "idle" });
    try {
      const result = await agentQuery({
        client_slug: clientSlug!,
        ref_kind: refKind!,
        ref_id: refId!,
        query_kind: kind,
        heuristic_note: baseNote,
        signals: [],
      });
      setExtraNotes((prev) => [...prev, result.note]);
      // Where the model ran, every time: a tenant cleared for cloud AI is
      // still answered by the local model while no cloud one is wired in.
      setStatus({
        kind: "ok",
        text: `+${result.llm_took_ms}ms · ${result.llm_locality ?? "local"} model`,
      });
    } catch (e) {
      if (e instanceof ApiError) {
        // 503 = disabled or unhealthy — never escalate to error UI.
        if (e.status === 503 || e.status === 412 /* PRECONDITION_FAILED */) {
          setStatus({
            kind: e.message.includes("disabled") ? "disabled" : "unavailable",
            text: e.message,
          });
        } else {
          setStatus({ kind: "error", text: e.message });
        }
      } else {
        setStatus({
          kind: "error",
          text: e instanceof Error ? e.message : "unknown error",
        });
      }
    } finally {
      setPendingKind(null);
    }
  };

  return (
    <div className="flex flex-col gap-2 rounded-sm border border-accent/30 bg-accent-soft p-3 text-[11px]">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-widest text-accent">
          ·· agent notes ··
        </span>
        <span className="font-mono text-[10px] text-text-dim">
          {allNotes.length} note{allNotes.length === 1 ? "" : "s"}
        </span>
      </div>

      {allNotes.length === 0 && (
        <div className="rounded-sm border border-dashed border-border/60 bg-bg-card/40 px-2 py-1.5 text-[10px] text-text-dim italic">
          No agent notes yet. Use the buttons below to ask octo for context.
        </div>
      )}

      {allNotes.length > 0 && (
        <ul role="list" className="flex flex-col gap-1.5">
          {allNotes.map((n, idx) => (
            <li
              key={`${n.id}-${idx}`}
              className="rounded-sm border border-border bg-bg-card px-2 py-1.5"
            >
              {/* Metadata row — flex-wrap so it stacks gracefully in
                  the 240px sidecar without horizontal overflow. */}
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 font-mono text-[10px] uppercase tracking-wider text-text-dim">
                <span className="text-accent">{n.agent_id}</span>
                <span className="text-text-dim/60">·</span>
                <span>{Math.round(n.confidence * 100)}%</span>
                {n.agent_id === "octo" && (
                  <>
                    <span className="text-text-dim/60">·</span>
                    <span
                      title={
                        "this confidence value is an uncalibrated " +
                        "model score — do not gate decisions on it. " +
                        "calibration loop is a future workstream."
                      }
                      className="rounded-sm bg-yellow-900/40 px-1 py-0.5 text-yellow-400/90 normal-case"
                    >
                      uncal
                    </span>
                  </>
                )}
                {noteQueryKind(n) && (
                  <>
                    <span className="text-text-dim/60">·</span>
                    <span title="query kind" className="truncate">
                      {noteQueryKind(n)!.replace(/_/g, "-")}
                    </span>
                  </>
                )}
                <span className="text-text-dim/60">·</span>
                <span className="truncate">{formatTs(n.created_at)}</span>
              </div>
              <div className="mt-1 break-words leading-relaxed text-text-primary">
                {n.note_text}
              </div>
            </li>
          ))}
        </ul>
      )}

      {canAsk && (
        <div className="mt-1 flex flex-col gap-1.5 border-t border-border/40 pt-2">
          {/* Collapsible header — default closed so the sidecar stays
              quiet until the operator wants to ask. Click toggles the
              button bar's visibility; the chevron flips. */}
          <button
            type="button"
            onClick={() => setAskBarOpen((v) => !v)}
            aria-expanded={askBarOpen}
            aria-controls="ask-octo-bar"
            className="flex items-center justify-between rounded-sm px-1 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-dim hover:text-accent"
          >
            <span>·· ask octo ··</span>
            <span aria-hidden="true" className="text-text-dim">
              {askBarOpen ? "▾" : "▸"}
            </span>
          </button>
          {askBarOpen && (
            <div id="ask-octo-bar" className="flex flex-col gap-1.5">
              <div className="flex flex-wrap gap-1.5">
                {CANNED_QUERIES.map((q) => (
                  <button
                    key={q.kind}
                    type="button"
                    onClick={() => void onAsk(q.kind)}
                    disabled={pendingKind !== null}
                    title={q.hint}
                    className="rounded-sm border border-accent/60 bg-accent/10 px-2 py-1 font-mono text-[10px] text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {pendingKind === q.kind ? "…" : q.label}
                  </button>
                ))}
              </div>
              {status.kind !== "idle" && (
                <div
                  className={[
                    "rounded-sm px-2 py-1 text-[10px]",
                    status.kind === "ok"
                      ? "border border-accent/30 bg-accent/5 text-accent"
                      : status.kind === "disabled"
                        ? "border border-border bg-bg-card text-text-dim"
                        : status.kind === "unavailable"
                          ? "border border-medium/40 bg-medium/5 text-medium"
                          : "border border-critical/40 bg-critical/5 text-critical",
                  ].join(" ")}
                  title={status.text}
                >
                  {status.kind === "ok" && `octo replied (${status.text})`}
                  {status.kind === "disabled" && (
                    /* Surface the bridge's specific message — it
                       differentiates "bundle disabled" / "user not
                       granted" / "preference off" so the operator
                       can see which gate is blocking them. */
                    status.text || "octo-llm disabled — heuristic only"
                  )}
                  {status.kind === "unavailable" && (status.text || "octo unavailable — heuristic only")}
                  {status.kind === "error" && (status.text ?? "error")}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};


function formatTs(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString([], { hour12: false });
  } catch {
    return iso;
  }
}


export default AgentNotesPanel;
export { AgentNotesPanel };
