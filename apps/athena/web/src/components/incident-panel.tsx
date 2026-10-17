/**
 * The incident panel at the top of a site's drawer (Tier Black slice 1).
 *
 * OPERATORS (`OperatorIncidentPanel`): the tier chip and rule@version, the
 * kill-chain strip, "Why Black" (each condition, with its event ids), "What
 * we ruled out", the timeline, rule coverage, the mode and its source
 * ("propose only"), the proposed steps (911 / life-safety first), the
 * client's recorded decisions — and the actions the role allows:
 * Acknowledge (stops the pulse and the paging, never the pin), Assign to
 * me, Note, Contain, Raise to Black, Close (a Black needs an admin with
 * step-up and the checklist), Reclassify a Black (admin, step-up: the Black
 * stays Black and CLOSED, a linked Red opens), EVIDENCE WINDOWS (Rick,
 * 2026-10-05: a confirmed threat's first detection → its all-clear is
 * evidence, kept until an admin releases it — each window's start, end or
 * "open", rows kept and ~events; an analyst WIDENS one back with a reason;
 * an admin ADDS one — the former legal hold — or EXTENDS one, and RELEASES
 * one after the all-clear, all with step-up), a lockdown REQUEST (recorded; nothing executes; 911 /
 * life-safety assets and every target that could not be checked against
 * them are left out). "Why this device?" and the freshness matrix frozen at
 * open; a contained Black quiet for 72 h asks "ready to close?". There is
 * no lower / mute / snooze — it does not exist on the server either.
 *
 * A RESTRICTED incident (B7, CSAM — v0.17.1): an analyst reads "Restricted
 * incident — admins only" and nothing more (the detail is not even asked
 * for). An admin gets the prominent "DO NOT OPEN" warning, the fixed
 * checklist and the lookups with their domains DEFANGED (never a link) —
 * and only acknowledge, assign, note, close and the evidence windows: no
 * containment, lockdown, raise or reclassify (nothing touches the device).
 *
 * A CLIENT USER (`ClientIncidentPanel`): the neutral line and exactly two
 * actions — "Lock down my network and contact my analyst" / "Allow this
 * traffic" — then the confirmation. Nothing on their network changes in
 * slice 1; their analyst is paged.
 */
import { type FC, useCallback, useEffect, useState } from "react";

import type { ClientSiteIncident, SiteIncident } from "@/contracts/fleet";
import type { CloseCode, EvidenceWindow, IncidentDetail } from "@/contracts/incidents";
import { ApiError } from "@/lib/api";
import { ageText } from "@/lib/fleet";
import {
  ackIncident,
  addEvidenceWindow,
  answerDecision,
  assignIncident,
  clientDecision,
  closeIncident,
  containIncident,
  fetchIncident,
  lockdownRequest,
  noteIncident,
  raiseIncident,
  reclassifyIncident,
  releaseEvidenceWindow,
  utc,
  widenEvidenceWindow,
  windowLine,
} from "@/lib/incidents";
import "./fleet.css";

const btn = "rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest transition-colors disabled:opacity-50";

const TierChip: FC<{ tier: "red" | "black" | null }> = ({ tier }) => (
  <span data-testid="incident-tier"
        className={[
          "inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest",
          tier === "black"
            ? "border-[var(--fleet-threat-ring)] bg-[var(--fleet-threat)] text-[var(--fleet-threat-text)]"
            : "border-critical/60 bg-critical/15 text-critical",
        ].join(" ")}>
    {tier === "black" && <span aria-hidden="true">⯃!</span>}
    {tier === "black" ? "black" : "red"}
  </span>
);

function messageOf(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { hour12: false });
}
// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

export interface OperatorIncidentPanelProps {
  incident: SiteIncident;
  tenantSlug: string;
  /** admin / super_admin: may close or reclassify a Black (with step-up)
   *  and add / extend / release an evidence window (with step-up). */
  canCloseBlack: boolean;
  /** The caller's operator id ("assign to me"). */
  callerId?: number | null;
  onChanged: () => void;
  onStepUpRequired?: () => void;
}

type Mode = "none" | "note" | "contain" | "raise" | "close" | "lockdown" | "reclassify"
  | "window_add" | "window_extend" | "window_widen" | "window_release";
const WINDOW_MODES: Mode[] = ["window_add", "window_extend", "window_widen", "window_release"];

/**
 * A RESTRICTED incident (B7, CSAM — Rick, 2026-10-06) is admin / super_admin
 * only: anyone else reads "restricted incident" and nothing more — the
 * detail is not even asked for (the server refuses it and audits the try).
 */
export const OperatorIncidentPanel: FC<OperatorIncidentPanelProps> = (props) => {
  if (props.incident.restricted && !props.canCloseBlack) {
    return <RestrictedNotice incident={props.incident} />;
  }
  return <IncidentPanelBody {...props} />;
};

const RestrictedNotice: FC<{ incident: SiteIncident }> = ({ incident }) => (
  <section data-testid="incident-panel" data-tier={incident.tier} data-restricted="true"
           className="mb-3 flex flex-col gap-1 rounded-sm border border-[var(--fleet-threat-ring)] px-3 py-2">
    <header className="flex flex-wrap items-center gap-2">
      <TierChip tier={incident.tier} />
      <span className="font-mono text-[10px] text-text-dim">
        #{incident.id} · {ageText(incident.age_s)}
        {incident.acked ? " · acknowledged" : " · UNACKNOWLEDGED"}
      </span>
    </header>
    <div className="text-[12px] font-semibold text-text-primary" data-testid="incident-restricted-line">
      Restricted incident — admins only
    </div>
    <div className="text-[11px] text-text-dim">
      Nothing about it is shown here. An admin handles it.
    </div>
  </section>
);

/** The admin's view of a restricted incident: the warning, the fixed
 *  checklist and the lookups — the domain DEFANGED, never a link. */
const RestrictedPanel: FC<{ detail: IncidentDetail }> = ({ detail }) => {
  const r = detail.restricted;
  if (!r) return null;
  return (
    <section data-testid="restricted-panel" className="flex flex-col gap-2">
      <div role="alert" data-testid="restricted-warning"
           className="rounded-sm border-2 border-critical bg-critical/15 px-2 py-1.5 text-[12px] font-bold uppercase tracking-wide text-critical">
        {r.warning}
      </div>
      <section data-testid="restricted-checklist">
        <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">checklist</h4>
        <ol className="list-decimal pl-4 text-[11px]">
          {r.checklist.map((c, i) => <li key={i}>{c}</li>)}
        </ol>
      </section>
      <section data-testid="restricted-evidence" className="text-[11px]">
        <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
          {r.lookups} blocked lookup{r.lookups === 1 ? "" : "s"} — shown defanged, never a link
        </h4>
        <ul className="flex flex-col gap-0.5">
          {r.evidence.map((e) => (
            <li key={e.id} data-testid={`restricted-lookup-${e.id}`} className="text-text-secondary">
              {utc(e.observed_at)} · {e.device_name ?? e.device_key ?? "an unidentified device"}
              {e.client_ip ? ` (${e.client_ip})` : ""} · <span className="font-mono">{e.domain_defanged}</span>
            </li>
          ))}
        </ul>
      </section>
      {(r.related ?? []).length > 0 && (
        <section data-testid="restricted-related" className="text-[11px]">
          <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
            other sensors naming it — hidden from every other view, shown defanged
          </h4>
          <ul className="flex flex-col gap-0.5">
            {(r.related ?? []).map((e) => (
              <li key={e.event_id} data-testid={`restricted-related-${e.event_id}`}
                  className="text-text-secondary">
                {utc(e.received_at)} · {e.source} {e.event_type}
                {e.source_host ? ` · ${e.source_host}` : ""} ·{" "}
                <span className="font-mono">{e.summary_defanged}</span>
                {e.payload_defanged && (
                  <div className="break-all font-mono text-[10px] text-text-dim">{e.payload_defanged}</div>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
      <div className="text-[11px] text-text-dim" data-testid="restricted-client-notice">
        The client {r.client_notice ? "sees the neutral line only (the MSP's switch is on)"
          : "sees nothing (the MSP's switch is off)"} — and is never offered an action.
      </div>
    </section>
  );
};

const IncidentPanelBody: FC<OperatorIncidentPanelProps> = ({
  incident, tenantSlug, canCloseBlack, callerId = null, onChanged, onStepUpRequired,
}) => {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<Mode>("none");
  const [text, setText] = useState("");
  const [code, setCode] = useState<CloseCode>("remediated");
  const [check, setCheck] = useState({ c2: "yes" as "yes" | "n/a", rescue: false, state: "",
                                        who: "", when: "" });
  // The evidence-window forms: which window, its start / end (UTC, typed).
  const [win, setWin] = useState<EvidenceWindow | null>(null);
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const load = useCallback(() => {
    fetchIncident(tenantSlug, incident.id)
      .then((d) => { setDetail(d); setError(null); })
      .catch((e: unknown) => setError(messageOf(e, "The incident could not be loaded")));
  }, [tenantSlug, incident.id]);
  useEffect(() => { load(); }, [load]);

  const run = async (fn: () => Promise<unknown>): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      setMode("none");
      setText("");
      setWin(null);
      setStart("");
      setEnd("");
      load();
      onChanged();
    } catch (e) {
      if (e instanceof ApiError && (e.code === "STEP_UP_REQUIRED" || e.code === "STEP_UP_NETWORK_CHANGED")) {
        setError("This needs a fresh sign-in check — confirm it and try again.");
        onStepUpRequired?.();
      } else {
        setError(messageOf(e, "The action failed"));
      }
    } finally {
      setBusy(false);
    }
  };

  const inc = detail?.incident;
  const tier = inc?.tier ?? incident.tier;
  const open = inc ? inc.open : true;
  const acked = inc ? inc.acked : incident.acked;
  const black = tier === "black";
  const mayClose = !black || canCloseBlack;
  // B7: nothing touches the device — no containment, lockdown, raise or
  // reclassify is offered (the server refuses them too).
  const restricted = Boolean(inc?.restricted ?? incident.restricted);
  const evidenceHeld = inc?.evidence_held ?? false;
  const windows = detail?.evidence_windows ?? [];
  const mine = callerId !== null && inc?.assigned_to === String(callerId);
  const windowMode = WINDOW_MODES.includes(mode);
  const openWindowForm = (m: Mode, w: EvidenceWindow | null): void => {
    setMode(m);
    setWin(w);
    setStart(w ? w.start : "");
    setEnd(w?.end ?? "");
    setText("");
  };
  const submit = (): void => {
    const t = text.trim();
    if (mode === "note") void run(() => noteIncident(tenantSlug, incident.id, t));
    if (mode === "contain") void run(() => containIncident(tenantSlug, incident.id, t));
    if (mode === "raise") void run(() => raiseIncident(tenantSlug, incident.id, t));
    if (mode === "lockdown") void run(() => lockdownRequest(tenantSlug, incident.id, t));
    if (mode === "reclassify") void run(() => reclassifyIncident(tenantSlug, incident.id, t));
    if (mode === "window_add") {
      void run(() => addEvidenceWindow(tenantSlug, incident.id, {
        start: start.trim(), ...(end.trim() ? { end: end.trim() } : {}), reason: t }));
    }
    if (mode === "window_extend" && win) {
      void run(() => addEvidenceWindow(tenantSlug, incident.id, {
        window_id: win.id, start: start.trim(),
        ...(end.trim() && end.trim() !== (win.end ?? "") ? { end: end.trim() } : {}),
        reason: t }));
    }
    if (mode === "window_widen" && win) {
      void run(() => widenEvidenceWindow(tenantSlug, incident.id, win.id, start.trim(), t));
    }
    if (mode === "window_release" && win) {
      void run(() => releaseEvidenceWindow(tenantSlug, incident.id, win.id, t));
    }
    if (mode === "close") {
      void run(() => closeIncident(tenantSlug, incident.id, {
        code, text: t,
        ...(black && code !== "false_positive" ? { checklist: {
          c2_blocked: check.c2, rescue_point_verified: check.rescue,
          device_state: check.state, client_notified_who: check.who,
          client_notified_when: check.when,
        } } : {}),
      }));
    }
  };

  return (
    <section data-testid="incident-panel" data-tier={tier}
             className={["mb-3 flex flex-col gap-2 rounded-sm border px-3 py-2",
                         black ? "border-[var(--fleet-threat-ring)]" : "border-critical/50"].join(" ")}>
      <header className="flex flex-wrap items-center gap-2">
        <TierChip tier={tier} />
        <span className="font-mono text-[10px] text-text-dim" data-testid="incident-rule">
          {incident.rule_id}@{inc?.rule_version ?? incident.rule_version ?? 1}
          {inc ? ` · ${inc.rule_title}` : ""}
        </span>
        <span className="font-mono text-[10px] text-text-dim">
          #{incident.id} · {ageText(incident.age_s)}
          {open ? (acked ? ` · acknowledged${inc?.acked_by_name ? ` by ${inc.acked_by_name}` : ""}` : " · UNACKNOWLEDGED") : ` · ${inc?.status ?? "closed"}`}
          {(inc?.contained ?? incident.contained) ? " · contained" : ""}
          {inc?.assigned_to_name ? ` · owner ${inc.assigned_to_name}` : ""}
          {evidenceHeld ? " · EVIDENCE KEPT" : ""}
        </span>
      </header>
      {open && inc?.ready_to_close && (
        <div role="status" data-testid="incident-ready-to-close"
             className="rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary">
          Contained for over 72 hours with no new evidence — ready to close?
          {canCloseBlack ? " Close it with the checklist." : " An admin closes a Black."}
        </div>
      )}
      <div className="text-[12px] font-semibold text-text-primary">
        {inc?.summary ?? incident.summary}
        {(inc?.device_label ?? incident.device_label) ? ` — ${inc?.device_label ?? incident.device_label}` : ""}
        {incident.unknown_location ? " (device location unknown)" : ""}
      </div>
      {error && <div className="text-[11px] text-critical" data-testid="incident-error">{error}</div>}

      {restricted && detail && <RestrictedPanel detail={detail} />}

      {open && (
        <div className="flex flex-wrap gap-1.5" data-testid="incident-actions">
          {!acked && (
            <button type="button" disabled={busy} data-testid="incident-ack"
                    onClick={() => void run(() => ackIncident(tenantSlug, incident.id))}
                    className={`${btn} border-[var(--fleet-threat-ring)] text-text-primary hover:bg-accent-soft`}>
              acknowledge
            </button>
          )}
          {callerId !== null && !mine && (
            <button type="button" disabled={busy} data-testid="incident-assign-me"
                    onClick={() => void run(() => assignIncident(tenantSlug, incident.id, callerId))}
                    className={`${btn} border-border text-text-secondary`}>
              assign to me
            </button>
          )}
          <button type="button" className={`${btn} border-border text-text-secondary`}
                  onClick={() => setMode("note")} data-testid="incident-note">note</button>
          {!restricted && !(inc?.contained ?? incident.contained) && (
            <button type="button" className={`${btn} border-border text-text-secondary`}
                    onClick={() => setMode("contain")} data-testid="incident-contain">mark contained</button>
          )}
          {!restricted && !black && (
            <button type="button" className={`${btn} border-[var(--fleet-threat-ring)] text-text-primary`}
                    onClick={() => setMode("raise")} data-testid="incident-raise">raise to black</button>
          )}
          {!restricted && (
            <button type="button" className={`${btn} border-border text-text-secondary`}
                    onClick={() => setMode("lockdown")} data-testid="incident-lockdown">lockdown request</button>
          )}
          {mayClose && (
            <button type="button" className={`${btn} border-border text-text-secondary`}
                    onClick={() => setMode("close")} data-testid="incident-close">close</button>
          )}
          {!restricted && black && canCloseBlack && (
            <button type="button" className={`${btn} border-border text-text-secondary`}
                    onClick={() => setMode("reclassify")} data-testid="incident-reclassify">
              reclassify to red
            </button>
          )}
          {!mayClose && (
            <span className="font-mono text-[10px] text-text-dim" data-testid="incident-close-admin">
              closing a Black needs an admin (with a fresh sign-in check)
            </span>
          )}
        </div>
      )}

      {detail && (
        <section data-testid="incident-evidence" className="text-[11px]">
          <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
            evidence windows — kept by every retention path until an admin releases them
          </h4>
          {windows.length === 0 && (
            <div className="text-text-dim">none</div>
          )}
          <ul className="flex flex-col gap-1">
            {windows.map((w) => (
              <li key={w.id} data-testid={`evidence-window-${w.id}`}
                  className={w.held ? "text-text-secondary" : "text-text-dim"}>
                <span className="font-mono">#{w.id} · {w.kind === "incident" ? "auto" : "manual"}</span>
                {" · "}{windowLine(w)}
                {w.incident_id !== incident.id ? ` · carried to #${w.incident_id}` : ""}
                {w.held ? "" : ` · RELEASED ${utc(w.released_at ?? "")}${w.released_by_name ? ` by ${w.released_by_name}` : ""}`}
                {w.held && (
                  <span className="ml-1 inline-flex gap-1">
                    <button type="button" className={`${btn} border-border text-text-secondary`}
                            data-testid={`evidence-widen-${w.id}`}
                            onClick={() => openWindowForm("window_widen", w)}>widen</button>
                    {canCloseBlack && (
                      <button type="button" className={`${btn} border-border text-text-secondary`}
                              data-testid={`evidence-extend-${w.id}`}
                              onClick={() => openWindowForm("window_extend", w)}>extend</button>
                    )}
                    {canCloseBlack && w.incident_open === false && (
                      <button type="button" className={`${btn} border-border text-text-secondary`}
                              data-testid={`evidence-release-${w.id}`}
                              onClick={() => openWindowForm("window_release", w)}>release</button>
                    )}
                  </span>
                )}
              </li>
            ))}
          </ul>
          {canCloseBlack && (
            <button type="button" className={`${btn} mt-1 border-border text-text-secondary`}
                    onClick={() => openWindowForm("window_add", null)}
                    data-testid="incident-evidence-add">
              add evidence window
            </button>
          )}
        </section>
      )}

      {mode !== "none" && (
        <form className="flex flex-col gap-1.5 rounded-sm border border-border bg-bg-card p-2"
              data-testid="incident-form"
              onSubmit={(e) => { e.preventDefault(); submit(); }}>
          {mode === "close" && (
            <select value={code} onChange={(e) => setCode(e.target.value as CloseCode)}
                    data-testid="incident-close-code"
                    className="rounded-sm border border-border bg-bg-input px-1 py-0.5 text-[11px]">
              <option value="remediated">remediated (true positive)</option>
              <option value="authorized_activity">authorized activity</option>
              <option value="duplicate">duplicate</option>
              <option value="false_positive">false positive</option>
            </select>
          )}
          {mode === "close" && black && code !== "false_positive" && (
            <fieldset className="flex flex-col gap-1 text-[11px]" data-testid="incident-checklist">
              <label className="flex items-center gap-1">C2 blocked
                <select value={check.c2} onChange={(e) => setCheck({ ...check, c2: e.target.value as "yes" | "n/a" })}
                        className="rounded-sm border border-border bg-bg-input px-1">
                  <option value="yes">yes</option><option value="n/a">n/a</option>
                </select>
              </label>
              <label className="flex items-center gap-1">
                <input type="checkbox" checked={check.rescue}
                       onChange={(e) => setCheck({ ...check, rescue: e.target.checked })} />
                rescue point verified
              </label>
              <input placeholder="device state" value={check.state}
                     onChange={(e) => setCheck({ ...check, state: e.target.value })}
                     className="rounded-sm border border-border bg-bg-input px-1" />
              <input placeholder="client notified — who" value={check.who}
                     onChange={(e) => setCheck({ ...check, who: e.target.value })}
                     className="rounded-sm border border-border bg-bg-input px-1" />
              <input placeholder="client notified — when" value={check.when}
                     onChange={(e) => setCheck({ ...check, when: e.target.value })}
                     className="rounded-sm border border-border bg-bg-input px-1" />
            </fieldset>
          )}
          {(mode === "window_add" || mode === "window_extend" || mode === "window_widen") && (
            <div className="flex flex-wrap items-center gap-1 text-[11px]" data-testid="evidence-form">
              <label className="flex items-center gap-1">from (UTC)
                <input value={start} onChange={(e) => setStart(e.target.value)}
                       data-testid="evidence-start" placeholder="2026-09-01T08:00"
                       className="rounded-sm border border-border bg-bg-input px-1" />
              </label>
              {mode !== "window_widen" && (
                <label className="flex items-center gap-1">to (UTC, optional)
                  <input value={end} onChange={(e) => setEnd(e.target.value)}
                         data-testid="evidence-end"
                         placeholder={mode === "window_add" ? "none: held until released" : "a later end"}
                         className="rounded-sm border border-border bg-bg-input px-1" />
                </label>
              )}
              <span className="text-text-dim">
                {mode === "window_widen" ? "only ever earlier — nobody shrinks a window"
                  : mode === "window_extend" ? "start the same or earlier, end the same or later"
                  : "everything of this client inside it is kept until an admin releases it"}
              </span>
            </div>
          )}
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={2}
                    data-testid="incident-text"
                    placeholder={mode === "contain" ? "receipt or reason (required)"
                      : mode === "raise" ? "why this is Black (required)"
                      : mode === "lockdown" ? "why (required) — 911 / life-safety systems are never blocked"
                      : mode === "reclassify" ? "why this is Red, not Black (required) — the Black stays on record, closed; a linked Red opens"
                      : mode === "window_add" ? "the claim or matter (required)"
                      : mode === "window_extend" ? "why it is extended (required)"
                      : mode === "window_widen" ? "why it starts earlier — e.g. the dwell time found (required)"
                      : mode === "window_release" ? "why this evidence may go (required) — its rows then age out normally; the other admins are told"
                      : mode === "close" ? "reason (required)" : "note"}
                    className="rounded-sm border border-border bg-bg-input px-1 py-0.5 text-[11px]" />
          <div className="flex gap-1.5">
            <button type="submit"
                    disabled={busy || text.trim().length < (mode === "note" ? 1 : 3)
                      || (windowMode && mode !== "window_release" && start.trim().length < 10)}
                    data-testid="incident-submit"
                    className={`${btn} border-accent text-accent`}>
              {mode === "lockdown" ? "record request"
                : mode === "window_add" ? "add window (step-up)"
                : mode === "window_extend" ? "extend (step-up)"
                : mode === "window_widen" ? "widen"
                : mode === "window_release" ? "release (step-up)" : mode}
            </button>
            <button type="button" className={`${btn} border-border text-text-dim`}
                    onClick={() => { setMode("none"); setText(""); }}>cancel</button>
          </div>
        </form>
      )}

      {detail && !restricted && (
        <>
          <ol className="flex flex-wrap gap-1" data-testid="incident-kill-chain" aria-label="kill chain">
            {detail.kill_chain.map((k) => (
              <li key={k.phase}
                  className={["rounded-sm border px-1 font-mono text-[9px] uppercase",
                              k.seen ? "border-critical text-critical" : "border-border text-text-dim"].join(" ")}>
                {k.phase}
              </li>
            ))}
          </ol>
          <section data-testid="incident-why">
            <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
              why {black ? "black" : "red"}
            </h4>
            <ul className="text-[11px]">
              {detail.why.map((w, i) => (
                <li key={i}>✓ {w.condition}{w.detail ? ` — ${w.detail}` : ""}
                  {w.event_ids && w.event_ids.length ? ` (events ${w.event_ids.join(", ")})` : ""}</li>
              ))}
            </ul>
          </section>
          {detail.why_device && detail.why_device.length > 0 && (
            <section data-testid="incident-why-device">
              <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">why this device?</h4>
              <ul className="text-[11px]">
                {detail.why_device.map((w, i) => <li key={i}>→ {w}</li>)}
              </ul>
            </section>
          )}
          <section data-testid="incident-ruled-out">
            <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">what we ruled out</h4>
            {detail.ruled_out.length > 0 ? (
              <div className="text-[11px]">{detail.ruled_out.map((r) => `${r.check} ${r.ok ? "✓" : "✗"}`).join(" · ")}</div>
            ) : (
              <div className="text-[11px] text-text-dim">{detail.ruled_out_note ?? "—"}</div>
            )}
          </section>
          <section data-testid="incident-mode" className="text-[11px]">
            <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">mode · </span>
            {detail.mode.mode === "propose_only" ? "propose only" : detail.mode.mode}
            {` (${detail.mode.source})`}
            {detail.mode.caps.length > 0 && <div className="text-text-secondary">{detail.mode.caps.join(" · ")}</div>}
          </section>
          <section data-testid="incident-steps">
            <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">proposed steps</h4>
            <ol className="list-decimal pl-4 text-[11px]">
              {detail.proposed_steps.map((s, i) => <li key={i}>{s}</li>)}
            </ol>
          </section>
          {detail.decisions.length > 0 && (
            <section data-testid="incident-decisions">
              <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">decisions</h4>
              <ul className="flex flex-col gap-1 text-[11px]">
                {detail.decisions.map((d) => (
                  <li key={d.id} data-testid={`incident-decision-${d.id}`}>
                    <strong>{d.requested_role === "client" ? "client" : "analyst"}</strong>
                    {` asked to ${d.kind === "lockdown" ? "LOCK DOWN" : "ALLOW"} · ${d.status.replace("_", " ")}`}
                    {d.excluded.length > 0 && (
                      <span className="text-text-dim"> · excluded: {d.excluded.map((x) => (x.unverified ? `${x.ref} (not checked — confirm first)` : x.ref)).join(", ")} ({d.notice})</span>
                    )}
                    {d.status === "pending_analyst" && (
                      <span className="ml-1 inline-flex gap-1">
                        <button type="button" className={`${btn} border-accent text-accent`}
                                data-testid={`decision-confirm-${d.id}`}
                                onClick={() => void run(() => answerDecision(tenantSlug, incident.id, d.id, true, "confirmed with the client"))}>
                          confirm
                        </button>
                        <button type="button" className={`${btn} border-border text-text-dim`}
                                onClick={() => void run(() => answerDecision(tenantSlug, incident.id, d.id, false, "declined after review"))}>
                          decline
                        </button>
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
          <section data-testid="incident-coverage" className="text-[11px]">
            <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">rule coverage</h4>
            {detail.coverage.filter((c) => !c.covered).map((c) => (
              <div key={c.rule_id} className="text-text-secondary">not covered: {c.rule_id} ({c.missing.join("; ")})</div>
            ))}
            {detail.coverage.every((c) => c.covered) && <div className="text-text-dim">every rule's inputs are configured</div>}
          </section>
          {detail.freshness && detail.freshness.length > 0 && (
            <section data-testid="incident-freshness" className="text-[11px]">
              <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
                freshness at open
              </h4>
              <table className="w-full text-left text-[10px]">
                <tbody>
                  {detail.freshness.map((f) => (
                    <tr key={`${f.source}-${f.label}`} data-testid={`freshness-${f.source}`}>
                      <td className="pr-2">{f.label}</td>
                      <td className="pr-2">{f.last_ok_at ? `ok ${when(f.last_ok_at)}` : "never ok"}</td>
                      <td className={f.blind ? "text-medium" : "text-text-dim"}>
                        {f.blind ? `BLIND${f.failing_since ? ` since ${when(f.failing_since)}` : ""}` : "fresh"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
          <section data-testid="incident-client-view" className="text-[11px]">
            <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">the client sees · </span>
            {detail.client_view ? detail.client_view.status_neutral : "nothing yet (after acknowledgement or 60 min)"}
          </section>
          <Timeline detail={detail} />
        </>
      )}
      {detail && restricted && <Timeline detail={detail} />}
    </section>
  );
};

const Timeline: FC<{ detail: IncidentDetail }> = ({ detail }) => (
  <section data-testid="incident-timeline">
    <h4 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">timeline</h4>
    <ul className="text-[10px] text-text-secondary">
      {detail.timeline.map((t) => (
        <li key={t.id}>{new Date(t.created_at).toLocaleString(undefined, { hour12: false })} · {t.kind} · {t.text}</li>
      ))}
    </ul>
  </section>
);

// ---------------------------------------------------------------------------
// A client user
// ---------------------------------------------------------------------------

export const ClientIncidentPanel: FC<{ incident: ClientSiteIncident }> = ({ incident }) => {
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const decide = async (kind: "lockdown" | "allow"): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const r = await clientDecision(incident.ref, kind);
      setConfirmation(r.confirmation);
    } catch (e) {
      setError(messageOf(e, "Your decision could not be recorded"));
    } finally {
      setBusy(false);
    }
  };
  const black = incident.tier === "black";
  return (
    <section data-testid="client-incident"
             className={["mb-3 flex flex-col gap-2 rounded-sm border px-3 py-2",
                         black ? "border-[var(--fleet-threat-ring)] bg-[var(--fleet-threat)] text-[var(--fleet-threat-text)]"
                           : "border-critical/50 bg-critical/10 text-critical"].join(" ")}>
      <div className="text-[12px] font-semibold" data-testid="client-incident-line">
        {incident.status_neutral}
      </div>
      {confirmation ? (
        <div role="status" className="text-[12px]" data-testid="client-incident-confirmation">
          {confirmation}
        </div>
      ) : (
        incident.actions.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {incident.actions.map((a) => (
              <button key={a.kind} type="button" disabled={busy}
                      data-testid={`client-action-${a.kind}`}
                      onClick={() => void decide(a.kind)}
                      className="rounded-sm border border-current px-2 py-1 text-[11px] font-semibold">
                {a.label}
              </button>
            ))}
          </div>
        )
      )}
      {error && <div className="text-[11px]">{error}</div>}
    </section>
  );
};
