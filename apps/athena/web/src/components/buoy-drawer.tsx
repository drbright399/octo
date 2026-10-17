/**
 * BuoyDrawer — per-buoy operator Management + status panel.
 *
 * Right-side slide-out (matches /search drawer + /tickets drawer
 * pattern). Three tabs:
 *   1. Management — quick actions grid + service status grid +
 *      terminal pane (read-only DEV preview, step-up gated) +
 *      recent command history. Replaces the slice-8 "Commands" tab
 *      per the 2026-05-19 fleet redesign handoff. Role-gated
 *      client-side via canIssueBuoyCommand (server is the load-
 *      bearing check). Reboot has typed-slug confirmation.
 *   2. Notes — placeholder for the per-buoy notepad (slice 12
 *      backend already shipped; UI lands in a follow-up port).
 *   3. Log Preview — read-only DEV surface for tail-log output.
 *      Filter rail + per-tenant events search lands with the rest
 *      of the fleet redesign UI.
 *
 * Step-up auth: queueing a destructive command requires an active
 * step-up window. The drawer self-fetches `/api/v1/search/status`
 * so it can render the locked/active visual state up front, and
 * the parent (fleet.tsx) opens the existing <StepUpModal> when the
 * drawer fires `onStepUpRequired`. Same TTL window as /search:
 * 30m sliding / 4h absolute, IP-bound server-side.
 *
 * Terminal pane: read-only DEV preview for v1. The input is
 * rendered (so the design shape is in place) but submissions are
 * no-ops. Real wire-up — per-keystroke audit + WebSocket attach +
 * step-up TTL renewal — is the Fleet Remote-Management milestone.
 */
import {
  type FC, useCallback, useEffect, useRef, useState,
} from "react";
import { createPortal } from "react-dom";

import {
  type BuoyCommandHistoryRow,
  type BuoyCommandKind,
  type BuoyFleetRow,
  canIssueBuoyCommand,
  listBuoyCommands,
  queueBuoyCommand,
  formatDuration,
  isRetiredService,
} from "@/lib/buoy";
import { ApiError, fetchStepUpStatus } from "@/lib/api";

import "./fleet.css";


export interface BuoyDrawerProps {
  buoy: BuoyFleetRow;
  callerRole: string | null;
  onClose: () => void;
  onStepUpRequired: () => void;
}

type TabId = "management" | "notes" | "log";

const TAB_LABEL: Record<TabId, string> = {
  management: "management",
  notes:      "notes",
  log:        "log preview",
};

const STEP_UP_REFRESH_MS = 30_000;


const BuoyDrawer: FC<BuoyDrawerProps> = ({
  buoy, callerRole, onClose, onStepUpRequired,
}) => {
  const [tab, setTab] = useState<TabId>("management");
  const [history, setHistory] = useState<readonly BuoyCommandHistoryRow[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [busy, setBusy] = useState<BuoyCommandKind | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [stepUpActive, setStepUpActive] = useState<boolean>(false);
  const drawerRef = useRef<HTMLDivElement | null>(null);

  // Reboot confirmation state — operator must type the slug to enable.
  const [rebootConfirmOpen, setRebootConfirmOpen] = useState(false);
  const [rebootTyped, setRebootTyped] = useState("");

  const refreshStepUp = useCallback(async () => {
    try {
      const s = await fetchStepUpStatus();
      setStepUpActive(s.elevated);
    } catch {
      // Soft-fail: assume not elevated. Server is the load-bearing check.
      setStepUpActive(false);
    }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const rows = await listBuoyCommands(buoy.slug);
      setHistory(rows);
      setHistoryError(null);
    } catch (e) {
      setHistoryError(
        e instanceof ApiError ? e.message : "Failed to load history",
      );
    }
  }, [buoy.slug]);

  useEffect(() => {
    void loadHistory();
    void refreshStepUp();
    const hId = setInterval(() => { void loadHistory(); }, 10_000);
    const sId = setInterval(() => { void refreshStepUp(); }, STEP_UP_REFRESH_MS);
    return () => { clearInterval(hId); clearInterval(sId); };
  }, [loadHistory, refreshStepUp]);

  const issueCommand = useCallback(async (
    kind: BuoyCommandKind, args: Record<string, string> = {},
  ): Promise<void> => {
    setBusy(kind);
    setActionError(null);
    try {
      await queueBuoyCommand(buoy.slug, kind, args);
      await loadHistory();
      // Successful command implies step-up clearance (for the gated
      // kinds) or no-op clearance state (for the open kinds). Refresh
      // so the UI reflects any sliding-TTL renewal.
      void refreshStepUp();
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.message === "STEP_UP_REQUIRED" || e.status === 401) {
          setStepUpActive(false);
          onStepUpRequired();
          return;
        }
        setActionError(e.message);
      } else {
        setActionError("Queue failed");
      }
    } finally {
      setBusy(null);
    }
  }, [buoy.slug, loadHistory, onStepUpRequired, refreshStepUp]);

  const onRebootClick = () => {
    setRebootTyped("");
    setRebootConfirmOpen(true);
  };
  const confirmReboot = async () => {
    setRebootConfirmOpen(false);
    await issueCommand("reboot");
  };

  return createPortal(
    <div
      ref={drawerRef}
      role="dialog" aria-modal="false" aria-label={`buoy ${buoy.slug}`}
      className="fixed right-0 top-0 z-40 flex h-full w-[640px] max-w-full flex-col border-l border-border-bright bg-bg-elevated shadow-2xl"
    >
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="min-w-0">
          <div className="text-[10px] font-mono uppercase tracking-widest text-accent">
            [ buoy ]
          </div>
          <div className="truncate text-sm font-semibold text-text-primary">
            {buoy.slug}
          </div>
          <div className="truncate font-mono text-[10px] text-text-dim">
            {buoy.hostname} · uptime {formatDuration(buoy.uptime_sec)}
          </div>
        </div>
        <button
          type="button" onClick={onClose}
          className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
        >✕ close</button>
      </header>

      {/* Tab strip */}
      <div className="flex items-center gap-1 border-b border-border bg-bg-surface px-3 py-1.5">
        {(["management", "notes", "log"] as TabId[]).map((id) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            aria-pressed={tab === id}
            className={[
              "rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors",
              tab === id
                ? "border-accent bg-accent text-text-on-accent"
                : "border-border bg-bg-card text-text-secondary hover:border-border-bright hover:text-accent",
            ].join(" ")}
          >
            {TAB_LABEL[id]}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-4 text-[11px]">
        {tab === "management" && (
          <ManagementTab
            buoy={buoy}
            callerRole={callerRole}
            busy={busy}
            actionError={actionError}
            history={history}
            historyError={historyError}
            stepUpActive={stepUpActive}
            onIssue={issueCommand}
            onReboot={onRebootClick}
            onStepUpRequired={onStepUpRequired}
          />
        )}
        {tab === "notes"    && <NotesTab    buoy={buoy} />}
        {tab === "log"      && <LogTab      buoy={buoy} callerRole={callerRole} />}
      </div>

      {/* Reboot confirm */}
      {rebootConfirmOpen && (
        <RebootConfirmModal
          slug={buoy.slug}
          typed={rebootTyped}
          onType={setRebootTyped}
          onConfirm={confirmReboot}
          onCancel={() => setRebootConfirmOpen(false)}
        />
      )}
    </div>,
    document.body,
  );
};


// ---------------------------------------------------------------------------
// Management tab — step-up banner + quick actions + service grid +
//                  terminal pane (demo) + recent commands.
// ---------------------------------------------------------------------------

// Per kit + role memo: ping/refresh/tail-log are read-only and don't need
// step-up. restart-service/reboot/update mutate buoy state and require it.
const STEP_UP_REQUIRED_KINDS: ReadonlySet<BuoyCommandKind> = new Set<BuoyCommandKind>([
  "restart-service", "reboot", "update",
]);

interface ManagementTabProps {
  buoy: BuoyFleetRow;
  callerRole: string | null;
  busy: BuoyCommandKind | null;
  actionError: string | null;
  history: readonly BuoyCommandHistoryRow[];
  historyError: string | null;
  stepUpActive: boolean;
  onIssue: (kind: BuoyCommandKind, args?: Record<string, string>) => Promise<void>;
  onReboot: () => void;
  onStepUpRequired: () => void;
}

const ManagementTab: FC<ManagementTabProps> = ({
  buoy, callerRole, busy, actionError, history, historyError, stepUpActive,
  onIssue, onReboot, onStepUpRequired,
}) => {
  const canPing    = canIssueBuoyCommand(callerRole, "ping");
  const canRefresh = canIssueBuoyCommand(callerRole, "refresh");
  const canTail    = canIssueBuoyCommand(callerRole, "tail-log");
  const canRestart = canIssueBuoyCommand(callerRole, "restart-service");
  const canReboot  = canIssueBuoyCommand(callerRole, "reboot");
  const canUpdate  = canIssueBuoyCommand(callerRole, "update");

  const buoyUnreachable = buoy.health === "red" || buoy.health === "stale";

  return (
    <div className="flex flex-col gap-4">
      {/* (1) Step-up banner */}
      <StepUpBanner active={stepUpActive} onStepUp={onStepUpRequired} />

      {/* (2) Quick actions */}
      <section>
        <SectionEyebrow n={1} label="quick actions"
          hint="Read-only actions (ping / refresh / tail-log) work without step-up. Destructive actions (restart / reboot / update) require step-up auth." />
        <div className="grid grid-cols-2 gap-2">
          <CmdBtn label="ping"
                  enabled={canPing}
                  busy={busy === "ping"}
                  onClick={() => onIssue("ping")} />
          <CmdBtn label="refresh"
                  enabled={canRefresh}
                  busy={busy === "refresh"}
                  onClick={() => onIssue("refresh")} />
          <CmdBtn label="tail-log"
                  enabled={canTail}
                  busy={busy === "tail-log"}
                  onClick={() => onIssue("tail-log", { unit: "buoy-forwarder", lines: "100" })} />
          <CmdBtn label="restart wazuh-agent"
                  enabled={canRestart}
                  busy={busy === "restart-service"}
                  stepUpRequired stepUpActive={stepUpActive}
                  onClick={() =>
                    stepUpActive
                      ? onIssue("restart-service", { unit: "wazuh-agent" })
                      : onStepUpRequired()
                  } />
          <CmdBtn label="reboot ⚠"
                  enabled={canReboot}
                  busy={busy === "reboot"}
                  destructive
                  stepUpRequired stepUpActive={stepUpActive}
                  onClick={() => stepUpActive ? onReboot() : onStepUpRequired()} />
          <CmdBtn label="update"
                  enabled={canUpdate}
                  busy={busy === "update"}
                  stepUpRequired stepUpActive={stepUpActive}
                  onClick={() =>
                    stepUpActive
                      ? onIssue("update")
                      : onStepUpRequired()
                  } />
        </div>
        {buoyUnreachable && (
          <div className="mt-2 rounded-sm border border-critical/40 bg-critical/10 px-2 py-1 font-mono text-[10px] text-critical">
            <strong>buoy unreachable</strong> · most commands will queue but
            won&apos;t dispatch until heartbeat resumes.
          </div>
        )}
        {actionError && (
          <div className="mt-2 rounded-sm border border-critical/40 bg-critical/10 px-2 py-1 text-critical">
            {actionError}
          </div>
        )}
      </section>

      {/* (3) Service status grid */}
      <section>
        <SectionEyebrow n={2} label="services"
          hint="Per-buoy daemon status from the heartbeat payload. Version + activity-stat fields land with the heartbeat-contract extension." />
        <ServiceGrid services={buoy.services} retired={buoy.retired_services} />
      </section>

      {/* (4) Terminal pane (read-only DEV preview, step-up gated) */}
      <section>
        <SectionEyebrow n={3} label="terminal"
          hint="Step-up gated. Read-only preview in this build — the real shell, with per-keystroke audit + WebSocket attach + sliding TTL renewal, lands in the Fleet Remote-Management milestone." />
        <BuoyTerminal
          buoy={buoy}
          unreachable={buoyUnreachable}
          stepUpActive={stepUpActive}
          onStepUp={onStepUpRequired}
        />
      </section>

      {/* (5) Recent commands */}
      <section>
        <SectionEyebrow n={4} label="recent commands"
          hint="Last 12 commands queued against this buoy. Status reflects the buoy-side execution result, not the queue insert." />
        {historyError && (
          <div className="rounded-sm border border-critical/40 bg-critical/10 px-2 py-1 text-critical">
            {historyError}
          </div>
        )}
        {!historyError && history.length === 0 && (
          <div className="rounded-sm border border-border bg-bg-card px-2 py-2 text-center text-text-dim italic">
            No commands queued yet for this buoy.
          </div>
        )}
        {history.length > 0 && (
          <ul className="flex flex-col gap-1" role="list">
            {history.slice(0, 12).map((c) => (
              <CommandRow key={c.id} cmd={c} />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
};


// ---------------------------------------------------------------------------
// Step-up banner — shows current step-up state at the top of Management.
// Read-only status: the actual elevation happens via the parent's
// <StepUpModal> triggered by `onStepUpRequired`.
// ---------------------------------------------------------------------------

const StepUpBanner: FC<{ active: boolean; onStepUp: () => void }> = ({
  active, onStepUp,
}) => {
  if (active) {
    return (
      <div
        role="status" aria-live="polite"
        className="flex items-center gap-2 rounded-sm border border-success/40 bg-success/5 px-2 py-1.5 font-mono text-[10px]"
      >
        <span aria-hidden="true" className="text-success">●</span>
        <span className="uppercase tracking-wider text-success">step-up active</span>
        <span className="text-text-dim">
          30m sliding · 4h absolute · IP-bound · destructive commands enabled
        </span>
      </div>
    );
  }
  return (
    <div
      role="status"
      className="flex items-center gap-2 rounded-sm border border-warning/40 bg-warning/5 px-2 py-1.5 font-mono text-[10px]"
    >
      <span aria-hidden="true" className="text-warning">⊞</span>
      <span className="uppercase tracking-wider text-warning">step-up required</span>
      <span className="flex-1 text-text-dim">
        password + TOTP needed for destructive commands
      </span>
      <button
        type="button"
        onClick={onStepUp}
        className="rounded-sm border border-accent bg-accent/10 px-2 py-0.5 uppercase tracking-wider text-accent transition-colors hover:bg-accent/20"
      >step up</button>
    </div>
  );
};


// ---------------------------------------------------------------------------
// Section eyebrow — numbered section header with help title.
// ---------------------------------------------------------------------------

const SectionEyebrow: FC<{ n: number; label: string; hint?: string }> = ({
  n, label, hint,
}) => (
  <div className="mb-1.5 flex items-baseline gap-2 font-mono text-[10px] uppercase tracking-widest">
    <span className="text-accent" aria-hidden="true">·· {n.toString().padStart(2, "0")} ··</span>
    <span className="text-text-dim">{label}</span>
    {hint && (
      <span
        className="cursor-help text-text-dim hover:text-text-secondary"
        title={hint}
        aria-label={hint}
      >?</span>
    )}
  </div>
);


// ---------------------------------------------------------------------------
// Service grid — one card per buoy-monitored daemon.
//
// Reads `buoy.services` (Record<unit-name, state>) from the existing
// heartbeat payload. version/stat/last_activity render as "—" until the
// heartbeat contract extension lands.
// ---------------------------------------------------------------------------

interface ServiceVisual {
  border: string;
  bg: string;
  dot: string;
  label: string;
  labelClass: string;
}

const SERVICE_VISUAL: Record<string, ServiceVisual> = {
  active:   { border: "border-success/40", bg: "bg-success/5", dot: "bg-success", label: "ACTIVE",   labelClass: "text-success" },
  degraded: { border: "border-warning/40", bg: "bg-warning/5", dot: "bg-warning", label: "DEGRADED", labelClass: "text-warning" },
  failed:   { border: "border-critical/40", bg: "bg-critical/5", dot: "bg-critical", label: "FAILED", labelClass: "text-critical" },
  inactive: { border: "border-border",     bg: "bg-bg-card",   dot: "bg-text-dim", label: "INACTIVE", labelClass: "text-text-dim" },
  missing:  { border: "border-border",     bg: "bg-bg-card",   dot: "bg-text-dim", label: "NOT INSTALLED", labelClass: "text-text-dim" },
  unknown:  { border: "border-border",     bg: "bg-bg-card",   dot: "bg-text-dim", label: "UNKNOWN",  labelClass: "text-text-dim" },
  // Disabled on purpose and not running: information, never a fault.
  retired:  { border: "border-border",     bg: "bg-bg-card",   dot: "bg-text-dim", label: "RETIRED (DISABLED)", labelClass: "text-text-dim" },
};
const SERVICE_FALLBACK: ServiceVisual = SERVICE_VISUAL.unknown!;

const SERVICE_ROLE: Record<string, string> = {
  "tailscaled":     "mesh",
  "wazuh-agent":    "EDR",
  "opencanary":     "deception",
  "suricata":       "NIDS",
  "buoy-forwarder": "relay",
  "octo-forwarder": "relay",
  "pihole-FTL":     "DNS",
  "nextdns":        "DNS",
};

const ServiceGrid: FC<{
  services: Record<string, import("@/lib/buoy").ServiceInfo>;
  retired?: readonly string[] | undefined;
}> = ({ services, retired }) => {
  const entries = Object.entries(services);
  if (entries.length === 0) {
    return (
      <div className="rounded-sm border border-border bg-bg-card px-2 py-2 text-center text-text-dim italic">
        No service status reported yet — waiting for first heartbeat.
      </div>
    );
  }
  return (
    <ul role="list" className="grid grid-cols-2 gap-2">
      {entries.map(([unit, info]) => {
        const shown = isRetiredService(unit, info, retired) ? "retired" : info.state;
        const v = SERVICE_VISUAL[shown] ?? SERVICE_FALLBACK;
        const role = SERVICE_ROLE[unit] ?? "—";
        const version = info.version ?? "—";
        const stat = info.stat ?? "—";
        const lastActivity = info.last_activity
          ? new Date(info.last_activity).toLocaleString(undefined, {
              hour12: false, dateStyle: "short", timeStyle: "short",
            })
          : "—";
        return (
          <li
            key={unit}
            className={`rounded-sm border ${v.border} ${v.bg} px-2 py-2`}
          >
            <header className="mb-1 flex items-center gap-2">
              <span className={`h-1.5 w-1.5 rounded-full ${v.dot}`} aria-hidden="true" />
              <span className="flex-1 truncate text-[11px] font-semibold text-text-primary">
                {unit}
              </span>
              <span className="font-mono text-[9px] uppercase tracking-wider text-text-dim">
                {role}
              </span>
            </header>
            <div className="mb-1 flex items-baseline justify-between">
              <span className={`font-mono text-[9px] uppercase tracking-wider ${v.labelClass}`}>
                {v.label}
              </span>
              <span className="font-mono text-[9px] text-text-dim" title={`version: ${version}`}>
                v{version}
              </span>
            </div>
            <div className="font-mono text-[9px] text-text-dim">{stat}</div>
            <div className="font-mono text-[9px] text-text-dim" title={info.last_activity ?? ""}>
              last activity: {lastActivity}
            </div>
          </li>
        );
      })}
    </ul>
  );
};


// ---------------------------------------------------------------------------
// BuoyTerminal — DEV-preview read-only terminal pane.
//
// v1: renders the shell shape + scrollback placeholder + step-up lock
// overlay. Input is rendered for the visual but accepts no submission
// (matches kit; production wires to WebSocket + per-keystroke audit).
// ---------------------------------------------------------------------------

interface BuoyTerminalProps {
  buoy: BuoyFleetRow;
  unreachable: boolean;
  stepUpActive: boolean;
  onStepUp: () => void;
}

const PLACEHOLDER_LINES: ReadonlyArray<{ kind: "prompt" | "out"; body: string }> = [
  { kind: "prompt", body: "systemctl status buoy-heartbeat" },
  { kind: "out",    body: "● buoy-heartbeat.service — Athena Buoy Heartbeat — fleet status push to OCTO" },
  { kind: "out",    body: "     Active: active (running) since boot" },
  { kind: "out",    body: "     Memory: 12.4M    Tasks: 1" },
  { kind: "prompt", body: "" },
];

const BuoyTerminal: FC<BuoyTerminalProps> = ({
  buoy, unreachable, stepUpActive, onStepUp,
}) => {
  const locked = !stepUpActive;
  const [input, setInput] = useState("");
  return (
    <div className="relative overflow-hidden rounded-sm border border-border bg-black">
      <header className="flex items-center gap-2 border-b border-border bg-bg-surface px-2 py-1 font-mono text-[10px]">
        <span className="text-accent">[ shell ]</span>
        <span className="text-text-secondary">root@{buoy.hostname}</span>
        <span aria-hidden="true" className={
          unreachable ? "ml-1 h-1.5 w-1.5 rounded-full bg-critical"
          : locked    ? "ml-1 h-1.5 w-1.5 rounded-full bg-warning"
          : "ml-1 h-1.5 w-1.5 rounded-full bg-success"
        } />
        <span className="ml-auto uppercase tracking-wider text-text-dim">
          {unreachable ? "unreachable" : locked ? "step-up required" : "connected"}
        </span>
      </header>

      <div
        role="log" aria-live="polite"
        className="max-h-48 overflow-auto px-3 py-2 font-mono text-[10px] text-text-secondary"
      >
        {PLACEHOLDER_LINES.map((l, i) => (
          <div key={i}>
            {l.kind === "prompt" ? (
              <>
                <span className="text-accent">$&nbsp;</span>
                <span>{l.body}</span>
              </>
            ) : (
              <span className="text-text-dim">{l.body}</span>
            )}
          </div>
        ))}
      </div>

      <form
        className="flex items-center gap-1 border-t border-border bg-bg-surface px-2 py-1 font-mono text-[10px]"
        onSubmit={(e) => { e.preventDefault(); /* DEV — no-op until WebSocket wire-up */ }}
        aria-label="buoy shell input"
      >
        <span className="text-accent">$&nbsp;</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={unreachable || locked}
          spellCheck={false}
          autoComplete="off"
          placeholder={
            unreachable ? "buoy offline"
              : locked   ? "step-up auth required"
              : "DEV preview — input is non-functional in this build"
          }
          className="flex-1 bg-transparent text-text-primary outline-none placeholder:text-text-dim"
        />
      </form>

      <p className="border-t border-border bg-warning/5 px-2 py-1 font-mono text-[9px] text-warning">
        DEV preview — design pane only. Real shell wires to per-keystroke
        audit + WebSocket attach + sliding step-up TTL in the Fleet
        Remote-Management milestone.
      </p>

      {locked && !unreachable && (
        <div className="fleet-terminal__lock-overlay">
          <span aria-hidden="true" className="font-mono text-xl text-warning">⊞</span>
          <span className="font-mono text-[10px] uppercase tracking-wider text-warning">
            shell is gated behind step-up auth
          </span>
          <button
            type="button"
            onClick={onStepUp}
            className="mt-1 rounded-sm border border-accent bg-accent px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent hover:opacity-90"
          >step up</button>
        </div>
      )}
    </div>
  );
};


// ---------------------------------------------------------------------------
// Command button — adds a step-up locked variant on top of the existing
// enabled/destructive variants.
// ---------------------------------------------------------------------------

const CmdBtn: FC<{
  label: string; enabled: boolean; busy?: boolean; destructive?: boolean;
  stepUpRequired?: boolean; stepUpActive?: boolean;
  onClick: () => void;
}> = ({ label, enabled, busy, destructive, stepUpRequired, stepUpActive, onClick }) => {
  const locked = Boolean(stepUpRequired && !stepUpActive);
  const disabled = !enabled || Boolean(busy);
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={[
        "flex items-center justify-center gap-1 rounded-sm border px-2 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors",
        destructive
          ? "border-critical/40 bg-critical/5 text-critical hover:border-critical hover:bg-critical/10"
          : "border-border bg-bg-card text-text-secondary hover:border-border-bright hover:text-text-primary",
        disabled && "opacity-40 cursor-not-allowed hover:border-border hover:text-text-secondary",
        locked && !disabled && "border-warning/30 text-warning/80",
      ].filter(Boolean).join(" ")}
      title={
        !enabled ? "Requires higher role"
        : locked  ? "Step-up auth required"
        : undefined
      }
    >
      {locked && !busy && <span aria-hidden="true">⊞</span>}
      <span>{busy ? "…" : label}</span>
    </button>
  );
};

// Re-export the constant so tests can assert which kinds require step-up.
export { STEP_UP_REQUIRED_KINDS };


const CommandRow: FC<{ cmd: BuoyCommandHistoryRow }> = ({ cmd }) => {
  const statusTone =
    cmd.status === "completed" ? "text-success" :
    cmd.status === "failed"    ? "text-critical" :
    cmd.status === "expired"   ? "text-text-dim" :
    cmd.status === "dispatched" ? "text-accent" :
    "text-warning";
  const localTime = (() => {
    try {
      return new Date(cmd.requested_at).toLocaleTimeString(undefined, { hour12: false });
    } catch {
      return "—";
    }
  })();
  return (
    <li className="flex items-baseline justify-between gap-2 rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-[10px]">
      <div className="flex items-baseline gap-2">
        <span className="text-text-secondary">{cmd.command_kind}</span>
        {Object.keys(cmd.args).length > 0 && (
          <span className="text-text-dim">
            {Object.entries(cmd.args).map(([k, v]) => `${k}=${v}`).join(" ")}
          </span>
        )}
      </div>
      <div className="flex items-baseline gap-2">
        <span className={`uppercase tracking-wider ${statusTone}`}>{cmd.status}</span>
        <span className="text-text-dim">{localTime}</span>
      </div>
    </li>
  );
};


// ---------------------------------------------------------------------------
// Notes tab — unchanged from slice 8. UI for the slice-12 notepad backend
// lands in a follow-up port pass.
// ---------------------------------------------------------------------------

const NotesTab: FC<{ buoy: BuoyFleetRow }> = () => (
  <div className="flex flex-col gap-2">
    <div className="rounded-sm border border-warning/40 bg-warning/5 px-2 py-1.5 font-mono text-[10px] text-warning">
      DEV — slice-12 backend is live (user + agent notepads). Frontend
      port lands with the rest of the fleet redesign.
    </div>
    <div className="text-text-dim italic">
      Free-form operator notes will live here — known FPs, install
      quirks, customer-specific tuning. Visibility gated by the
      existing client-DB access grant.
    </div>
  </div>
);


// ---------------------------------------------------------------------------
// Log preview tab — unchanged from slice 8 placeholder. Filter rail +
// per-tenant events search lands with the rest of the fleet redesign.
// ---------------------------------------------------------------------------

const LogTab: FC<{ buoy: BuoyFleetRow; callerRole: string | null }> = ({
  buoy: _buoy, callerRole,
}) => {
  const isSuperAdmin = callerRole === "super_admin";
  if (!isSuperAdmin) {
    return (
      <div className="rounded-sm border border-border bg-bg-card px-2 py-2 text-center text-text-dim italic">
        Log preview is restricted to super_admin operators.
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <div className="rounded-sm border border-warning/40 bg-warning/5 px-2 py-1.5 font-mono text-[10px] text-warning">
        DEV — in development. Filter rail + per-tenant events search land
        with the rest of the fleet redesign port.
      </div>
      <div className="rounded-sm border border-border bg-black px-3 py-3 font-mono text-[10px] text-text-secondary">
        <div className="text-accent">▸ buoy-heartbeat.service — live tail (placeholder)</div>
        <div className="mt-2 text-text-dim">
          $ journalctl -u buoy-heartbeat -f
        </div>
        <div className="mt-1 text-text-dim italic">
          (stream wiring queued — issue tail-log via the Management tab
          for one-shot output in the result panel)
        </div>
      </div>
    </div>
  );
};


// ---------------------------------------------------------------------------
// Reboot confirm modal — typed-slug match required (unchanged from slice 8).
// ---------------------------------------------------------------------------

const RebootConfirmModal: FC<{
  slug: string;
  typed: string;
  onType: (v: string) => void;
  onConfirm: () => void;
  onCancel: () => void;
}> = ({ slug, typed, onType, onConfirm, onCancel }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
    <div
      role="dialog" aria-modal="true" aria-label="Confirm reboot"
      className="w-full max-w-md rounded-sm border border-critical/50 bg-bg-elevated p-4 shadow-2xl"
    >
      <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-critical">
        ⚠ destructive action
      </div>
      <div className="mb-3 text-sm text-text-primary">
        Reboot buoy <code className="font-mono text-critical">{slug}</code>?
      </div>
      <div className="mb-2 text-[11px] text-text-secondary">
        The buoy will be offline for ~60s. Existing buoy-forwarder
        queue is preserved on disk. To confirm, type the buoy slug:
      </div>
      <input
        type="text"
        value={typed}
        onChange={(e) => onType(e.target.value)}
        className="mb-3 w-full rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-[11px] text-text-primary focus:border-critical focus:outline-none"
        placeholder={slug}
        autoFocus
      />
      <div className="flex justify-end gap-2">
        <button
          type="button" onClick={onCancel}
          className="rounded-sm border border-border bg-bg-card px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-secondary hover:border-border-bright"
        >cancel</button>
        <button
          type="button"
          disabled={typed !== slug}
          onClick={onConfirm}
          className="rounded-sm border border-critical bg-critical px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent disabled:opacity-40 disabled:cursor-not-allowed"
        >reboot</button>
      </div>
    </div>
  </div>
);


export default BuoyDrawer;
