/**
 * AlertDrawer — portal'd right-side drawer for opening an alert from the
 * dashboard feed (or any other AlertRow source) without navigating
 * away. Mirrors the FloatingTicketWindow + TicketDrawer pattern from
 * /tickets and the search drawer on /search.
 *
 * Visual layout matches Design's 2026-05-13 spec:
 *   - LEFT column: alert metadata (severity, tenant, source, summary,
 *     occurred-at)
 *   - RIGHT column: sidecar with actions + cross-links
 *     - "View full payload in /search →" (the only path to the gated
 *       payload — search has step-up auth; dashboard's recent-events
 *       feed is intentionally metadata-only)
 *     - "Create ticket from this alert →" (stub → bumps over to
 *       /tickets with focus stash; the from-alert create flow is
 *       wired on the search drawer side per P3.8)
 *
 * Security note: this drawer NEVER renders the raw payload. The dashboard
 * endpoint that feeds it (`/dashboard/recent-events`, analyst+) carries
 * metadata plus — for sources that present their alerts — the adapter's own
 * bounded, sanitised headline/detail (≤ 1000 chars of the vendor's alert
 * text). It is rendered as a text node. The "Open in /search" affordance hands
 * off to the step-up-gated surface for the full payload.
 *
 * Vendor links ("Open in Datto RMM") come from the server, which builds them
 * from the vendor's own ids and sends none to a Viewer; they open in a new tab
 * with rel="noopener noreferrer". The DEVICE page is different: its address
 * only exists at the vendor, so the server sends a reference and looks the
 * address up when the operator clicks (never per row). If that fails, nothing
 * opens and the server's reason is shown.
 */
import { type FC, useEffect, useRef } from "react";
import { createPortal } from "react-dom";

import { ResolvedLinkButton } from "@widgets/resolved-link-button";
import { AgentNotesPanel } from "@/components/agent-notes-panel";
import { EntityResolutionPanel } from "@/components/entity-resolution-panel";
import { type AlertRow, vendorSessionNote } from "@/contracts/alert";
import { resolveVendorDeviceLink } from "@/lib/api";

/** The alert sources entity resolution reads (NextDNS security blocks and
 *  UniFi IPS alerts; the server answers `not_applicable` for any other kind
 *  of those sources). */
const ENTITY_SOURCES: ReadonlySet<string> = new Set(["nextdns", "unifi"]);

interface Props {
  alert: AlertRow;
  onClose: () => void;
}

const SEVERITY_STYLE: Record<string, string> = {
  info: "border-text-dim/40 text-text-dim",
  low: "border-text-secondary/40 text-text-secondary",
  medium: "border-medium/60 text-medium",
  high: "border-high/60 text-high",
  critical: "border-critical/60 text-critical",
};

const STATUS_LABEL: Record<AlertRow["status"], string> = {
  open: "OPEN",
  acknowledged: "ACK",
  resolved: "RESOLVED",
  suppressed: "SUPPRESSED",
};

const AlertDrawer: FC<Props> = ({ alert, onClose }) => {
  const drawerRef = useRef<HTMLDivElement | null>(null);
  const vendorLinks = (alert.vendor_links ?? []).filter((l) =>
    l.url.startsWith("https://"),
  );
  const deviceRef = alert.vendor_device_ref ?? null;
  // "Open in Datto RMM" → the portal's name, for the sign-in note.
  const portalName = (deviceRef?.label ?? vendorLinks[0]?.label ?? "")
    .replace(/^Open (device )?in /, "") || undefined;
  const sessionNote = vendorSessionNote(portalName);

  // Escape closes — matches the /tickets + /search drawer pattern.
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const onJumpToSearch = (): void => {
    // /search reads `?focus=<slug>:<event_id>` on mount and pre-opens
    // the event payload drawer (after the operator clears step-up).
    // Matches the ticket-window deep-link pattern at
    // floating-ticket-window.tsx — single canonical mechanism rather
    // than the old localStorage stash (which /search didn't consume).
    //
    // alert.id shape from /dashboard/recent-events is already
    // "<tenant>:<event_id>" per dashboard.tsx mapping, so we can drop
    // it straight into the focus param.
    const focus = encodeURIComponent(alert.id);
    window.history.pushState({}, "", `/search/events?focus=${focus}`);
    window.dispatchEvent(new CustomEvent("athena:navigate"));
  };

  const onCreateTicket = (): void => {
    // Stash a structured prefill payload so /tickets can open the
    // NewTicketModal with the fields populated from this alert.
    // /tickets reads + clears the key on mount.
    const colonIdx = alert.id.lastIndexOf(":");
    const eventId = colonIdx > 0 ? Number(alert.id.slice(colonIdx + 1)) : null;
    const prefill = {
      tenant: alert.tenant,
      source_event_id: Number.isFinite(eventId) ? eventId : null,
      title: alert.title,
      description: `Opened from alert: ${alert.title}\n\n`
        + `Source: ${alert.source}\n`
        + (alert.device ? `Device: ${alert.device}\n` : "")
        + (alert.site ? `Site: ${alert.site}\n` : "")
        + `Occurred: ${alert.occurred_at}\n`
        + (eventId !== null ? `Source event: #${eventId} (tenant ${alert.tenant})\n` : ""),
      severity: alert.severity,
    };
    try {
      window.localStorage.setItem(
        "athena.tickets.create_from_alert",
        JSON.stringify(prefill),
      );
    } catch { /* ignore */ }
    window.history.pushState({}, "", "/tickets");
    window.dispatchEvent(new CustomEvent("athena:navigate"));
  };

  return createPortal(
    <div
      ref={drawerRef}
      role="dialog"
      aria-modal="false"
      aria-label={`Alert ${alert.title}`}
      className="fixed right-0 top-0 z-40 flex h-full w-[680px] max-w-full flex-col border-l border-border-bright bg-bg-elevated shadow-2xl"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <div className="font-mono text-[10px] uppercase tracking-widest text-accent">
            ·· alert · {alert.tenant} ··
          </div>
          <div className="mt-1 truncate text-sm font-semibold text-text-primary">
            {alert.title}
          </div>
        </div>
        <span
          className={[
            "shrink-0 rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase",
            SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE.low,
          ].join(" ")}
        >
          {alert.severity}
        </span>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close drawer"
          className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[11px] text-text-secondary hover:border-border-bright hover:text-text-primary"
        >
          ✕
        </button>
      </header>

      {/* Two-column body per Design spec: metadata left, sidecar right */}
      <div className="grid flex-1 min-h-0 grid-cols-[1fr_240px] gap-4 overflow-hidden p-4">
        {/* LEFT — metadata + summary */}
        <div className="flex flex-col gap-3 overflow-y-auto pr-2 text-[12px] font-mono">
          <div className="grid grid-cols-[auto_1fr] items-baseline gap-x-3 gap-y-1.5 text-[11px]">
            <span className="text-text-dim">tenant</span>
            <span className="text-text-secondary">{alert.tenant}</span>

            <span className="text-text-dim">source</span>
            <span className="text-text-secondary">{alert.source || "—"}</span>

            {alert.device ? (
              <>
                <span className="text-text-dim">device</span>
                <span className="break-all text-text-secondary">{alert.device}</span>
              </>
            ) : null}

            {alert.site ? (
              <>
                <span className="text-text-dim">site</span>
                <span className="text-text-secondary">{alert.site}</span>
              </>
            ) : null}

            <span className="text-text-dim">status</span>
            <span className="text-text-secondary">
              {STATUS_LABEL[alert.status]}
            </span>

            <span className="text-text-dim">occurred</span>
            <span className="text-text-secondary">{alert.occurred_at}</span>
          </div>

          <section className="rounded-sm border border-border bg-bg-surface p-3">
            <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-text-dim">
              summary
            </div>
            {/* The feed row clamps this to two lines; here it is whole.
                Vendor text: a text node, line breaks kept, never HTML. */}
            <div
              data-testid="alert-drawer-summary"
              className="whitespace-pre-wrap break-words text-[12px] text-text-primary"
            >
              {alert.summary || (
                <span className="italic text-text-dim">
                  no summary — see /search for full payload
                </span>
              )}
            </div>
          </section>

          {(() => {
            // Entity resolution: where / device / why — only for the sources
            // it reads (NextDNS blocks, UniFi IPS alerts), and only when the
            // client's switch is on (the server decides; analyst+; any other
            // alert kind answers `not_applicable`).
            if (!ENTITY_SOURCES.has(alert.source)) return null;
            const colonIdx = alert.id.lastIndexOf(":");
            const eventId = colonIdx > 0 ? Number(alert.id.slice(colonIdx + 1)) : NaN;
            return Number.isFinite(eventId) && eventId > 0 ? (
              <EntityResolutionPanel key={alert.id} slug={alert.tenant} eventId={eventId} />
            ) : null;
          })()}

          <div className="rounded-sm border border-dashed border-border/60 bg-bg-card/40 px-3 py-2 text-[10px] text-text-dim">
            Full event payload + IOCs + agent insights live behind
            step-up auth in /search. Use the sidecar to jump.
          </div>
        </div>

        {/* RIGHT — actions sidecar */}
        <aside className="flex flex-col gap-2 overflow-y-auto border-l border-border pl-3 text-[11px]">
          <div className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
            ·· actions ··
          </div>
          {/* "Open in <vendor>": built server-side from the vendor's own ids,
              absent when it cannot be built exactly (and for a Viewer). */}
          {vendorLinks.map((link) => (
            <a
              key={`${link.kind}:${link.url}`}
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              title={sessionNote}
              data-testid={`alert-drawer-vendor-link-${link.kind}`}
              className="rounded-sm border border-border-bright bg-bg-card px-2 py-1.5 text-left font-mono text-[11px] text-text-primary hover:border-accent hover:text-accent"
            >
              {link.label} ↗
            </a>
          ))}
          {deviceRef ? (
            <ResolvedLinkButton
              // A new alert in the same drawer starts from "not looked up".
              key={`${deviceRef.client_slug}:${deviceRef.event_id}`}
              label={deviceRef.label}
              resolve={() => resolveVendorDeviceLink(deviceRef)}
              title={sessionNote}
              testId="alert-drawer-vendor-device"
              className="rounded-sm border border-border-bright bg-bg-card px-2 py-1.5 text-left font-mono text-[11px] text-text-primary hover:border-accent hover:text-accent"
            />
          ) : null}
          {vendorLinks.length > 0 || deviceRef ? (
            // The one reason an exact link still lands on the vendor's home
            // page: the vendor's own sign-in. Said here, not left to be
            // reported as a broken link.
            <p data-testid="alert-drawer-vendor-session-note" className="text-[10px] leading-snug text-text-dim">
              {sessionNote}
            </p>
          ) : null}
          <button
            type="button"
            onClick={onJumpToSearch}
            className="rounded-sm border border-accent/60 bg-accent/10 px-2 py-1.5 text-left font-mono text-[11px] text-accent hover:bg-accent/20"
          >
            View payload in /search →
          </button>
          <button
            type="button"
            onClick={onCreateTicket}
            className="rounded-sm border border-border bg-bg-card px-2 py-1.5 text-left font-mono text-[11px] text-text-primary hover:border-border-bright"
          >
            Create ticket from this alert →
          </button>

          {/* Agent notes + "ask octo" enrichment. The drawer's
              metadata-only feed doesn't carry pre-existing notes
              (those live behind step-up in /search), but the operator
              can still fire a canned query — the alert summary is a
              valid heuristic_note input. New notes returned by octo
              append to the local panel state for this drawer view.
              Failure modes (octo disabled / unhealthy / unreachable)
              surface inline without breaking the drawer per §11.5. */}
          {(() => {
            const colonIdx = alert.id.lastIndexOf(":");
            const eventId = colonIdx > 0
              ? Number(alert.id.slice(colonIdx + 1)) : NaN;
            if (!Number.isFinite(eventId)) {
              return (
                <div className="mt-3 rounded-sm border border-dashed border-border/60 bg-bg-card/40 px-2 py-2 text-[10px] text-text-dim">
                  ·· agent notes ·· no event ref on this alert
                </div>
              );
            }
            return (
              <div className="mt-3">
                <AgentNotesPanel
                  notes={[]}
                  clientSlug={alert.tenant}
                  refKind="event"
                  refId={eventId}
                  // Headline + detail; the endpoint caps the note at 2048.
                  heuristicNote={
                    [alert.title, alert.summary].filter(Boolean).join("\n").slice(0, 2000)
                  }
                />
              </div>
            );
          })()}
        </aside>
      </div>
    </div>,
    document.body,
  );
};

export default AlertDrawer;
