/**
 * FleetSiteDrawer — one site: its worst state and why, the four layers
 * (network, security, endpoints, buoy) with their numbers, deep links
 * (UniFi, NextDNS, Datto — operators only) and the site's recent alerts
 * (analyst+, fetched when the drawer opens).
 *
 * A client user (`view: "client"`) gets the layers with neutral names and
 * counts only: no vendor name, no link, no alerts list, no location.
 *
 * Admin+ (`canEditLocation`) get "Set location" / "Fix location": this
 * site's own locked map pin (SiteLocationDialog). A pin confirmed from an
 * Autotask proposal says so to operators ("from Autotask, confirmed by …").
 *
 * Tier Black: a site with an open Red / Black opens on its INCIDENT PANEL
 * (operators: evidence, why, what we ruled out, the actions; a client user:
 * the neutral line and their two actions) — above the layers. Operators
 * (analyst+) can also DECLARE BLACK on the site or one of its devices (B6 —
 * "the client calls: someone is controlling my screen") and CONFIRM AS
 * THREAT any recent alert (R8: Red, a reason of at least 20 characters):
 * the console's only ways to open a Red or a Black in slice 1.
 *
 * v0.17.2: the alerts list is "needs attention" — an analyst may ACKNOWLEDGE
 * an alert (it leaves the list and the site's Yellow until a new
 * occurrence) or mark it EXPECTED (a known condition, until its review
 * date); each row carries the operator enrichment (`site-alert-row`). The
 * health layers say how many hits a human took out of their counts. Red /
 * Black never change for either.
 */
import { type FC, useEffect, useState } from "react";
import { createPortal } from "react-dom";

import {
  LAYER_NAMES,
  type ClientSiteIncident,
  type FleetLayer,
  type FleetSite,
  type LayerName,
  type SiteAlert,
  type SiteIncident,
} from "@/contracts/fleet";
import { ClientIncidentPanel, OperatorIncidentPanel } from "@/components/incident-panel";
import SiteAlertRow from "@/components/site-alert-row";
import SiteLocationDialog from "@/components/site-location-dialog";
import { ApiError } from "@/lib/api";
import { LAYER_LABEL, STATE_LABEL, STATE_TONE, fetchSiteAlerts } from "@/lib/fleet";
import { CONFIRM_REASON_MIN, confirmSignal, declareBlack } from "@/lib/incidents";

export interface FleetSiteDrawerProps {
  site: FleetSite;
  view: "operator" | "client";
  onClose: () => void;
  /** Admin+: may set this site's own map location. */
  canEditLocation?: boolean;
  /** After a location save / clear (the page refreshes the fleet). */
  onLocationSaved?: () => void;
  /** The location editor's "Review" on an Autotask suggestion. */
  onReviewProposals?: (tenantSlug: string, proposalId: number) => void;
  /** A dialog of the page is open over the drawer (the proposals panel, the
   *  host pin): Escape is that dialog's, never the drawer's. */
  suspendEscape?: boolean;
  /** The caller's highest role — admin / super_admin may close a Black. */
  callerRole?: string | null;
  /** The caller's operator id ("assign to me"). */
  callerId?: number | null;
  /** An incident action changed something (the page refreshes the fleet). */
  onIncidentChanged?: () => void;
  /** A Black close needs a fresh sign-in check (the page's step-up modal). */
  onStepUpRequired?: () => void;
}

const ORIGIN_NAME: Record<string, string> = { autotask: "Autotask" };

const SOURCE_LABEL: Record<string, string> = {
  site: "pinned by hand", manual: "client fallback location", unifi: "console location",
};

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

function when(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { hour12: false });
}

const Row: FC<{ label: string; value: React.ReactNode; testid?: string }> = ({ label, value, testid }) => (
  <div className="flex items-baseline justify-between gap-3" data-testid={testid}>
    <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">{label}</span>
    <span className="text-right text-text-primary">{value}</span>
  </div>
);

function layerRows(layer: FleetLayer, view: "operator" | "client"): React.ReactNode[] {
  const d = layer.data;
  const rows: React.ReactNode[] = [];
  if (layer.name === "network") {
    const total = num(d.devices_total);
    const online = num(d.devices_online);
    if (total !== null) {
      rows.push(<Row key="dev" label="devices online" testid="net-devices"
                     value={`${online ?? "?"} / ${total}`} />);
    }
    if (d.gateway_online !== undefined && d.gateway_online !== null) {
      rows.push(<Row key="gw" label="gateway" value={d.gateway_online ? "online" : "OFFLINE"} />);
    }
    if (view === "operator") {
      const up = (d.wan_up as string[] | undefined) ?? [];
      const down = (d.wan_down as string[] | undefined) ?? [];
      const unused = (d.wan_unconfigured as string[] | undefined) ?? [];
      const backup = new Set((d.backup_down as string[] | undefined) ?? []);
      if (up.length || down.length || unused.length) {
        rows.push(<Row key="wan" label="WAN" testid="net-wan"
                       value={[...up.map((w) => `${w} up`),
                               ...down.map((w) => (backup.has(w) ? `${w} down (backup line)` : `${w} DOWN`)),
                               ...unused.map((w) => `${w} not configured`)].join(" · ")} />);
      }
      if (d.isp) {
        rows.push(<Row key="isp" label="ISP" testid="net-isp"
                       value={`${String(d.isp)}${d.asn ? ` (AS${String(d.asn)})` : ""}`} />);
      }
    } else {
      const up = num(d.connections_up) ?? 0;
      const down = num(d.connections_down) ?? 0;
      if (up || down) {
        rows.push(<Row key="wan" label="internet" value={down ? `${down} connection(s) down` : "up"} />);
      }
    }
    const issues = num(d.internet_issues);
    // The issue list may be a history: its count is shown as data; only an
    // entry new in the last hour counts (one = a notice, recurring = warn,
    // several nearby sites at once = likely regional, a notice).
    if (issues) {
      const recent = num(d.internet_issues_recent_count);
      const fresh = d.internet_issues_recent === true
        ? ` · ${recent ? `${recent} ` : ""}new in the last hour${d.internet_issues_regional === true ? " · likely regional" : ""}`
        : " · none new";
      rows.push(<Row key="iss" label="internet issues listed" testid="net-issues"
                     value={`${issues}${fresh}`} />);
    }
    const pending = num(d.pending_updates);
    if (pending) rows.push(<Row key="upd" label="pending updates" value={pending} />);
  } else if (layer.name === "security") {
    const det = num(d.ips_detected_24h);
    const blk = num(d.ips_blocked_24h);
    if (det !== null || blk !== null) {
      const gone = view === "operator" ? num(d.ips_hidden_24h) : null;
      rows.push(<Row key="ips" label={view === "operator" ? "IPS 24 h" : "intrusions 24 h"}
                     testid="sec-ips"
                     value={`${blk ?? 0} blocked · ${det ?? 0} NOT blocked${gone ? ` (${gone} of them acknowledged / expected)` : ""}`} />);
    }
    if (view === "operator" && Array.isArray(d.dns_profiles)) {
      for (const p of d.dns_profiles as { profile_id: string; name: string; state: string; threats_24h: number }[]) {
        rows.push(<Row key={`dns-${p.profile_id}`} label="NextDNS"
                       testid={`sec-dns-${p.profile_id}`}
                       value={`${p.name} · ${p.state}${p.threats_24h ? ` · ${p.threats_24h} threats 24 h` : ""}`} />);
      }
    } else if (d.dns_protection) {
      const counts = d.dns_protection as Record<string, number>;
      rows.push(<Row key="dns" label="DNS protection"
                     value={Object.entries(counts).map(([s, n]) => `${n} ${s}`).join(" · ")} />);
    }
    const threats = num(d.dns_threats_24h);
    if (threats) rows.push(<Row key="thr" label="DNS threats 24 h" value={threats} />);
    if (view === "operator") {
      const dnsGone = num(d.dns_hidden_24h);
      const rcGone = num(d.rc_hidden);
      if (dnsGone || rcGone) {
        rows.push(<Row key="gone" label="acknowledged / expected" testid="sec-hidden"
                       value={[dnsGone ? `${dnsGone} DNS blocks` : "", rcGone ? `${rcGone} RocketCyber` : ""]
                         .filter(Boolean).join(" · ")} />);
      }
    }
    const open = num(d.open_incidents);
    if (open !== null) {
      rows.push(<Row key="rc" label={view === "operator" ? "RocketCyber open" : "open incidents"}
                     testid="sec-incidents" value={open} />);
    }
  } else if (layer.name === "endpoints") {
    const total = num(d.agents_total);
    if (total !== null) {
      rows.push(<Row key="ag" label="agents online" testid="end-agents"
                     value={`${num(d.agents_online) ?? 0} / ${total}`} />);
      rows.push(<Row key="off" label="offline" value={num(d.agents_offline) ?? 0} />);
      const srv = num(d.servers_offline);
      if (srv) rows.push(<Row key="srv" label="servers offline" value={srv} />);
    }
  } else if (layer.name === "buoy") {
    if (d.health) rows.push(<Row key="h" label="heartbeat" value={String(d.health)} />);
    const touches = num(d.canary_touches_24h);
    if (touches) rows.push(<Row key="canary" label={view === "operator" ? "decoy touches 24 h" : "decoy touches"} value={touches} />);
    const touchGone = view === "operator" ? num(d.canary_hidden_24h) : null;
    if (touchGone) rows.push(<Row key="canary-gone" label="decoy touches acknowledged" value={touchGone} />);
  } else if (layer.name === "threat") {
    if (view === "operator") {
      const black = num(d.open_black) ?? 0;
      const red = num(d.open_red) ?? 0;
      if (black || red) {
        rows.push(<Row key="open" label="open incidents" testid="threat-open"
                       value={`${black} black · ${red} red`} />);
      }
      if (d.stale_since) {
        rows.push(<Row key="stale" label="records read" value={`stale since ${when(String(d.stale_since))}`} />);
      }
    } else if (d.status_neutral) {
      rows.push(<Row key="neutral" label="status" value={String(d.status_neutral)} />);
    }
  }
  return rows;
}

const LayerCard: FC<{ layer: FleetLayer; view: "operator" | "client"; tenantSites: number }> = ({
  layer, view, tenantSites,
}) => {
  const present = layer.present && layer.state !== "absent";
  const st = present ? layer.state as Exclude<FleetLayer["state"], "absent"> : null;
  const tone = st ? STATE_TONE[st] : null;
  const rows = present ? layerRows(layer, view) : [];
  return (
    <section
      className="rounded-sm border border-border bg-bg-card px-3 py-2"
      data-testid={`layer-${layer.name}`}
      data-state={st ?? "absent"}
    >
      <header className="mb-1.5 flex items-center justify-between gap-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-text-secondary">
          {LAYER_LABEL[view][layer.name as LayerName]}
        </span>
        <span className="flex items-center gap-1.5">
          {present && layer.scope === "tenant" && tenantSites > 1 && (
            <span className="rounded-sm border border-border px-1 font-mono text-[9px] uppercase tracking-wider text-text-dim"
                  title="The client's, shown on each of its sites">client-wide</span>
          )}
          <span className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${tone ? tone.chip : "border-border text-text-dim"}`}>
            {st ? STATE_LABEL[st] : "not monitored"}
          </span>
        </span>
      </header>
      {present ? (
        <div className="flex flex-col gap-1 text-[11px]">
          {rows}
          {layer.reasons.length > 0 && (
            <ul className="mt-1 flex flex-col gap-0.5" data-testid={`reasons-${layer.name}`}>
              {layer.reasons.map((r, i) => (
                <li key={i} className={`flex items-center gap-1.5 ${STATE_TONE[r.state]?.text ?? ""}`}>
                  <span aria-hidden="true">▸</span>{r.text}
                </li>
              ))}
            </ul>
          )}
          {layer.as_of && (
            <div className="font-mono text-[9px] text-text-dim">as of {when(layer.as_of)}</div>
          )}
        </div>
      ) : (
        <div className="text-[11px] text-text-dim">
          {layer.note ?? "Not monitored for this site."}
        </div>
      )}
    </section>
  );
};

const confirmBtn = "rounded-sm border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest transition-colors disabled:opacity-50";

/** R8 — "Confirm as threat" on one recent alert: RED, with a reason of at
 *  least 20 characters (the server checks it again). */
const ConfirmThreat: FC<{ tenantSlug: string; eventId: number; onDone: () => void }> = ({
  tenantSlug, eventId, onDone,
}) => {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = reason.trim().replace(/\s+/g, " ").length >= CONFIRM_REASON_MIN;
  if (!open) {
    return (
      <button type="button" data-testid={`confirm-threat-${eventId}`} onClick={() => setOpen(true)}
              className={`${confirmBtn} border-critical/60 text-critical hover:bg-critical/10`}>
        confirm as threat
      </button>
    );
  }
  return (
    <form className="mt-1 flex flex-col gap-1" data-testid={`confirm-threat-form-${eventId}`}
          onSubmit={(e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            confirmSignal(tenantSlug, eventId, reason.trim())
              .then(() => { setOpen(false); setReason(""); onDone(); })
              .catch((err: unknown) => setError(err instanceof ApiError ? err.message
                : "The signal could not be confirmed as a threat"))
              .finally(() => setBusy(false));
          }}>
      <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2}
                data-testid={`confirm-threat-reason-${eventId}`}
                placeholder={`why this is a real threat (at least ${CONFIRM_REASON_MIN} characters) — it opens a RED incident`}
                className="rounded-sm border border-border bg-bg-input px-1 py-0.5 text-[11px]" />
      <div className="flex gap-1.5">
        <button type="submit" disabled={busy || !ready} data-testid={`confirm-threat-submit-${eventId}`}
                className={`${confirmBtn} border-critical text-critical`}>confirm (red)</button>
        <button type="button" onClick={() => { setOpen(false); setReason(""); }}
                className={`${confirmBtn} border-border text-text-dim`}>cancel</button>
      </div>
      {error && <div className="text-[11px] text-critical">{error}</div>}
    </form>
  );
};

/** B6 — an analyst+ declares the site, or one of its devices, BLACK: "the
 *  client calls: someone is controlling my screen". A reason is required. */
const DeclareBlack: FC<{ site: FleetSite; onDone: () => void }> = ({ site, onDone }) => {
  const [open, setOpen] = useState(false);
  const [summary, setSummary] = useState("");
  const [device, setDevice] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!site.tenant_slug) return null;
  const tenant = site.tenant_slug;
  if (!open) {
    return (
      <button type="button" data-testid="declare-black" onClick={() => setOpen(true)}
              className="rounded-sm border border-[var(--fleet-threat-ring)] bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-text-primary transition-colors hover:bg-[var(--fleet-threat)] hover:text-[var(--fleet-threat-text)]">
        ⯃! declare black
      </button>
    );
  }
  const ready = summary.trim().length >= 3 && reason.trim().length >= 3;
  return (
    <form data-testid="declare-black-form"
          className="flex flex-col gap-1.5 rounded-sm border border-[var(--fleet-threat-ring)] bg-bg-card p-2 text-[11px]"
          onSubmit={(e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            const dev = device.trim();
            declareBlack({ tenant, site_key: site.key, summary: summary.trim(), reason: reason.trim(),
                           ...(dev ? { device_ref: dev } : {}) })
              .then(() => { setOpen(false); onDone(); })
              .catch((err: unknown) => setError(err instanceof ApiError ? err.message
                : "The incident could not be declared"))
              .finally(() => setBusy(false));
          }}>
      <div className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
        declare black — pulses, pages everyone in scope and is audited at once
      </div>
      <input value={summary} onChange={(e) => setSummary(e.target.value)}
             data-testid="declare-black-summary" placeholder="what is happening (required)"
             className="rounded-sm border border-border bg-bg-input px-1 py-0.5" />
      <input value={device} onChange={(e) => setDevice(e.target.value)}
             data-testid="declare-black-device" placeholder="device (optional — empty: the whole site)"
             className="rounded-sm border border-border bg-bg-input px-1 py-0.5" />
      <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2}
                data-testid="declare-black-reason" placeholder="why this is Black (required)"
                className="rounded-sm border border-border bg-bg-input px-1 py-0.5" />
      <div className="flex gap-1.5">
        <button type="submit" disabled={busy || !ready} data-testid="declare-black-submit"
                className="rounded-sm border border-[var(--fleet-threat-ring)] px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest">
          declare black
        </button>
        <button type="button" onClick={() => setOpen(false)}
                className="rounded-sm border border-border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-text-dim">
          cancel
        </button>
      </div>
      {error && <div className="text-critical" data-testid="declare-black-error">{error}</div>}
    </form>
  );
};

/** How long after a list with a pending remote lookup it is read again
 *  (once): the background worker has usually answered by then. */
const ENRICH_RETRY_MS = 6_000;

/** The drawer's recent alerts — "needs attention" by default (v0.17.2): an
 *  acknowledged or expected alert is left out ("N acknowledged / expected
 *  not shown"), "show acknowledged" lists them too, greyed. Operators only. */
const AlertsSection: FC<{ site: FleetSite; onConfirmed?: () => void }> = ({
  site, onConfirmed,
}) => {
  const [items, setItems] = useState<SiteAlert[] | null>(null);
  const [hidden, setHidden] = useState(0);
  const [showHandled, setShowHandled] = useState(false);
  const [reload, setReload] = useState(0);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    let retry: ReturnType<typeof setTimeout> | null = null;
    setError(null);
    const load = (again: boolean): void => {
      fetchSiteAlerts(site.key, showHandled ? { acknowledged: true } : {})
        .then((r) => {
          if (cancelled) return;
          setItems(r.items);
          setHidden(r.hidden ?? 0);
          const pending = r.items.some((a) => a.enrichment?.kind === "unifi_ips"
            && a.enrichment.remote?.pending === true);
          if (pending && again) retry = setTimeout(() => load(false), ENRICH_RETRY_MS);
        })
        .catch((e: unknown) => {
          if (!cancelled) setError(e instanceof ApiError ? e.message : "Recent alerts could not be loaded");
        });
    };
    load(true);
    return () => { cancelled = true; if (retry) clearTimeout(retry); };
  }, [site.key, showHandled, reload]);
  const changed = (): void => { setReload((n) => n + 1); onConfirmed?.(); };
  return (
    <section data-testid="site-alerts" className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
          {showHandled ? "recent alerts · 24 h" : "needs attention · 24 h"}
        </h3>
        <label className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-widest text-text-dim">
          <input type="checkbox" checked={showHandled} data-testid="alerts-show-acknowledged"
                 onChange={(e) => setShowHandled(e.target.checked)} />
          show acknowledged{!showHandled && hidden > 0 ? ` (${hidden})` : ""}
        </label>
      </div>
      {error && <div className="text-[11px] text-critical">{error}</div>}
      {!error && items === null && <div className="text-[11px] text-text-dim">loading…</div>}
      {items !== null && items.length === 0 && (
        <div className="text-[11px] text-text-dim">
          {hidden > 0 && !showHandled
            ? "Nothing needs attention — every recent alert is acknowledged or expected."
            : "No medium-or-higher alerts in the last 24 hours."}
        </div>
      )}
      {!showHandled && hidden > 0 && items !== null && items.length > 0 && (
        <div className="text-[10px] text-text-dim" data-testid="alerts-hidden-count">
          {hidden} acknowledged / expected not shown
        </div>
      )}
      {items !== null && items.length > 0 && (
        <ul className="flex flex-col gap-1">
          {items.map((a) => (
            <SiteAlertRow key={a.event_id} alert={a} tenantSlug={site.tenant_slug}
                          tenantWideNote={a.tenant_wide} onChanged={changed}
                          confirm={site.tenant_slug ? (
                            <ConfirmThreat tenantSlug={site.tenant_slug} eventId={a.event_id}
                                           onDone={changed} />
                          ) : null} />
          ))}
        </ul>
      )}
    </section>
  );
};

const FleetSiteDrawer: FC<FleetSiteDrawerProps> = ({
  site, view, onClose, canEditLocation = false, onLocationSaved, onReviewProposals,
  suspendEscape = false, callerRole = null, callerId = null, onIncidentChanged, onStepUpRequired,
}) => {
  const [editing, setEditing] = useState(false);
  useEffect(() => {
    // Escape closes the location dialog first (its own handler), then the
    // drawer — never the drawer under a dialog.
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape" && !editing && !suspendEscape) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, editing, suspendEscape]);
  const canEdit = view === "operator" && canEditLocation;
  const tone = STATE_TONE[site.state];
  return createPortal(
    <div
      role="dialog" aria-modal="false" aria-label={`site ${site.name}`}
      data-testid="fleet-site-drawer"
      className="fixed right-0 top-0 z-40 flex h-full w-[560px] max-w-full flex-col border-l border-border-bright bg-bg-elevated shadow-2xl"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <div className="font-mono text-[10px] uppercase tracking-widest text-accent">
            [ {site.kind === "tenant" ? "client" : "site"} ]
          </div>
          <div className="truncate text-sm font-semibold text-text-primary">{site.name}</div>
          <div className="truncate font-mono text-[10px] text-text-dim">
            {view === "operator" && site.tenant_name}
            {view === "operator" && site.console_name ? ` · ${site.console_name}` : ""}
            {view === "operator" && site.location
              ? ` · ${site.location.label || "located"} (${SOURCE_LABEL[site.location.source] ?? "located"})`
              : ""}
            {view === "operator" && !site.location ? " · no location" : ""}
          </div>
          {view === "operator" && site.location && site.provenance && (
            <div className="truncate font-mono text-[10px] text-text-dim" data-testid="site-provenance">
              from {ORIGIN_NAME[site.provenance.origin] ?? site.provenance.origin}
              {site.provenance.by ? `, confirmed by ${site.provenance.by}` : ", confirmed"}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          {canEdit && (
            <button type="button" onClick={() => setEditing(true)} data-testid="site-set-location"
                    className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[11px] text-accent transition-colors hover:border-accent">
              {site.location ? "Fix location" : "Set location"}
            </button>
          )}
          <button type="button" onClick={onClose}
                  className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary">
            ✕ close
          </button>
        </div>
      </header>

      <div className="flex-1 overflow-auto p-4 text-[11px]">
        <div className={`mb-3 flex items-center gap-2 rounded-sm border px-3 py-2 ${tone.chip}`}
             data-testid="site-verdict" data-state={site.state}>
          <span className="font-mono text-[10px] uppercase tracking-widest">
            {site.state === "black" && <span aria-hidden="true">⯃! </span>}{STATE_LABEL[site.state]}
          </span>
          <span className="text-text-primary">{site.reason}</span>
        </div>
        {site.partial && (
          <div className="mb-3 rounded-sm border border-border px-3 py-1.5 text-[11px] text-text-dim">
            Part of this site&apos;s data was not read within the page&apos;s time budget — shown as unknown.
          </div>
        )}
        {view === "operator" && site.vendor_ref?.problem && (
          <div className="mb-3 rounded-sm border border-medium/50 px-3 py-1.5 text-[11px] text-medium">
            {site.vendor_ref.problem}
          </div>
        )}

        {view === "operator" && site.incident && site.tenant_slug && "id" in site.incident && (
          <OperatorIncidentPanel
            incident={site.incident as SiteIncident}
            tenantSlug={(site.incident as SiteIncident).tenant_slug ?? site.tenant_slug}
            canCloseBlack={callerRole === "admin" || callerRole === "super_admin"}
            callerId={callerId}
            onChanged={() => onIncidentChanged?.()}
            {...(onStepUpRequired ? { onStepUpRequired } : {})}
          />
        )}
        {view === "operator" && site.tenant_slug && (
          <div className="mb-3">
            <DeclareBlack site={site} onDone={() => onIncidentChanged?.()} />
          </div>
        )}
        {view === "client" && site.incident && "ref" in site.incident && (
          <ClientIncidentPanel incident={site.incident as ClientSiteIncident} />
        )}

        <div className="flex flex-col gap-2">
          {LAYER_NAMES.map((name) => {
            const layer = site.layers[name];
            return layer
              ? <LayerCard key={name} layer={layer} view={view} tenantSites={site.tenant_sites} />
              : null;
          })}
        </div>

        {view === "operator" && site.links.length > 0 && (
          <section className="mt-4 flex flex-col gap-1" data-testid="site-links">
            <h3 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">open in</h3>
            <div className="flex flex-wrap gap-1.5">
              {site.links.map((l) => (
                <a key={l.url} href={l.url} target="_blank" rel="noopener noreferrer"
                   className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] text-accent transition-colors hover:border-accent"
                   title={l.verified ? l.url : `${l.url} — path not verified against the live portal`}>
                  {l.label}{l.verified ? "" : " ·?"}
                </a>
              ))}
            </div>
          </section>
        )}

        {view === "operator" && (
          <div className="mt-4">
            <AlertsSection site={site} onConfirmed={() => onIncidentChanged?.()} />
          </div>
        )}
      </div>
      {editing && canEdit && (
        <SiteLocationDialog
          site={site}
          onClose={() => setEditing(false)}
          onSaved={() => { setEditing(false); onLocationSaved?.(); }}
          {...(onReviewProposals ? {
            onReviewProposals: (slug: string, id: number) => { setEditing(false); onReviewProposals(slug, id); },
          } : {})}
        />
      )}
    </div>,
    document.body,
  );
};

export default FleetSiteDrawer;
