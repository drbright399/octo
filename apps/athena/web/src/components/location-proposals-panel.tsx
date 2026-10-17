/**
 * LocationProposalsPanel — "Proposed locations": Autotask addresses proposed
 * as site pins, for an admin to CONFIRM or REJECT (admin+; the Fleet page
 * shows it to admins only, the server enforces it). Nothing here is on the
 * map until it is confirmed.
 *
 * Rows are grouped by client: the Autotask address (its suite kept), the
 * site it is for — or a site picker when Athena could not tell ("pick a
 * site") —, what the map shows for THAT site today, and the warnings in
 * plain words (the same address or company as another client, an incomplete
 * address, a site named for something else, far from where the console says
 * it is, a pin already set). When the operator picks or changes the site,
 * "Now" and the pin / distance warnings follow the site picked. Look up asks
 * the server's address lookup for THAT address only (hidden when it is off —
 * the panel says so); a match is picked, or coordinates / a map link pasted
 * (parsed here). Confirm and Reject both need a reason (audited by the server
 * before anything is written). A confirm carries what was reviewed (the
 * proposal as loaded, the site's pin as shown): when either changed
 * meanwhile the server refuses and the panel reloads.
 *
 * Refresh from Autotask reads the mapped, active companies now (it also runs
 * daily); Reload only re-reads the list. When Autotask does not let Athena
 * read company locations, the panel says that only the company addresses
 * were used. Escape closes it.
 */
import { type FC, useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  LocationProposal,
  ProposalCurrentPin,
  ProposalFlag,
  ProposalTarget,
  ProposalsResponse,
} from "@/contracts/proposals";
import { ErrorLine, ModalFrame, inputCls } from "@/components/tenant-dialogs";
import { ApiError } from "@/lib/api";
import { parseCoordinates } from "@/lib/fleet";
import {
  type ConfirmBody,
  confirmProposal,
  fetchProposals,
  lookupProposal,
  refreshProposals,
  rejectProposal,
} from "@/lib/proposals";

const primaryBtn =
  "rounded-sm border border-accent-cta bg-accent-cta px-2.5 py-1 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50";
const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";

const errText = (e: unknown, fallback: string): string =>
  e instanceof ApiError || e instanceof Error ? e.message : fallback;

const isConflict = (e: unknown): boolean => e instanceof ApiError && e.status === 409;

const MISSING: Record<string, string> = { zip: "ZIP", street: "street", city: "city", state: "state" };

/** The warnings recomputed for the site the operator picks (server-side
 *  they are for the proposed site only). */
const SITE_FLAGS = new Set(["current_pin_differs", "far_from_console"]);
const FAR_KM = 25;
const SAME_PIN_KM = 0.25;
const NO_TARGETS: ProposalTarget[] = [];

/** Great-circle distance in km (the server's `km`). */
export function kmBetween(a: { lat: number; lng: number }, b: { lat: number; lng: number }): number {
  const rad = (d: number): number => (d * Math.PI) / 180;
  const h = Math.sin(rad(b.lat - a.lat) / 2) ** 2
    + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(rad(b.lng - a.lng) / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(h)));
}

const names = (f: ProposalFlag): string => {
  const list = f.tenants ?? [];
  return list.length
    ? list.join(", ") + (f.others_hidden ? " and another client" : "")
    : "another client";
};

/** A warning as people read it. */
export function flagText(f: ProposalFlag): string {
  switch (f.code) {
    case "shared_address":
      return `Same address as ${names(f)} — confirm both are really here.`;
    case "shared_company":
      return `Autotask maps this company to ${names(f)} too — confirm this address is really this client's.`;
    case "incomplete": {
      const parts = (f.missing ?? []).map((m) =>
        m === "street" && f.po_box ? "only a PO box" : `no ${MISSING[m] ?? m}`);
      return `Incomplete address (${parts.join(", ")}) — the lookup may miss it; check before confirming.`;
    }
    case "several_addresses":
      return `Autotask lists ${f.count ?? "several"} addresses for this client — confirm the one where this site is.`;
    case "site_name_differs":
      return `This client's only site is "${f.site ?? "?"}" — check this address is that site's, not another building of the client.`;
    case "current_pin_differs":
      if (f.pin?.source === "manual") {
        return "This site is drawn at the client's fallback location (Settings → Tenants) now — confirming pins it here instead.";
      }
      return `This site already has a hand-set pin${f.pin?.label ? ` (${f.pin.label}${f.pin.origin === "autotask" ? ", from Autotask" : ""})` : ""} — confirming replaces it.`;
    case "far_from_console":
      return `The lookup's match is ${f.km ?? "?"} km from where the UniFi console says this site is — check before confirming.`;
    default:
      return f.code.replace(/_/g, " ");
  }
}

/** "Now: …" — what the map shows for the site today. */
export function nowText(c: ProposalCurrentPin): string {
  const how = c.source === "unifi" ? "console location"
    : c.source === "manual" ? "the client's fallback location (Settings → Tenants)"
      : c.origin === "autotask" ? `from Autotask${c.by ? `, confirmed by ${c.by}` : ""}`
        : "pinned by hand";
  return `Now: ${c.label || "—"} (${how})`;
}

const PREVIOUS: Record<string, string> = {
  confirmed: "the pin in use", rejected: "rejected earlier", proposed: "not reviewed",
  superseded: "not reviewed",
};

const LOCATIONS_NOTE: Record<string, string> = {
  refused: "Autotask does not let Athena read company locations (the API user's security level) — only the company addresses were used.",
  unavailable: "Company locations could not be read last time — only the company addresses were used.",
};

export interface LocationProposalsPanelProps {
  onClose: () => void;
  /** After a refresh or a decision: the page refreshes the fleet + badge. */
  onChanged: () => void;
  /** Open on one client (the site editor's Review). */
  tenant?: string | null;
  /** …and point at one proposal. */
  focusId?: number | null;
}

const LocationProposalsPanel: FC<LocationProposalsPanelProps> = ({
  onClose, onChanged, tenant = null, focusId = null,
}) => {
  const [resp, setResp] = useState<ProposalsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [onlyTenant, setOnlyTenant] = useState<string | null>(tenant);

  const load = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      setResp(await fetchProposals({ status: "open", tenant: onlyTenant }));
      setError(null);
    } catch (e) {
      setError(errText(e, "The proposed locations could not be loaded"));
    } finally {
      setLoading(false);
    }
  }, [onlyTenant]);
  useEffect(() => { void load(); }, [load]);

  const refresh = async (): Promise<void> => {
    setRefreshing(true);
    setError(null);
    try {
      const r = await refreshProposals();
      const created = typeof r.summary.created === "number" ? r.summary.created : null;
      setNote(`Autotask read — ${r.open} to review${created !== null ? `, ${created} new` : ""}.`);
      await load();
      onChanged();
    } catch (e) {
      setError(errText(e, "Autotask could not be read"));
    } finally {
      setRefreshing(false);
    }
  };

  const decided = (text: string): void => {
    setNote(text);
    void load();
    onChanged();
  };

  // A proposal (or its site's pin) changed since it was loaded: show it as
  // it is now — the operator reviews it again.
  const stale = (text: string): void => {
    setNote(`${text} The list was reloaded.`);
    void load();
  };

  const groups = useMemo(() => {
    const out = new Map<string, LocationProposal[]>();
    for (const p of resp?.items ?? []) {
      const list = out.get(p.tenant_slug) ?? [];
      list.push(p);
      out.set(p.tenant_slug, list);
    }
    return [...out.entries()].sort((a, b) => a[1][0]!.tenant_name.localeCompare(b[1][0]!.tenant_name));
  }, [resp]);

  const last = resp?.last_refresh ?? null;
  const locNote = last?.locations ? LOCATIONS_NOTE[last.locations] : undefined;
  const skipped = last?.skipped_non_us ?? [];

  return (
    <ModalFrame label="Proposed locations" testId="proposals-panel" busy={refreshing} onClose={onClose} wide keyboard>
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-text-primary">Proposed locations</h2>
          <p className="mt-1 text-xs leading-relaxed text-text-secondary">
            Addresses from Autotask, proposed as map pins. Nothing is placed until you confirm it;
            a rejected address is not proposed again unless it changes in Autotask.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button type="button" className={secondaryBtn} data-testid="proposals-reload"
                  disabled={loading || refreshing} onClick={() => void load()}>
            Reload
          </button>
          <button type="button" className={secondaryBtn} data-testid="proposals-refresh"
                  disabled={refreshing || (resp !== null && !resp.autotask)} onClick={() => void refresh()}
                  title={resp && !resp.autotask ? "Autotask is not connected" : undefined}>
            {refreshing ? "Reading Autotask…" : "Refresh from Autotask"}
          </button>
          <button type="button" className={secondaryBtn} onClick={onClose}>Close</button>
        </div>
      </div>

      <div className="mt-2 flex flex-col gap-1 text-[11px] text-text-dim" data-testid="proposals-status">
        {loading && <div data-testid="proposals-loading">Loading…</div>}
        {resp && !resp.autotask && <div>Autotask is not connected — connect it under Settings → Integrations.</div>}
        {resp && resp.items.length > 0 && !resp.geocoder && (
          <div data-testid="proposals-geocoder-off">
            Address lookup is off on this server — paste coordinates or a map link for each address.
          </div>
        )}
        {last?.at && (
          <div>Last read from Autotask {new Date(last.at).toLocaleString(undefined, { hour12: false })}
            {last.trigger === "daily" ? " (daily)" : ""}.</div>
        )}
        {locNote && <div className="text-medium" data-testid="proposals-locations-note">{locNote}</div>}
        {skipped.length > 0 && (
          <div data-testid="proposals-skipped">
            Skipped (outside the US — the address lookup is US-only): {skipped.join(", ")}.
          </div>
        )}
        {onlyTenant && (
          <div>
            Showing one client.{" "}
            <button type="button" className="text-accent underline" onClick={() => setOnlyTenant(null)}>
              Show all
            </button>
          </div>
        )}
      </div>
      {note && <div className="mt-2 text-xs text-success" role="status" data-testid="proposals-note">{note}</div>}
      <ErrorLine message={error} />

      {resp && resp.items.length === 0 && (
        <div className="mt-4 rounded border border-border bg-bg-card px-3 py-6 text-center text-xs text-text-dim"
             data-testid="proposals-empty">
          Nothing to review.{resp.autotask ? " Refresh from Autotask to read it now." : ""}
        </div>
      )}

      <div className="mt-3 flex flex-col gap-4">
        {groups.map(([slug, items]) => (
          <section key={slug} data-testid={`proposals-tenant-${slug}`}>
            <h3 className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-text-dim">
              {items[0]!.tenant_name} · {items.length}
            </h3>
            <div className="flex flex-col gap-2">
              {items.map((p) => (
                <ProposalRow key={p.id} proposal={p} targets={resp?.targets[slug] ?? NO_TARGETS}
                             geocoder={resp?.geocoder ?? null} focused={p.id === focusId}
                             onDecided={decided} onStale={stale} />
              ))}
            </div>
          </section>
        ))}
      </div>
    </ModalFrame>
  );
};


/** The site a row starts on: the proposed one when it is still one of the
 *  client's; else the only one — never for "pick a site" (a choice the
 *  operator makes). */
function initialTarget(p: LocationProposal, targets: ProposalTarget[]): string {
  if (targets.some((t) => t.key === p.target_key)) return p.target_key!;
  return targets.length === 1 && p.target_mode !== "pick" ? targets[0]!.key : "";
}

const ProposalRow: FC<{
  proposal: LocationProposal;
  targets: ProposalTarget[];
  geocoder: string | null;
  focused: boolean;
  onDecided: (note: string) => void;
  onStale: (note: string) => void;
}> = ({ proposal: initial, targets, geocoder, focused, onDecided, onStale }) => {
  const [p, setP] = useState(initial);
  const [target, setTarget] = useState<string>(() => initialTarget(initial, targets));
  const [picked, setPicked] = useState(false);
  useEffect(() => {
    setP(initial);
    if (!picked) setTarget(initialTarget(initial, targets));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- a reload, not a pick
  }, [initial, targets]);
  const known = targets.some((t) => t.key === initial.target_key);
  const [matchIndex, setMatchIndex] = useState<number | null>(null);
  const [paste, setPaste] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (focused) ref.current?.scrollIntoView?.({ behavior: "smooth", block: "center" });
  }, [focused]);

  const what = `${p.label} (${p.tenant_name})`;
  const chosen = targets.find((t) => t.key === target) ?? null;
  // The server's "Now", distances and pin / distance warnings are for the
  // PROPOSED site; for another site picked here they are worked out here.
  const asProposed = target !== "" && target === p.target_key;
  const pasted = paste.trim() ? parseCoordinates(paste) : null;
  const point = pasted ?? (matchIndex !== null ? p.matches[matchIndex] ?? null : null);
  const kmOf = (m: { lat: number; lng: number; km_from_console?: number }): number | undefined =>
    asProposed ? m.km_from_console
      : chosen?.console ? Math.round(kmBetween(m, chosen.console) * 10) / 10 : undefined;
  const now: ProposalCurrentPin | null = asProposed ? p.current : chosen?.current ?? null;
  const flags: ProposalFlag[] = useMemo(() => {
    if (asProposed) return p.flags;
    const out = p.flags.filter((f) => !SITE_FLAGS.has(f.code));
    if (!chosen) return out;
    const pin = chosen.current;
    const first = p.matches[0];
    if (pin && (pin.source === "site" || pin.source === "manual")
        && !(first && kmBetween(first, pin) <= SAME_PIN_KM)) {
      out.push({ code: "current_pin_differs", pin: { lat: pin.lat, lng: pin.lng, label: pin.label,
        source: pin.source, ...(pin.origin ? { origin: pin.origin } : {}) } });
    }
    const km = first && chosen.console ? kmBetween(first, chosen.console) : null;
    if (km !== null && km > FAR_KM) out.push({ code: "far_from_console", km: Math.round(km * 10) / 10 });
    return out;
  }, [asProposed, p, chosen]);

  const canConfirm = !busy && point !== null && target !== "" && reason.trim().length >= 3;
  const canReject = !busy && reason.trim().length >= 3;
  const targetName = (key: string): string => targets.find((t) => t.key === key)?.name ?? p.target_name ?? key;

  const failed = (e: unknown, fallback: string): void => {
    setError(errText(e, fallback));
    if (isConflict(e)) onStale(errText(e, fallback));
  };

  const lookup = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const r = await lookupProposal(p.id);
      setP(r.proposal);
      setMatchIndex(r.proposal.matches.length === 1 ? 0 : null);
    } catch (e) {
      failed(e, "The address could not be looked up");
    } finally {
      setBusy(false);
    }
  };

  const confirm = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    const body: ConfirmBody = {
      reason: reason.trim(), target_key: target,
      expected_updated_at: p.updated_at, expected_pin_set_at: chosen?.pin_set_at ?? null,
    };
    if (pasted) {
      body.lat = pasted.lat;
      body.lng = pasted.lng;
    } else if (matchIndex !== null) {
      body.match_index = matchIndex;
    }
    try {
      await confirmProposal(p.id, body);
      setBusy(false);
      onDecided(`${p.tenant_name}: ${targetName(target)} pinned at ${p.label}.`);
    } catch (e) {
      setBusy(false);
      failed(e, "The location could not be confirmed");
    }
  };

  const reject = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await rejectProposal(p.id, reason.trim());
      setBusy(false);
      onDecided(`${p.tenant_name}: "${p.label}" rejected.`);
    } catch (e) {
      setBusy(false);
      failed(e, "The proposal could not be rejected");
    }
  };

  return (
    <div ref={ref} data-testid={`proposal-row-${p.id}`}
         className={`rounded-sm border bg-bg-card px-3 py-2 text-xs ${focused ? "border-accent" : "border-border"}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div className="min-w-0">
          <div className="text-text-primary" data-testid={`proposal-address-${p.id}`}>{p.label}</div>
          <div className="font-mono text-[10px] text-text-dim">
            Autotask {p.origin === "location" ? `location "${p.name}"` : "company address"}
          </div>
        </div>
        <div className="shrink-0 text-right" data-testid={`proposal-target-${p.id}`}>
          {targets.length > 1 || !known || p.target_mode === "pick" ? (
            <label className="flex items-center gap-1 text-[11px] text-text-secondary">
              for
              <select aria-label={`site for ${what}`} className={`${inputCls} py-0.5 text-xs`}
                      value={target} onChange={(e) => { setTarget(e.target.value); setPicked(true); }}>
                <option value="">pick a site…</option>
                {targets.map((t) => <option key={t.key} value={t.key}>{t.name}</option>)}
              </select>
            </label>
          ) : (
            <span className="text-[11px] text-text-secondary">
              for <span className="text-text-primary">{targetName(target)}</span>
              {p.target_mode === "tenant" ? " (the client)" : ""}
            </span>
          )}
        </div>
      </div>

      <div className="mt-1 text-[11px] text-text-secondary" data-testid={`proposal-current-${p.id}`}>
        {target === "" ? "Pick the site this address is for."
          : now ? nowText(now) : "Now: not on the map"}
      </div>
      {p.previous && (
        <div className="mt-0.5 text-[11px] text-text-dim" data-testid={`proposal-previous-${p.id}`}>
          Changed in Autotask — was: {p.previous.label ?? "—"} ({PREVIOUS[p.previous.status] ?? "not reviewed"}).
        </div>
      )}
      {p.confirmed_before && (
        <div className="mt-0.5 text-[11px] text-text-dim" data-testid={`proposal-reoffered-${p.id}`}>
          Confirmed earlier for this client before it had this site — offered again for the site.
        </div>
      )}

      {flags.length > 0 && (
        <ul className="mt-1.5 flex flex-col gap-0.5">
          {flags.map((f) => (
            <li key={f.code} data-testid={`proposal-flag-${p.id}-${f.code}`}
                className={`flex gap-1.5 ${f.code === "incomplete" ? "text-text-secondary" : "text-medium"}`}>
              <span aria-hidden="true">⚠</span>{flagText(f)}
            </li>
          ))}
        </ul>
      )}

      <div className="mt-2 flex flex-wrap items-center gap-2">
        {geocoder && (
          <button type="button" className={secondaryBtn} disabled={busy} onClick={() => void lookup()}
                  aria-label={`Look up ${what}`} data-testid={`proposal-lookup-${p.id}`}>
            {p.looked_up_at ? "Look up again" : "Look up"}
          </button>
        )}
        <input aria-label={`paste coordinates for ${what}`} className={`${inputCls} flex-1 font-mono text-xs`}
               value={paste} placeholder={geocoder ? "or paste coordinates / a map link" : "paste coordinates / a map link"}
               onChange={(e) => setPaste(e.target.value)} />
      </div>
      {paste.trim() && (
        <div className={`mt-1 text-[10px] ${pasted ? "text-text-dim" : "text-medium"}`}>
          {pasted ? `found ${pasted.lat}, ${pasted.lng}` : "no coordinates found in that"}
        </div>
      )}
      {p.looked_up_at && p.matches.length === 0 && (
        <div className="mt-1 text-[11px] text-medium" data-testid={`proposal-no-match-${p.id}`}>
          No match — paste the coordinates or a map link instead.
        </div>
      )}
      {p.matches.length > 0 && !pasted && (
        <ul className="mt-1 flex flex-col gap-1" data-testid={`proposal-matches-${p.id}`}>
          {p.matches.map((m, i) => {
            const km = kmOf(m);
            return (
              <li key={`${m.lat},${m.lng},${i}`}>
                <button type="button" data-testid={`proposal-match-${p.id}-${i}`} onClick={() => setMatchIndex(i)}
                        aria-pressed={matchIndex === i}
                        className={`w-full rounded-sm border px-2 py-1 text-left text-[11px] ${
                          matchIndex === i ? "border-accent text-text-primary" : "border-border text-text-secondary hover:text-text-primary"}`}>
                  {m.label} ({m.lat.toFixed(4)}, {m.lng.toFixed(4)})
                  {km !== undefined ? ` · ${km} km from the console` : ""}
                </button>
              </li>
            );
          })}
        </ul>
      )}

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input aria-label={`reason for ${what}`} className={`${inputCls} flex-1 font-mono text-xs`}
               value={reason} maxLength={500} placeholder="reason (required — recorded in the audit log)"
               onChange={(e) => setReason(e.target.value)} />
        <button type="button" className={secondaryBtn} disabled={!canReject} onClick={() => void reject()}
                aria-label={`Reject ${what}`} data-testid={`proposal-reject-${p.id}`}>
          Reject
        </button>
        <button type="button" className={primaryBtn} disabled={!canConfirm} onClick={() => void confirm()}
                aria-label={`Confirm ${what}`} data-testid={`proposal-confirm-${p.id}`}>
          Confirm
        </button>
      </div>
      <ErrorLine message={error} />
    </div>
  );
};

export default LocationProposalsPanel;
