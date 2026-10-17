/**
 * EntityLinksPanel — one client's "Links to review" (entity resolution) and
 * its rollout switch.
 *
 *   Sites         "this NextDNS profile belongs to this site" suggestions
 *                 (L-SOLE / L-EGRESS — traffic evidence, shown as counts:
 *                 the profile's NAME, the site with its location, and how
 *                 much of the profile's traffic came from the site's own
 *                 internet address over how many days — never just a name)
 *   Name matches  the same name only — NEVER proof (two businesses can share
 *                 a name): its own tab, low priority
 *   Devices       NextDNS app device ↔ Datto device: unique name + the same
 *                 LAN address links itself (auto); a name alone waits here.
 *                 A linked PC is watched: "NextDNS stopped reporting from a
 *                 PC Datto says is online"
 *   Conflicts     a rule that ran into an operator decision, two sites
 *                 claiming one alert, a profile whose traffic comes from none
 *                 of the client's sites. "Mark resolved" sticks until the
 *                 evidence materially changes; a routing card can be
 *                 "accepted as expected" (a branch office without UniFi,
 *                 roaming laptops) — the check stops for that profile until
 *                 someone reopens it
 *
 * Confirm is one click; Reject needs a reason (it also stops the rule from
 * suggesting the pair again). Every decision is audited server-side and
 * wins over every rule. Admins switch the client off / shadow / on (with a
 * reason). Text nodes only.
 */
import { type FC, useCallback, useEffect, useState } from "react";

import type { EntityMode, EntityStatus, ReviewQueue } from "@/contracts/entity";
import {
  acceptConflict,
  confirmLink,
  getEntityStatus,
  getReviewQueue,
  rejectLink,
  reopenConflict,
  resolveConflict,
  setEntityMode,
} from "@/lib/entity";

type Tab = "sites" | "names" | "devices" | "conflicts";

/** The evidence a site-link card carries, in words (counts, never a name
 *  alone): "93% of 12,345 queries from the site's address, on 6 of 7 days". */
export function evidenceText(evidence: Record<string, unknown>): string {
  const parts: string[] = [];
  const cov = evidence["coverage"];
  if (cov && typeof cov === "object") {
    const c = cov as Record<string, unknown>;
    const share = typeof c["share"] === "number" ? Math.round((c["share"] as number) * 100) : null;
    const total = typeof c["queries"] === "number" ? (c["queries"] as number) : null;
    const days = typeof c["days_from_site"] === "number" ? (c["days_from_site"] as number) : null;
    const of = typeof c["days_with_data"] === "number" ? (c["days_with_data"] as number) : null;
    if (share !== null && total !== null) {
      parts.push(`${share}% of ${total.toLocaleString("en-US")} queries came from the site's own internet address`);
    }
    if (days !== null && of !== null) parts.push(`on ${days} of ${of} day(s) with data`);
  }
  const src = evidence["match_source"];
  if (typeof src === "string") {
    parts.push(src === "manual" ? "the profile was mapped to this client by a person"
      : `the profile's mapping is a ${src} match (not a person's)`);
  }
  if (evidence["same_name"] === true) parts.push("the same name only");
  // One combined suggestion per (site, profile): the other rules that agree.
  const rules = evidence["rules"];
  if (Array.isArray(rules) && rules.includes("N-SITE") && evidence["same_name"] !== true) {
    parts.push("the names match too (never proof on its own)");
  }
  const why = evidence["why"];
  if (typeof why === "string") parts.push(why);
  return parts.length ? parts.join("; ") : "no traffic evidence yet";
}

interface Props {
  readonly slug: string;
  readonly canAdmin: boolean;
}

const btn =
  "rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] text-text-secondary hover:border-border-bright disabled:opacity-50";

export const EntityLinksPanel: FC<Props> = ({ slug, canAdmin }) => {
  const [status, setStatus] = useState<EntityStatus | null>(null);
  const [queue, setQueue] = useState<ReviewQueue | null>(null);
  const [tab, setTab] = useState<Tab>("sites");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [rejecting, setRejecting] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [mode, setMode] = useState<EntityMode>("off");
  const [modeReason, setModeReason] = useState("");

  const load = useCallback(async () => {
    try {
      const [s, q] = await Promise.all([getEntityStatus(slug), getReviewQueue(slug)]);
      setStatus(s);
      setMode(s.mode);
      setQueue(q);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load the links");
    }
  }, [slug]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (fn: () => Promise<unknown>): Promise<void> => {
    setBusy(true);
    try {
      await fn();
      setRejecting(null);
      setReason("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "The action failed");
    } finally {
      setBusy(false);
    }
  };

  const decide = (key: string, onConfirm: (() => Promise<unknown>) | null,
                  onReject: (why: string) => Promise<unknown>, rejectLabel = "Reject…") => (
    rejecting === key ? (
      <span className="flex gap-1">
        <input
          aria-label="reason"
          className="min-w-[160px] rounded-sm border border-border bg-bg-card px-1 py-0.5 text-[11px]"
          value={reason}
          maxLength={500}
          placeholder="reason (required)"
          onChange={(e) => setReason(e.target.value)}
        />
        <button type="button" className={btn} disabled={busy || reason.trim().length < 3}
          data-testid={`links-send-${key}`} onClick={() => void act(() => onReject(reason.trim()))}>
          Send
        </button>
      </span>
    ) : (
      <span className="flex gap-1">
        {onConfirm ? (
          <button type="button" className={btn} disabled={busy} data-testid={`links-confirm-${key}`}
            onClick={() => void act(onConfirm)}>
            Confirm
          </button>
        ) : null}
        <button type="button" className={btn} disabled={busy} data-testid={`links-reject-${key}`}
          onClick={() => setRejecting(key)}>
          {rejectLabel}
        </button>
      </span>
    )
  );

  const counts = {
    sites: queue?.sites.length ?? 0,
    names: queue?.names.length ?? 0,
    devices: queue?.devices.length ?? 0,
    conflicts: queue?.conflicts.length ?? 0,
  };

  return (
    <section data-testid="entity-links-panel" className="rounded-lg border border-border bg-bg-surface p-4 text-[12px]">
      <header className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-text-primary">Entity resolution — {slug}</h2>
          {status ? (
            <p className="text-[11px] text-text-dim">
              {status.sites} site(s) · {status.open_leases} connected device(s) · {status.resolutions} resolved
              alert(s) · switch: <span data-testid="links-mode">{status.mode}</span>
            </p>
          ) : null}
        </div>
        {canAdmin ? (
          <div className="flex items-center gap-1">
            <select aria-label="entity resolution mode" value={mode}
              onChange={(e) => setMode(e.target.value as EntityMode)}
              className="rounded-sm border border-border bg-bg-card px-1 py-0.5 text-[11px]">
              <option value="off">off</option>
              <option value="shadow">shadow (compute, do not show)</option>
              <option value="on">on</option>
            </select>
            <input aria-label="mode reason" placeholder="reason" value={modeReason} maxLength={500}
              onChange={(e) => setModeReason(e.target.value)}
              className="w-40 rounded-sm border border-border bg-bg-card px-1 py-0.5 text-[11px]" />
            <button type="button" className={btn} data-testid="links-mode-save"
              disabled={busy || mode === status?.mode || modeReason.trim().length < 3}
              onClick={() => void act(() => setEntityMode(slug, mode, modeReason.trim()))}>
              Apply
            </button>
          </div>
        ) : null}
      </header>
      {error ? <p role="alert" className="mb-2 text-[11px] text-critical">{error}</p> : null}

      <div className="mb-2 flex gap-1" role="tablist" aria-label="links to review">
        {(["sites", "names", "devices", "conflicts"] as Tab[]).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t}
            data-testid={`links-tab-${t}`} onClick={() => setTab(t)}
            className={`${btn} ${tab === t ? "border-accent text-accent" : ""}`}>
            {t === "names" ? "Name matches" : t.charAt(0).toUpperCase() + t.slice(1)} ({counts[t]})
          </button>
        ))}
      </div>

      {queue && !queue.resolved ? (
        <p className="text-text-dim">Nothing yet — entity resolution has no data for this client.</p>
      ) : null}

      {tab === "sites" && queue ? (
        <ul className="space-y-1.5" data-testid="links-sites">
          {queue.sites.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 rounded-sm border border-border px-2 py-1">
              <span>
                {r.vendor}{" "}
                {r.vendor_label ? <span className="text-text-primary">{r.vendor_label} </span> : null}
                <span className="font-mono text-text-dim">({r.vendor_scope_id})</span> → {r.site_label ?? r.site_id}
                {r.site_location ? <span className="text-text-dim"> — {r.site_location}</span> : null}{" "}
                <span className="text-text-dim">({r.state}, {r.rule_id}, score {r.score})</span>
                <span className="block text-[11px] text-text-secondary" data-testid={`links-evidence-${r.id}`}>
                  {evidenceText(r.evidence)}
                </span>
              </span>
              {decide(`site-${r.id}`, r.state === "suggested" ? () => confirmLink(slug, "site", r.id) : null,
                (why) => rejectLink(slug, "site", r.id, why), r.state === "auto" ? "Revoke…" : "Reject…")}
            </li>
          ))}
          {queue.sites.length === 0 ? <li className="text-text-dim">Nothing to review.</li> : null}
        </ul>
      ) : null}

      {tab === "names" && queue ? (
        <div data-testid="links-names">
          <p className="mb-1 text-[11px] text-medium">
            The same name is not proof — different businesses can share a name. Confirm only what you know.
          </p>
          <ul className="space-y-1.5">
            {queue.names.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 rounded-sm border border-border px-2 py-1">
                <span>
                  {r.vendor}{" "}
                  {r.vendor_label ? <span className="text-text-primary">{r.vendor_label} </span> : null}
                  <span className="font-mono text-text-dim">({r.vendor_scope_id})</span> → {r.site_label ?? r.site_id}
                  {r.site_location ? <span className="text-text-dim"> — {r.site_location}</span> : null}{" "}
                  <span className="text-text-dim">(name match, score {r.score})</span>
                </span>
                {decide(`name-${r.id}`, () => confirmLink(slug, "site", r.id),
                  (why) => rejectLink(slug, "site", r.id, why))}
              </li>
            ))}
            {queue.names.length === 0 ? <li className="text-text-dim">No name matches.</li> : null}
          </ul>
        </div>
      ) : null}

      {tab === "devices" && queue ? (
        <ul className="space-y-1.5" data-testid="links-devices">
          {queue.devices.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 rounded-sm border border-border px-2 py-1">
              <span>
                NextDNS <span className="text-text-primary">{d.nextdns?.name ?? "?"}</span> ↔ Datto{" "}
                <span className="text-text-primary">{d.datto?.hostname ?? "?"}</span>{" "}
                <span className="text-text-dim">
                  ({d.state}, {d.rule}{d.evidence["same_lan_ip"] ? ", same LAN address" : ", name only"})
                  {d.watch?.state === "silent" ? " · NextDNS SILENT" : ""}
                </span>
              </span>
              {d.state === "confirmed" ? null : decide(`device-${d.id}`,
                d.state === "suggested" ? () => confirmLink(slug, "device", d.id) : null,
                (why) => rejectLink(slug, "device", d.id, why), d.state === "auto" ? "Revoke…" : "Reject…")}
            </li>
          ))}
          {queue.devices.length === 0 ? <li className="text-text-dim">No NextDNS app device matches a Datto device yet.</li> : null}
        </ul>
      ) : null}

      {tab === "conflicts" && queue ? (
        <ul className="space-y-1.5" data-testid="links-conflicts">
          {queue.conflicts.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 rounded-sm border border-critical/40 px-2 py-1">
              <span>
                {c.kind.replace(/_/g, " ")}: <span className="font-mono">{c.subject}</span>{" "}
                <span className="text-text-dim">({c.hits}×, last {c.last_seen})</span>
              </span>
              <span className="flex gap-1">
                {decide(`conflict-${c.id}`, null, (why) => resolveConflict(slug, c.id, why), "Mark resolved…")}
                {c.kind === "routing" && rejecting !== `conflict-${c.id}`
                  ? decide(`accept-${c.id}`, null, (why) => acceptConflict(slug, c.id, why), "Accept as expected…")
                  : null}
              </span>
            </li>
          ))}
          {queue.conflicts.length === 0 ? <li className="text-text-dim">No conflicts.</li> : null}
          {(queue.accepted ?? []).map((c) => (
            <li key={`accepted-${c.id}`} data-testid={`links-accepted-${c.id}`}
              className="flex flex-wrap items-center justify-between gap-2 rounded-sm border border-border px-2 py-1">
              <span>
                accepted as expected: <span className="font-mono">{c.subject}</span>{" "}
                <span className="text-text-dim">({c.resolved_by ?? "?"}, {c.resolved_at ?? "?"})</span>
              </span>
              {decide(`reopen-${c.id}`, null, (why) => reopenConflict(slug, c.id, why), "Reopen…")}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
};

export default EntityLinksPanel;
