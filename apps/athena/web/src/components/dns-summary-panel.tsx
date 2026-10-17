/**
 * DnsSummaryPanel — the dashboard's DNS summary widget body.
 *
 * Renders GET /dashboard/dns-summary: per tenant with buoy DNS telemetry, the
 * last 24 h's lookups (counted by one sensor — Pi-hole, else Suricata's
 * query records), blocked lookups, the top domains and the domains the
 * tenant had never looked up before. Domains arrive MASKED from the server — the full values are tenant
 * data, available only through the step-up-gated DNS search API — and no device
 * is ever named here.
 *
 * Every state says what it is: loading, not-for-your-role, failed, empty
 * (with the server's reason), partial (a tenant's store couldn't be read),
 * "baseline building" while a tenant's first-seen ledger is younger than
 * a week (nearly every domain is new then), a telemetry-store fault
 * (answered lookups stored in events.db instead — moved by the nightly
 * sweep), and — neutrally, not as a fault — answered lookups from before
 * the upgrade still waiting for the one-off move.
 *
 * "Who looked this name up?" has no page yet: it is the API
 * `POST /api/v1/search/dns` (re-authentication), said so plainly.
 */
import type { FC } from "react";

import type { DnsSummaryResponse, DnsTenantSummary } from "@/contracts/dns-summary";
import { formatRelative } from "@/lib/time";

export type DnsSummaryState =
  | { readonly status: "loading" }
  | { readonly status: "forbidden" }
  | { readonly status: "error" }
  | { readonly status: "ready"; readonly data: DnsSummaryResponse };

interface Props {
  readonly state: DnsSummaryState;
  readonly now?: Date;
}

const Note: FC<{ children: string }> = ({ children }) => (
  <div className="px-2 py-4 text-center text-[11px] italic text-text-dim">{children}</div>
);

const fmt = (n: number): string => n.toLocaleString("en-US");

const SOURCE_LABEL: Record<string, string> = {
  pihole: "Pi-hole",
  suricata: "Suricata queries",
};

const TenantBlock: FC<{ t: DnsTenantSummary; now: Date }> = ({ t, now }) => {
  const newest = t.first_seen[0];
  const fallback = t.fallback_rows ?? 0;
  const awaiting = t.awaiting_move_rows ?? 0;
  const refused = t.recent_store_fallbacks ?? 0;
  const windowHours = t.store_fallback_window_hours ?? 24;
  return (
  <li className="rounded border border-border bg-bg-card px-3 py-2" data-testid={`dns-tenant-${t.tenant}`}>
    <div className="flex items-baseline justify-between gap-2 font-mono text-[11px]">
      <span className="truncate text-text-primary">{t.tenant}</span>
      <span className="shrink-0 text-[10px] text-text-dim">
        {fmt(t.lookups)} lookups
        {t.lookups_source ? ` (${SOURCE_LABEL[t.lookups_source] ?? t.lookups_source})` : ""}
        {" · "}
        {fmt(t.blocked)} blocked
      </span>
    </div>
    {t.top_domains.length > 0 && (
      <ol className="mt-1 flex flex-col gap-0.5 font-mono text-[10px]" aria-label={`Top domains in ${t.tenant}`}>
        {t.top_domains.map((d, i) => (
          <li key={`${d.masked_domain}-${i}`} className="flex justify-between gap-2">
            <span className="truncate text-text-secondary">{d.masked_domain}</span>
            <span className="shrink-0 text-text-dim">
              {fmt(d.lookups)} · {d.devices} device{d.devices === 1 ? "" : "s"}
            </span>
          </li>
        ))}
      </ol>
    )}
    <div className="mt-1 font-mono text-[10px] text-text-dim">
      <span className={t.first_seen_count > 0 && !t.baseline_building ? "text-warning" : ""}>
        {fmt(t.first_seen_count)} first-seen domain{t.first_seen_count === 1 ? "" : "s"}
      </span>
      {newest && (
        <span>
          {" · newest "}
          {newest.masked_domain} ({formatRelative(newest.first_seen, now)})
        </span>
      )}
    </div>
    {(fallback > 0 || refused > 0) && (
      <div className="mt-0.5 text-[10px] text-warning" data-testid={`dns-fallback-${t.tenant}`}>
        Telemetry store fault: {fmt(Math.max(fallback, refused))} answered lookup
        {Math.max(fallback, refused) === 1 ? "" : "s"} stored with the events instead (not
        counted above; the nightly sweep moves them)
        {refused > 0 ? ` — ${fmt(refused)} refused in the last ${windowHours} h` : ""}.
      </div>
    )}
    {awaiting > 0 && (
      <div className="mt-0.5 text-[10px] text-text-dim" data-testid={`dns-awaiting-move-${t.tenant}`}>
        {fmt(awaiting)} answered lookup{awaiting === 1 ? "" : "s"} from before the upgrade
        {" "}still in the events store (not counted above) — run the one-off
        move_telemetry_out_of_events.py.
      </div>
    )}
    {t.baseline_building && (
      <div className="mt-0.5 text-[10px] italic text-text-dim">
        Baseline still building
        {t.baseline_since ? ` (since ${t.baseline_since.slice(0, 10)})` : ""} — nearly every
        domain is new during a tenant&apos;s first week.
      </div>
    )}
  </li>
  );
};

const DnsSummaryPanel: FC<Props> = ({ state, now }) => {
  if (state.status === "loading") return <Note>Loading DNS summary…</Note>;
  if (state.status === "forbidden") {
    return <Note>The DNS summary is available to analysts and above.</Note>;
  }
  if (state.status === "error") return <Note>Couldn&apos;t load the DNS summary — retrying.</Note>;

  const { data } = state;
  const reference = now ?? new Date();
  return (
    <div className="flex h-full flex-col gap-2">
      {data.tenants.length === 0 ? (
        <Note>{data.empty_detail ?? "No DNS telemetry to show."}</Note>
      ) : (
        <>
          <div className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
            {fmt(data.totals.lookups)} lookups · {fmt(data.totals.blocked)} blocked ·{" "}
            {fmt(data.totals.first_seen)} first-seen · last {data.window_hours}h
          </div>
          <ul className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto" role="list">
            {data.tenants.map((t) => (
              <TenantBlock key={t.tenant} t={t} now={reference} />
            ))}
          </ul>
        </>
      )}
      {data.unreadable_tenants > 0 && (
        <p data-testid="dns-summary-partial" className="text-[10px] text-warning">
          {data.unreadable_tenants === 1
            ? "1 tenant's telemetry couldn't be read — retrying."
            : `${data.unreadable_tenants} tenants' telemetry couldn't be read — retrying.`}
        </p>
      )}
      <p className="mt-auto border-t border-border/40 pt-1.5 text-[10px] text-text-dim">
        Domains are masked here. Full values and &quot;who looked this up?&quot; have no page
        yet: the API POST /api/v1/search/dns (re-authentication).
      </p>
    </div>
  );
};

export default DnsSummaryPanel;
