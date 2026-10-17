/**
 * SourceHealthPanel — the dashboard's "Source health" widget body.
 *
 * One view of every ingest source (integration instances, ingest tokens such
 * as the Wazuh shim, buoys), each with its status and last-event age on the
 * server's receive clock, stale ones floated to the top by the rotator.
 * Owns its own polling, so it repaints whenever its data changes regardless
 * of the dashboard's widget memo.
 *
 * What it shows follows the server's `view`:
 *   full    (analyst+) tier counts + the per-source rotator, and the tenants
 *           a failing source delivers into;
 *   tenant  (viewer — a client user) their own tenants' "alerts last
 *           received …" lines only, as information — never a warning. The
 *           server sends no vendor or instance name, threshold or health
 *           verdict in this view and this component has none to show.
 */
import { type FC, useEffect, useMemo, useState } from "react";
import {
  DefaultAttentionRotator,
  type RotatableSource,
  type ServiceState,
} from "@widgets/default-attention-rotator";
import {
  fetchSourceHealth,
  formatAge,
  formatSpan,
  type SourceHealthResponse,
  type SourceHealthRow,
  type TenantFreshnessRow,
} from "@/lib/source-health";
import { navigateTo } from "@/lib/router";

export const SOURCE_HEALTH_POLL_MS = 30_000;

const KIND_TAG: Record<SourceHealthRow["kind"], string> = {
  adapter: "INTEGRATION",
  ingest_token: "INGEST",
  buoy: "BUOY",
};

const BASIS_LABEL: Record<SourceHealthRow["freshness_basis"], string> = {
  contact: "last poll",
  event: "last event",
  heartbeat: "last heartbeat",
};

function basisAge(s: SourceHealthRow): number | null {
  return s.freshness_basis === "event" ? s.last_event_age_sec : s.last_contact_age_sec;
}

/** One rotator card per source. Every row carries the source's own status,
 *  so the card's rollup is exactly what the server decided. */
export function toRotatable(s: SourceHealthRow): RotatableSource {
  const age = basisAge(s);
  const rows: ServiceState[] = [{
    id: "freshness",
    name: BASIS_LABEL[s.freshness_basis],
    status: s.status,
    detail: age === null
      ? "none yet"
      : `${formatAge(age)}${s.stale ? ` · expected within ${formatSpan(s.stale_after_sec)}` : ""}`,
  }];
  if (s.freshness_basis !== "event") {
    rows.push({
      id: "last-event",
      name: "last event",
      status: s.status,
      detail: s.last_event_age_sec === null ? "none yet" : formatAge(s.last_event_age_sec),
    });
  } else if (s.kind === "ingest_token" && s.last_contact_age_sec !== null) {
    // Accepted or not: next to "last event" (its last ACCEPTED post) this
    // shows a sender that keeps posting and keeps being refused.
    rows.push({
      id: "last-request",
      name: "last request",
      status: s.status,
      detail: formatAge(s.last_contact_age_sec),
    });
  }
  if (s.detail) {
    rows.push({ id: "note", name: s.detail, status: s.status });
  }
  const p = s.protection;
  if (p && p.profiles.length) {
    // One line for the fleet of sites, one per site whose DNS filtering
    // stopped reporting (those float the card up).
    const missing = p.missing ?? p.profiles.filter((x) => x.missing).length;
    const troubled = p.profiles.filter((x) => x.problem && !x.missing);
    rows.push({
      id: "protection",
      name: "protection",
      status: p.lapsed || missing || troubled.length ? "degraded" : "ok",
      detail:
        `${p.active} active · ${p.pending} pending rollout` +
        (p.lapsed ? ` · ${p.lapsed} stopped reporting` : "") +
        (missing ? ` · ${missing} not visible to the key` : "") +
        (troubled.length ? ` · ${troubled.length} need a look` : ""),
    });
    for (const prof of p.profiles.filter((x) => x.state === "lapsed" || x.missing || x.problem)) {
      const why = prof.missing
        ? "not visible to the API key any more"
        : prof.state === "lapsed"
          ? "stopped reporting"
          : (prof.problem ?? "needs a look");
      rows.push({
        id: `${prof.missing ? "missing" : prof.state === "lapsed" ? "lapsed" : "problem"}-${prof.profile_id}`,
        name: prof.name || prof.profile_id,
        status: "degraded",
        detail: `${why}${prof.tenant_slug ? ` · ${prof.tenant_slug}` : ""}`,
      });
    }
  }
  return {
    id: s.id,
    name: s.name,
    ...(s.tenant_slug ? { tenant: s.tenant_slug } : {}),
    tags: s.throttled ? [KIND_TAG[s.kind], "THROTTLED"] : [KIND_TAG[s.kind]],
    services: rows,
  };
}

const COUNT_TONE = {
  down: { tone: "border-critical/40 bg-critical/5 text-critical", dot: "bg-critical" },
  degraded: { tone: "border-warning/40 bg-warning/5 text-warning", dot: "bg-warning" },
  pending: { tone: "border-warning/40 bg-warning/5 text-warning", dot: "bg-warning" },
  ok: { tone: "border-success/40 bg-success/5 text-success", dot: "bg-success" },
  unknown: { tone: "border-border bg-bg-card text-text-dim", dot: "bg-text-dim" },
} as const;

const FullView: FC<{ data: SourceHealthResponse }> = ({ data }) => {
  const sources = useMemo(() => data.sources.map(toRotatable), [data.sources]);
  const counts = useMemo(() => {
    const c = { down: 0, degraded: 0, pending: 0, ok: 0, unknown: 0 };
    for (const s of data.sources) c[s.status] += 1;
    return c;
  }, [data.sources]);
  // Rate limited by a vendor right now: said as its own count — a throttle
  // is not a failure.
  const throttled = data.sources.filter((s) => s.throttled).length;
  const affected = data.tenants.filter((t) => t.state === "degraded");

  return (
    <div className="flex flex-col gap-3" data-testid="source-health-full">
      {data.sources.length > 0 ? (
        <div
          role="list"
          aria-label="source health counts"
          className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]"
        >
          {(["down", "degraded", "pending", "ok", "unknown"] as const)
            .filter((k) => counts[k] > 0)
            .map((k) => (
              <span
                key={k}
                role="listitem"
                data-testid={`source-count-${k}`}
                className={`inline-flex items-center gap-1.5 rounded-sm border ${COUNT_TONE[k].tone} px-1.5 py-0.5`}
              >
                <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${COUNT_TONE[k].dot}`} />
                <span className="font-semibold">{counts[k]}</span>
                <span className="text-[9px] uppercase tracking-wider text-text-dim">{k}</span>
              </span>
            ))}
          {throttled > 0 ? (
            <span
              role="listitem"
              data-testid="source-count-throttled"
              className="inline-flex items-center gap-1.5 rounded-sm border border-warning/40 bg-bg-card px-1.5 py-0.5 text-warning"
              title="A vendor is rate limiting Athena: calls wait and back off on their own. Not a failure."
            >
              <span className="font-semibold">{throttled}</span>
              <span className="text-[9px] uppercase tracking-wider text-text-dim">throttled</span>
            </span>
          ) : null}
        </div>
      ) : null}
      <DefaultAttentionRotator
        sources={sources}
        intervalMs={4000}
        emptyLabel="No sources connected yet. Add an integration in Settings."
        canSelect={(src) => src.id.startsWith("buoy:")}
        onSelect={(src) => {
          // The Fleet page opens the drawer for `focus` (search, step-up,
          // remote terminal).
          const slug = src.id.slice("buoy:".length);
          navigateTo(`/fleet?focus=${encodeURIComponent(slug)}`);
        }}
      />
      {affected.length > 0 ? (
        <p data-testid="affected-tenants" className="font-mono text-[11px] text-warning">
          {affected.length} tenant{affected.length === 1 ? "" : "s"} fed by a failing source:{" "}
          {affected.slice(0, 5).map((t) => (
            `${t.display_name} (${t.last_event_age_sec === null ? "no alerts yet" : `last alert ${formatAge(t.last_event_age_sec)}`})`
          )).join(", ")}
          {affected.length > 5 ? ", …" : ""}
        </p>
      ) : null}
    </div>
  );
};

/** Information only: a quiet feed is usually good news, and a client user
 *  is never shown a warning about the MSP's sources. */
function tenantLine(t: TenantFreshnessRow): string {
  if (t.last_event_age_sec === null) return "no alerts received yet";
  return `alerts last received ${formatAge(t.last_event_age_sec)}`;
}

const TENANT_DOT: Record<TenantFreshnessRow["state"], string> = {
  ok: "bg-success",
  // Never sent in this view; neutral if it were — no warning dot here.
  degraded: "bg-text-dim",
  none: "bg-text-dim",
};

const TenantView: FC<{ tenants: readonly TenantFreshnessRow[] }> = ({ tenants }) => {
  if (tenants.length === 0) {
    return (
      <div className="px-4 py-6 text-center text-sm italic text-text-dim">
        No feeds to show.
      </div>
    );
  }
  return (
    <ul className="flex flex-col gap-1.5" aria-label="feed freshness" data-testid="source-health-tenant">
      {tenants.map((t) => (
        <li
          key={t.slug}
          data-testid={`tenant-freshness-${t.slug}`}
          className="flex items-center gap-2 rounded-sm bg-bg-input px-2 py-1.5 text-xs"
        >
          <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${TENANT_DOT[t.state]}`} />
          <span className="font-semibold text-text-primary">{t.display_name}</span>
          <span className="text-text-secondary">{tenantLine(t)}</span>
        </li>
      ))}
    </ul>
  );
};

const SourceHealthPanel: FC = () => {
  const [data, setData] = useState<SourceHealthResponse | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const body = await fetchSourceHealth();
        if (!cancelled) {
          setData(body);
          setFailed(false);
        }
      } catch {
        // Keep the last good snapshot; say so only when there is none.
        if (!cancelled) setFailed(true);
      }
    };
    void load();
    const id = window.setInterval(() => {
      if (document.visibilityState !== "hidden") void load();
    }, SOURCE_HEALTH_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  if (!data) {
    return (
      <div className="px-4 py-6 text-center text-sm italic text-text-dim">
        {failed ? "Source health is unavailable right now." : "Loading…"}
      </div>
    );
  }
  return data.view === "full" ? <FullView data={data} /> : <TenantView tenants={data.tenants} />;
};

export default SourceHealthPanel;
