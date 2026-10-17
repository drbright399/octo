/**
 * AdminNotices — "a super admin changed a tenant ALONE" (v0.10).
 *
 * When one super admin merges or offboards a tenant on their own typed
 * attestation (the exception to two-person approval), every OTHER admin+
 * gets a notice. This strip shows the signed-in admin their open notices on
 * every page, on every load, until they acknowledge each one (audited
 * server-side). Admin+ only: for an analyst or viewer it fetches nothing and
 * renders nothing (the endpoint is 403 for them anyway).
 *
 * The text is the server's; the attestation itself is on the change record
 * — "Review it" leads to Settings → Tenants, where the change is listed
 * under "Single-person changes" with its post-review action. A platform
 * `mapping_review` notice (name-matched tenant mappings to re-review, the
 * same-name fix) leads to Settings → Integrations instead; an
 * `entity_review` notice (entity links to review for one client) to Settings
 * → Tenants → Links to review with that client selected. Neither is a
 * single-person change and neither is counted as one. Bodies keep their
 * line breaks (text nodes, never HTML).
 *
 * Tier Black (slice 1): the in-app step of the threat paging ladder is a
 * notice too (`threat_black`, `threat_red`, `threat_escalation`,
 * `threat_client`, `threat_coverage`), and analysts are paged — so the strip
 * is ANALYST+ now (the endpoint serves an analyst their own inbox; they are
 * never a recipient of a tenant-change notice). A threat notice's "Review
 * it" leads to the fleet map (the incident is there); a `threat_registry`
 * notice (a life-safety tag, exception, brake or Yellow setting changed) to
 * Settings → Threats. A viewer (client user) still fetches nothing.
 */
import { type FC, useCallback, useEffect, useState } from "react";
import { canManageRole, type MeResponse } from "@/contracts/operator";
import type { OperatorNotice } from "@/contracts/notice";
import { acknowledgeNotice, listNotices } from "@/lib/api";
import { formatRelative } from "@/lib/time";

export const NOTICE_POLL_MS = 60_000;

/** Tier Black notice kinds (migration 044): the paging ladder's in-app step,
 *  client decisions, detection-coverage outages and registry changes. */
export function isThreatNotice(kind: string): boolean {
  return kind.startsWith("threat_");
}

interface Props {
  readonly me: MeResponse | null;
  readonly onNavigate: (path: string) => void;
}

const AdminNotices: FC<Props> = ({ me, onNavigate }) => {
  // Analyst+ (Tier Black: analysts are paged); a viewer fetches nothing.
  const isAdminPlus = me ? canManageRole(me.role, "analyst") : false;
  const [notices, setNotices] = useState<readonly OperatorNotice[]>([]);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    try {
      setNotices((await listNotices()).notices);
    } catch {
      // Glance-level: a failed poll keeps what is shown.
    }
  }, []);

  useEffect(() => {
    if (!isAdminPlus) {
      setNotices([]);
      return undefined;
    }
    void load();
    const id = window.setInterval(() => {
      if (document.visibilityState !== "hidden") void load();
    }, NOTICE_POLL_MS);
    return () => window.clearInterval(id);
  }, [isAdminPlus, load]);

  const acknowledge = async (n: OperatorNotice): Promise<void> => {
    setBusy(n.id);
    setError(null);
    try {
      await acknowledgeNotice(n.id);
      setNotices((all) => all.filter((x) => x.id !== n.id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not acknowledge the notice");
    } finally {
      setBusy(null);
    }
  };

  if (!isAdminPlus || notices.length === 0) return null;
  const threats = notices.filter((n) => isThreatNotice(n.kind)).length;
  const reviews = notices.filter((n) => n.kind === "mapping_review").length;
  const entity = notices.filter((n) => n.kind === "entity_review").length;
  const changes = notices.length - reviews - entity - threats;
  const plural = (n: number): string => `${n} notice${n === 1 ? "" : "s"}`;
  const heading = [
    threats ? `security incidents — ${plural(threats)}` : "",
    changes ? `applied without a second approver — ${plural(changes)}` : "",
    reviews ? `tenant mappings to re-review — ${plural(reviews)}` : "",
    entity ? `entity links to review — ${plural(entity)}` : "",
  ].filter(Boolean).join(" · ");
  const label = threats ? "security incidents"
    : changes ? "single-person tenant changes"
      : reviews ? "tenant mappings to re-review" : "entity links to review";
  const target = (n: OperatorNotice): string =>
    n.kind === "threat_registry" ? "/settings/threats"
      : isThreatNotice(n.kind) ? "/fleet"
        : n.kind === "mapping_review" ? "/settings/integrations"
          : n.kind === "entity_review"
            ? `/settings/tenants/links?client=${encodeURIComponent(n.subject_slug)}`
            : "/settings/tenants";
  return (
    <aside
      role="alert"
      aria-label={label}
      data-testid="admin-notices"
      className="mb-4 flex flex-col gap-2 rounded-lg border border-critical/60 bg-critical/10 px-4 py-3 text-xs text-text-primary"
    >
      <span className="font-mono text-[10px] uppercase tracking-wider text-critical">{heading}</span>
      {notices.map((n) => (
        <div key={n.id} className="flex flex-wrap items-start gap-2" data-testid={`admin-notice-${n.id}`}>
          <div className="min-w-[260px] flex-1">
            <div className="font-semibold">{n.title}</div>
            <div className="whitespace-pre-line text-text-secondary">{n.body}</div>
            <div className="text-[10px] text-text-dim">{formatRelative(n.created_at)}</div>
          </div>
          <button
            type="button"
            className="rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary hover:text-text-primary"
            onClick={() => onNavigate(target(n))}
            data-testid={`admin-notice-review-${n.id}`}
          >
            Review it
          </button>
          <button
            type="button"
            className="rounded-sm border border-critical bg-critical px-2 py-1 text-[11px] font-semibold text-white disabled:opacity-50"
            disabled={busy === n.id}
            onClick={() => void acknowledge(n)}
            data-testid={`admin-notice-ack-${n.id}`}
          >
            Acknowledge
          </button>
        </div>
      ))}
      {error ? <span className="text-critical">{error}</span> : null}
    </aside>
  );
};

export default AdminNotices;
