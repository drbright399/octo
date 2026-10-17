/**
 * NeedsReviewNotice — the dashboard's small "a human is needed" strip.
 *
 * Admin+ only: it polls `GET /admin/tenants/review-summary` (a few COUNTs,
 * unaudited, no per-tenant store opened) and renders nothing at all while
 * every count is zero, or for an analyst / viewer (a viewer is a client
 * user: the endpoint is 403 for them and this component never calls it).
 * Each count links into the Tenants tab view that resolves it — including
 * cloud-AI sign-offs about to lapse (a batch signed together lapses
 * together) and those already lapsed (those tenants run as local).
 */
import { type FC, useEffect, useState } from "react";
import { canManageRole, type MeResponse } from "@/contracts/operator";
import type { ReviewSummary } from "@/contracts/tenant";
import { fetchReviewSummary } from "@/lib/api";
import { navigateTo } from "@/lib/router";

export const REVIEW_POLL_MS = 60_000;

interface Props {
  readonly me: MeResponse | null;
}

const NeedsReviewNotice: FC<Props> = ({ me }) => {
  const isAdminPlus = me ? canManageRole(me.role, "admin") : false;
  const [summary, setSummary] = useState<ReviewSummary | null>(null);

  useEffect(() => {
    if (!isAdminPlus) {
      setSummary(null);
      return undefined;
    }
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const s = await fetchReviewSummary();
        if (!cancelled) setSummary(s);
      } catch {
        // Glance-level: a failed poll keeps the last value, never an error tile.
      }
    };
    void load();
    const id = window.setInterval(() => {
      if (document.visibilityState !== "hidden") void load();
    }, REVIEW_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [isAdminPlus]);

  if (!isAdminPlus || !summary) return null;
  const { pending_review, quarantined, pending_requests } = summary;
  const expiring = summary.signoffs_expiring ?? 0;
  const expired = summary.signoffs_expired ?? 0;
  if (pending_review + quarantined + pending_requests + expiring + expired === 0) return null;

  const link = "underline decoration-dotted underline-offset-2 hover:text-accent";
  return (
    <aside
      role="status"
      aria-label="needs review"
      data-testid="needs-review-notice"
      className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-high/50 bg-high/10 px-4 py-2 text-xs text-text-primary"
    >
      <span className="font-mono text-[10px] uppercase tracking-wider text-high">needs review</span>
      {pending_review > 0 ? (
        <button type="button" className={link} onClick={() => navigateTo("/settings/tenants?filter=needs-review")} data-testid="review-tenants-link">
          {pending_review} tenant{pending_review === 1 ? "" : "s"} awaiting a tag
        </button>
      ) : null}
      {quarantined > 0 ? (
        <button type="button" className={link} onClick={() => navigateTo("/settings/tenants/quarantine")} data-testid="review-quarantine-link">
          {quarantined} event{quarantined === 1 ? "" : "s"} in quarantine
        </button>
      ) : null}
      {pending_requests > 0 ? (
        <button type="button" className={link} onClick={() => navigateTo("/settings/tenants")} data-testid="review-requests-link">
          {pending_requests} change request{pending_requests === 1 ? "" : "s"} awaiting approval
        </button>
      ) : null}
      {expiring > 0 ? (
        <button type="button" className={link} onClick={() => navigateTo("/settings/tenants")} data-testid="review-signoffs-expiring-link">
          {expiring} cloud-AI sign-off{expiring === 1 ? "" : "s"} expiring within 30 days
        </button>
      ) : null}
      {expired > 0 ? (
        <button type="button" className={link} onClick={() => navigateTo("/settings/tenants")} data-testid="review-signoffs-expired-link">
          {expired} tenant{expired === 1 ? "" : "s"} running as local — cloud-AI sign-off expired
        </button>
      ) : null}
    </aside>
  );
};

export default NeedsReviewNotice;
