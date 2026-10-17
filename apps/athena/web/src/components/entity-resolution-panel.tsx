/**
 * EntityResolutionPanel — "Where / Device / Why?" on an alert (entity
 * resolution, slice 1).
 *
 *   Where   the client's site the alert happened at, with its tier
 *           (STRONG 99 …) and basis ("located + policy").
 *   Device  the device when one is named (PROBABLE at most in slice 1 — a
 *           fakeable key never reaches EXACT), else the ranked candidate list
 *           ("9 devices were connected at that moment"), never a pick.
 *   Why?    the chain in plain sentences — deterministic server text, never
 *           the LLM. Flags (provisional, data gap, later hits …) underneath.
 *   Review  a link the answer used that only a human can settle (a suggested
 *           "this NextDNS profile belongs to this site") — Confirm / Reject
 *           (a reason is required), audited server-side; the operator's
 *           decision always wins over the rules.
 *
 * Shadow mode: the server says `visible: false` and nothing is shown; an
 * alert of a kind entity resolution never reads (`reason: not_applicable`)
 * shows nothing either — never "resolved within a minute". Device
 * names are shown unmasked (owner decision 2026-10-01). Everything is a text
 * node — server and vendor text never becomes HTML.
 */
import { type FC, useCallback, useEffect, useState } from "react";

import { BASIS_LABEL, TIER_LABEL, type Resolution, type Tier } from "@/contracts/entity";
import { ApiError } from "@/lib/api";
import { confirmLink, getResolution, rejectLink, resolveNow } from "@/lib/entity";

interface Props {
  readonly slug: string;
  readonly eventId: number;
}

const TIER_STYLE: Record<Tier, string> = {
  exact: "border-accent text-accent",
  strong: "border-accent/70 text-accent",
  medium: "border-medium/60 text-medium",
  weak: "border-text-secondary/40 text-text-secondary",
  candidate: "border-border-bright text-text-secondary",
  suggest: "border-border text-text-dim",
  conflict: "border-critical/60 text-critical",
  none: "border-border text-text-dim",
};

const Badge: FC<{ tier: Tier | null | undefined; score?: number | null | undefined; testId: string }> = ({
  tier,
  score,
  testId,
}) => {
  const t: Tier = tier ?? "none";
  return (
    <span
      data-testid={testId}
      className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase ${TIER_STYLE[t]}`}
    >
      {TIER_LABEL[t]}
      {typeof score === "number" && t !== "none" && t !== "candidate" ? ` ${score}` : ""}
    </span>
  );
};

export const EntityResolutionPanel: FC<Props> = ({ slug, eventId }) => {
  const [data, setData] = useState<Resolution | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showWhy, setShowWhy] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [rejecting, setRejecting] = useState<number | null>(null);
  const [reason, setReason] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await getResolution(slug, eventId));
      setError(null);
    } catch (e) {
      // Not this caller's (403 / 404): show nothing rather than a sentence.
      if (e instanceof ApiError && (e.status === 403 || e.status === 404)) {
        setData(null);
        setError(null);
        return;
      }
      setError(e instanceof Error ? e.message : "The resolution could not be loaded");
    }
  }, [slug, eventId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return (
      <section data-testid="entity-panel-error" className="rounded-sm border border-border bg-bg-surface p-3 text-[11px] text-text-dim">
        Where / device: {error}
      </section>
    );
  }
  if (data === null || data.mode === "off" || data.reason === "not_applicable" ||
      (!data.visible && data.mode !== "on")) {
    // off; shadow (computed but not shown); or an alert of a kind entity
    // resolution never reads (Datto, RocketCyber, a lapse …): nothing to say.
    return null;
  }

  const act = async (fn: () => Promise<unknown>): Promise<void> => {
    setBusy(true);
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "The action failed");
    } finally {
      setBusy(false);
    }
  };

  if (!data.resolved) {
    return (
      <section data-testid="entity-panel" className="rounded-sm border border-border bg-bg-surface p-3 text-[11px]">
        <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-text-dim">where / device</div>
        <p className="text-text-secondary">Not resolved yet — Athena works it out within a minute.</p>
        <button
          type="button"
          disabled={busy}
          onClick={() => void act(() => resolveNow(slug, eventId))}
          data-testid="entity-resolve-now"
          className="mt-2 rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-[11px] text-text-primary hover:border-border-bright disabled:opacity-50"
        >
          Resolve now
        </button>
      </section>
    );
  }

  const where = data.where;
  const device = data.device;
  const cands = showAll ? data.candidates : data.candidates.slice(0, 5);
  const isSet = device?.tier === "candidate";

  return (
    <section data-testid="entity-panel" className="rounded-sm border border-border bg-bg-surface p-3 text-[11px]">
      <div className="mb-2 flex items-center justify-between font-mono text-[10px] uppercase tracking-widest text-text-dim">
        <span>where / device</span>
        {data.status === "provisional" ? (
          <span data-testid="entity-provisional" className="rounded-sm border border-medium/60 px-1 text-medium">
            provisional — waiting for UniFi
          </span>
        ) : null}
      </div>

      <div className="grid grid-cols-[auto_1fr] items-baseline gap-x-3 gap-y-1.5">
        <span className="text-text-dim">where</span>
        <span className="flex flex-wrap items-center gap-2 text-text-primary">
          <span data-testid="entity-where">{where?.label ?? "Not located"}</span>
          <Badge tier={where?.tier} score={where?.score} testId="entity-where-tier" />
          {where?.basis ? <span className="text-text-dim">{BASIS_LABEL[where.basis] ?? where.basis}</span> : null}
        </span>

        <span className="text-text-dim">device</span>
        <span className="flex flex-wrap items-center gap-2 text-text-primary">
          <Badge tier={device?.tier} score={device?.score} testId="entity-device-tier" />
          {isSet ? (
            <span data-testid="entity-candidate-count">
              {device?.n_candidates ?? 0} device(s) were connected at that moment — not identified
            </span>
          ) : device?.tier === "none" ? (
            <span className="text-text-dim">Not identified.</span>
          ) : (
            <span data-testid="entity-device">{data.candidates[0]?.label ?? device?.ref}</span>
          )}
        </span>
      </div>

      {isSet && cands.length > 0 ? (
        <ol data-testid="entity-candidates" className="mt-2 list-decimal space-y-0.5 pl-5 text-text-secondary">
          {cands.map((c, i) => (
            <li key={`${c.lease_id ?? "x"}-${i}`}>
              <span className="text-text-primary">{c.label}</span>
              {c.features.length > 0 ? <span className="text-text-dim"> · {c.features.join(" ")}</span> : null}
            </li>
          ))}
        </ol>
      ) : null}
      {isSet && data.candidates.length > 5 ? (
        <button type="button" className="mt-1 text-[10px] text-accent" onClick={() => setShowAll(!showAll)}>
          {showAll ? "Show fewer" : `Show all ${data.candidates.length}`}
        </button>
      ) : null}
      {data.candidates_aged_out ? (
        <p className="mt-1 text-[10px] text-text-dim">The device details have aged out (retention); the count stays.</p>
      ) : null}

      <button
        type="button"
        onClick={() => setShowWhy(!showWhy)}
        data-testid="entity-why-toggle"
        className="mt-2 rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] text-text-secondary hover:border-border-bright"
      >
        {showWhy ? "Hide why" : "Why?"}
      </button>
      {showWhy ? (
        <div data-testid="entity-why" className="mt-2 space-y-1 text-text-secondary">
          <ol className="list-decimal space-y-0.5 pl-5">
            {data.why.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ol>
          {data.flags.length > 0 ? (
            <ul className="list-disc space-y-0.5 pl-5 text-text-dim">
              {data.flags.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {data.review.filter((r) => r.state === "suggested").map((r) => (
        <div key={r.id} data-testid={`entity-review-${r.id}`} className="mt-2 rounded-sm border border-dashed border-border px-2 py-1.5 text-text-secondary">
          <div>
            Does {r.vendor} {r.vendor === "nextdns" ? "profile" : "scope"} <span className="font-mono">{r.scope}</span> belong
            to this site? <span className="text-text-dim">({r.rule}, score {r.score})</span>
          </div>
          {rejecting === r.id ? (
            <div className="mt-1 flex gap-1">
              <input
                aria-label="reason"
                className="min-w-0 flex-1 rounded-sm border border-border bg-bg-card px-1 py-0.5 text-[11px]"
                value={reason}
                maxLength={500}
                placeholder="why not (required)"
                onChange={(e) => setReason(e.target.value)}
              />
              <button
                type="button"
                disabled={busy || reason.trim().length < 3}
                onClick={() => void act(async () => {
                  await rejectLink(slug, "site", r.id, reason.trim());
                  setRejecting(null);
                  setReason("");
                })}
                data-testid={`entity-reject-send-${r.id}`}
                className="rounded-sm border border-critical/60 px-1.5 text-[10px] text-critical disabled:opacity-50"
              >
                Reject
              </button>
            </div>
          ) : (
            <div className="mt-1 flex gap-1">
              <button
                type="button"
                disabled={busy}
                onClick={() => void act(() => confirmLink(slug, "site", r.id))}
                data-testid={`entity-confirm-${r.id}`}
                className="rounded-sm border border-accent/60 px-1.5 text-[10px] text-accent disabled:opacity-50"
              >
                Confirm
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setRejecting(r.id)}
                data-testid={`entity-reject-${r.id}`}
                className="rounded-sm border border-border px-1.5 text-[10px] text-text-secondary"
              >
                Reject…
              </button>
            </div>
          )}
        </div>
      ))}
    </section>
  );
};

export default EntityResolutionPanel;
