/**
 * WebhookReachability — "has the vendor's webhook ever REACHED Athena?", on
 * an integration card. Adapter-agnostic: it renders for any instance whose
 * webhooks are switched on.
 *
 * The vendor's own test result cannot answer that question. A 403 or a block
 * page there is produced by whatever fronts the ingest hostname (CDN bot
 * protection, a WAF, an access gate) — Athena's webhook URL never answers
 * 403 — so without this line an edge problem reads as an Athena fault. Three states, and only one of them is a warning:
 *
 *   nothing has arrived   calm note + the edge checklist (not an error: the
 *                         vendor may simply not have sent anything yet)
 *   arriving, rejected    warning, with the count and the reason class
 *   accepted              quiet "Last webhook received: …"
 *
 * All sentences except the timestamp line are authored by the backend.
 */
import type { FC } from "react";
import type { WebhookReceipt } from "@/contracts/integration";
import { formatRelative } from "@/lib/time";

interface Props {
  readonly slug: string;
  readonly receipt: WebhookReceipt;
}

export const WebhookReachability: FC<Props> = ({ slug, receipt }) => {
  if (!receipt.enabled) return null;
  const rejecting = receipt.recent_rejections.length > 0;

  return (
    <div data-testid={`integration-webhook-receipt-${slug}`} className="mb-3 text-[11px] leading-relaxed">
      <p
        data-testid={`integration-webhook-last-${slug}`}
        className="font-mono text-[10px] text-text-dim"
      >
        {receipt.last_accepted_at ? (
          <>
            Last webhook received:{" "}
            <time dateTime={receipt.last_accepted_at}>
              {formatRelative(receipt.last_accepted_at)} ({receipt.last_accepted_at})
            </time>
          </>
        ) : receipt.ever_reached ? (
          "No webhook has been accepted yet — requests are reaching Athena but are being rejected."
        ) : (
          "No webhook has reached Athena yet."
        )}
      </p>

      {rejecting ? (
        <ul role="alert" data-testid={`integration-webhook-rejections-${slug}`} className="mt-1 text-warning">
          {receipt.recent_rejections.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      ) : receipt.last_rejected_at && receipt.last_reject_detail ? (
        // Nothing rejected lately (or the counters restarted with the
        // service): the persisted last rejection, as information.
        <p data-testid={`integration-webhook-last-rejected-${slug}`} className="mt-1 text-text-dim">
          Last rejected request:{" "}
          <time dateTime={receipt.last_rejected_at}>
            {formatRelative(receipt.last_rejected_at)}
          </time>{" "}
          — {receipt.last_reject_detail}.
        </p>
      ) : null}

      {receipt.guidance.length > 0 ? (
        // Guidance, not a fault: no alert role, no warning colour — and
        // folded away by default. "Nothing yet" is the normal state of a
        // quiet client for days; four bullets of edge checklist on every
        // card visit would make that card the tallest in the grid and read
        // as a problem. The operator who DOES have a vendor-side 403 opens
        // it; the setup guide carries the same text in full.
        <details
          data-testid={`integration-webhook-guidance-${slug}`}
          className="mt-1.5 rounded border border-border bg-bg-surface px-3 py-2 text-text-secondary"
        >
          <summary className="cursor-pointer text-text-primary">
            That is normal until the vendor sends one. The vendor says it sent one
            but nothing arrived?
          </summary>
          <ul className="mt-1.5 list-disc space-y-1 pl-4">
            {receipt.guidance.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
};
