import type { IntegrationInstance } from "@/contracts/integration";

// Status changes SERVER-side after this page has loaded (the poller reports
// every vendor round-trip), so a page that fetched once kept showing
// "connected" over an integration that had since failed — and kept showing a
// red card long after the operator fixed the vendor side.
export const STATUS_REFRESH_MS = 20_000;
// start() writes running/'started' before the first poll has run; look again
// once that poll has had time to report what it actually observed.
export const AFTER_SAVE_REFRESH_MS = 4_000;

/** Headline for a card in `error`: only what was OBSERVED. A failing poller
 *  does not stop inbound webhooks, so "no data is being collected" is kept
 *  for the case where nothing else can be delivering — which includes an
 *  instance with webhooks switched on but no usable secret: the backend only
 *  sets `receives_webhooks` when a webhook could actually be accepted. */
export function problemHeadline(instance: IntegrationInstance, vendorName: string): string {
  if (instance.contact_failure_kind) {
    return `Polling is failing — alerts are not being pulled from ${vendorName}`;
  }
  return instance.receives_webhooks
    ? "Not working"
    : "Not working — no data is being collected";
}

/**
 * The backend's tenant-lifecycle warning SENTENCES ("N tenant(s) … await
 * review", "N event(s) … held in quarantine", "Auto-create is PAUSED") say the
 * same thing as the structured counters the card now renders WITH links into
 * Settings → Tenants. When the counter is present the sentence is dropped so
 * the card does not say it twice; an older backend (no counters) keeps its
 * sentences. Fragments, not exact text: the sentence wording is the
 * backend's to change.
 */
export function withoutLifecycleSentences(
  instance: IntegrationInstance,
  warnings: readonly string[],
): string[] {
  return warnings.filter((w) => {
    if (instance.auto_created_pending && /\bawait review\b/i.test(w)) return false;
    if (instance.quarantined && /held in quarantine pending review/i.test(w)) return false;
    if (instance.autocreate_limited && /auto-create is paused/i.test(w)) return false;
    return true;
  });
}
