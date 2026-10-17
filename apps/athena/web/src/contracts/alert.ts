/**
 * Row shape consumed by `default-alert-feed`. Bridge query templates that
 * feed alert-feed widgets are expected to project rows into this shape.
 *
 * Validation lives at the boundary (bridge-client deserialization, ships
 * with the bridge wiring). Components downstream trust the shape.
 */

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export type AlertStatus = "open" | "acknowledged" | "resolved" | "suppressed";

/**
 * An "Open in <vendor>" target for the ALERT. Built SERVER-side from the
 * vendor's own ids and a validated per-instance portal URL; never carries a
 * credential. The server sends none to a Viewer. Always rendered as a new-tab
 * link with rel="noopener noreferrer".
 */
export interface AlertVendorLink {
  readonly kind: "alert";
  readonly label: string;
  readonly url: string;
  readonly vendor: string;
}

/**
 * "Open device in <vendor>" — a REFERENCE, not a URL. The vendor portal
 * addresses a device by an id no alert carries, so the address is looked up
 * at the vendor when the operator clicks (POST /dashboard/vendor-device-link
 * with this reference), never per row. Null/absent when no lookup could
 * succeed, and for a Viewer.
 */
export interface VendorDeviceRef {
  readonly vendor: string;
  readonly label: string;
  readonly client_slug: string;
  readonly event_id: number;
}

/**
 * Why a correct vendor link can still "go to the home dashboard": the
 * portal needs its OWN sign-in in this browser. Without this sentence the
 * V1 complaint recurs from the vendor's side with no cue. Shown wherever a
 * vendor link is rendered; `portal` names the vendor when known.
 */
export const vendorSessionNote = (portal?: string): string =>
  `Opens in a new tab and needs an active ${portal ?? "vendor portal"} sign-in in this browser. ` +
  `If ${portal ?? "the portal"} shows its sign-in page, sign in there and open the link again.`;

export interface AlertRow {
  readonly id: string;
  readonly severity: AlertSeverity;
  readonly status: AlertStatus;
  readonly source: string;
  readonly tenant: string;
  /** The headline. For sources without one, the event type. */
  readonly title: string;
  /**
   * The longer text under the title. Untrusted vendor text, possibly
   * multi-line: the feed clamps it to two lines, the drawer shows all of it.
   * Text nodes only — never HTML.
   */
  readonly summary: string;
  readonly occurred_at: string;
  // Optional (contract 1.1): rows from sources that do not supply them render
  // exactly as before.
  readonly device?: string | null;
  readonly site?: string | null;
  readonly vendor_links?: readonly AlertVendorLink[];
  readonly vendor_device_ref?: VendorDeviceRef | null;
}

export const ALERT_SEVERITIES: readonly AlertSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;
