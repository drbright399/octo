/**
 * VendorLink — "open in vendor UI" affordance for events.
 *
 * Ported from Design's kit (2026-05-13). Two sizes:
 *   - sm (default): tiny ↗ icon, used inline in event rows
 *   - lg: full chip(s) with vendor name, used in the payload drawer
 *
 * Wiring to the adapter layer (Task #103) is pending — the backend
 * will return `vendor_deep_links: VendorDeepLink[]` per event once the
 * adapter contract is extended. Until then this renders nothing when
 * `vendors` is empty.
 *
 * Click never bubbles — these are external nav, the parent row should
 * keep its own click handler (e.g., open drawer).
 */
import type { FC, MouseEvent } from "react";

export interface VendorDeepLink {
  readonly vendor: string;       // slug — e.g. "datto-rmm", "wazuh"
  readonly url: string;          // composed by the adapter, never has tokens
  readonly label?: string;       // human label — falls back to vendor slug
  readonly target_kind?: "device" | "alert" | "host" | "tenant";
}

const VENDOR_LABELS: Record<string, string> = {
  "datto-rmm": "Datto RMM",
  "datto-edr": "Datto EDR",
  "wazuh": "Wazuh",
  "rocketcyber": "RocketCyber",
  "nextdns": "NextDNS",
  "unifi": "UniFi",
  "autotask": "Autotask",
  "itglue": "IT Glue",
};

interface VendorLinkProps {
  readonly vendors: VendorDeepLink | readonly VendorDeepLink[] | null | undefined;
  readonly size?: "sm" | "lg";
}

const VendorLink: FC<VendorLinkProps> = ({ vendors, size = "sm" }) => {
  const list = Array.isArray(vendors) ? vendors : vendors ? [vendors] : [];
  if (list.length === 0) return null;

  const named = list.map((v) => ({
    ...v,
    label: v.label ?? VENDOR_LABELS[v.vendor] ?? v.vendor,
  }));

  const stop = (e: MouseEvent): void => e.stopPropagation();

  if (size === "sm") {
    const title = named.length === 1
      ? `Open in ${named[0]!.label}`
      : `Open · ${named.map((v) => v.label).join(" · ")}`;
    return (
      <a
        href={named[0]!.url}
        target="_blank"
        rel="noopener noreferrer"
        title={title}
        aria-label={title}
        onClick={stop}
        className="vendor-link vendor-link--sm"
      >
        <span aria-hidden="true">↗</span>
        {named.length > 1 && (
          <span className="vendor-link__count" aria-hidden="true">{named.length}</span>
        )}
      </a>
    );
  }

  return (
    <span className="vendor-link-row">
      {named.map((v) => (
        <a
          key={v.vendor}
          href={v.url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={stop}
          className="vendor-link vendor-link--lg"
        >
          <span aria-hidden="true">↗</span>
          <span>{v.label}</span>
        </a>
      ))}
    </span>
  );
};

export default VendorLink;
