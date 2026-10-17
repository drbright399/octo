/**
 * SiteLocationDialog — ONE site's map location (Fleet v2, the drawer's "Set
 * location" — admin+). For a console that reports the wrong place, a site
 * with none, or each site of a multi-site client on its own.
 *
 * Three ways in (LocationPicker), the saved pair is LOCKED (never looked up
 * again, never moved by a console's report):
 *   - an ADDRESS: Find asks the server, which asks the US Census geocoder
 *     with the typed address only (hidden when the server has it off);
 *   - a PASTED pair or map link ("41.25, -100.75", a Google Maps URL) —
 *     parsed in the browser, nothing leaves it;
 *   - typed latitude / longitude.
 * What the console reports and the client's fallback stay visible. Every
 * save / clear carries a reason and is audited by the server BEFORE it is
 * written. Precedence on the map: this, else the console's location, else
 * the client's fallback (Settings → Tenants), else no pin.
 *
 * A pin confirmed from an Autotask proposal says so ("from Autotask,
 * confirmed by …"); an OPEN proposal for this site shows as "Autotask
 * suggests: <address>" with Review (the proposals panel) — and one of the
 * client's that no site was picked for yet as "Autotask has an address for
 * this client not yet assigned to a site". Escape closes it.
 */
import { type FC, useEffect, useState } from "react";

import type { FleetSite, SiteLocation } from "@/contracts/fleet";
import { ErrorLine, ModalFrame, inputCls } from "@/components/tenant-dialogs";
import { coordError } from "@/components/tenant-location-dialog";
import LocationPicker, { fmtPoint as fmt, labelCls } from "@/components/location-picker";
import { ApiError } from "@/lib/api";
import { clearSiteLocation, getSiteLocation, saveSiteLocation } from "@/lib/fleet";

const primaryBtn =
  "rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50";
const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";

export interface SiteLocationDialogProps {
  site: Pick<FleetSite, "key" | "name" | "tenant_name">;
  onClose: () => void;
  /** After a save / clear: refresh the fleet. */
  onSaved: (note: string) => void;
  /** "Review" on an Autotask suggestion: open the proposals panel. */
  onReviewProposals?: (tenantSlug: string, proposalId: number) => void;
}

const EFFECTIVE: Record<SiteLocation["effective"], string> = {
  site: "pinned by hand (locked)",
  unifi: "the UniFi console's location",
  tenant: "the client's fallback location",
  none: "not on the map (listed only)",
};

const SOURCE_NAME: Record<string, string> = { autotask: "Autotask" };

const errText = (e: unknown, fallback: string): string =>
  e instanceof ApiError || e instanceof Error ? e.message : fallback;

const SiteLocationDialog: FC<SiteLocationDialogProps> = ({ site, onClose, onSaved, onReviewProposals }) => {
  const [current, setCurrent] = useState<SiteLocation | null>(null);
  const [lat, setLat] = useState("");
  const [lng, setLng] = useState("");
  const [label, setLabel] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSiteLocation(site.key).then((r) => {
      if (cancelled) return;
      setCurrent(r);
      if (r.override) {
        setLat(String(r.override.lat));
        setLng(String(r.override.lng));
        setLabel(r.override.label);
      }
    }).catch((e: unknown) => {
      if (!cancelled) setError(errText(e, "The site's location could not be loaded"));
    });
    return () => { cancelled = true; };
  }, [site.key]);

  const invalid = coordError(lat, lng);
  const canSave = !busy && !invalid && label.trim().length > 0 && reason.trim().length >= 3;

  const save = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const r = await saveSiteLocation(site.key, {
        lat: Number(lat), lng: Number(lng), label: label.trim(), reason: reason.trim(),
      });
      setCurrent(r);
      setBusy(false);
      onSaved(`${site.name}: map location set (${label.trim()}).`);
    } catch (e) {
      setError(errText(e, "The site's location could not be saved"));
      setBusy(false);
    }
  };

  const clear = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const r = await clearSiteLocation(site.key, reason.trim());
      setCurrent(r);
      setBusy(false);
      onSaved(`${site.name}: hand-set map location cleared.`);
    } catch (e) {
      setError(errText(e, "The site's location could not be cleared"));
      setBusy(false);
    }
  };

  const fromAutotask = current?.override?.origin && current.override.origin !== "manual";
  const suggestions = current?.proposals ?? [];

  return (
    <ModalFrame label={`Map location of ${site.name}`} testId="site-location-dialog"
                busy={busy} onClose={onClose} keyboard>
      <h2 className="text-base font-semibold text-text-primary">Map location — {site.name}</h2>
      <p className="mt-1 text-xs text-text-dim">{site.tenant_name}</p>
      <p className="mt-2 text-xs leading-relaxed text-text-secondary">
        Pin this site where it really is. A location set here wins over what the UniFi console
        reports and is locked: it is never looked up again or moved by the console. Never derived
        from an IP address.
      </p>

      {current && (
        <div className="mt-3 flex flex-col gap-0.5 rounded border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary"
             data-testid="site-loc-current">
          <div>
            Now: <span className="text-text-primary">{EFFECTIVE[current.effective]}</span>
            {current.current ? ` — ${fmt(current.current)}` : ""}
          </div>
          {fromAutotask && (
            <div data-testid="site-loc-provenance">
              From {SOURCE_NAME[current.override!.origin!] ?? current.override!.origin}, confirmed
              by {current.override!.set_by_name || "an operator"}.
            </div>
          )}
          {current.console ? (
            <div data-testid="site-loc-console">
              The console reports: {fmt(current.console)}
              {current.console_shared ? " — a console shared with another client: it pins nobody" : ""}
              {!current.console_shared && current.console_sites > 1
                ? ` — where the console is (it carries ${current.console_sites} sites)` : ""}
            </div>
          ) : (
            current.kind === "site" && <div>The console reports no location.</div>
          )}
          {current.tenant_fallback && (
            <div>Client fallback: {fmt(current.tenant_fallback)}</div>
          )}
        </div>
      )}

      {suggestions.map((p) => (
        <div key={p.id} data-testid={`site-loc-suggestion-${p.id}`}
             className="mt-2 flex items-center justify-between gap-2 rounded border border-accent/40 bg-accent/5 px-3 py-1.5 text-xs text-text-secondary">
          {p.unassigned ? (
            <span>
              {SOURCE_NAME[p.source] ?? p.source} has an address for this client not yet assigned to a
              site: <span className="text-text-primary">{p.label}</span>
            </span>
          ) : (
            <span>
              {SOURCE_NAME[p.source] ?? p.source} suggests: <span className="text-text-primary">{p.label}</span>
            </span>
          )}
          {onReviewProposals && current && (
            <button type="button" className={secondaryBtn} data-testid={`site-loc-review-${p.id}`}
                    onClick={() => onReviewProposals(current.tenant_slug, p.id)}>
              Review
            </button>
          )}
        </div>
      ))}

      <LocationPicker
        geocoder={current?.geocoder}
        lat={lat} lng={lng}
        onLatLng={(a, b) => { setLat(a); setLng(b); }}
        onPick={(p) => { if (p.label) setLabel(p.label.slice(0, 120)); }}
        onError={setError}
        testPrefix="site-loc"
      />
      <label className={`mt-3 ${labelCls}`}>
        label
        <input aria-label="label" className={inputCls} value={label} maxLength={120}
               placeholder="1 Main St (front office)" onChange={(e) => setLabel(e.target.value)} />
      </label>
      <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
        <span>
          Reason <span className="text-critical">*</span>{" "}
          <span className="text-text-dim">— recorded in the audit log.</span>
        </span>
        <input aria-label="reason" className={`${inputCls} font-mono`} value={reason} maxLength={500}
               placeholder="e.g. the console reports the wrong state" onChange={(e) => setReason(e.target.value)} />
      </label>
      <ErrorLine message={error} />
      <div className="mt-4 flex items-center justify-between gap-2">
        <div>
          {current?.override && (
            <button type="button" className={secondaryBtn} disabled={busy || reason.trim().length < 3}
                    onClick={() => void clear()} data-testid="site-loc-clear">
              Clear hand-set location
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button type="button" disabled={busy} onClick={onClose} className={secondaryBtn}>Cancel</button>
          <button type="button" disabled={!canSave} onClick={() => void save()} className={primaryBtn}
                  data-testid="site-loc-save">
            {busy ? "Saving…" : "Save location"}
          </button>
        </div>
      </div>
    </ModalFrame>
  );
};

export default SiteLocationDialog;
