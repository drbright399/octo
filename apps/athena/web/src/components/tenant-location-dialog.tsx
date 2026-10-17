/**
 * TenantLocationDialog — the client's FALLBACK map location (Fleet v2), from
 * Settings → Tenants (admin+). For a client without UniFi, or sites whose
 * console reports no location. Precedence on the map: a site's own pin (set
 * in the Fleet drawer — the way to fix a console that reports the wrong
 * place, per site), else the console's location, else this, else no pin
 * (listed only). The consoles' reported locations stay visible here. No IP
 * geolocation — the operator types the coordinates (and they never leave the
 * box: the map tiles are self-hosted). Every save / clear carries a reason
 * and is audited by the server before it is written. */
import { type FC, useEffect, useState } from "react";

import type { TenantLocation } from "@/contracts/fleet";
import type { Tenant } from "@/contracts/tenant";
import { ErrorLine, ModalFrame, inputCls } from "@/components/tenant-dialogs";
import { clearTenantLocation, getTenantLocation, saveTenantLocation } from "@/lib/fleet";

const primaryBtn =
  "rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50";
const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";

export interface TenantLocationDialogProps {
  tenant: Pick<Tenant, "slug" | "display_name">;
  onClose: () => void;
  onDone: (note: string) => void;
}

/** Validates "lat" / "lng" text the way the server does (±90 / ±180, not
 *  (0, 0)). Null = valid. */
export function coordError(lat: string, lng: string): string | null {
  const la = Number(lat);
  const ln = Number(lng);
  if (lat.trim() === "" || lng.trim() === "" || !Number.isFinite(la) || !Number.isFinite(ln)) {
    return "Enter a latitude and a longitude in decimal degrees (e.g. 41.25, -100.75).";
  }
  if (Math.abs(la) > 90 || Math.abs(ln) > 180) {
    return "Latitude must be within ±90 and longitude within ±180.";
  }
  if (la === 0 && ln === 0) return "(0, 0) is not a location.";
  return null;
}

const TenantLocationDialog: FC<TenantLocationDialogProps> = ({ tenant, onClose, onDone }) => {
  const [current, setCurrent] = useState<TenantLocation | null>(null);
  const [lat, setLat] = useState("");
  const [lng, setLng] = useState("");
  const [label, setLabel] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getTenantLocation(tenant.slug).then((r) => {
      if (cancelled) return;
      setCurrent(r);
      if (r.override) {
        setLat(String(r.override.lat));
        setLng(String(r.override.lng));
        setLabel(r.override.label);
      }
    }).catch((e: unknown) => {
      if (!cancelled) setError(e instanceof Error ? e.message : "The location could not be loaded");
    });
    return () => { cancelled = true; };
  }, [tenant.slug]);

  const invalid = coordError(lat, lng);
  const canSave = !busy && !invalid && label.trim().length > 0 && reason.trim().length >= 3;

  const save = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const r = await saveTenantLocation(tenant.slug, {
        lat: Number(lat), lng: Number(lng), label: label.trim(), reason: reason.trim(),
      });
      setCurrent(r);
      setBusy(false);
      onDone(`${tenant.display_name}: map location set (${label.trim()}).`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The location could not be saved");
      setBusy(false);
    }
  };

  const clear = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const r = await clearTenantLocation(tenant.slug, reason.trim());
      setCurrent(r);
      setBusy(false);
      onDone(`${tenant.display_name}: manual map location cleared.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The location could not be cleared");
      setBusy(false);
    }
  };

  return (
    <ModalFrame label={`Map location of ${tenant.display_name}`} testId="tenant-location-dialog"
                busy={busy} onClose={onClose}>
      <h2 className="text-base font-semibold text-text-primary">
        Map location — {tenant.display_name}
      </h2>
      <p className="mt-2 text-xs leading-relaxed text-text-secondary">
        The client&apos;s fallback location: used for its sites that have no location of their
        own — a client without UniFi, or a console that reports none. A console that reports the
        WRONG place is fixed per site: open the site in Fleet and use Fix location (that pin wins
        over the console and over this). Never derived from an IP address.
      </p>
      {current && (
        <div className="mt-3 rounded border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary"
             data-testid="location-current">
          {current.unifi_sites.length > 0 && (
            <div>
              The UniFi console{current.unifi_sites.length === 1 ? " reports" : "s report"}:
              <ul className="ml-3 list-disc" data-testid="location-reported">
                {current.unifi_sites.map((u, i) => (
                  <li key={`${u.name}-${i}`}>
                    {u.name} — {u.label || "no address"} ({u.lat.toFixed(3)}, {u.lng.toFixed(3)})
                  </li>
                ))}
              </ul>
              {current.unlocated_unifi_sites > 0 && (
                <div>{current.unlocated_unifi_sites} more without a console location.</div>
              )}
            </div>
          )}
          {current.unifi_sites.length === 0 && current.unlocated_unifi_sites > 0 && (
            <div>{current.unlocated_unifi_sites} UniFi site(s) without a console location — this applies to them.</div>
          )}
          {(current.site_pins ?? 0) > 0 && (
            <div data-testid="location-site-pins">
              {current.site_pins} site{current.site_pins === 1 ? " is" : "s are"} pinned by hand in
              the Fleet drawer (those pins win).
            </div>
          )}
          {(current.multi_site_console_sites ?? 0) > 0 && (
            <div data-testid="location-multi-site">
              {current.multi_site_console_sites} site{current.multi_site_console_sites === 1 ? "" : "s"} on
              a console that carries several sites — the console reports where IT is, not each site.
            </div>
          )}
          <div>
            Now: <span className="text-text-primary">
              {current.effective === "none" ? "not on the map (listed only)"
                : current.effective === "manual" ? "this fallback location"
                  : current.effective === "mixed" ? "site locations + this fallback"
                    : "each site's own location (this fallback is not used)"}
            </span>
          </div>
        </div>
      )}
      <div className="mt-3 grid grid-cols-2 gap-2">
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim">
          latitude
          <input aria-label="latitude" className={`${inputCls} font-mono`} value={lat}
                 inputMode="decimal" placeholder="41.25" onChange={(e) => setLat(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim">
          longitude
          <input aria-label="longitude" className={`${inputCls} font-mono`} value={lng}
                 inputMode="decimal" placeholder="-100.75" onChange={(e) => setLng(e.target.value)} />
        </label>
      </div>
      {(lat || lng) && invalid && (
        <div className="mt-1 text-xs text-critical" data-testid="location-invalid">{invalid}</div>
      )}
      <label className="mt-3 flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim">
        label
        <input aria-label="label" className={inputCls} value={label} maxLength={120}
               placeholder="Main office" onChange={(e) => setLabel(e.target.value)} />
      </label>
      <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
        <span>
          Reason <span className="text-critical">*</span>{" "}
          <span className="text-text-dim">— recorded in the audit log.</span>
        </span>
        <input aria-label="reason" className={`${inputCls} font-mono`} value={reason} maxLength={500}
               placeholder="e.g. address confirmed with the client" onChange={(e) => setReason(e.target.value)} />
      </label>
      <ErrorLine message={error} />
      <div className="mt-4 flex items-center justify-between gap-2">
        <div>
          {current?.override && (
            <button type="button" className={secondaryBtn} disabled={busy || reason.trim().length < 3}
                    onClick={() => void clear()} data-testid="location-clear">
              Clear manual location
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button type="button" disabled={busy} onClick={onClose} className={secondaryBtn}>Cancel</button>
          <button type="button" disabled={!canSave} onClick={() => void save()} className={primaryBtn}
                  data-testid="location-save">
            {busy ? "Saving…" : "Save location"}
          </button>
        </div>
      </div>
    </ModalFrame>
  );
};

export default TenantLocationDialog;
