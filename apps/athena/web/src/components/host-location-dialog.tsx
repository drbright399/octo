/**
 * HostLocationDialog — where the map draws THIS bundle's OCTO hub (the host
 * pin: the MSP's office). A bundle-level setting: super_admin only (the page
 * shows the control to super_admin only; the server enforces it).
 *
 * The same ways in as a site's pin (LocationPicker): an address (Find — the
 * US Census geocoder, the typed address only; hidden when the server has it
 * off), a pasted pair or map link (parsed here), typed latitude / longitude.
 * Plus the hub's display name and the city line under it. Every save carries
 * a reason and is audited by the server BEFORE it is written.
 *
 * Only what the operator changed is sent: the hub's city line (and name)
 * are kept unless edited — also when the dialog opens before the page has
 * read the hub (it reads it itself, and fills what was not typed yet).
 * Escape closes it.
 */
import { type FC, useEffect, useState } from "react";

import type { FleetPoint } from "@/contracts/fleet";
import LocationPicker, { labelCls } from "@/components/location-picker";
import { ErrorLine, ModalFrame, inputCls } from "@/components/tenant-dialogs";
import { coordError } from "@/components/tenant-location-dialog";
import { ApiError } from "@/lib/api";
import { fetchOctoLocation, type OctoLocationResponse } from "@/lib/buoy";
import { fetchGeocoder, saveHostLocation } from "@/lib/fleet";

const primaryBtn =
  "rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50";
const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";

export interface HostLocationDialogProps {
  /** Where the hub is drawn now (null: not read yet — the dialog reads it). */
  current: OctoLocationResponse | null;
  onClose: () => void;
  onSaved: (saved: OctoLocationResponse) => void;
}

/** "1 EXAMPLE RD, EXAMPLETON, IL, 00001" → "Exampleton, IL" (a Census match). */
export function cityFromMatch(label: string): string {
  const parts = label.split(",").map((p) => p.trim()).filter(Boolean);
  if (parts.length < 3) return "";
  const city = parts[parts.length - 3]!;
  const state = parts[parts.length - 2]!;
  if (!/^[A-Z]{2}$/i.test(state)) return "";
  const title = city.toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());
  return `${title}, ${state.toUpperCase()}`;
}

const HostLocationDialog: FC<HostLocationDialogProps> = ({ current, onClose, onSaved }) => {
  const [read, setRead] = useState<OctoLocationResponse | null>(null);
  const known = current ?? read;
  const [lat, setLat] = useState(current ? String(current.lat) : "");
  const [lng, setLng] = useState(current ? String(current.lng) : "");
  const [display, setDisplay] = useState(current?.display ?? "");
  const [city, setCity] = useState(current?.city ?? "");
  // What the operator typed is never overwritten by a late read.
  const [touched, setTouched] = useState({ point: false, display: false, city: false });
  const [reason, setReason] = useState("");
  const [geocoder, setGeocoder] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchGeocoder().then((g) => { if (!cancelled) setGeocoder(g); })
      .catch(() => { if (!cancelled) setGeocoder(null); });         // no Find, never a guess
    return () => { cancelled = true; };
  }, []);

  // Opened before the page read the hub (or its read failed): read it here.
  useEffect(() => {
    if (current) return undefined;
    let cancelled = false;
    fetchOctoLocation().then((r) => { if (!cancelled) setRead(r); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [current]);

  // Fill what was not typed yet once the hub is known.
  useEffect(() => {
    if (!known) return;
    if (!touched.point) { setLat(String(known.lat)); setLng(String(known.lng)); }
    if (!touched.display) setDisplay(known.display ?? "");
    if (!touched.city) setCity(known.city ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only when the hub becomes known
  }, [known]);

  const invalid = coordError(lat, lng);
  const canSave = !busy && !invalid && reason.trim().length >= 3;

  const onPick = (m: FleetPoint): void => {
    const c = cityFromMatch(m.label);
    if (c) {
      setCity(c);
      setTouched((t) => ({ ...t, city: true }));
    }
  };

  const save = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const body: Parameters<typeof saveHostLocation>[0] = {
        lat: Number(lat), lng: Number(lng), reason: reason.trim(),
      };
      if (display.trim()) body.display = display.trim();
      // The city line only when it was changed: an unknown hub's city is
      // never erased by an empty field.
      const was = known?.city ?? "";
      if (city.trim() !== was && (known !== null || city.trim() !== "")) body.city = city.trim();
      const saved = await saveHostLocation(body);
      setBusy(false);
      onSaved(saved);
    } catch (e) {
      setError(e instanceof ApiError || e instanceof Error ? e.message : "The host location could not be saved");
      setBusy(false);
    }
  };

  return (
    <ModalFrame label="Host location" testId="host-location-dialog" busy={busy} onClose={onClose} keyboard>
      <h2 className="text-base font-semibold text-text-primary">Host location — {known?.display ?? "OCTO hub"}</h2>
      <p className="mt-2 text-xs leading-relaxed text-text-secondary">
        Where the map draws this Athena host (the hub the buoys report to) — your office, not a
        client&apos;s. Bundle-wide; recorded in the audit log.
      </p>
      {known && (
        <div className="mt-3 rounded border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary"
             data-testid="host-loc-current">
          Now: <span className="text-text-primary">{known.city || known.display}</span>
          {` (${known.lat.toFixed(4)}, ${known.lng.toFixed(4)})`}
        </div>
      )}
      <LocationPicker
        geocoder={geocoder}
        lat={lat} lng={lng}
        onLatLng={(a, b) => { setLat(a); setLng(b); setTouched((t) => ({ ...t, point: true })); }}
        onPick={onPick}
        onError={setError}
        testPrefix="host-loc"
      />
      <div className="mt-3 grid grid-cols-2 gap-2">
        <label className={labelCls}>
          display name
          <input aria-label="display name" className={inputCls} value={display} maxLength={60}
                 placeholder="Primary"
                 onChange={(e) => { setDisplay(e.target.value); setTouched((t) => ({ ...t, display: true })); }} />
        </label>
        <label className={labelCls}>
          city
          <input aria-label="city" className={inputCls} value={city} maxLength={120}
                 placeholder="Exampleton, IL"
                 onChange={(e) => { setCity(e.target.value); setTouched((t) => ({ ...t, city: true })); }} />
        </label>
      </div>
      <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
        <span>
          Reason <span className="text-critical">*</span>{" "}
          <span className="text-text-dim">— recorded in the audit log.</span>
        </span>
        <input aria-label="reason" className={`${inputCls} font-mono`} value={reason} maxLength={500}
               placeholder="e.g. the office moved" onChange={(e) => setReason(e.target.value)} />
      </label>
      <ErrorLine message={error} />
      <div className="mt-4 flex items-center justify-end gap-2">
        <button type="button" disabled={busy} onClick={onClose} className={secondaryBtn}>Cancel</button>
        <button type="button" disabled={!canSave} onClick={() => void save()} className={primaryBtn}
                data-testid="host-loc-save">
          {busy ? "Saving…" : "Save host location"}
        </button>
      </div>
    </ModalFrame>
  );
};

export default HostLocationDialog;
