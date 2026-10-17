/**
 * LocationPicker — the "where is it" part of the location editors (a site's
 * pin, the host pin): three ways to a coordinate pair.
 *   - an ADDRESS: Find asks the server, which asks the US Census geocoder
 *     with the typed address only (hidden when the server has it off);
 *   - a PASTED pair or map link ("41.25, -100.75", a Google Maps URL) —
 *     parsed in the browser, nothing leaves it;
 *   - typed latitude / longitude.
 * The parent owns lat / lng (and what a picked match fills besides them, e.g.
 * a label); errors go to the parent's error line.
 */
import { type FC, useState } from "react";

import type { FleetPoint } from "@/contracts/fleet";
import { inputCls } from "@/components/tenant-dialogs";
import { coordError } from "@/components/tenant-location-dialog";
import { ApiError } from "@/lib/api";
import { geocodeAddress, parseCoordinates } from "@/lib/fleet";

const secondaryBtn =
  "rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50";
export const labelCls = "flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim";

export const fmtPoint = (p: FleetPoint): string =>
  `${p.label || "—"} (${p.lat.toFixed(4)}, ${p.lng.toFixed(4)})`;

export interface LocationPickerProps {
  /** "census" when the address lookup is on; falsy hides Find. */
  geocoder: string | null | undefined;
  lat: string;
  lng: string;
  onLatLng: (lat: string, lng: string) => void;
  /** A lookup match was picked (lat / lng are already set). */
  onPick?: (match: FleetPoint) => void;
  onError: (message: string | null) => void;
  /** Test-id prefix ("site-loc" → "site-loc-find", "site-loc-matches", …). */
  testPrefix: string;
}

const LocationPicker: FC<LocationPickerProps> = ({
  geocoder, lat, lng, onLatLng, onPick, onError, testPrefix,
}) => {
  const [address, setAddress] = useState("");
  const [matches, setMatches] = useState<FleetPoint[] | null>(null);
  const [finding, setFinding] = useState(false);
  const [paste, setPaste] = useState("");

  const pick = (p: FleetPoint): void => {
    onLatLng(String(p.lat), String(p.lng));
    onPick?.(p);
  };

  const find = async (): Promise<void> => {
    setFinding(true);
    onError(null);
    setMatches(null);
    try {
      const r = await geocodeAddress(address.trim());
      setMatches(r.matches);
      if (r.matches.length === 1) pick(r.matches[0]!);
    } catch (e) {
      onError(e instanceof ApiError || e instanceof Error ? e.message : "The address could not be looked up");
    } finally {
      setFinding(false);
    }
  };

  const pasted = paste.trim() ? parseCoordinates(paste) : null;
  const onPaste = (text: string): void => {
    setPaste(text);
    const pair = parseCoordinates(text);
    if (pair) onLatLng(String(pair.lat), String(pair.lng));
  };
  const invalid = coordError(lat, lng);

  return (
    <>
      {geocoder && (
        <div className="mt-3">
          <label className={labelCls}>
            find by address
            <span className="flex gap-2">
              <input aria-label="address" className={`${inputCls} flex-1`} value={address} maxLength={200}
                     placeholder="street, city, state" onChange={(e) => setAddress(e.target.value)}
                     onKeyDown={(e) => { if (e.key === "Enter" && address.trim().length >= 5) void find(); }} />
              <button type="button" className={secondaryBtn} data-testid={`${testPrefix}-find`}
                      disabled={finding || address.trim().length < 5} onClick={() => void find()}>
                {finding ? "Finding…" : "Find"}
              </button>
            </span>
          </label>
          <div className="mt-1 text-[10px] text-text-dim">
            Only the address you type is sent (US Census geocoder); nothing is kept until you save.
          </div>
          {matches !== null && matches.length === 0 && (
            <div className="mt-1 text-xs text-medium" data-testid={`${testPrefix}-no-match`}>
              No match — check the address, or paste the coordinates / a map link below.
            </div>
          )}
          {matches !== null && matches.length > 0 && (
            <ul className="mt-1 flex flex-col gap-1" data-testid={`${testPrefix}-matches`}>
              {matches.map((m, i) => (
                <li key={`${m.lat},${m.lng},${i}`}>
                  <button type="button" data-testid={`${testPrefix}-match-${i}`}
                          onClick={() => pick(m)}
                          className={`w-full rounded-sm border px-2 py-1 text-left text-xs ${
                            String(m.lat) === lat && String(m.lng) === lng
                              ? "border-accent text-text-primary" : "border-border text-text-secondary hover:text-text-primary"}`}>
                    {fmtPoint(m)}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <label className={`mt-3 ${labelCls}`}>
        or paste coordinates / a map link
        <input aria-label="paste coordinates or map link" className={`${inputCls} font-mono`} value={paste}
               placeholder="41.25, -100.75  or  https://www.google.com/maps/@41.25,-100.75,17z"
               onChange={(e) => onPaste(e.target.value)} />
      </label>
      {paste.trim() && (
        <div className={`mt-1 text-[10px] ${pasted ? "text-text-dim" : "text-medium"}`}
             data-testid={`${testPrefix}-paste-result`}>
          {pasted ? `found ${pasted.lat}, ${pasted.lng}` : "no coordinates found in that"}
        </div>
      )}

      <div className="mt-3 grid grid-cols-2 gap-2">
        <label className={labelCls}>
          latitude
          <input aria-label="latitude" className={`${inputCls} font-mono`} value={lat}
                 inputMode="decimal" placeholder="41.25" onChange={(e) => onLatLng(e.target.value, lng)} />
        </label>
        <label className={labelCls}>
          longitude
          <input aria-label="longitude" className={`${inputCls} font-mono`} value={lng}
                 inputMode="decimal" placeholder="-100.75" onChange={(e) => onLatLng(lat, e.target.value)} />
        </label>
      </div>
      {(lat || lng) && invalid && (
        <div className="mt-1 text-xs text-critical" data-testid={`${testPrefix}-invalid`}>{invalid}</div>
      )}
    </>
  );
};

export default LocationPicker;
