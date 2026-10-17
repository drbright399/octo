/**
 * VendorLinksPanel — admin settings for "Open in <vendor>" links.
 *
 * Two non-secret fields: the vendor portal's base URL (normally derived by
 * the server from the integration's API URL) and the alert path template.
 * Blank = use the default, which is shown as the placeholder.
 *
 * There is NO device path: the portal addresses a device by an id only the
 * vendor's API knows, so a device page is looked up at the vendor when an
 * operator clicks Open — and must land on the portal base set here.
 *
 * The point of the panel is VERIFICATION: an earlier version of this product
 * had vendor links that "sometimes just went to the home dashboard". The
 * server refuses anything that is not an exact https portal URL, and this
 * panel shows the sample alert link — and says plainly if the default path
 * was never checked against the live portal — so an admin can open a real
 * alert from the dashboard and confirm where it lands.
 *
 * All validation is the server's; this component only shows its answer.
 */
import { type FC, useEffect, useState } from "react";

import { vendorSessionNote } from "@/contracts/alert";
import {
  fetchVendorLinkSettings,
  saveVendorLinkSettings,
  type VendorLinkSettingField,
  type VendorLinkSettings,
} from "@/lib/api";

interface Props {
  readonly vendorSlug: string;
  readonly instanceId: number;
  readonly vendorName: string;
  readonly onDone: () => void;
}

const FIELDS: ReadonlyArray<{
  readonly name: VendorLinkSettingField;
  readonly label: string;
  readonly help: string;
}> = [
  {
    name: "portal_base_url",
    label: "Portal base URL",
    help: "The site only — https://host, no path.",
  },
  {
    name: "alert_path_template",
    label: "Alert path",
    help: "Must contain {alert_uid}.",
  },
];

const defaultFor = (s: VendorLinkSettings, field: VendorLinkSettingField): string => {
  if (field === "portal_base_url") return s.derived_portal_base_url ?? "";
  return s.default_alert_path_template;
};

export const VendorLinksPanel: FC<Props> = ({ vendorSlug, instanceId, vendorName, onDone }) => {
  const [settings, setSettings] = useState<VendorLinkSettings | null>(null);
  const [values, setValues] = useState<Record<VendorLinkSettingField, string>>({
    portal_base_url: "",
    alert_path_template: "",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const adopt = (s: VendorLinkSettings): void => {
    setSettings(s);
    setValues({
      portal_base_url: s.overrides.portal_base_url ?? "",
      alert_path_template: s.overrides.alert_path_template ?? "",
    });
  };

  useEffect(() => {
    let cancelled = false;
    fetchVendorLinkSettings(vendorSlug, instanceId)
      .then((s) => {
        if (!cancelled) adopt(s);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load");
      });
    return () => {
      cancelled = true;
    };
  }, [vendorSlug, instanceId]);

  const onSave = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      adopt(await saveVendorLinkSettings(vendorSlug, instanceId, values));
      setSaved(true);
    } catch (e) {
      // The server says which field it refused and why — show that.
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  if (!settings) {
    return (
      <div className="p-5 text-xs text-text-dim" aria-busy={error ? undefined : "true"}>
        {error ? <p role="alert" className="text-critical">{error}</p> : "Loading…"}
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-y-auto p-5 text-xs text-text-secondary">
      <p className="mb-3">
        Alerts from {vendorName} get an “Open in {settings.portal_name}” link
        (analysts and above; never client viewers), built on the server from{" "}
        {settings.portal_name}’s own alert id. If a link cannot be built exactly,
        none is shown.
      </p>
      <p className="mb-3" data-testid="vendor-links-session-note">
        {vendorSessionNote(settings.portal_name)} An exact link that still lands
        on the {settings.portal_name} home page is that sign-in, not the link.
      </p>
      <p className="mb-3" data-testid="vendor-links-device-note">
        {settings.device_links_resolved
          ? `Device pages have no path setting: ${settings.portal_name} addresses a device by an id only its API knows, so the page is looked up when an operator clicks Open — and is only opened if it is on the portal address below.`
          : `Device pages are looked up in ${settings.portal_name} when an operator clicks Open — once a portal address is known.`}
      </p>

      {settings.problem ? (
        <p role="alert" data-testid="vendor-links-problem" className="mb-3 text-warning">
          {settings.problem}
        </p>
      ) : null}
      {!settings.paths_verified ? (
        <p role="note" data-testid="vendor-links-unverified" className="mb-3 text-text-dim">
          The default alert path has not been verified against the live{" "}
          {settings.portal_name} portal. Open a real alert from the dashboard once;
          if it lands on the wrong page, copy the path from your browser’s address
          bar here, replacing the id with the placeholder.
        </p>
      ) : null}

      {FIELDS.map((f) => (
        <label key={f.name} className="mb-3 block">
          <span className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-text-dim">
            {f.label}
          </span>
          <input
            type="text"
            value={values[f.name]}
            placeholder={defaultFor(settings, f.name) || "not derivable — enter it"}
            onChange={(e) => {
              setSaved(false);
              setValues((v) => ({ ...v, [f.name]: e.target.value }));
            }}
            data-testid={`vendor-links-${f.name}`}
            spellCheck={false}
            autoComplete="off"
            className="w-full rounded-sm border border-border bg-bg-input px-2 py-1.5 font-mono text-[12px] text-text-primary focus:border-accent focus:outline-none"
          />
          <span className="mt-1 block text-[11px] text-text-dim">
            {f.help}
            {f.name === "portal_base_url"
              ? ` Must be a host under ${settings.allowed_domain}.`
              : ` Placeholders: ${settings.placeholders.join(" ")}`}
            {" Blank = default."}
          </span>
        </label>
      ))}

      <div className="mb-4 rounded-sm border border-border bg-bg-surface p-3">
        <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-text-dim">
          link in use (sample id)
        </div>
        <div data-testid="vendor-links-sample-alert" className="break-all font-mono text-[11px]">
          alert · {settings.sample_alert_url ?? "— no link —"}
        </div>
        <div data-testid="vendor-links-sample-device" className="break-all font-mono text-[11px]">
          device · {settings.device_links_resolved ? "looked up on click" : "— no link —"}
        </div>
      </div>

      {error ? (
        <p role="alert" data-testid="vendor-links-error" className="mb-3 text-critical">
          {error}
        </p>
      ) : null}
      {saved ? (
        <p role="status" className="mb-3 text-success">
          Saved. New links apply to the dashboard’s next refresh.
        </p>
      ) : null}

      <div className="mt-auto flex justify-end gap-2">
        <button
          type="button"
          onClick={onDone}
          className="rounded-sm border border-border bg-bg-input px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary"
        >
          Close
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => void onSave()}
          data-testid="vendor-links-save"
          className="rounded-sm border border-border-bright bg-accent-soft px-3 py-1.5 text-xs text-accent hover:bg-accent/20 disabled:opacity-50"
        >
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
};

export default VendorLinksPanel;
