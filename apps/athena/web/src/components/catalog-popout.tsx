/**
 * CatalogPopout — right-side slide-out for adding a new integration.
 *
 * Stepped flow inside one panel:
 *   1. browse: category rail (left), filterable adapter grid (right)
 *   2. configure: cred wizard for the picked adapter
 *   3. secret (only when the platform generated a webhook token): the
 *      one-time header name + value to configure on the vendor side
 *   4. map: tenant mapping for the new instance
 *
 * Reusable section-level pattern (the catalog opens as a sidebar
 * pop-out, not a separate page).
 *
 * Security: credential VALUES live only in component state for the life
 * of the panel. On save the parent receives the resulting
 * IntegrationInstance metadata; the form values are wiped from state
 * immediately afterward. No localStorage, no logging. The same holds for a
 * platform-generated webhook token: it is held in this component's state for
 * the one screen that shows it, then dropped (on continue, and on close).
 */
import { type FC, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { CredentialFieldInput } from "@/components/credential-field-input";
import { OnboardingGuide } from "@/components/onboarding-guide";
import { OneTimeSecretPanel } from "@/components/one-time-secret-panel";
import { NextDnsProfilePanel } from "@/components/nextdns-profile-panel";
import { TenantMappingPanel } from "@/components/tenant-mapping-panel";
import { UniFiSitePanel } from "@/components/unifi-site-panel";
import { createIntegration, fetchAdapterCatalog, testIntegration } from "@/lib/api";
import { allRequiredFilled, recoveryPath, visibleFields } from "@/lib/integration-fields";
import type {
  CatalogAdapter,
  CatalogResponse,
  GeneratedWebhookSecret,
  IntegrationInstance,
} from "@/contracts/integration";

interface Props {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly onConfigured: (instance: IntegrationInstance) => void;
  /** Test seam: caller may pre-supply catalog data instead of hitting the API. */
  readonly initialCatalog?: CatalogResponse;
}

type Step = "browse" | "configure" | "secret" | "map";

export const CatalogPopout: FC<Props> = ({
  open,
  onClose,
  onConfigured,
  initialCatalog,
}) => {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(
    initialCatalog ?? null,
  );
  const [loading, setLoading] = useState(!initialCatalog);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [step, setStep] = useState<Step>("browse");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [picked, setPicked] = useState<CatalogAdapter | null>(null);
  const [savedInstance, setSavedInstance] = useState<IntegrationInstance | null>(null);
  // One-time, platform-generated webhook token. Component state ONLY.
  const [oneTimeSecret, setOneTimeSecret] = useState<GeneratedWebhookSecret | null>(null);

  useEffect(() => {
    if (!open || initialCatalog) return;
    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    fetchAdapterCatalog()
      .then((r) => {
        if (cancelled) return;
        setCatalog(r);
      })
      .catch((e: Error) => !cancelled && setLoadError(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [open, initialCatalog]);

  // When the popout closes, reset internal state so reopening starts clean.
  // `selectedCategory` is intentionally reset to null ("All") — the operator
  // re-opening the popout starts back at the unfiltered view, which is the
  // friendliest default for browsing the catalog.
  useEffect(() => {
    if (open) return;
    setStep("browse");
    setPicked(null);
    setSavedInstance(null);
    setOneTimeSecret(null);
    setSearch("");
    setSelectedCategory(null);
  }, [open]);

  const visibleAdapters = useMemo<readonly CatalogAdapter[]>(() => {
    if (!catalog) return [];
    const q = search.trim().toLowerCase();
    const pool = selectedCategory
      ? (catalog.categories.find((c) => c.category === selectedCategory)?.adapters ?? [])
      : catalog.adapters;
    if (!q) return pool;
    return pool.filter(
      (a) =>
        a.vendor_display_name.toLowerCase().includes(q) ||
        a.vendor_slug.toLowerCase().includes(q),
    );
  }, [catalog, selectedCategory, search]);

  // The NextDNS mapping panel reports unsaved profile choices (as it does in
  // the card's drawer): the backdrop and the ✕ ask before discarding them.
  const mapDirtyRef = useRef(false);

  if (!open) return null;

  const unsavedMapping = (): boolean =>
    step === "map" &&
    mapDirtyRef.current &&
    !window.confirm(
      `You have unsaved ${savedInstance?.slug === "unifi" ? "site" : "profile"} choices. Discard them and close?`,
    );

  // Closing on the secret step drops a token that can NEVER be shown again
  // (recovery = disable, re-create, re-map). The backdrop ignores clicks on
  // that step; the header ✕ asks first. The only silent exit is the panel's
  // own "I've stored it safely" button.
  const onHeaderClose = (): void => {
    if (
      step === "secret" &&
      !window.confirm("The token cannot be shown again — close anyway?")
    ) {
      return;
    }
    if (unsavedMapping()) return;
    onClose();
  };

  const onBackdrop = (): void => {
    if (unsavedMapping()) return;
    onClose();
  };

  // Portal to document.body — escapes the App-root's z-10 stacking
  // context so the status-strip footer doesn't paint over the
  // drawer's bottom action buttons. See settings/integrations.tsx
  // for the full root-cause writeup.
  return createPortal(
    <>
      <div
        // A stray backdrop click must not discard a token that can never be
        // shown again — on that step, leaving takes an explicit button.
        onClick={step === "secret" ? undefined : onBackdrop}
        aria-hidden="true"
        data-testid="catalog-popout-backdrop"
        className="fixed inset-0 z-40 bg-black/50"
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Add integration"
        data-testid="catalog-popout"
        className="fixed right-0 top-0 z-50 flex h-full w-[min(820px,100vw)] flex-col border-l border-border-bright bg-bg-elevated shadow-xl"
      >
        <header className="flex items-center justify-between border-b border-border bg-bg-surface px-5 py-4">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
              {step === "browse"
                ? "Add integration"
                : step === "map"
                  ? "Map clients"
                  : step === "secret"
                    ? "Webhook token — shown once"
                    : "Configure"}
            </span>
            <h2 className="mt-0.5 text-base font-semibold text-text-primary">
              {step === "browse"
                ? "Source-adapter catalog"
                : (picked?.vendor_display_name ?? "")}
            </h2>
          </div>
          <div className="flex items-center gap-2">
            {step === "configure" ? (
              <button
                type="button"
                onClick={() => {
                  setStep("browse");
                  setPicked(null);
                }}
                className="rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-secondary hover:text-text-primary"
              >
                ← Back to catalog
              </button>
            ) : null}
            <button
              type="button"
              onClick={onHeaderClose}
              aria-label="Close"
              className="rounded-sm p-1 text-text-secondary hover:bg-accent-soft hover:text-accent"
            >
              ✕
            </button>
          </div>
        </header>

        {step === "browse" ? (
          <BrowseStep
            catalog={catalog}
            loading={loading}
            loadError={loadError}
            selectedCategory={selectedCategory}
            onSelectCategory={setSelectedCategory}
            search={search}
            onSearch={setSearch}
            visibleAdapters={visibleAdapters}
            onPick={(a) => {
              setPicked(a);
              setStep("configure");
            }}
          />
        ) : step === "configure" ? (
          <ConfigureStep
            adapter={picked!}
            onCancel={() => {
              setStep("browse");
              setPicked(null);
            }}
            onConfigured={(inst, generated) => {
              onConfigured(inst);
              setSavedInstance(inst);
              // A generated token gets its own screen first; otherwise step
              // into tenant mapping for the new instance (needs its id), and
              // fall back to closing if the id is absent.
              if (generated) {
                setOneTimeSecret(generated);
                setStep("secret");
              } else if (inst.id != null) {
                setStep("map");
              } else {
                onClose();
              }
            }}
          />
        ) : step === "secret" && oneTimeSecret ? (
          <OneTimeSecretPanel
            vendorName={picked?.vendor_display_name ?? "the vendor"}
            secret={oneTimeSecret}
            steps={picked?.onboarding?.steps}
            onContinue={() => {
              setOneTimeSecret(null);
              if (savedInstance?.id != null) setStep("map");
              else onClose();
            }}
          />
        ) : savedInstance && savedInstance.id != null && savedInstance.slug === "nextdns" ? (
          <NextDnsProfilePanel
            instanceId={savedInstance.id}
            onDone={onClose}
            onDirtyChange={(d) => {
              mapDirtyRef.current = d;
            }}
          />
        ) : savedInstance && savedInstance.id != null && savedInstance.slug === "unifi" ? (
          <UniFiSitePanel
            instanceId={savedInstance.id}
            onDone={onClose}
            onDirtyChange={(d) => {
              mapDirtyRef.current = d;
            }}
          />
        ) : savedInstance && savedInstance.id != null ? (
          <TenantMappingPanel
            vendorSlug={savedInstance.slug}
            instanceId={savedInstance.id}
            vendorName={picked?.vendor_display_name}
            shape={picked?.tenant_mapping_shape}
            onDone={onClose}
          />
        ) : null}
      </aside>
    </>,
    document.body,
  );
};

// ---------------------------------------------------------------------------
// Browse step — category rail + adapter grid + filter input
// ---------------------------------------------------------------------------

interface BrowseStepProps {
  readonly catalog: CatalogResponse | null;
  readonly loading: boolean;
  readonly loadError: string | null;
  readonly selectedCategory: string | null;
  readonly onSelectCategory: (slug: string | null) => void;
  readonly search: string;
  readonly onSearch: (q: string) => void;
  readonly visibleAdapters: readonly CatalogAdapter[];
  readonly onPick: (a: CatalogAdapter) => void;
}

const BrowseStep: FC<BrowseStepProps> = ({
  catalog,
  loading,
  loadError,
  selectedCategory,
  onSelectCategory,
  search,
  onSearch,
  visibleAdapters,
  onPick,
}) => {
  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center p-6 text-text-dim">
        Loading catalog…
      </div>
    );
  }
  if (loadError) {
    return (
      <div className="flex flex-1 items-center justify-center p-6 text-critical" role="alert">
        {loadError}
      </div>
    );
  }
  if (!catalog || catalog.adapters.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center p-6 text-text-dim">
        No adapters registered.
      </div>
    );
  }

  return (
    <div className="flex flex-1 overflow-hidden">
      {/* Left rail — categories */}
      <nav
        aria-label="Adapter categories"
        className="flex w-44 shrink-0 flex-col gap-px border-r border-border bg-bg-surface py-3"
      >
        <CategoryButton
          label="All"
          count={catalog.adapters.length}
          active={selectedCategory === null}
          onClick={() => onSelectCategory(null)}
        />
        {catalog.categories.map((g) => (
          <CategoryButton
            key={g.category}
            label={g.display_label}
            count={g.adapters.length}
            active={selectedCategory === g.category}
            onClick={() => onSelectCategory(g.category)}
          />
        ))}
      </nav>

      {/* Right pane — search + cards */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <div className="border-b border-border bg-bg-surface px-5 py-3">
          <label htmlFor="catalog-search" className="sr-only">
            Search adapters
          </label>
          <input
            id="catalog-search"
            type="search"
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            placeholder="Filter adapters…"
            className="w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
          />
        </div>

        <ul
          role="list"
          data-testid="catalog-adapter-list"
          className="grid flex-1 auto-rows-min grid-cols-1 gap-2 overflow-y-auto p-4 md:grid-cols-2"
        >
          {visibleAdapters.length === 0 ? (
            <li className="col-span-full text-center text-sm text-text-dim">
              No adapters match.
            </li>
          ) : (
            visibleAdapters.map((a) => (
              <li key={a.vendor_slug}>
                <button
                  type="button"
                  onClick={() => onPick(a)}
                  data-testid={`catalog-adapter-${a.vendor_slug}`}
                  className="flex w-full flex-col items-start gap-1 rounded-sm border border-border bg-bg-card p-3 text-left hover:border-accent hover:bg-accent-soft/40"
                >
                  <span className="text-sm font-semibold text-text-primary">
                    {a.vendor_display_name}
                  </span>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
                    {a.vendor_category}
                    {a.delivery_mode ? ` · ${a.delivery_mode}` : null}
                  </span>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
                    {a.auth_model}
                  </span>
                </button>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
};

const CategoryButton: FC<{
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}> = ({ label, count, active, onClick }) => (
  <button
    type="button"
    onClick={onClick}
    aria-pressed={active}
    className={[
      "flex items-center justify-between px-3 py-1.5 text-left text-xs",
      active
        ? "border-l-2 border-accent bg-accent-soft text-text-primary"
        : "border-l-2 border-transparent text-text-secondary hover:bg-bg-card hover:text-text-primary",
    ].join(" ")}
  >
    <span>{label}</span>
    <span className="font-mono text-[10px] text-text-dim">{count}</span>
  </button>
);

// ---------------------------------------------------------------------------
// Configure step — cred wizard for the picked adapter
// ---------------------------------------------------------------------------

interface ConfigureStepProps {
  readonly adapter: CatalogAdapter;
  readonly onCancel: () => void;
  readonly onConfigured: (
    instance: IntegrationInstance,
    generated: GeneratedWebhookSecret | null,
  ) => void;
}

const ConfigureStep: FC<ConfigureStepProps> = ({ adapter, onCancel, onConfigured }) => {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(adapter.credential_shape.map((f) => [f.name, ""])),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(
    null,
  );

  // A webhook token WE define (vs. one the vendor issues, e.g. Resend's
  // signing secret): the operator chooses webhooks on/off, and "on + blank"
  // means "generate it for me".
  const platformSecretField =
    adapter.credential_shape.find((f) => f.secret_origin === "platform") ?? null;
  // No public ingest hostname → a webhook could never arrive. Default to
  // poll-only so a first-time owner is not handed a token they cannot use yet
  // and must then keep safe indefinitely. (They may still switch it on.)
  const noIngestHost = Boolean(adapter.onboarding?.webhook_url_problem);
  const [enableWebhook, setEnableWebhook] = useState(!noIngestHost);
  const vendorName = adapter.vendor_display_name;

  const setField = (name: string, value: string): void =>
    setValues((prev) => ({ ...prev, [name]: value }));

  const allFilled = allRequiredFilled(adapter.credential_shape, values);

  const wipeValues = (): void =>
    setValues(Object.fromEntries(adapter.credential_shape.map((f) => [f.name, ""])));

  const onSave = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      // Poll-only: never send a token the operator typed before switching off.
      const submitted =
        platformSecretField && !enableWebhook
          ? { ...values, [platformSecretField.name]: "" }
          : values;
      const created = await createIntegration(
        adapter.vendor_slug,
        submitted,
        platformSecretField ? { enableWebhook } : {},
      );
      wipeValues();
      onConfigured(created.instance, created.generatedWebhookSecret);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  const onTest = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      const r = await testIntegration(adapter.vendor_slug, values);
      setTestResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void onSave();
        }}
        className="flex flex-1 flex-col overflow-y-auto p-5"
      >
        {adapter.onboarding ? (
          <OnboardingGuide
            onboarding={adapter.onboarding}
            deliveryMode={adapter.delivery_mode}
          />
        ) : null}
        <p className="mb-4 rounded border border-accent/30 bg-accent-soft px-3 py-2 text-xs text-text-secondary">
          Values are submitted once over HTTPS and pubkey-encrypted at rest
          inside this deployment&apos;s credential store. The browser does not
          store them. A webhook token Athena generates is shown here once, right
          after saving, and then exists only encrypted on the server.
        </p>

        {visibleFields(adapter.credential_shape, values)
          .filter((field) => field !== platformSecretField)
          .map((field) => (
            <CredentialFieldInput
              key={field.name}
              field={field}
              value={values[field.name] ?? ""}
              onChange={(v) => setField(field.name, v)}
            />
          ))}

        {platformSecretField ? (
          <fieldset className="mb-3 rounded border border-border p-3">
            <label className="flex items-start gap-2 text-xs text-text-primary">
              <input
                type="checkbox"
                checked={enableWebhook}
                onChange={(e) => setEnableWebhook(e.target.checked)}
                aria-describedby="enable-webhook-hint"
                className="mt-0.5"
              />
              <span className="font-semibold">Enable real-time webhooks</span>
            </label>
            {/* A description, not part of the checkbox's name. */}
            <p id="enable-webhook-hint" className="ml-5 mt-0.5 text-[11px] text-text-dim">
              {enableWebhook
                ? `Athena generates the ${platformSecretField.label} when you save and shows it once, with copy buttons, on the next screen. Leave the field below blank unless you need to supply your own.`
                : `Poll-only: no ${platformSecretField.label} is created and inbound webhooks are rejected. To turn this on later: ${recoveryPath(vendorName)}.`}
            </p>
            {noIngestHost ? (
              <p
                role="note"
                data-testid="no-ingest-host-webhook-hint"
                className="mt-2 rounded border border-border bg-bg-surface px-2 py-1.5 text-[11px] leading-relaxed text-text-secondary"
              >
                This deployment has no public ingest hostname, so webhooks cannot work
                yet — start poll-only{enableWebhook ? "" : " (that is why this is off)"}. To enable them later:
                set the ingest hostname in the bundle&apos;s compose file
                (OCTO_PUBLIC_INGEST_BASE_URL in docker-compose.yml), recreate the
                octo-core container — the bundle deploy guide (docs/operations/bundle.md)
                has the steps — then {recoveryPath(vendorName)}.
              </p>
            ) : null}
            {enableWebhook ? (
              <div className="mt-3">
                <CredentialFieldInput
                  field={{
                    ...platformSecretField,
                    label: `${platformSecretField.label} (optional)`,
                  }}
                  value={values[platformSecretField.name] ?? ""}
                  onChange={(v) => setField(platformSecretField.name, v)}
                />
              </div>
            ) : null}
          </fieldset>
        ) : null}

        {error ? (
          <div
            role="alert"
            className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            {error}
          </div>
        ) : null}
        {testResult ? (
          <div
            role="status"
            className={[
              "mt-3 rounded border px-3 py-2 text-xs",
              testResult.ok
                ? "border-success/50 bg-success/10 text-success"
                : "border-critical bg-critical/10 text-critical",
            ].join(" ")}
          >
            {testResult.ok ? "✓ " : "✗ "}
            {testResult.detail}
          </div>
        ) : null}
      </form>

      <footer className="flex items-center justify-end gap-2 border-t border-border bg-bg-surface px-5 py-3">
        <button
          type="button"
          disabled={busy || !allFilled}
          onClick={() => void onTest()}
          className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:border-border-bright hover:text-text-primary disabled:opacity-50"
        >
          Test connection
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={busy || !allFilled}
          onClick={() => void onSave()}
          className="rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
        >
          {busy ? "Saving…" : "Save & encrypt"}
        </button>
      </footer>
    </>
  );
};
