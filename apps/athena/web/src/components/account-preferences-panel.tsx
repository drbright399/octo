/**
 * AccountPreferencesPanel — Settings → Account section for per-
 * operator preferences. Slice 5b ships with the l2_llm_enabled
 * toggle; future slices add theme accent, density, etc. to the
 * same panel.
 *
 * Pattern: load on mount, optimistic toggle, revert + show error
 * on failure.
 */
import { type FC, useEffect, useState } from "react";

import { ApiError, getLlmStatus, type LlmStatusResponse } from "@/lib/api";


interface OperatorPreferences {
  l2_llm_enabled: boolean;
}


async function getPreferences(): Promise<OperatorPreferences> {
  const r = await fetch("/api/v1/account/preferences", {
    credentials: "include",
  });
  if (!r.ok) {
    throw new ApiError("Failed to load preferences", r.status);
  }
  return (await r.json()) as OperatorPreferences;
}


async function putPreferences(
  patch: Partial<OperatorPreferences>,
): Promise<OperatorPreferences> {
  const r = await fetch("/api/v1/account/preferences", {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message ?? "Failed to update",
      r.status,
    );
  }
  return (await r.json()) as OperatorPreferences;
}


const AccountPreferencesPanel: FC = () => {
  const [prefs, setPrefs] = useState<OperatorPreferences | null>(null);
  const [status, setStatus] = useState<LlmStatusResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getPreferences()
      .then((r) => !cancelled && setPrefs(r))
      .catch((e: Error) => !cancelled && setLoadError(e.message));
    getLlmStatus()
      .then((r) => !cancelled && setStatus(r))
      .catch(() => { /* Status is informational — silent failure ok. */ });
    return () => { cancelled = true; };
  }, []);

  const toggleLlm = async (): Promise<void> => {
    if (prefs === null || saving) return;
    const next = !prefs.l2_llm_enabled;
    // Optimistic update.
    setPrefs({ ...prefs, l2_llm_enabled: next });
    setSaving(true);
    setError(null);
    try {
      const result = await putPreferences({ l2_llm_enabled: next });
      setPrefs(result);
      // Refresh the LLM status chip so it reflects the new
      // preference state immediately. Silent failure ok — the
      // chip is informational.
      try {
        const fresh = await getLlmStatus();
        setStatus(fresh);
      } catch { /* ignore — chip stays stale until next load */ }
    } catch (e) {
      // Revert.
      setPrefs({ ...prefs });
      setError(e instanceof Error ? e.message : "Update failed");
    } finally {
      setSaving(false);
    }
  };

  if (loadError) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6">
        <h2 className="mb-1 text-base font-semibold text-text-primary">
          Preferences
        </h2>
        <p className="text-sm text-critical">{loadError}</p>
      </section>
    );
  }
  if (prefs === null) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6 text-center text-text-dim">
        Loading preferences…
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-border bg-bg-surface p-6">
      <h2 className="mb-1 text-base font-semibold text-text-primary">
        Preferences
      </h2>
      <p className="mb-4 text-xs text-text-dim">
        Personal settings stored in your operator profile. Take effect
        immediately on save.
      </p>

      <div className="flex items-start justify-between gap-4 rounded border border-border bg-bg-card p-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-text-primary">
            Octo AI enrichment
          </div>
          <div className="mt-1 text-xs text-text-dim">
            When enabled, the &ldquo;Ask Octo&rdquo; buttons on alerts,
            events, and tickets call the L2 LLM for context. When
            disabled, you see only the deterministic heuristic notes
            (no AI suggestions). This is independent of the bundle-
            wide enable flag — when bundle is on but you turn this
            off, only your account is affected.
          </div>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={prefs.l2_llm_enabled}
          onClick={() => void toggleLlm()}
          disabled={saving}
          className={[
            "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition-colors",
            prefs.l2_llm_enabled
              ? "border-accent bg-accent/40"
              : "border-border bg-bg-card",
            saving ? "opacity-60" : "",
          ].join(" ")}
        >
          <span
            className={[
              "inline-block h-4 w-4 transform rounded-full bg-text-primary transition-transform",
              prefs.l2_llm_enabled ? "translate-x-6" : "translate-x-1",
            ].join(" ")}
          />
        </button>
      </div>

      {/* LLM status chip — universal visibility (Slice 5d-2).
          Surfaces the four-gate AND so operators know whether their
          next "ask octo" click will fire, and what model would run. */}
      {status && (
        <div className="mt-4 rounded border border-border bg-bg-card p-3 text-xs">
          <div className="mb-2 flex items-center justify-between gap-2">
            <span className="font-mono uppercase tracking-wider text-text-dim">
              ·· current llm status ··
            </span>
            <span
              className={[
                "rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase",
                status.effectively_active
                  ? "border border-accent/60 text-accent"
                  : "border border-border text-text-dim",
              ].join(" ")}
            >
              {status.effectively_active ? "active" : "inactive"}
            </span>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[10px]">
            <dt className="text-text-dim">model</dt>
            <dd className="text-text-secondary">{status.active_model}</dd>
            <dt className="text-text-dim">your grant</dt>
            <dd className={status.your_grant ? "text-accent" : "text-text-dim"}>
              {status.your_grant ? "granted" : "not granted — ask admin"}
            </dd>
            <dt className="text-text-dim">your preference</dt>
            <dd className={status.your_preference ? "text-accent" : "text-text-dim"}>
              {status.your_preference ? "enabled" : "disabled (above)"}
            </dd>
            <dt className="text-text-dim">bundle</dt>
            <dd className={status.bundle_enabled ? "text-accent" : "text-text-dim"}>
              {status.bundle_enabled ? "enabled" : "disabled by super_admin"}
            </dd>
          </dl>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
        >
          {error}
        </div>
      )}
    </section>
  );
};


export default AccountPreferencesPanel;
export { AccountPreferencesPanel };
