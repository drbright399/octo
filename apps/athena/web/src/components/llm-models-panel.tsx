/**
 * LlmModelsPanel — Settings → System section listing installed
 * L2 LLM models and allowing super_admin to switch the active one.
 *
 * Slice 5c scaffold:
 *   - read-only file listing (size, mtime, name)
 *   - radio-select to change active model
 *   - "restart required" hint after a change lands
 *
 * Slice 5d adds the download UI + hot-swap restart orchestration.
 */
import { type FC, useEffect, useRef, useState } from "react";

import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";
import {
  ApiError,
  getLlmBundleConfig,
  getLlmModelManifest,
  probeOctoLlm,
  putLlmBundleConfig,
  restartOctoLlm,
  type LlmBundleConfig,
  type ManifestResponse,
  type SiblingProbeResponse,
} from "@/lib/api";
import HelpTooltip from "@/components/help-tooltip";


interface ModelInfo {
  name: string;
  filename: string;
  size_bytes: number;
  sha256: string | null;
  mtime: string;
  is_active: boolean;
}

interface ModelListResponse {
  active: string;
  models: ModelInfo[];
  models_dir: string;
}


async function getModels(): Promise<ModelListResponse> {
  const r = await fetch("/api/v1/admin/llm/models", { credentials: "include" });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message ?? "Failed to load models",
      r.status,
    );
  }
  return (await r.json()) as ModelListResponse;
}


async function setActive(name: string): Promise<ModelListResponse> {
  const r = await fetch("/api/v1/admin/llm/models/active", {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message ?? "Failed to set active",
      r.status,
      (body as { code?: string }).code,  // carries STEP_UP_REQUIRED etc.
    );
  }
  return (await r.json()) as ModelListResponse;
}


function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = b / 1024;
  for (const u of units) {
    if (v < 1024) return `${v.toFixed(1)} ${u}`;
    v /= 1024;
  }
  return `${v.toFixed(1)} PB`;
}


const LlmModelsPanel: FC = () => {
  const [data, setData] = useState<ModelListResponse | null>(null);
  const [bundleCfg, setBundleCfg] = useState<LlmBundleConfig | null>(null);
  const [probe, setProbe] = useState<SiblingProbeResponse | null>(null);
  const [manifest, setManifest] = useState<ManifestResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [pendingName, setPendingName] = useState<string | null>(null);
  const [bundleSaving, setBundleSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [restartHint, setRestartHint] = useState<boolean>(false);

  const reload = async (): Promise<void> => {
    try {
      const r = await getModels();
      setData(r);
      setLoadError(null);
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : "Load failed");
    }
    try {
      const cfg = await getLlmBundleConfig();
      setBundleCfg(cfg);
    } catch {
      // Silent — the model list is the primary surface.
    }
    try {
      const p = await probeOctoLlm();
      setProbe(p);
    } catch {
      // Silent — probe is informational.
    }
    try {
      const m = await getLlmModelManifest();
      setManifest(m);
    } catch {
      // Silent — manifest is informational.
    }
  };

  useEffect(() => {
    void reload();
  }, []);

  const onToggleBundle = async (): Promise<void> => {
    if (bundleCfg === null || bundleSaving) return;
    const next = !bundleCfg.l2_llm_enabled;
    setBundleCfg({ ...bundleCfg, l2_llm_enabled: next });
    setBundleSaving(true);
    try {
      const r = await putLlmBundleConfig({ l2_llm_enabled: next });
      setBundleCfg(r);
    } catch (e) {
      setBundleCfg({ ...bundleCfg });
      setError(e instanceof Error ? e.message : "bundle toggle failed");
    } finally {
      setBundleSaving(false);
    }
  };

  // Slice 7j — Restart sibling. Issues a SIGTERM via the backend
  // (factory-admin gated server-side); the dev runner's respawn loop
  // brings it back up within ~1s. UI polls probe afterwards so the
  // operator sees the new state without manual refresh.
  const [restarting, setRestarting] = useState<boolean>(false);
  const [restartMsg, setRestartMsg] = useState<string | null>(null);

  const onRestart = async (): Promise<void> => {
    if (restarting) return;
    if (!window.confirm(
      "Restart octo-llm now? In-flight enrichment calls will fail-"
      + "closed (operators see 'octo unavailable — heuristic only')."
    )) return;
    setRestarting(true);
    setRestartMsg(null);
    setError(null);
    try {
      const r = await restartOctoLlm();
      setRestartMsg(r.detail);
      // Wait a beat then poll the probe so the sibling-state block
      // reflects the new process.
      setTimeout(() => { void reload(); }, 1500);
      setTimeout(() => { void reload(); }, 4000);
    } catch (e) {
      setError(e instanceof Error ? e.message : "restart failed");
    } finally {
      setRestarting(false);
    }
  };

  // Step-up: the model SWAP is factory + step-up gated server-side. When
  // the session isn't elevated the PUT returns code STEP_UP_REQUIRED (or
  // STEP_UP_NETWORK_CHANGED) — prompt for re-auth, then retry the swap.
  // (Previously this just surfaced the error text with no prompt — the
  // dropdown looked broken.)
  const [stepUpReason, setStepUpReason] = useState<StepUpReason | null>(null);
  const pendingSwapRef = useRef<string | null>(null);

  const performSwap = async (name: string): Promise<void> => {
    setPendingName(name);
    setError(null);
    try {
      await setActive(name);
      setRestartHint(true);
      // Refetch the full model list (and bundle config + manifest +
      // probe) so the panel reflects the new active model + flips
      // the radio/dropdown selection.
      //
      // Slice 7k bugfix: previously did setData(r) where r is the
      // SetActiveResponse {active, restart_required} — wrong shape
      // for `data`, so the next render hit `data.models = undefined`
      // and crashed the whole panel.
      await reload();
    } catch (e) {
      if (e instanceof ApiError
          && (e.code === "STEP_UP_REQUIRED" || e.code === "STEP_UP_NETWORK_CHANGED")) {
        pendingSwapRef.current = name;
        setStepUpReason(e.code === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
      } else {
        setError(e instanceof Error ? e.message : "update failed");
      }
    } finally {
      setPendingName(null);
    }
  };

  const onSelect = async (name: string): Promise<void> => {
    if (pendingName !== null || data === null || name === data.active) return;
    await performSwap(name);
  };

  const onStepUpSuccess = (): void => {
    setStepUpReason(null);
    const retry = pendingSwapRef.current;
    pendingSwapRef.current = null;
    if (retry !== null) void performSwap(retry);
  };

  const onStepUpClose = (): void => {
    setStepUpReason(null);
    pendingSwapRef.current = null;
  };

  if (loadError) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6">
        <h3 className="mb-1 text-sm font-semibold text-text-primary">
          L2 LLM Model
        </h3>
        <p className="text-xs text-critical">{loadError}</p>
      </section>
    );
  }
  if (data === null) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6 text-center text-text-dim">
        Loading models…
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-border bg-bg-surface p-6">
      <header className="mb-3 flex items-baseline justify-between gap-3">
        <div>
          <h3 className="flex items-baseline gap-2 text-sm font-semibold text-text-primary">
            L2 LLM Model
            <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
              (Super_Admin only)
            </span>
            <HelpTooltip>
              The L2 LLM is the optional intelligence layer that
              answers operator-triggered "Ask Octo" enrichment
              queries and (in a later slice) auto-triage decisions.
              Only super_admin can pick the active model; the
              factory super_admin is also required for model
              swap + restart actions (step-up auth + audit row per
              change). The model swap takes effect after restarting
              the octo-llm sibling — use the button to the right.
            </HelpTooltip>
          </h3>
          <p className="mt-0.5 text-xs text-text-dim">
            Active model loaded by octo-llm. Pick a different installed
            model below, then click Restart to apply.
          </p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <span className="font-mono text-[10px] text-text-dim">
            {data.models_dir}
          </span>
          <button
            type="button"
            onClick={() => void onRestart()}
            disabled={restarting}
            className={[
              "rounded-sm border px-2 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors",
              restarting
                ? "border-text-dim/40 bg-bg-card text-text-dim cursor-not-allowed"
                : "border-medium/60 bg-medium/5 text-medium hover:bg-medium/10",
            ].join(" ")}
            title="SIGTERM octo-llm. Respawn loop in dev.sh relaunches it within ~1s. In-flight enrichment calls fail-closed to heuristic during the restart window."
          >
            {restarting ? "restarting…" : "↻ restart octo-llm"}
          </button>
          {restartMsg && (
            <span
              className="max-w-[280px] text-right font-mono text-[9px] text-text-dim"
              title={restartMsg}
            >
              {restartMsg.length > 60 ? restartMsg.slice(0, 60) + "…" : restartMsg}
            </span>
          )}
        </div>
      </header>

      {/* Slice 7a — bundle-wide enable toggle.
          Controls the bundle_config.l2_llm_enabled flag that every
          operator's bridge call AND the Account-page status chip
          read. Super_admin-gated; the API rejects PUT for lower
          tiers. The UI rendering of the panel is also super_admin-
          only (Settings → System), so the toggle is unreachable
          for analyst+viewer. */}
      {bundleCfg !== null && (
        <div className="mb-4 flex items-start justify-between gap-4 rounded border border-border bg-bg-card p-3">
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium text-text-primary">
              Bundle-wide LLM enable
            </div>
            <div className="mt-1 text-xs text-text-dim">
              When off, NO operator on this bundle can reach octo-llm,
              regardless of their per-account preference or admin
              grant. Use as a global kill-switch.
            </div>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={bundleCfg.l2_llm_enabled}
            onClick={() => void onToggleBundle()}
            disabled={bundleSaving}
            className={[
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition-colors",
              bundleCfg.l2_llm_enabled
                ? "border-accent bg-accent/40"
                : "border-border bg-bg-card",
              bundleSaving ? "opacity-60" : "",
            ].join(" ")}
          >
            <span
              className={[
                "inline-block h-4 w-4 transform rounded-full bg-text-primary transition-transform",
                bundleCfg.l2_llm_enabled ? "translate-x-6" : "translate-x-1",
              ].join(" ")}
            />
          </button>
        </div>
      )}

      {/* Slice 7g — live sibling state. Surfaces WHY enrichment is
          failing when bundle/grant/preference are all on. Operator can
          tell at a glance: sibling unreachable / sibling in stub mode
          / model not loaded / fully healthy. */}
      {probe && (
        <div
          className={[
            "mb-4 rounded border p-3 text-xs",
            probe.reachable && probe.model_loaded
              ? "border-accent/30 bg-accent/5"
              : "border-medium/40 bg-medium/5",
          ].join(" ")}
        >
          <div className="mb-2 flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
              ·· octo-llm sibling ··
            </span>
            <span
              className={[
                "rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase",
                probe.reachable && probe.model_loaded
                  ? "border border-accent/60 text-accent"
                  : "border border-medium/60 text-medium",
              ].join(" ")}
            >
              {!probe.reachable
                ? "unreachable"
                : probe.model_loaded
                  ? "ready"
                  : "no model"}
            </span>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[10px]">
            <dt className="text-text-dim">url</dt>
            <dd className="break-all text-text-secondary">{probe.octo_llm_url}</dd>
            {probe.error && (
              <>
                <dt className="text-text-dim">error</dt>
                <dd className="text-critical">{probe.error}</dd>
              </>
            )}
            {probe.backend && (
              <>
                <dt className="text-text-dim">backend</dt>
                <dd className={probe.backend === "llama-cpp" ? "text-accent" : "text-text-dim"}>
                  {probe.backend}
                  {probe.backend === "stub" && (
                    <span className="ml-2 italic text-text-dim">
                      (stub returns canned text; set
                      OCTO_LLM_BACKEND=llama-cpp on dev.sh for real model)
                    </span>
                  )}
                </dd>
              </>
            )}
            {probe.model_version && (
              <>
                <dt className="text-text-dim">model_version</dt>
                <dd className="text-text-secondary">{probe.model_version}</dd>
              </>
            )}
            <dt className="text-text-dim">model_loaded</dt>
            <dd className={probe.model_loaded ? "text-accent" : "text-medium"}>
              {String(probe.model_loaded)}
            </dd>
            {probe.uptime_seconds !== null && (
              <>
                <dt className="text-text-dim">uptime</dt>
                <dd className="text-text-secondary">
                  {Math.round(probe.uptime_seconds)}s
                </dd>
              </>
            )}
            {probe.mem_used_mb !== null && (
              <>
                <dt className="text-text-dim">mem_used</dt>
                <dd className="text-text-secondary">{probe.mem_used_mb} MB</dd>
              </>
            )}
          </dl>
          {!probe.reachable && (
            <div className="mt-2 text-[10px] text-medium">
              Backend can't reach octo-llm at this URL. Verify the
              sibling process is running and the OCTO_LLM_URL env var
              points to it.
            </div>
          )}
          {probe.reachable && !probe.model_loaded && (
            <div className="mt-2 text-[10px] text-medium">
              octo-llm is up but reports no loaded model. Check
              OCTO_LLM_MODEL_PATH (llama-cpp backend) or restart with
              the correct env.
            </div>
          )}
        </div>
      )}

      {/* Slice 7k — unified dropdown. Merges the on-disk model list
          and the factory manifest selection into one control that
          scales as the catalog grows (download-broker UI in slice
          5d-4 will land new entries here without needing two
          parallel lists). Each option shows installed/not status +
          tier badge inline. Non-installed entries are disabled until
          the download broker ships. */}
      {(() => {
        // Build the union of (manifest entries + on-disk-only files
        // not in manifest). Manifest entries lead; on-disk extras
        // append. Dedup by name.
        type UnifiedEntry = {
          name: string;
          display_name: string;
          installed: boolean;
          tier: string | null;
          size_bytes: number;
          description: string;
          source: "manifest" | "on-disk";
          is_default: boolean;
        };
        const seen = new Set<string>();
        const entries: UnifiedEntry[] = [];
        if (manifest) {
          for (const m of manifest.models) {
            seen.add(m.name);
            entries.push({
              name: m.name,
              display_name: m.display_name || m.name,
              installed: m.installed,
              tier: m.tier,
              size_bytes: m.size_bytes_approx,
              description: m.description,
              source: "manifest",
              is_default: m.default,
            });
          }
        }
        for (const d of data.models) {
          if (seen.has(d.name)) continue;
          seen.add(d.name);
          entries.push({
            name: d.name,
            display_name: d.name,
            installed: true,
            tier: null,
            size_bytes: d.size_bytes,
            description: "Local GGUF (not in factory manifest).",
            source: "on-disk",
            is_default: false,
          });
        }

        if (entries.length === 0) {
          return (
            <div className="rounded border border-dashed border-border/60 bg-bg-card/40 px-3 py-4 text-center text-xs text-text-dim italic">
              No GGUF models found in {data.models_dir}. Run a factory
              download script or drop a .gguf manually into the path.
            </div>
          );
        }

        const activeEntry = entries.find((e) => e.name === data.active);

        return (
          <div className="flex flex-col gap-3">
            {/* The dropdown itself */}
            <div className="flex flex-col gap-1">
              <label className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
                active model
              </label>
              <select
                value={data.active}
                disabled={pendingName !== null}
                onChange={(e) => void onSelect(e.target.value)}
                className="rounded border border-border bg-bg-card px-3 py-2 font-mono text-[11px] text-text-primary focus:border-accent focus:outline-none"
              >
                {entries.map((e) => (
                  <option
                    key={e.name}
                    value={e.name}
                    disabled={!e.installed}
                  >
                    {e.display_name}
                    {e.tier ? ` [${e.tier}]` : ""}
                    {e.is_default ? " · default" : ""}
                    {e.installed ? "" : " — not installed"}
                  </option>
                ))}
              </select>
              {pendingName !== null && (
                <span className="font-mono text-[10px] text-text-dim">
                  …saving (factory + step-up required)
                </span>
              )}
            </div>

            {/* Active entry's full detail strip */}
            {activeEntry && (
              <div className="rounded border border-accent/30 bg-accent/5 p-3 text-xs">
                <div className="mb-1 flex items-baseline justify-between gap-3">
                  <span className="font-mono text-[11px] text-accent">
                    {activeEntry.display_name}
                  </span>
                  <span className="flex shrink-0 items-baseline gap-2 font-mono text-[10px]">
                    {activeEntry.tier && (
                      <span
                        className={[
                          "rounded-sm px-1.5 py-0.5 uppercase",
                          activeEntry.tier === "dev"
                            ? "border border-text-dim/40 text-text-dim"
                            : activeEntry.tier === "balanced"
                              ? "border border-accent/40 text-accent"
                              : "border border-medium/40 text-medium",
                        ].join(" ")}
                      >
                        {activeEntry.tier}
                      </span>
                    )}
                    <span
                      className={
                        activeEntry.installed ? "text-accent" : "text-medium"
                      }
                    >
                      {activeEntry.installed ? "✓ installed" : "not installed"}
                    </span>
                  </span>
                </div>
                <div className="text-[10px] leading-relaxed text-text-secondary">
                  {activeEntry.description}
                </div>
                <div className="mt-1 font-mono text-[9px] text-text-dim">
                  {fmtBytes(activeEntry.size_bytes)}
                  {" · "}
                  {activeEntry.source === "manifest" ? "factory" : "byom"}
                </div>
              </div>
            )}

            {/* Non-installed manifest entries — hint at the download
                broker that's still pending. */}
            {entries.some((e) => !e.installed) && (
              <div className="text-[10px] text-text-dim italic">
                Not-installed entries are disabled. Use{" "}
                <code className="font-mono text-text-secondary">
                  ./scripts/dev_download_&lt;name&gt;.sh
                </code>{" "}
                to install, or wait for the in-UI download button
                (slice 5d-4).
              </div>
            )}
          </div>
        );
      })()}

      {restartHint && (
        <div className="mt-3 rounded border border-medium/40 bg-medium/5 px-3 py-2 text-[11px] text-medium">
          Active model changed. <strong>Restart the octo-llm container</strong>
          {" "}so the new model loads. Until then, in-flight calls still hit
          the previously-loaded weights.
        </div>
      )}

      {error && (
        <div role="alert" className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-[11px] text-critical">
          {error}
        </div>
      )}

      <StepUpModal
        open={stepUpReason !== null}
        reason={stepUpReason ?? "required"}
        onClose={onStepUpClose}
        onSuccess={onStepUpSuccess}
      />
    </section>
  );
};


export default LlmModelsPanel;
export { LlmModelsPanel };
