/**
 * Settings → System (super_admin only).
 *
 * Today's surface is **Data Management** — storage stats per tenant +
 * global DB stats + disk capacity + retention timeframes, with the
 * enforcement status of the nightly retention job (migration 036).
 *
 * Future sub-panels on this same tab:
 *   - MSP branding
 *   - Bundle config (one bundle per MSP)
 *   - Octopus telemetry opt-in
 *   - Octo-updater control (Task #26)
 *
 * Access: super_admin only. Below-tier callers get 403 from the
 * backend; the SettingsPage tab visibility gate also hides it from
 * non-super_admin nav.
 */
import { type FC, useCallback, useEffect, useState } from "react";
import {
  ApiError,
  fetchStorageStats,
  fetchRetention,
  formatRowCount,
  patchRetention,
  type StorageStatsResponse,
  type RetentionResponse,
  type RetentionPolicy,
} from "@/lib/api";
import { LlmModelsPanel } from "@/components/llm-models-panel";
import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";
import { RetentionEnforcementStatus } from "@/components/retention-status";

// Auto-refresh interval for storage stats. 30s is a fair tradeoff —
// fast enough to see disk fills during heavy ingest, slow enough not
// to thrash the audit log with super_admin's open-tab. Refresh ONLY
// while the tab is visible (visibilitychange) so an idle browser
// doesn't keep auditing.
const AUTO_REFRESH_MS = 30_000;

const SystemTab: FC = () => {
  const [stats, setStats] = useState<StorageStatsResponse | null>(null);
  const [retention, setRetention] = useState<RetentionResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const refresh = useCallback(async (initial = false): Promise<void> => {
    if (!initial) setRefreshing(true);
    try {
      const [s, r] = await Promise.all([fetchStorageStats(), fetchRetention()]);
      setStats(s);
      setRetention(r);
      setLastRefresh(new Date());
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      if (initial) setLoading(false);
      else setRefreshing(false);
    }
  }, []);

  useEffect(() => { void refresh(true); }, [refresh]);

  // Auto-refresh on a 30s tick while the tab is in the foreground.
  // Hidden tabs skip — `document.visibilityState !== "visible"`.
  useEffect(() => {
    const tick = (): void => {
      if (document.visibilityState === "visible") void refresh();
    };
    const id = window.setInterval(tick, AUTO_REFRESH_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  if (loading) {
    return <div className="p-8 text-center text-xs text-text-dim">·· loading system view ··</div>;
  }
  if (err && !stats) {
    return (
      <div role="alert" className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">
        {err}
      </div>
    );
  }

  return (
    <section className="flex flex-col gap-6" aria-labelledby="system-title">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="system-title" className="text-sm font-semibold text-text-primary">
            System
          </h2>
          <p className="text-xs leading-relaxed text-text-secondary">
            super_admin surface for storage, retention, and bundle-level
            config. Every fetch and (future) write is audit-logged.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] text-text-dim">
          <span aria-live="polite">
            {refreshing
              ? "·· refreshing ··"
              : lastRefresh
                ? `auto-refresh · last ${lastRefresh.toLocaleTimeString()}`
                : ""}
          </span>
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={refreshing}
            className="rounded-sm border border-border bg-bg-card px-2 py-0.5 uppercase tracking-wider text-text-secondary hover:border-border-bright hover:text-text-primary disabled:opacity-50"
          >
            ↻ refresh
          </button>
        </div>
      </header>

      {err && stats && (
        <div role="alert" className="rounded-sm border border-high/40 bg-high/10 px-3 py-2 text-[11px] text-high">
          Refresh failed: {err} · showing last successful snapshot.
        </div>
      )}

      {stats && <DiskOverview stats={stats} />}
      {stats && <TenantStorageTable stats={stats} />}
      {stats && <GlobalsTable stats={stats} />}
      {retention && (
        <RetentionTable
          retention={retention}
          onApplied={() => void refresh()}
        />
      )}
      <LlmModelsPanel />
    </section>
  );
};

/* -------------------------------------------------------------------- */

const DiskOverview: FC<{ stats: StorageStatsResponse }> = ({ stats }) => {
  const { disk } = stats;
  const hasQuota = disk.quota_bytes !== null && disk.used_pct_against_quota !== null;
  return (
    <div className="rounded-sm border border-border bg-bg-surface p-4">
      <div className="mb-2 flex items-baseline justify-between">
        <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
          ·· disk ··
        </span>
        <span className="font-mono text-[10px] text-text-dim">
          snapshot {stats.snapshot_at}
        </span>
      </div>

      {/* Mount point + device, when the backend could resolve it.
          Helps cloud/self-hosted operators correlate this report with
          their attached volume / VM disk. */}
      {(disk.mount_point || disk.mount_device) && (
        <div className="mb-3 font-mono text-[10px] leading-relaxed text-text-dim">
          <div>
            mount: <span className="text-text-secondary">{disk.mount_point ?? "—"}</span>
            {disk.mount_device && (
              <> · device: <span className="text-text-secondary">{disk.mount_device}</span></>
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px] sm:grid-cols-4">
        <Stat label="total" value={fmtBytes(disk.total_bytes)} />
        <Stat label="used" value={fmtBytes(disk.used_bytes)} />
        <Stat label="free" value={fmtBytes(disk.free_bytes)} />
        <Stat label="data_root" value={fmtBytes(disk.data_root_bytes)} />
      </div>

      {/* Raw volume usage bar. When a quota is declared, this stays
          as the secondary 'whole-volume' line; the primary bar below
          becomes the bundle's own allocated-cap measurement. */}
      <div className="mt-3 h-2 w-full overflow-hidden rounded-sm border border-border bg-bg-card">
        <div
          className={[
            "h-full",
            disk.used_pct >= 90 ? "bg-critical"
              : disk.used_pct >= 75 ? "bg-high"
              : "bg-accent",
          ].join(" ")}
          style={{ width: `${Math.min(100, disk.used_pct)}%` }}
          aria-label={`Volume ${disk.used_pct}% used`}
        />
      </div>
      <div className="mt-1 text-right font-mono text-[10px] text-text-dim">
        {disk.used_pct.toFixed(1)}% of volume
      </div>

      {hasQuota && (
        <>
          <div className="mt-3 font-mono text-[10px] uppercase tracking-wider text-text-dim">
            bundle quota · {fmtBytes(disk.quota_bytes!)} allocated
          </div>
          <div className="mt-1 h-2 w-full overflow-hidden rounded-sm border border-border bg-bg-card">
            <div
              className={[
                "h-full",
                disk.used_pct_against_quota! >= 90 ? "bg-critical"
                  : disk.used_pct_against_quota! >= 75 ? "bg-high"
                  : "bg-accent",
              ].join(" ")}
              style={{ width: `${Math.min(100, disk.used_pct_against_quota!)}%` }}
              aria-label={`Bundle ${disk.used_pct_against_quota}% of quota used`}
            />
          </div>
          <div className="mt-1 text-right font-mono text-[10px] text-text-dim">
            {disk.used_pct_against_quota!.toFixed(1)}% of allocated quota
          </div>
        </>
      )}
    </div>
  );
};

const TenantStorageTable: FC<{ stats: StorageStatsResponse }> = ({ stats }) => (
  <div className="rounded-sm border border-border bg-bg-surface p-4">
    <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-text-dim">
      ·· per-tenant storage ··
    </div>
    {stats.tenants.length === 0 ? (
      <div className="text-xs text-text-dim">no tenants registered</div>
    ) : (
      <table className="w-full text-[11px] font-mono">
        <thead>
          <tr className="border-b border-border text-left text-text-dim">
            <th className="px-2 py-1">tenant</th>
            <th className="px-2 py-1 text-right">events</th>
            <th className="px-2 py-1 text-right">indicators</th>
            <th className="px-2 py-1 text-right">audit</th>
            <th className="px-2 py-1 text-right" title="DNS / flow telemetry (raw 7 days, hourly counts 180 days)">telemetry</th>
            <th className="px-2 py-1 text-right">total</th>
            <th className="px-2 py-1 text-right">events rows</th>
          </tr>
        </thead>
        <tbody>
          {stats.tenants.map((t) => {
            const e = t.dbs.find((d) => d.name === "events");
            const i = t.dbs.find((d) => d.name === "indicators");
            const a = t.dbs.find((d) => d.name === "audit");
            const tel = t.dbs.find((d) => d.name === "telemetry");
            return (
              <tr key={t.slug} className="border-b border-border/40">
                <td className="px-2 py-1">
                  <div className="text-text-primary">{t.display_name ?? t.slug}</div>
                  <div className="text-[10px] text-text-dim">{t.slug} · {t.status}</div>
                </td>
                <td className="px-2 py-1 text-right">{fmtBytes(e?.size_bytes ?? 0)}</td>
                <td className="px-2 py-1 text-right">{fmtBytes(i?.size_bytes ?? 0)}</td>
                <td className="px-2 py-1 text-right">{fmtBytes(a?.size_bytes ?? 0)}</td>
                <td className="px-2 py-1 text-right">{tel ? fmtBytes(tel.size_bytes) : "—"}</td>
                <td className="px-2 py-1 text-right text-text-primary">
                  {fmtBytes(t.total_size_bytes)}
                </td>
                <td
                  className="px-2 py-1 text-right"
                  data-testid={`tenant-rows-${t.slug}`}
                  title={e?.row_count_exact === false
                    ? "Estimated (large file): rowid span × sampled density"
                    : undefined}
                >
                  {formatRowCount(e)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    )}
  </div>
);

const GlobalsTable: FC<{ stats: StorageStatsResponse }> = ({ stats }) => (
  <div className="rounded-sm border border-border bg-bg-surface p-4">
    <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-text-dim">
      ·· global databases ··
    </div>
    <table className="w-full text-[11px] font-mono">
      <thead>
        <tr className="border-b border-border text-left text-text-dim">
          <th className="px-2 py-1">db</th>
          <th className="px-2 py-1 text-right">size</th>
          <th className="px-2 py-1 text-right">rows</th>
          <th className="px-2 py-1">last modified</th>
        </tr>
      </thead>
      <tbody>
        {stats.globals.map((g) => (
          <tr key={g.name} className="border-b border-border/40">
            <td className="px-2 py-1 text-text-primary">{g.name}</td>
            <td className="px-2 py-1 text-right">{fmtBytes(g.size_bytes)}</td>
            <td
              className="px-2 py-1 text-right"
              data-testid={`global-rows-${g.name}`}
              title={g.row_count_exact === false
                ? "Estimated (large file): rowid span × sampled density"
                : undefined}
            >
              {formatRowCount(g)}
            </td>
            <td className="px-2 py-1 text-text-dim">{g.last_modified ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const RetentionTable: FC<{
  retention: RetentionResponse;
  onApplied: () => void;
}> = ({ retention, onApplied }) => (
  <div className="rounded-sm border border-border bg-bg-surface p-4">
    <div className="mb-2 flex items-baseline justify-between">
      <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
        ·· retention timeframes ··
      </span>
      <span className="font-mono text-[10px] text-text-dim">super_admin · audit-logged</span>
    </div>
    <p className="mb-3 text-[11px] leading-relaxed text-text-secondary">
      {retention.note}
    </p>
    <RetentionEnforcementStatus retention={retention} />
    <div className="flex flex-col gap-1">
      {retention.policies.map((p) => (
        <RetentionRow key={p.data_class} policy={p} onApplied={onApplied} />
      ))}
    </div>
  </div>
);

const RetentionRow: FC<{
  policy: RetentionPolicy;
  onApplied: () => void;
}> = ({ policy, onApplied }) => {
  const [pending, setPending] = useState<number | null>(null);

  // A pick doesn't apply directly — it queues the value for the
  // disclosure modal, which is the only path that can reach the
  // backend PATCH. This is the "edit is a knowing-act" gate the spec
  // calls for: even matching the regulator baseline still surfaces
  // the modal so super_admin sees the citation in writing.
  const openModal = (days: number): void => {
    if (days === policy.days) return;
    setPending(days);
  };

  const belowBaseline =
    policy.legal_baseline_days !== null
    && policy.days !== null
    && policy.days < policy.legal_baseline_days;

  return (
    <>
      <div className="flex items-start gap-3 rounded-sm border border-border bg-bg-card px-3 py-2 text-[11px]">
        <div className="w-36 shrink-0">
          <div className="font-mono uppercase tracking-wider text-accent">
            {policy.data_class.replace(/_/g, " ")}
          </div>
          <div className="mt-1 font-mono text-[10px] text-text-dim">
            {policy.days === null ? "permanent" : `${policy.days} days`}
            {!policy.editable && " · regulator"}
          </div>
          {belowBaseline && (
            <div
              className="mt-1 font-mono text-[10px] text-critical"
              title={`Regulator baseline is ${policy.legal_baseline_days} days. Current setting is below baseline.`}
            >
              ⚠ below baseline ({policy.legal_baseline_days}d)
            </div>
          )}
          {policy.floored && policy.effective_days != null && (
            <div
              className="mt-1 font-mono text-[10px] text-text-dim"
              title="The retention job never deletes below the legal baseline."
            >
              enforced at {policy.effective_days}d (baseline floor)
            </div>
          )}
          {policy.enforced === false && policy.days !== null && (
            <div className="mt-1 font-mono text-[10px] text-text-dim">not enforced · no store yet</div>
          )}
          {policy.last_run_deleted != null && policy.enforced !== false && (
            <div className="mt-1 font-mono text-[10px] text-text-dim">
              last run: {policy.last_run_deleted.toLocaleString("en-US")} deleted
            </div>
          )}
        </div>
        <div className="flex-1 leading-relaxed text-text-secondary">
          {policy.description}
          {policy.regulator_basis && (
            <div className="mt-1 font-mono text-[10px] text-text-dim">
              basis: {policy.regulator_basis}
            </div>
          )}
        </div>
        {policy.editable && policy.allowed_days.length > 0 && (
          <div className="shrink-0 self-center">
            <select
              aria-label={`Retention for ${policy.data_class}`}
              value={policy.days ?? ""}
              onChange={(e) => openModal(Number(e.target.value))}
              className={[
                "cursor-pointer rounded-sm border bg-bg-surface px-2 py-1 font-mono text-[10px] transition-colors hover:border-border-bright focus:border-accent focus:outline-none",
                belowBaseline
                  ? "border-critical/60 text-critical"
                  : "border-accent/60 text-accent",
              ].join(" ")}
            >
              {policy.allowed_days.map((d) => (
                <option key={d} value={d} className="bg-bg-surface text-text-primary">
                  {d}d
                </option>
              ))}
            </select>
          </div>
        )}
      </div>
      {pending !== null && (
        <RetentionDisclosureModal
          policy={policy}
          proposed={pending}
          onCancel={() => setPending(null)}
          onConfirmed={() => {
            setPending(null);
            onApplied();
          }}
        />
      )}
    </>
  );
};

const RetentionDisclosureModal: FC<{
  policy: RetentionPolicy;
  proposed: number;
  onCancel: () => void;
  onConfirmed: () => void;
}> = ({ policy, proposed, onCancel, onConfirmed }) => {
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // v0.11: the nightly job ENFORCES this value, so the change needs a fresh
  // re-authentication (server: 401 STEP_UP_REQUIRED) — prompt, then retry.
  const [stepUp, setStepUp] = useState<StepUpReason | null>(null);

  const baseline = policy.legal_baseline_days;
  const belowBaseline = baseline !== null && proposed < baseline;
  const aboveBaseline = baseline !== null && proposed > baseline;

  const apply = async (): Promise<void> => {
    setBusy(true);
    setErr(null);
    try {
      await patchRetention(policy.data_class, proposed);
      onConfirmed();
    } catch (e) {
      if (e instanceof ApiError
          && (e.code === "STEP_UP_REQUIRED" || e.code === "STEP_UP_NETWORK_CHANGED")) {
        setStepUp(e.code === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
      } else {
        setErr(e instanceof Error ? e.message : String(e));
      }
      setBusy(false);
    }
  };

  const onConfirm = async (): Promise<void> => {
    if (!ack || busy) return;
    await apply();
  };

  return (
    <>
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="retention-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onClick={onCancel}
    >
      <div
        className={[
          "w-full max-w-lg rounded-sm border bg-bg-surface p-5 font-mono text-[12px]",
          belowBaseline ? "border-critical" : "border-accent",
        ].join(" ")}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-baseline justify-between">
          <h2
            id="retention-modal-title"
            className="text-[11px] uppercase tracking-widest text-accent"
          >
            ·· retention change · disclosure ··
          </h2>
          <span className="text-[10px] text-text-dim">audit-logged</span>
        </div>

        <div className="mb-3 grid grid-cols-2 gap-3 rounded-sm border border-border bg-bg-card p-3 text-[11px]">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">data class</div>
            <div className="text-text-primary">{policy.data_class}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">regulator baseline</div>
            <div className="text-text-primary">
              {baseline === null ? "n/a" : `${baseline} days`}
            </div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">current</div>
            <div className="text-text-primary">
              {policy.days === null ? "permanent" : `${policy.days} days`}
            </div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-dim">proposed</div>
            <div
              className={belowBaseline ? "text-critical" : "text-text-primary"}
            >
              {proposed} days
            </div>
          </div>
        </div>

        {policy.regulator_basis && (
          <p className="mb-3 text-[11px] leading-relaxed text-text-secondary">
            <span className="text-text-dim">basis: </span>
            {policy.regulator_basis}
          </p>
        )}

        {belowBaseline && (
          <p className="mb-3 rounded-sm border border-critical/40 bg-critical/10 p-2 text-[11px] leading-relaxed text-critical">
            This value is BELOW the regulator baseline. Reducing
            retention here may put MSP customers out of compliance with
            HIPAA / SOC2 / CJIS recordkeeping requirements. Only
            proceed if you have explicit, documented authorization from
            the affected tenants' compliance officer.
          </p>
        )}
        {aboveBaseline && (
          <p className="mb-3 rounded-sm border border-border bg-bg-card p-2 text-[11px] leading-relaxed text-text-secondary">
            This value is ABOVE the regulator baseline. Storage cost
            and PII exposure window will grow proportionally; confirm
            this matches the deployed bundle's storage budget.
          </p>
        )}
        {!belowBaseline && !aboveBaseline && baseline !== null && (
          <p className="mb-3 text-[11px] leading-relaxed text-text-secondary">
            This value matches the regulator baseline. The change is
            still audit-logged.
          </p>
        )}

        <label className="mb-3 flex items-start gap-2 text-[11px] leading-relaxed text-text-secondary">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
            className="mt-0.5 h-3.5 w-3.5 accent-accent"
          />
          <span>
            I acknowledge this retention change, understand that it is
            recorded in the append-only audit log against my operator
            account, and confirm I have authority to make it.
          </span>
        </label>

        {err && (
          <div role="alert" className="mb-3 rounded-sm border border-critical/40 bg-critical/10 p-2 text-[11px] text-critical">
            {err}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded-sm border border-border bg-bg-card px-3 py-1 text-[11px] uppercase tracking-wider text-text-secondary hover:border-border-bright"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void onConfirm()}
            disabled={!ack || busy}
            className={[
              "rounded-sm border px-3 py-1 text-[11px] uppercase tracking-wider transition-colors",
              ack && !busy
                ? belowBaseline
                  ? "border-critical bg-critical text-white hover:bg-critical/80"
                  : "border-accent bg-accent text-text-on-accent hover:bg-accent/80"
                : "cursor-not-allowed border-border bg-bg-card text-text-dim",
            ].join(" ")}
          >
            {busy ? "applying..." : "Confirm change"}
          </button>
        </div>
      </div>
    </div>
    {/* A sibling, not a child: a click inside it must not reach the
        disclosure's backdrop (which cancels). */}
    <StepUpModal
      open={stepUp !== null}
      reason={stepUp ?? "required"}
      onClose={() => setStepUp(null)}
      onSuccess={() => {
        setStepUp(null);
        void apply();
      }}
    />
    </>
  );
};

const Stat: FC<{ label: string; value: string }> = ({ label, value }) => (
  <div>
    <div className="text-[10px] uppercase tracking-widest text-text-dim">{label}</div>
    <div className="text-text-primary">{value}</div>
  </div>
);

function fmtBytes(b: number): string {
  if (b === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log10(b) / 3));
  const v = b / 1000 ** i;
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}

export default SystemTab;
