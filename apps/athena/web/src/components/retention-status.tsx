/**
 * RetentionEnforcementStatus — Settings → System: is retention actually
 * enforced, when did it last run and what did it delete, when is the next
 * run, and is raw telemetry archived before it is pruned (migration 036).
 *
 * Says plainly when retention has never been enforced, when the nightly
 * schedule is off, and when the cold archive is disabled or unusable — the
 * states that used to be invisible ("retention is policy only") — and
 * whether the archive is encrypted (2026-10-07).
 */
import type { FC } from "react";

import type { RetentionResponse } from "@/lib/api";

const STATUS_TONE: Record<string, string> = {
  ok: "text-accent",
  partial: "text-warning",
  failed: "text-critical",
  running: "text-text-secondary",
};

export const RetentionEnforcementStatus: FC<{ retention: RetentionResponse }> = ({ retention }) => {
  const run = retention.last_run ?? null;
  const sched = retention.scheduler;
  const archive = retention.archive;
  const store = retention.telemetry_store;
  const held = retention.policies.find((p) => p.data_class === "events")?.last_run_referenced ?? 0;
  // Every class: rows kept inside an evidence window (a confirmed threat's
  // first detection → its all-clear, until an admin releases it).
  const windowed = retention.policies.reduce((n, p) => n + (p.last_run_evidence ?? 0), 0);
  return (
    <div
      data-testid="retention-enforcement"
      className="mb-3 grid gap-1 rounded-sm border border-border bg-bg-card px-3 py-2 font-mono text-[10px] leading-relaxed"
    >
      <div>
        <span className="uppercase tracking-wider text-text-dim">last run · </span>
        {run ? (
          <>
            <span className={STATUS_TONE[run.status] ?? "text-text-secondary"}>{run.status}</span>
            <span className="text-text-secondary">
              {" "}· {run.started_at.replace("T", " ").slice(0, 16)} UTC · {run.trigger} ·{" "}
              {run.deleted_total.toLocaleString("en-US")} row{run.deleted_total === 1 ? "" : "s"} deleted
              across {run.tenants} tenant{run.tenants === 1 ? "" : "s"}
            </span>
            {held > 0 && (
              <div className="text-text-secondary">
                {held.toLocaleString("en-US")} expired event{held === 1 ? "" : "s"} held as
                evidence — a ticket, agent note, pattern link or incident cites{" "}
                {held === 1 ? "it" : "them"}
              </div>
            )}
            {windowed > 0 && (
              <div className="text-text-secondary" data-testid="retention-evidence-windows">
                {windowed.toLocaleString("en-US")} expired row{windowed === 1 ? "" : "s"} kept
                inside evidence windows — a confirmed threat&apos;s first detection to its
                all-clear, until an admin releases the window (Settings → Threats)
              </div>
            )}
            {run.error && <div className="text-warning">{run.error}</div>}
          </>
        ) : (
          <span className="text-warning">
            retention has never been enforced on this bundle
          </span>
        )}
      </div>
      <div>
        <span className="uppercase tracking-wider text-text-dim">schedule · </span>
        {sched?.enabled ? (
          <span className="text-text-secondary">
            nightly at {String(sched.hour_utc ?? 0).padStart(2, "0")}:00 UTC
            {sched.next_run_at ? ` · next ${sched.next_run_at.replace("T", " ").slice(0, 16)} UTC` : ""}
          </span>
        ) : (
          <span className="text-warning">
            not scheduled in this process (OCTO_RETENTION_SCHEDULE is off) — runs only when started by hand
          </span>
        )}
        {sched?.last_failure && (
          <div data-testid="retention-schedule-failure" className="text-critical">
            last scheduled run failed — nothing was done: {sched.last_failure}
          </div>
        )}
      </div>
      {store && (
        <div data-testid="retention-telemetry-store">
          <span className="uppercase tracking-wider text-text-dim">telemetry store · </span>
          {store.recent_fallbacks > 0 || store.last_sweep_errors.length > 0 ? (
            <span className="text-warning">
              {store.recent_fallbacks > 0 &&
                `${store.recent_fallbacks.toLocaleString("en-US")} write${
                  store.recent_fallbacks === 1 ? "" : "s"
                } refused in the last ${store.window_hours} h (${Object.keys(store.tenants).join(", ")})${
                  store.last_fallback_at
                    ? `, latest ${store.last_fallback_at.replace("T", " ").slice(0, 16)} UTC`
                    : ""
                } — stored with the events, moved by the nightly sweep`}
              {store.last_sweep_errors.length > 0 &&
                ` · last sweep failed: ${store.last_sweep_errors.join("; ")}`}
            </span>
          ) : (
            <span className="text-text-secondary">
              writes accepted
              {store.last_sweep_moved
                ? ` · last sweep moved ${store.last_sweep_moved.toLocaleString("en-US")} fallback row${
                    store.last_sweep_moved === 1 ? "" : "s"
                  }`
                : ""}
            </span>
          )}
        </div>
      )}
      <div>
        <span className="uppercase tracking-wider text-text-dim">cold archive · </span>
        {archive?.enabled ? (
          archive.usable === false ? (
            <span className="text-critical">
              unusable — raw telemetry is NOT being pruned: {archive.reason}
            </span>
          ) : (
            <span className="text-text-secondary">
              raw telemetry archived before pruning → {archive.root}
            </span>
          )
        ) : (
          <span className="text-warning">
            disabled — raw telemetry older than its retention is pruned without a copy
          </span>
        )}
        {archive?.enabled && archive.warning && (
          <div data-testid="retention-archive-warning" className="text-warning">
            {archive.warning}
          </div>
        )}
        {archive?.enabled && <ArchiveEncryptionLine archive={archive} />}
      </div>
    </div>
  );
};

/** Archive encryption (age, X25519 — 2026-10-07): required and to whom
 *  (public-key short forms + fingerprints only), required but unusable (the
 *  archive then prunes nothing), or plaintext ("archive NOT encrypted");
 *  plus how many files are plaintext vs encrypted. */
const ArchiveEncryptionLine: FC<{ archive: NonNullable<RetentionResponse["archive"]> }> = ({
  archive,
}) => {
  const enc = archive.encryption;
  const files = archive.files;
  if (!enc) return null;
  return (
    <div data-testid="retention-archive-encryption">
      <span className="uppercase tracking-wider text-text-dim">encryption · </span>
      {enc.mode === "required" ? (
        enc.encrypted ? (
          <span className="text-text-secondary">
            required — new files encrypted (age X25519) to {enc.recipients.length} recipient
            {enc.recipients.length === 1 ? "" : "s"}:{" "}
            {enc.recipients.map((r) => `${r.short} (${r.fingerprint})`).join(", ")} · private key
            held by the operator, off this machine
          </span>
        ) : (
          <span className="text-critical">
            required but UNUSABLE — nothing is archived or pruned: {enc.error}
          </span>
        )
      ) : (
        <span className="text-warning">
          {archive.encryption_note ?? enc.note ?? "archive NOT encrypted"}
        </span>
      )}
      {enc.mode !== "required" && enc.recipients_error && (
        <div className="text-warning">recipients file: {enc.recipients_error}</div>
      )}
      {files && (
        <div className="text-text-secondary" data-testid="retention-archive-files">
          {files.plaintext.toLocaleString("en-US")} plaintext ·{" "}
          {files.encrypted.toLocaleString("en-US")} encrypted file
          {files.encrypted === 1 ? "" : "s"}
          {files.complete ? "" : " (count incomplete)"}
          {files.plaintext_temp
            ? ` — ${files.plaintext_temp.toLocaleString("en-US")} of the plaintext are temp files interrupted writes left (plaintext rows inside): encrypt_archive.py --delete-plaintext removes them`
            : ""}
          {files.plaintext > 0 && enc.encrypted
            ? " — convert the plaintext ones with encrypt_archive.py (dry run → apply → verify → delete)"
            : ""}
        </div>
      )}
    </div>
  );
};

export default RetentionEnforcementStatus;
