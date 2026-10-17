/**
 * RetentionEnforcementStatus (Settings → System) — never-run, scheduled,
 * archive disabled / unusable / enabled, and a finished run with counts.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

import { RetentionEnforcementStatus } from "@/components/retention-status";
import type { RetentionResponse } from "@/lib/api";

afterEach(cleanup);

const BASE: RetentionResponse = { policies: [], note: "" };

describe("RetentionEnforcementStatus", () => {
  it("says plainly when nothing enforces retention", () => {
    render(<RetentionEnforcementStatus retention={BASE} />);
    const box = screen.getByTestId("retention-enforcement");
    expect(box).toHaveTextContent("retention has never been enforced on this bundle");
    expect(box).toHaveTextContent("not scheduled in this process");
    expect(box).toHaveTextContent("disabled — raw telemetry older than its retention is pruned without a copy");
  });

  it("shows the last run, the schedule and the archive", () => {
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          last_run: {
            run_id: "r-1", started_at: "2026-09-29T09:00:01.000Z",
            finished_at: "2026-09-29T09:00:07.000Z", trigger: "scheduler", status: "ok",
            archive_enabled: true, tenants: 3, deleted_total: 21870, error: null,
          },
          scheduler: { enabled: true, hour_utc: 9, next_run_at: "2026-09-30T09:00:00Z" },
          archive: { enabled: true, root: "/var/lib/octo/archive", usable: true, reason: null },
        }}
      />,
    );
    const box = screen.getByTestId("retention-enforcement");
    expect(box).toHaveTextContent("ok · 2026-09-29 09:00 UTC · scheduler · 21,870 rows deleted across 3 tenants");
    expect(box).toHaveTextContent("nightly at 09:00 UTC · next 2026-09-30 09:00 UTC");
    expect(box).toHaveTextContent("raw telemetry archived before pruning → /var/lib/octo/archive");
  });

  it("flags an unusable archive and a partial run", () => {
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          last_run: {
            run_id: "r-2", started_at: "2026-09-29T09:00:01.000Z", finished_at: null,
            trigger: "script", status: "partial", archive_enabled: true, tenants: 1,
            deleted_total: 1, error: "acme-corp: archive unusable",
          },
          archive: {
            enabled: true, root: "/var/lib/octo/archive", usable: false,
            reason: "archive root /var/lib/octo/archive does not exist (mount missing?)",
          },
        }}
      />,
    );
    const box = screen.getByTestId("retention-enforcement");
    expect(box).toHaveTextContent("partial");
    expect(box).toHaveTextContent("1 row deleted across 1 tenant");
    expect(box).toHaveTextContent("acme-corp: archive unusable");
    expect(box).toHaveTextContent("unusable — raw telemetry is NOT being pruned");
  });
});

describe("RetentionEnforcementStatus — evidence holds and the telemetry store", () => {
  it("says how many expired events were held as evidence", () => {
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          policies: [{
            data_class: "events", days: 365, editable: true, description: "", overridden: false,
            allowed_days: [], legal_baseline_days: 365, regulator_basis: "",
            last_run_deleted: 3, last_run_referenced: 2,
          }],
          last_run: {
            run_id: "r-3", started_at: "2026-09-29T09:00:01.000Z",
            finished_at: "2026-09-29T09:00:02.000Z", trigger: "scheduler", status: "ok",
            archive_enabled: false, tenants: 1, deleted_total: 3, error: null,
          },
        }}
      />,
    );
    expect(screen.getByTestId("retention-enforcement")).toHaveTextContent(
      "2 expired events held as evidence — a ticket, agent note, pattern link or incident cites them",
    );
    expect(screen.queryByTestId("retention-evidence-windows")).toBeNull();
  });

  it("says how many expired rows evidence windows kept, across every class", () => {
    const policy = (data_class: string, kept: number) => ({
      data_class, days: 7, editable: true, description: "", overridden: false,
      allowed_days: [], legal_baseline_days: 7, regulator_basis: "", last_run_deleted: 0,
      last_run_evidence: kept,
    });
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          policies: [policy("events", 3), policy("telemetry_raw", 1200), policy("audit", 0)],
          last_run: {
            run_id: "r-4", started_at: "2026-09-29T09:00:01.000Z",
            finished_at: "2026-09-29T09:00:02.000Z", trigger: "scheduler", status: "ok",
            archive_enabled: false, tenants: 1, deleted_total: 0, error: null,
          },
        }}
      />,
    );
    expect(screen.getByTestId("retention-evidence-windows")).toHaveTextContent(
      "1,203 expired rows kept inside evidence windows — a confirmed threat's first detection to its all-clear",
    );
  });

  it("warns when telemetry writes were refused, and is quiet when they were not", () => {
    const { rerender } = render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          telemetry_store: {
            recent_fallbacks: 4, window_hours: 24, last_fallback_at: "2026-09-29T08:15:02.000Z",
            tenants: { "acme-corp": 4 },
            last_sweep_moved: 10, last_sweep_errors: ["globex: OperationalError: disk I/O error"],
          },
        }}
      />,
    );
    const line = screen.getByTestId("retention-telemetry-store");
    expect(line).toHaveTextContent(
      "4 writes refused in the last 24 h (acme-corp), latest 2026-09-29 08:15 UTC",
    );
    expect(line).toHaveTextContent("last sweep failed: globex: OperationalError: disk I/O error");
    rerender(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          telemetry_store: {
            recent_fallbacks: 0, window_hours: 24, last_fallback_at: null, tenants: {},
            last_sweep_moved: 1, last_sweep_errors: [],
          },
        }}
      />,
    );
    expect(screen.getByTestId("retention-telemetry-store")).toHaveTextContent(
      "writes accepted · last sweep moved 1 fallback row",
    );
  });
  it("shows a refused scheduled run and an archive root open to others", () => {
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          scheduler: {
            enabled: true, hour_utc: 9, next_run_at: "2027-10-02T09:00:00Z",
            last_failure: "clock check: this run's clock is 367.0 days after the last run",
          },
          archive: {
            enabled: true, root: "/var/lib/octo/archive", usable: true, reason: null,
            warning: "archive root /var/lib/octo/archive is accessible to other users (mode 0755)",
          },
        }}
      />,
    );
    expect(screen.getByTestId("retention-schedule-failure")).toHaveTextContent(
      "last scheduled run failed — nothing was done: clock check: this run's clock is 367.0 days",
    );
    expect(screen.getByTestId("retention-archive-warning")).toHaveTextContent("mode 0755");
  });

  it("shows the archive's encryption: required, to whom, and the file counts", () => {
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          archive: {
            enabled: true, root: "/var/lib/octo/archive", usable: true, reason: null,
            encrypted: true, encryption_note: null,
            encryption: {
              mode: "required", source: "default", custody: "operator", scheme: "age-x25519",
              encrypted: true, recipients_path: "/var/lib/octo/secrets/archive-recipients.txt",
              recipients: [
                { short: "age1qyqszqgp…xmpl01", fingerprint: "0f1e2d3c4b5a6978" },
                { short: "age1zqgpqyqs…xmpl02", fingerprint: "8796a5b4c3d2e1f0" },
              ],
              error: null, note: null,
            },
            files: { plaintext: 3, encrypted: 12, complete: true },
          },
        }}
      />,
    );
    const line = screen.getByTestId("retention-archive-encryption");
    expect(line).toHaveTextContent(
      "required — new files encrypted (age X25519) to 2 recipients: age1qyqszqgp…xmpl01 (0f1e2d3c4b5a6978), age1zqgpqyqs…xmpl02 (8796a5b4c3d2e1f0)",
    );
    expect(line).toHaveTextContent("private key held by the operator, off this machine");
    expect(screen.getByTestId("retention-archive-files")).toHaveTextContent(
      "3 plaintext · 12 encrypted files — convert the plaintext ones with encrypt_archive.py",
    );
  });

  it("shows a required encryption that is unusable, and plaintext archives", () => {
    const encryption = {
      mode: "required", source: "env", custody: "operator", scheme: "age-x25519",
      encrypted: false, recipients_path: "/var/lib/octo/secrets/archive-recipients.txt",
      recipients: [], note: null,
      error: "recipients file /var/lib/octo/secrets/archive-recipients.txt does not exist",
    };
    const { rerender } = render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          archive: {
            enabled: true, root: "/var/lib/octo/archive", usable: false,
            reason: "archive encryption is required but unusable — recipients file missing",
            encrypted: false, encryption,
            files: { plaintext: 5, encrypted: 0, complete: true },
          },
        }}
      />,
    );
    expect(screen.getByTestId("retention-enforcement")).toHaveTextContent(
      "unusable — raw telemetry is NOT being pruned: archive encryption is required but unusable",
    );
    expect(screen.getByTestId("retention-archive-encryption")).toHaveTextContent(
      "required but UNUSABLE — nothing is archived or pruned: recipients file /var/lib/octo/secrets/archive-recipients.txt does not exist",
    );
    rerender(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          archive: {
            enabled: true, root: "/var/lib/octo/archive", usable: true, reason: null,
            encrypted: false,
            encryption_note:
              "archive NOT encrypted — OCTO_ARCHIVE_ENCRYPTION=off: new files are plaintext gzip",
            encryption: { ...encryption, mode: "off", error: null },
            files: { plaintext: 5, encrypted: 0, complete: false },
          },
        }}
      />,
    );
    const line = screen.getByTestId("retention-archive-encryption");
    expect(line).toHaveTextContent("archive NOT encrypted — OCTO_ARCHIVE_ENCRYPTION=off");
    expect(screen.getByTestId("retention-archive-files")).toHaveTextContent(
      "5 plaintext · 0 encrypted files (count incomplete)",
    );
    expect(screen.getByTestId("retention-archive-files")).not.toHaveTextContent("encrypt_archive.py");
  });

  it("says when plaintext files are temps an interrupted write left", () => {
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          archive: {
            enabled: true, root: "/var/lib/octo/archive", usable: true, reason: null,
            encrypted: true, encryption_note: null,
            encryption: {
              mode: "required", source: "archive", custody: "operator", scheme: "age-x25519",
              encrypted: true, recipients_path: "/var/lib/octo/secrets/archive-recipients.txt",
              recipients: [{ short: "age1qyqszqgp…xmpl01", fingerprint: "0f1e2d3c4b5a6978" }],
              error: null, note: null,
            },
            files: { plaintext: 2, encrypted: 9, plaintext_temp: 2, complete: true },
          },
        }}
      />,
    );
    expect(screen.getByTestId("retention-archive-files")).toHaveTextContent(
      "2 plaintext · 9 encrypted files — 2 of the plaintext are temp files interrupted writes left (plaintext rows inside): encrypt_archive.py --delete-plaintext removes them",
    );
  });

  it("shows neither line when there is nothing to say", () => {
    render(
      <RetentionEnforcementStatus
        retention={{
          ...BASE,
          scheduler: { enabled: true, hour_utc: 9, next_run_at: null, last_failure: null },
          archive: { enabled: true, root: "/a", usable: true, reason: null, warning: null },
        }}
      />,
    );
    expect(screen.queryByTestId("retention-schedule-failure")).not.toBeInTheDocument();
    expect(screen.queryByTestId("retention-archive-warning")).not.toBeInTheDocument();
  });
});
