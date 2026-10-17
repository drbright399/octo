import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import SystemTab from "@/pages/settings/system";

/**
 * Settings → System retention change (v0.11): the nightly job ENFORCES the
 * value, so the PATCH is step-up gated server-side. A 401 STEP_UP_REQUIRED
 * opens the re-auth dialog (not a dead error); after re-auth the change is
 * retried. Any other error is shown as its message. Real page, stubbed fetch.
 */

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const STATS = {
  tenants: [], globals: [],
  disk: { total_bytes: 10 ** 12, used_bytes: 10 ** 11, free_bytes: 9 * 10 ** 11,
          data_root_bytes: 1, used_pct: 10, mount_point: "/", mount_device: null,
          quota_bytes: null, used_pct_against_quota: null },
  snapshot_at: "2026-09-29T12:00:00.000Z",
};

const RETENTION = {
  policies: [{
    data_class: "telemetry_raw", days: 7, editable: true, description: "Raw DNS",
    allowed_days: [7, 14, 30, 90], legal_baseline_days: 7, regulator_basis: "Operational",
    effective_days: 7, floored: false, enforced: true, last_run_deleted: null,
    last_run_referenced: null,
  }],
  note: "", last_run: null, scheduler: { enabled: false },
  archive: { enabled: false, root: null, usable: null, reason: "" }, telemetry_store: null,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

function wire(patch: () => ReturnType<typeof jsonResponse>) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = (init?.method ?? "GET").toUpperCase();
    if (url === "/api/v1/admin/data/storage-stats") return jsonResponse(200, STATS);
    if (url === "/api/v1/admin/data/retention") return jsonResponse(200, RETENTION);
    if (url === "/api/v1/admin/data/retention/telemetry_raw" && method === "PATCH") {
      calls.push("patch");
      return patch();
    }
    if (url.includes("/search/elevate")) {
      calls.push("elevate");
      return jsonResponse(200, { elevated: true });
    }
    return jsonResponse(404, {});
  }));
  return calls;
}

async function confirmChangeTo(days: string) {
  render(<SystemTab />);
  const select = await screen.findByLabelText("Retention for telemetry_raw");
  fireEvent.change(select, { target: { value: days } });
  fireEvent.click(await screen.findByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: /confirm change/i }));
}

describe("retention change needs step-up", () => {
  it("opens the re-auth dialog on STEP_UP_REQUIRED and retries after it", async () => {
    let first = true;
    const calls = wire(() => {
      if (first) {
        first = false;
        return jsonResponse(401, { code: "STEP_UP_REQUIRED", message: "step-up required" });
      }
      return jsonResponse(200, { data_class: "telemetry_raw", retention_days: 14,
                                 previous_days: 7, updated_at: "2026-09-29T12:00:00Z" });
    });
    await confirmChangeTo("14");
    await waitFor(() =>
      expect(screen.getByText(/Re-authentication required/i)).toBeInTheDocument());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw1234567890" } });
    fireEvent.change(screen.getByLabelText(/code/i), { target: { value: "123456" } });
    fireEvent.submit(screen.getByLabelText(/password/i).closest("form")!);
    await waitFor(() => expect(calls).toEqual(["patch", "elevate", "patch"]));
    await waitFor(() =>
      expect(screen.queryByText(/retention change · disclosure/i)).not.toBeInTheDocument());
  });

  it("shows any other error as its message, without a re-auth prompt", async () => {
    wire(() => jsonResponse(422, { code: "VALIDATION_FAILED", message: "not in allowed set" }));
    await confirmChangeTo("30");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("not in allowed set"));
    expect(screen.queryByText(/Re-authentication required/i)).not.toBeInTheDocument();
  });
});
