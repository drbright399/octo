import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import SystemTab from "@/pages/settings/system";
import { formatRowCount } from "@/lib/api";

/**
 * Settings → System storage tables (v0.11 S1): a DB over the exact-count
 * gate shows a fast ESTIMATE marked "≈" instead of "—"; exact counts stay
 * exact. The real page runs against a stubbed fetch.
 */

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const STATS = {
  tenants: [{
    slug: "acme-corp", display_name: "Acme Corp", status: "active", total_size_bytes: 3_000_000_000,
    dbs: [
      { name: "events", size_bytes: 2_900_000_000, row_count_estimate: 1_234_000,
        row_count_exact: false, last_modified: null },
      { name: "indicators", size_bytes: 1_000_000, row_count_estimate: 40,
        row_count_exact: true, last_modified: null },
    ],
  }, {
    slug: "globex", display_name: "Globex", status: "active", total_size_bytes: 10_000,
    dbs: [{ name: "events", size_bytes: 10_000, row_count_estimate: 12,
            row_count_exact: true, last_modified: null }],
  }],
  globals: [
    { name: "registry", size_bytes: 500_000, row_count_estimate: 7, row_count_exact: true,
      last_modified: null },
    { name: "audit", size_bytes: 400_000_000, row_count_estimate: 2_000_000,
      row_count_exact: false, last_modified: null },
    { name: "patterns", size_bytes: 0, row_count_estimate: null, row_count_exact: true,
      last_modified: null },
  ],
  disk: { total_bytes: 10 ** 12, used_bytes: 10 ** 11, free_bytes: 9 * 10 ** 11,
          data_root_bytes: 3_000_000_000, used_pct: 10, mount_point: "/", mount_device: null,
          quota_bytes: null, used_pct_against_quota: null },
  snapshot_at: "2026-09-29T12:00:00.000Z",
};

const RETENTION = { policies: [], note: "", last_run: null, scheduler: { enabled: false },
                    archive: { enabled: false, root: null, usable: null, reason: "" },
                    telemetry_store: null };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("formatRowCount", () => {
  it("is exact, ≈ for an estimate, — when unknown", () => {
    expect(formatRowCount({ row_count_estimate: 1234, row_count_exact: true })).toBe("1,234");
    expect(formatRowCount({ row_count_estimate: 1234 })).toBe("1,234");     // older backend
    expect(formatRowCount({ row_count_estimate: 1234, row_count_exact: false })).toBe("≈ 1,234");
    expect(formatRowCount({ row_count_estimate: null, row_count_exact: true })).toBe("—");
    expect(formatRowCount(undefined)).toBe("—");
  });
});

describe("SystemTab storage tables", () => {
  it("marks estimated counts with ≈ and keeps exact ones exact", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url === "/api/v1/admin/data/storage-stats") return jsonResponse(200, STATS);
      if (url === "/api/v1/admin/data/retention") return jsonResponse(200, RETENTION);
      return jsonResponse(404, {});
    }));
    render(<SystemTab />);
    await waitFor(() => expect(screen.getByTestId("tenant-rows-acme-corp")).toBeInTheDocument());
    expect(screen.getByTestId("tenant-rows-acme-corp")).toHaveTextContent("≈ 1,234,000");
    expect(screen.getByTestId("tenant-rows-globex")).toHaveTextContent(/^12$/);
    expect(screen.getByTestId("global-rows-audit")).toHaveTextContent("≈ 2,000,000");
    expect(screen.getByTestId("global-rows-registry")).toHaveTextContent(/^7$/);
    expect(screen.getByTestId("global-rows-patterns")).toHaveTextContent("—");
  });
});
