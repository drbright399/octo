import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

import { LlmModelsPanel } from "@/components/llm-models-panel";

const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });
const err = (status: number, body: object): Response =>
  new Response(JSON.stringify(body), { status });

const MODELS = {
  active: "qwen-2.5-3b-q4",
  models_dir: "/models",
  models: [
    { name: "qwen-2.5-3b-q4", filename: "qwen.gguf", size_bytes: 1, sha256: null,
      mtime: "2026-06-01T00:00:00Z", is_active: true },
    { name: "granite-3.1-8b-q4", filename: "granite.gguf", size_bytes: 2, sha256: null,
      mtime: "2026-06-01T00:00:00Z", is_active: false },
  ],
};

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => { global.fetch = originalFetch; vi.restoreAllMocks(); });

/** Route fetches: model list ok; bundle/probe/manifest fail (silently
 * caught by the panel); the active-model PUT returns STEP_UP_REQUIRED. */
function wireFetch(opts: { activeStatus: number; activeBody: object;
                          onActivePut?: () => void }): void {
  global.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (url.endsWith("/api/v1/admin/llm/models") && method === "GET") return ok(MODELS);
    if (url.includes("/admin/llm/models/active") && method === "PUT") {
      opts.onActivePut?.();
      return err(opts.activeStatus, opts.activeBody);
    }
    if (url.includes("/search/elevate")) return ok({ elevated: true });
    // bundle config / probe / manifest → fail; panel catches silently.
    return err(500, { code: "INTERNAL_ERROR", message: "n/a" });
  }) as unknown as typeof fetch;
}

describe("LlmModelsPanel step-up", () => {
  it("prompts re-auth when the model swap needs step-up", async () => {
    wireFetch({ activeStatus: 401,
                activeBody: { code: "STEP_UP_REQUIRED", message: "step-up required" } });
    render(<LlmModelsPanel />);

    const select = await screen.findByRole("combobox");
    fireEvent.change(select, { target: { value: "granite-3.1-8b-q4" } });

    // The step-up modal appears (instead of a dead error).
    await waitFor(() =>
      expect(screen.getByText(/Re-authentication required/i)).toBeInTheDocument());
  });

  it("does NOT prompt re-auth for a non-step-up error (shows the error)", async () => {
    wireFetch({ activeStatus: 409,
                activeBody: { code: "CONFLICT", message: "model busy" } });
    render(<LlmModelsPanel />);

    const select = await screen.findByRole("combobox");
    fireEvent.change(select, { target: { value: "granite-3.1-8b-q4" } });

    await waitFor(() => expect(screen.getByText(/model busy/i)).toBeInTheDocument());
    expect(screen.queryByText(/Re-authentication required/i)).not.toBeInTheDocument();
  });
});
