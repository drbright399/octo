import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchThroughput, ApiError } from "@/lib/api";

const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });

let originalFetch: typeof fetch;

beforeEach(() => {
  originalFetch = global.fetch;
});
afterEach(() => {
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("fetchThroughput", () => {
  it("returns the parsed points + window metadata on success", async () => {
    const fixture = {
      points: [
        { t: "2026-05-12T18:00:00Z", v: 3162 },
        { t: "2026-05-12T19:00:00Z", v: 3255 },
      ],
      window_hours: 24,
      bucket_minutes: 60,
      scope_slugs: ["*"],
    };
    global.fetch = vi.fn().mockResolvedValueOnce(ok(fixture));
    const r = await fetchThroughput({ windowHours: 24, bucketMinutes: 60 });
    expect(r.points).toHaveLength(2);
    expect(r.points[0]).toEqual({ t: "2026-05-12T18:00:00Z", v: 3162 });
    expect(r.window_hours).toBe(24);
    expect(r.scope_slugs).toEqual(["*"]);
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/dashboard/throughput?window_hours=24&bucket_minutes=60",
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("omits query string when called without args", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(
      ok({
        points: [],
        window_hours: 24,
        bucket_minutes: 60,
        scope_slugs: [],
      }),
    );
    await fetchThroughput();
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/dashboard/throughput",
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("throws ApiError when the backend returns non-2xx", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response("", { status: 401 }));
    await expect(fetchThroughput()).rejects.toBeInstanceOf(ApiError);
  });
});
