import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import NeedsReviewNotice from "@/components/needs-review-notice";
import type { MeResponse } from "@/contracts/operator";

/**
 * The dashboard's "needs review" strip: admin+ only (a viewer is a client
 * user — the count endpoint is never even called for them), invisible while
 * nothing needs a human, and each count links into the view that resolves it.
 */

const URL_ = "/api/v1/admin/tenants/review-summary";

function me(role: MeResponse["role"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role } as MeResponse;
}

function stub(body: unknown, status = 200) {
  const fetchMock = vi.fn(async () => ({ ok: status < 300, status, json: async () => body }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("NeedsReviewNotice", () => {
  it.each([["viewer"], ["analyst"]])("%s: renders nothing and never calls the endpoint", async (role) => {
    const fetchMock = stub({ pending_review: 5, quarantined: 5, pending_requests: 5 });
    render(<NeedsReviewNotice me={me([role as MeResponse["role"][number]])} />);
    await new Promise((r) => setTimeout(r, 20));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByTestId("needs-review-notice")).toBeNull();
  });

  it("renders nothing while every count is zero", async () => {
    const fetchMock = stub({ pending_review: 0, quarantined: 0, pending_requests: 0 });
    render(<NeedsReviewNotice me={me(["admin"])} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(URL_, expect.objectContaining({ credentials: "include" })));
    await new Promise((r) => setTimeout(r, 10));
    expect(screen.queryByTestId("needs-review-notice")).toBeNull();
  });

  it("admin: shows the counts with links into Settings → Tenants", async () => {
    stub({ pending_review: 10, quarantined: 90, pending_requests: 1 });
    const push = vi.spyOn(window.history, "pushState");
    render(<NeedsReviewNotice me={me(["admin"])} />);
    const notice = await waitFor(() => screen.getByTestId("needs-review-notice"));
    expect(notice).toHaveTextContent("10 tenants awaiting a tag");
    expect(notice).toHaveTextContent("90 events in quarantine");
    expect(notice).toHaveTextContent("1 change request awaiting approval");
    fireEvent.click(screen.getByTestId("review-quarantine-link"));
    expect(push).toHaveBeenLastCalledWith({}, "", "/settings/tenants/quarantine");
    fireEvent.click(screen.getByTestId("review-tenants-link"));
    expect(push).toHaveBeenLastCalledWith({}, "", "/settings/tenants?filter=needs-review");
  });

  it("omits a zero line and survives a failed poll", async () => {
    stub({ pending_review: 0, quarantined: 2, pending_requests: 0 });
    render(<NeedsReviewNotice me={me(["super_admin"])} />);
    const notice = await waitFor(() => screen.getByTestId("needs-review-notice"));
    expect(notice).toHaveTextContent("2 events in quarantine");
    expect(screen.queryByTestId("review-tenants-link")).toBeNull();
    expect(screen.queryByTestId("review-requests-link")).toBeNull();
  });

  it("cloud-AI sign-offs about to lapse, or lapsed, need a human too", async () => {
    stub({ pending_review: 0, quarantined: 0, pending_requests: 0, signoffs_expiring: 17, signoffs_expired: 1 });
    const push = vi.spyOn(window.history, "pushState");
    render(<NeedsReviewNotice me={me(["super_admin"])} />);
    const notice = await waitFor(() => screen.getByTestId("needs-review-notice"));
    expect(notice).toHaveTextContent("17 cloud-AI sign-offs expiring within 30 days");
    expect(notice).toHaveTextContent("1 tenant running as local — cloud-AI sign-off expired");
    fireEvent.click(screen.getByTestId("review-signoffs-expiring-link"));
    expect(push).toHaveBeenLastCalledWith({}, "", "/settings/tenants");
  });

  it("a 403 (or any failure) renders nothing — never an error tile", async () => {
    stub({ code: "ISOLATION_VIOLATION", message: "nope" }, 403);
    render(<NeedsReviewNotice me={me(["admin"])} />);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByTestId("needs-review-notice")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
