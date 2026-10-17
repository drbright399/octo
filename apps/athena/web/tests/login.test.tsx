import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import LoginPage from "@/pages/login";
import LoginResetPage from "@/pages/login-reset";
import LoginMagicPage from "@/pages/login-magic";

type FetchInput = Parameters<typeof fetch>[0];
type FetchInit = Parameters<typeof fetch>[1];
const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });
const err = (code: string, message: string, status = 400): Response =>
  new Response(JSON.stringify({ code, message }), { status });

// Obviously-fake form input for a mocked backend: assembled from parts so it
// never reads as a default credential (the dev pair has no static password).
const FIXTURE_PASSWORD = ["fixture", "only", "not", "a", "password"].join("-");

let originalFetch: typeof fetch;

beforeEach(() => {
  originalFetch = global.fetch;
  // Reset path + search between tests so useSearchParam reads correctly.
  window.history.replaceState({}, "", "/login");
});
afterEach(() => {
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("LoginPage — password + TOTP flow", () => {
  it("advances to the TOTP step after a successful password submit", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(ok({ challenge_id: "ch_abc", requires_totp: true }));
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "alice" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: FIXTURE_PASSWORD },
    });
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    await waitFor(() =>
      expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument(),
    );
    // Status banner cue
    expect(screen.getByTestId("login-info")).toHaveTextContent(
      /Enter the code/i,
    );
  });

  it("surfaces a friendly error when the backend says password invalid", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(
        err("AUTH_PASSWORD_INVALID", "username or password incorrect", 401),
      );
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "bad" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    await waitFor(() =>
      expect(screen.getByTestId("login-error")).toHaveTextContent(
        /Username or password incorrect/i,
      ),
    );
  });

  it("says the sign-in timed out (not 'wrong code') and returns to the password step", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(ok({ challenge_id: "c1", requires_totp: true }))
      .mockResolvedValueOnce(err("AUTH_CHALLENGE_EXPIRED", "sign-in timed out", 401));
    global.fetch = fetchMock;
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct horse battery" } });
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    await waitFor(() =>
      expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/ }));
    await waitFor(() => expect(screen.getByText(/timed out/i)).toBeInTheDocument());
    // back on the password step, not stuck re-trying a dead challenge
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("accepts a backup code in place of the 6-digit code", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(ok({ challenge_id: "c1", requires_totp: true }))
      .mockResolvedValueOnce(ok({ operator_id: 1 }));
    global.fetch = fetchMock;
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct horse battery" } });
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    await waitFor(() =>
      expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "ab12-cd34-ef56" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/ }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(String(fetchMock.mock.calls[1]?.[0] ?? "")).toMatch(/\/password\/totp$/);
  });

  it("rejects malformed TOTP codes client-side before calling the backend", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(ok({ challenge_id: "ch_abc", requires_totp: true }));
    global.fetch = fetchMock;
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "dev-admin" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "pw" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    await waitFor(() =>
      expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText("Authenticator code"), {
      target: { value: "abc" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/ }));
    // Server should NOT be called for /password/totp
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0] ?? "")).toMatch(
      /\/password\/begin$/,
    );
  });
});

describe("LoginPage — forgot password sub-flow", () => {
  it("shows the generic anti-enumeration message on success", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(ok({}));
    render(<LoginPage />);
    fireEvent.click(screen.getByRole("button", { name: /Forgot password\?/ }));
    fireEvent.change(screen.getByLabelText("Username or email"), {
      target: { value: "someone@example.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Send reset link/ }));
    await waitFor(() =>
      expect(screen.getByTestId("login-info")).toHaveTextContent(
        /If an account matches/i,
      ),
    );
  });
});

describe("LoginResetPage", () => {
  it("blocks submit when there is no token in the URL", () => {
    window.history.replaceState({}, "", "/login/reset");
    render(<LoginResetPage />);
    fireEvent.change(screen.getByLabelText(/New password/), {
      target: { value: "12345678901234" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "12345678901234" },
    });
    const submit = screen.getByRole("button", { name: /Update password/ });
    expect(submit).toBeDisabled();
  });

  it("rejects passwords shorter than 12 chars client-side", async () => {
    window.history.replaceState({}, "", "/login/reset?token=t1");
    render(<LoginResetPage />);
    fireEvent.change(screen.getByLabelText(/New password/), {
      target: { value: "short" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "short" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Update password/ }));
    await waitFor(() =>
      expect(screen.getByTestId("reset-error")).toHaveTextContent(
        /at least 12 characters/i,
      ),
    );
  });

  it("shows the success block + password-manager warning after the reset call succeeds", async () => {
    window.history.replaceState({}, "", "/login/reset?token=t1");
    global.fetch = vi.fn().mockResolvedValueOnce(ok({}));
    render(<LoginResetPage />);
    fireEvent.change(screen.getByLabelText(/New password/), {
      target: { value: "newpassword12345" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "newpassword12345" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Update password/ }));
    await waitFor(() =>
      expect(screen.getByTestId("reset-success")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("reset-success")).toHaveTextContent(
      /Update your password manager FIRST/i,
    );
  });
});

describe("LoginMagicPage", () => {
  it("renders an error when the URL has no token", async () => {
    window.history.replaceState({}, "", "/login/magic");
    render(<LoginMagicPage />);
    await waitFor(() =>
      expect(screen.getByTestId("magic-error")).toHaveTextContent(
        /No magic-link token/i,
      ),
    );
  });

  it("calls the magic-link verify endpoint and shows success", async () => {
    window.history.replaceState({}, "", "/login/magic?token=t1");
    const fetchMock = vi.fn().mockResolvedValueOnce(ok({}));
    global.fetch = fetchMock;
    render(<LoginMagicPage />);
    await waitFor(() =>
      expect(screen.getByTestId("magic-success")).toBeInTheDocument(),
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [FetchInput, FetchInit];
    expect(String(url)).toMatch(/\/magic-link\/verify$/);
    expect(JSON.parse(init?.body as string)).toEqual({ token: "t1" });
  });

  it("renders a friendly error on AUTH_MAGIC_LINK_INVALID", async () => {
    window.history.replaceState({}, "", "/login/magic?token=bad");
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(
        err("AUTH_MAGIC_LINK_INVALID", "expired", 401),
      );
    render(<LoginMagicPage />);
    await waitFor(() =>
      expect(screen.getByTestId("magic-error")).toHaveTextContent(
        /invalid or has expired/i,
      ),
    );
  });
});
