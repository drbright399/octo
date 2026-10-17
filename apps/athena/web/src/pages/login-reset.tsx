/**
 * /login/reset?token=… — Athena Console password-reset page.
 *
 * Port of V2's login-reset.html flow. Reads the reset token from the
 * query string, posts (token, new_password) to /api/v1/auth/password/reset,
 * shows the password-manager-autofill guidance on success.
 *
 * The reset endpoint server-side ALSO revokes all of this operator's
 * existing sessions — that's why we don't auto-redirect; the user has
 * to sign in fresh, ideally after updating their password manager.
 *
 * The success banner explicitly tells the operator to update their
 * saved password BEFORE next sign-in, since browser pw managers will otherwise stomp
 * the new password with the stale saved value at submit time.
 */
import { type FC, type FormEvent, useState } from "react";
import { useSearchParam } from "@/lib/router";

const AUTH_BASE = "/api/v1/auth";

class AuthError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function authCall(path: string, body: object): Promise<void> {
  const res = await fetch(AUTH_BASE + path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let data: { code?: string; message?: string } = {};
    try {
      data = (await res.json()) as { code?: string; message?: string };
    } catch {
      /* non-JSON */
    }
    throw new AuthError(
      data.code ?? `HTTP_${res.status}`,
      res.status,
      data.message ?? `Request failed (${res.status})`,
    );
  }
}

function userMessage(err: unknown): string {
  const friendly: Record<string, string> = {
    AUTH_MAGIC_LINK_INVALID:
      "This reset link is invalid or has expired. Request a new one.",
    AUTH_MAGIC_LINK_USED: "This reset link has already been used.",
    AUTH_OPERATOR_DISABLED:
      "This account is disabled. Contact your administrator.",
    VALIDATION_FAILED: "Password must be at least 12 characters.",
    RATE_LIMITED: "Too many attempts. Slow down and try again shortly.",
  };
  if (err instanceof AuthError) {
    const m = friendly[err.code];
    if (m) return m;
  }
  if (err instanceof Error) return err.message;
  return "Something went wrong. Try again.";
}

const LoginResetPage: FC = () => {
  const token = useSearchParam("token");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const onSubmit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    setError(null);
    if (!token) {
      setError(
        "No reset token in this URL. Open the link from your email in " +
          "full, or request a new reset from the sign-in page.",
      );
      return;
    }
    if (newPw.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    if (newPw !== confirmPw) {
      setError("The two password fields don't match.");
      return;
    }
    setBusy(true);
    try {
      await authCall("/password/reset", { token, new_password: newPw });
      setDone(true);
      setNewPw("");
      setConfirmPw("");
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg-base p-6">
      <div className="w-full max-w-md rounded-lg border border-border bg-bg-surface p-6 shadow-xl">
        <header className="mb-6">
          <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
            Athena Console
          </span>
          <h1 className="mt-1 text-lg font-semibold text-text-primary">
            Reset password
          </h1>
        </header>

        {error ? (
          <div
            role="alert"
            data-testid="reset-error"
            className="mb-4 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            {error}
          </div>
        ) : null}

        {done ? (
          <div data-testid="reset-success">
            <div
              role="status"
              className="mb-4 rounded border border-success/50 bg-success/10 px-3 py-2 text-xs text-success"
            >
              Password updated. Every active session for this account has
              been signed out — you'll need to sign in again.
            </div>
            <div className="rounded border border-accent/30 bg-accent-soft px-3 py-2 text-[11px] text-text-secondary">
              <strong>Update your password manager FIRST</strong> before
              signing in. Browser password managers will otherwise auto-fill
              the old password at submit time and lock you out for 15
              minutes.
            </div>
            <a
              href="/login"
              className="mt-4 block w-full rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-center text-xs font-semibold text-white hover:bg-accent-strong"
            >
              Continue to sign in
            </a>
          </div>
        ) : (
          <form onSubmit={(e) => void onSubmit(e)}>
            <label className="mb-3 block">
              <span className="mb-1 block text-xs text-text-secondary">
                New password
                <span className="ml-2 font-mono text-[10px] uppercase tracking-wider text-text-dim">
                  min 12 chars
                </span>
              </span>
              <input
                type="password"
                autoComplete="new-password"
                autoFocus
                required
                minLength={12}
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                className="w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
              />
            </label>
            <label className="mb-3 block">
              <span className="mb-1 block text-xs text-text-secondary">
                Confirm new password
              </span>
              <input
                type="password"
                autoComplete="new-password"
                required
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                className="w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
              />
            </label>
            <button
              type="submit"
              disabled={busy || !token}
              className="mt-2 w-full rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
            >
              {busy ? "Updating…" : "Update password"}
            </button>
          </form>
        )}
      </div>
    </main>
  );
};

export default LoginResetPage;
