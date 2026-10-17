/**
 * /login — Athena Console sign-in page.
 *
 * Port of V2's login.html + login.js flow, refactored into React + TS
 * while preserving the auth-call shape verbatim (a security
 * invariant):
 *   step 1: POST /api/v1/auth/password/begin → returns challenge_id
 *   step 2: POST /api/v1/auth/password/totp  → returns session-cookie
 *
 * Side flows on the same page:
 *   - Forgot password (POST /api/v1/auth/password/forgot)
 *   - Magic-link consumption (POST /api/v1/auth/magic-link/verify) — the
 *     full magic-link landing page lives at /login/magic, but if the URL
 *     carries ?token=… we offer the inline shortcut as V2 did.
 *
 * Passkey/WebAuthn from V2 is NOT ported in this slice — it's a separate
 * client-crypto port and not on the critical path for v1 deployments.
 *
 * Security:
 *   - Session is set as an HttpOnly cookie by the backend; JS never
 *     reads or stores it.
 *   - Error codes are mapped to friendly strings via `friendlyByCode`,
 *     mirroring V2's anti-enumeration posture (e.g. wrong-password and
 *     no-such-user both surface as "Username or password incorrect").
 *   - The password field uses autoComplete="current-password" so the
 *     manager fills it predictably; reset flows handle the post-rotation
 *     "update your saved password" guidance.
 */
import { type FC, type FormEvent, useEffect, useState } from "react";
import { useSearchParam } from "@/lib/router";

const AUTH_BASE = "/api/v1/auth";

type AuthErrorCode =
  | "AUTH_PASSWORD_INVALID"
  | "AUTH_TOTP_REQUIRED"
  | "AUTH_TOTP_INVALID"
  | "AUTH_CHALLENGE_EXPIRED"
  | "AUTH_LOCKED"
  | "AUTH_SESSION_INVALID"
  | "AUTH_MAGIC_LINK_INVALID"
  | "AUTH_MAGIC_LINK_USED"
  | "AUTH_MFA_NOT_ENROLLED"
  | "AUTH_OPERATOR_DISABLED"
  | "AUTH_NO_ATHENA_ACCOUNT"
  | "RATE_LIMITED"
  | string;

class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number;
  constructor(code: AuthErrorCode, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function authCall<T>(path: string, body?: object): Promise<T> {
  const init: RequestInit = {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const res = await fetch(AUTH_BASE + path, init);
  let data: { code?: string; message?: string } | null = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok) {
    throw new AuthError(
      data?.code ?? `HTTP_${res.status}`,
      res.status,
      data?.message ?? `Request failed (${res.status})`,
    );
  }
  return (data ?? {}) as T;
}

// Map server error codes → user-facing strings. Mirrors V2's mapping.
function userMessage(err: unknown): string {
  const friendlyByCode: Record<string, string> = {
    AUTH_PASSWORD_INVALID:    "Username or password incorrect.",
    AUTH_TOTP_REQUIRED:       "Enter the code from your authenticator.",
    AUTH_TOTP_INVALID:        "That code didn't match. Try the next one.",
    // >5 min between password and code. NOT a wrong code — say so, and the
    // handler below returns to the password step.
    AUTH_CHALLENGE_EXPIRED:   "Sign-in timed out (5 minutes). Enter your password again, then the code.",
    AUTH_LOCKED:              "Account temporarily locked after repeated failures. Try again in 15 minutes.",
    AUTH_SESSION_INVALID:     "Your session expired. Sign in again.",
    AUTH_MAGIC_LINK_INVALID:  "This link is invalid or has expired. Ask your admin for a new one.",
    AUTH_MAGIC_LINK_USED:     "This link has already been used.",
    AUTH_MFA_NOT_ENROLLED:    "No MFA factor enrolled. Contact your administrator.",
    AUTH_OPERATOR_DISABLED:   "This account is disabled. Contact your administrator.",
    AUTH_NO_ATHENA_ACCOUNT:   "No Athena account exists for this identity.",
    RATE_LIMITED:             "Too many attempts. Slow down and try again shortly.",
  };
  if (err instanceof AuthError) {
    const m = friendlyByCode[err.code];
    if (m) return m;
  }
  if (err instanceof Error) return err.message;
  return "Something went wrong. Try again.";
}

interface LoginProps {
  /** Path to redirect to after successful login. Defaults to /. */
  readonly redirectTo?: string;
}

const LoginPage: FC<LoginProps> = ({ redirectTo = "/" }) => {
  const [mode, setMode] = useState<"password" | "forgot">("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [challengeId, setChallengeId] = useState<string | null>(null);

  const [forgotIdentifier, setForgotIdentifier] = useState("");

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // If the URL carried ?token=… we hand off to /login/magic instead of
  // inlining the magic-link flow here — keeps this page focused on the
  // password+TOTP path.
  const tokenFromUrl = useSearchParam("token");
  useEffect(() => {
    if (tokenFromUrl) {
      window.location.replace(
        `/login/magic?token=${encodeURIComponent(tokenFromUrl)}`,
      );
    }
  }, [tokenFromUrl]);

  const clearBanners = (): void => {
    setError(null);
    setInfo(null);
  };

  const onPasswordSubmit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    clearBanners();

    // Step 2 — caller already provided TOTP, finish the flow.
    if (challengeId) {
      const code = totp.trim();
      // 6-digit authenticator code, or a single-use backup code
      // (XXXX-XXXX-XXXX; dashes optional).
      const isTotp = /^\d{6,8}$/.test(code);
      const isBackup = /^[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}$/.test(code);
      if (!isTotp && !isBackup) {
        setError("Enter the 6-digit code, or one of your backup codes.");
        return;
      }
      setBusy(true);
      try {
        await authCall("/password/totp", {
          challenge_id: challengeId,
          totp_code: code,
        });
        setInfo("Signed in. Redirecting…");
        window.location.href = redirectTo;
      } catch (err) {
        setError(userMessage(err));
        if (err instanceof AuthError && err.code === "AUTH_TOTP_INVALID") {
          setTotp("");
        } else {
          // Reset to password step on locked / invalid challenge
          setChallengeId(null);
          setPassword("");
        }
      } finally {
        setBusy(false);
      }
      return;
    }

    // Step 1 — submit username + password.
    if (!username.trim() || !password) {
      setError("Username and password required.");
      return;
    }
    setBusy(true);
    try {
      const r = await authCall<{
        challenge_id: string;
        requires_totp: boolean;
      }>("/password/begin", {
        username: username.trim(),
        password,
      });
      if (r.requires_totp === false) {
        // Operator has no MFA enrolled — backend issued a session
        // directly. Setup-gate middleware will route them to
        // /login/setup. Hand off to / and let App.tsx pick it up.
        setInfo("Signed in. Continuing to account setup…");
        window.location.href = redirectTo;
        return;
      }
      setChallengeId(r.challenge_id);
      setInfo("Enter the code from your authenticator app.");
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const onForgotSubmit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    clearBanners();
    const identifier = forgotIdentifier.trim();
    if (!identifier) {
      setError("Enter your username or email first.");
      return;
    }
    setBusy(true);
    try {
      await authCall("/password/forgot", { identifier });
      // Server always returns 202 + identical body (anti-enumeration).
      setInfo(
        "If an account matches that identifier, we've emailed a reset " +
          "link. The link expires in 10 minutes — check spam if it " +
          "doesn't arrive in the next minute or two.",
      );
      setForgotIdentifier("");
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const goBackToPassword = (): void => {
    setMode("password");
    clearBanners();
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg-base p-6">
      <div className="w-full max-w-md rounded-lg border border-border bg-bg-surface p-6 shadow-xl">
        <header className="mb-6">
          <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
            Athena Console
          </span>
          <h1 className="mt-1 text-lg font-semibold text-text-primary">
            {mode === "forgot" ? "Reset password" : "Sign in"}
          </h1>
        </header>

        {error ? (
          <div
            role="alert"
            data-testid="login-error"
            className="mb-4 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            {error}
          </div>
        ) : null}
        {info ? (
          <div
            role="status"
            data-testid="login-info"
            className="mb-4 rounded border border-success/50 bg-success/10 px-3 py-2 text-xs text-success"
          >
            {info}
          </div>
        ) : null}

        {mode === "forgot" ? (
          <form onSubmit={(e) => void onForgotSubmit(e)}>
            <label className="mb-3 block">
              <span className="mb-1 block text-xs text-text-secondary">
                Username or email
              </span>
              <input
                type="text"
                autoComplete="username"
                autoFocus
                value={forgotIdentifier}
                onChange={(e) => setForgotIdentifier(e.target.value)}
                className="w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
              />
            </label>
            <div className="mt-4 flex gap-2">
              <button
                type="submit"
                disabled={busy}
                className="flex-1 rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
              >
                {busy ? "Sending…" : "Send reset link"}
              </button>
              <button
                type="button"
                onClick={goBackToPassword}
                className="rounded-sm border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary hover:text-text-primary"
              >
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={(e) => void onPasswordSubmit(e)}>
            {!challengeId ? (
              <>
                <label className="mb-3 block">
                  <span className="mb-1 block text-xs text-text-secondary">
                    Username
                  </span>
                  <input
                    type="text"
                    autoComplete="username"
                    autoFocus
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
                  />
                </label>
                <label className="mb-3 block">
                  <span className="mb-1 block text-xs text-text-secondary">
                    Password
                  </span>
                  <input
                    type="password"
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
                  />
                </label>
              </>
            ) : (
              <label className="mb-3 block">
                <span className="mb-1 block text-xs text-text-secondary">
                  Authenticator code
                </span>
                <input
                  type="text"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                  maxLength={16}
                  value={totp}
                  onChange={(e) => setTotp(e.target.value)}
                  className="w-full rounded border border-border bg-bg-input px-3 py-2 text-center font-mono text-lg tracking-widest text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
                />
              </label>
            )}
            {challengeId ? (
              // Outside the <label>: keeps the input's accessible name exact.
              <p className="-mt-2 mb-3 text-[11px] text-text-dim">
                Lost your authenticator? Enter one of your backup codes instead.
              </p>
            ) : null}

            <button
              type="submit"
              disabled={busy}
              className="mt-2 w-full rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
            >
              {busy
                ? "Working…"
                : challengeId
                  ? "Sign in"
                  : "Continue"}
            </button>

            <div className="mt-4 flex justify-between text-[11px]">
              <button
                type="button"
                onClick={() => {
                  setMode("forgot");
                  setForgotIdentifier(username.trim());
                  clearBanners();
                }}
                className="text-text-dim hover:text-accent"
              >
                Forgot password?
              </button>
              {challengeId ? (
                <button
                  type="button"
                  onClick={() => {
                    setChallengeId(null);
                    setTotp("");
                    clearBanners();
                  }}
                  className="text-text-dim hover:text-accent"
                >
                  Back to password
                </button>
              ) : null}
            </div>
          </form>
        )}
      </div>
    </main>
  );
};

export default LoginPage;
