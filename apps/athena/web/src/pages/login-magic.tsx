/**
 * /login/magic?token=… — Athena Console magic-link consumption page.
 *
 * Reads the token from the query string and posts to /api/v1/auth/magic-link/verify.
 * On success, the backend issues a session cookie and we redirect to /.
 *
 * Fires automatically on mount (no form to fill out — this URL IS the
 * confirmation). If the URL has no token, show an error inviting the
 * operator to grab the link from their email.
 */
import { type FC, useEffect, useRef, useState } from "react";
import { useSearchParam } from "@/lib/router";

const AUTH_BASE = "/api/v1/auth";

class AuthError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function userMessage(err: unknown): string {
  const friendly: Record<string, string> = {
    AUTH_MAGIC_LINK_INVALID:
      "This link is invalid or has expired. Ask your admin for a new one. " +
      "If this was the first-run setup link for a new install, generate a " +
      "fresh one on the server (see “Locked out / link expired” in the bundle " +
      "deploy guide, docs/operations/bundle.md).",
    AUTH_MAGIC_LINK_USED:
      "This link has already been used. If you set a password before closing " +
      "the page, sign in with it to finish setup; otherwise ask your admin for " +
      "a new link (first-run installs: generate one on the server).",
    AUTH_OPERATOR_DISABLED:
      "This account is disabled. Contact your administrator.",
    RATE_LIMITED: "Too many attempts. Slow down and try again shortly.",
  };
  if (err instanceof AuthError) {
    const m = friendly[err.code];
    if (m) return m;
  }
  if (err instanceof Error) return err.message;
  return "Something went wrong. Try again.";
}

const LoginMagicPage: FC = () => {
  const token = useSearchParam("token");
  const [status, setStatus] = useState<"working" | "ok" | "error">("working");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  // Guard against React 18 strict-mode double-invoke firing two POSTs
  // against an idempotency-sensitive endpoint.
  const consumed = useRef(false);

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setErrorMsg(
        "No magic-link token in this URL. Open the complete link you were " +
          "given, or request a new one from your administrator.",
      );
      return;
    }
    if (consumed.current) return;
    consumed.current = true;

    const consume = async (): Promise<void> => {
      const res = await fetch(`${AUTH_BASE}/magic-link/verify`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
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
          data.message ?? `Request failed (${res.status})`,
        );
      }
    };

    consume()
      .then(() => {
        setStatus("ok");
        // Short delay so the operator sees the success state before redirect.
        window.setTimeout(() => {
          window.location.href = "/";
        }, 600);
      })
      .catch((err: unknown) => {
        setStatus("error");
        setErrorMsg(userMessage(err));
      });
  }, [token]);

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg-base p-6">
      <div className="w-full max-w-md rounded-lg border border-border bg-bg-surface p-6 text-center shadow-xl">
        <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
          Athena Console
        </span>
        <h1 className="mt-1 mb-6 text-lg font-semibold text-text-primary">
          {status === "working"
            ? "Signing you in…"
            : status === "ok"
              ? "Signed in"
              : "Sign-in failed"}
        </h1>

        {status === "working" ? (
          <p className="text-xs text-text-dim">
            Verifying your magic link.
          </p>
        ) : null}

        {status === "ok" ? (
          <p data-testid="magic-success" className="text-xs text-success">
            Redirecting to the dashboard…
          </p>
        ) : null}

        {status === "error" ? (
          <>
            <div
              role="alert"
              data-testid="magic-error"
              className="mb-4 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              {errorMsg}
            </div>
            <a
              href="/login"
              className="mt-2 block w-full rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong"
            >
              Back to sign in
            </a>
          </>
        ) : null}
      </div>
    </main>
  );
};

export default LoginMagicPage;
