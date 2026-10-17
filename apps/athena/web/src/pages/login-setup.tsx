/**
 * /login/setup — forced first-login wizard.
 *
 * Three steps, gated by the operator's account state:
 *   1. set initial password (skipped if must_change_password=false)
 *   2. enroll TOTP            (skipped if mfa_enabled=true)
 *   3. save backup codes      (shown once after TOTP enrollment succeeds)
 *
 * The page calls `/auth/me` on mount to decide where to start. The
 * backend setup_gate middleware enforces the SAME rule server-side —
 * the SPA can't bypass setup by navigating directly to / because every
 * other endpoint returns 403 SETUP_REQUIRED until both flags clear.
 *
 * Visual pass 2026-05-13 — lifts the structure from Design's
 * LoginSetupWizard kit (bracketed-A header, labeled step pills, two-pane
 * TOTP layout). Auth logic + endpoints + error handling unchanged. QR
 * code visual still deferred to Task #106 (we render the real
 * otpauth-URI + base32 secret in styled cards).
 */
import { type FC, type FormEvent, type ReactNode, useEffect, useState } from "react";
import { getMe } from "@/lib/api";
import AthenaMark from "@/components/athena-mark";
import TotpQr from "@/components/totp-qr";

const AUTH_BASE = "/api/v1/auth";

type Stage = "loading" | "set-password" | "enroll-totp" | "backup-codes" | "done";

interface BeginTotp {
  pending_token: string;
  secret_b32: string;
  otpauth_uri: string;
}

class AuthError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

async function postJson<T>(path: string, body: object): Promise<T> {
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
      data.message ?? `Request failed (${res.status})`,
    );
  }
  return (await res.json()) as T;
}

const LoginSetupPage: FC = () => {
  const [stage, setStage] = useState<Stage>("loading");

  // Step 1 (password)
  const [pw, setPw] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");

  // Step 2 (TOTP)
  const [totpData, setTotpData] = useState<BeginTotp | null>(null);
  const [totpCode, setTotpCode] = useState("");

  // Step 3 (backup codes)
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [backupAck, setBackupAck] = useState(false);
  const [copied, setCopied] = useState(false);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Decide starting stage from /auth/me.
  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((me) => {
        if (cancelled) return;
        if (me === null) {
          window.location.href = "/login";
          return;
        }
        if (me.must_change_password) {
          setStage("set-password");
        } else if (!me.mfa_enabled) {
          setStage("enroll-totp");
        } else {
          window.location.href = "/";
        }
      })
      .catch(() => {
        window.location.href = "/login";
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const onPasswordSubmit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    setError(null);
    if (pw.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    if (pw !== pwConfirm) {
      setError("The two password fields don't match.");
      return;
    }
    setBusy(true);
    try {
      // current_password intentionally omitted — backend bypasses the
      // check because must_change_password=1 (or password_hash IS NULL).
      await postJson("/password/change", { new_password: pw });
      setPw("");
      setPwConfirm("");
      const me = await getMe();
      if (me && !me.mfa_enabled) {
        setStage("enroll-totp");
      } else {
        window.location.href = "/";
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not set password.");
    } finally {
      setBusy(false);
    }
  };

  // Auto-start TOTP enrollment as soon as we enter that stage.
  useEffect(() => {
    if (stage !== "enroll-totp" || totpData !== null) return;
    let cancelled = false;
    setBusy(true);
    setError(null);
    postJson<BeginTotp>("/totp/enroll/begin", {})
      .then((r) => {
        if (!cancelled) setTotpData(r);
      })
      .catch((e: Error) => {
        if (!cancelled) {
          setError(`Could not start TOTP enrollment: ${e.message}`);
        }
      })
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [stage, totpData]);

  const onTotpSubmit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    setError(null);
    if (!totpData) {
      setError("Enrollment isn't ready yet — give it a second and retry.");
      return;
    }
    if (!/^\d{6,8}$/.test(totpCode.trim())) {
      setError("Code must be 6 digits.");
      return;
    }
    setBusy(true);
    try {
      const r = await postJson<{ backup_codes: string[] }>(
        "/totp/enroll/complete",
        { pending_token: totpData.pending_token, totp_code: totpCode.trim() },
      );
      setBackupCodes(r.backup_codes);
      setTotpCode("");
      setStage("backup-codes");
    } catch (err) {
      setError(err instanceof Error ? err.message : "TOTP enrollment failed.");
    } finally {
      setBusy(false);
    }
  };

  const onFinish = (): void => {
    if (!backupAck) {
      setError("Confirm you've saved the codes before continuing.");
      return;
    }
    window.location.href = "/";
  };

  const onCopyCodes = (): void => {
    void navigator.clipboard?.writeText(backupCodes.join("\n"));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg-base p-6">
      <div className="w-full max-w-2xl rounded-md border border-border bg-bg-surface p-7 shadow-xl">
        <WizardHeader stage={stage} />

        {error ? (
          <div
            role="alert"
            data-testid="setup-error"
            className="mb-4 rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 font-mono text-xs text-critical"
          >
            {error}
          </div>
        ) : null}

        {stage === "loading" ? (
          <p className="font-mono text-xs text-text-dim">·· reading account state ··</p>
        ) : null}

        {stage === "set-password" ? (
          <form
            onSubmit={(e) => void onPasswordSubmit(e)}
            data-testid="setup-password-form"
          >
            <p className="mb-4 rounded-sm border border-accent/30 bg-accent-soft px-3 py-2 text-xs leading-relaxed text-text-secondary">
              Pick a password you don't reuse anywhere else. Minimum 12
              characters. You can change it later from Settings → Account.
            </p>
            <div className="mb-4 flex flex-col gap-3">
              <FieldLabel
                label="New password"
                hint="min 12 chars"
              >
                <input
                  type="password"
                  autoComplete="new-password"
                  autoFocus
                  required
                  minLength={12}
                  value={pw}
                  onChange={(e) => setPw(e.target.value)}
                  className="w-full rounded-sm border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
                />
              </FieldLabel>
              <FieldLabel label="Confirm new password">
                <input
                  type="password"
                  autoComplete="new-password"
                  required
                  value={pwConfirm}
                  onChange={(e) => setPwConfirm(e.target.value)}
                  className="w-full rounded-sm border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
                />
              </FieldLabel>
            </div>
            <div className="flex justify-end">
              <PrimaryButton type="submit" disabled={busy}>
                {busy ? "Saving…" : "Continue → enroll authenticator"}
              </PrimaryButton>
            </div>
          </form>
        ) : null}

        {stage === "enroll-totp" ? (
          <div data-testid="setup-totp-form">
            <p className="mb-4 rounded-sm border border-accent/30 bg-accent-soft px-3 py-2 text-xs leading-relaxed text-text-secondary">
              Open your authenticator app (Google Authenticator, Microsoft
              Authenticator, Duo Mobile, 1Password, Authy…) and{" "}
              <strong>scan the QR code</strong>. Can’t scan? Add the account
              manually with the setup key on the right. Then type the 6-digit
              code it shows.
            </p>

            {totpData ? (
              <div className="mb-4 grid gap-4 md:grid-cols-[180px_minmax(0,1fr)]">
                <TotpQr value={totpData.otpauth_uri} size={168} />
                <div className="flex flex-col gap-3">
                  <CodeCard
                    eyebrow="·· base32 secret · manual entry ··"
                    code={totpData.secret_b32}
                    accent
                    testId="setup-totp-secret"
                  />
                  <CodeCard
                    eyebrow="·· otpauth URI ··"
                    code={totpData.otpauth_uri}
                    small
                    testId="setup-totp-uri"
                  />
                </div>
              </div>
            ) : (
              <p className="mb-4 font-mono text-xs text-text-dim">
                ·· generating enrollment secret ··
              </p>
            )}

            <form onSubmit={(e) => void onTotpSubmit(e)}>
              <FieldLabel label="6-digit code from authenticator">
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                  pattern="\d{6,8}"
                  maxLength={8}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                  className="w-full rounded-sm border border-border bg-bg-input px-3 py-2 text-center font-mono text-lg tracking-[0.4em] text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
                />
              </FieldLabel>
              <div className="mt-4 flex justify-end">
                <PrimaryButton type="submit" disabled={busy || !totpData}>
                  {busy ? "Verifying…" : "Verify & continue"}
                </PrimaryButton>
              </div>
            </form>
          </div>
        ) : null}

        {stage === "backup-codes" ? (
          <div data-testid="setup-backup-codes">
            <p className="mb-4 rounded-sm border border-critical/30 bg-critical/10 px-3 py-2 text-xs leading-relaxed text-text-secondary">
              <strong className="text-critical">Save these codes now.</strong>{" "}
              Each is a single-use fallback if you lose access to your
              authenticator. They are shown <strong>ONCE</strong> — closing
              this page without saving means losing fallback access.
            </p>

            <ul
              role="list"
              data-testid="setup-backup-code-list"
              className="mb-3 grid grid-cols-1 gap-1 rounded-sm border border-border bg-bg-card p-3 sm:grid-cols-2"
            >
              {backupCodes.map((c, i) => (
                <li
                  key={i}
                  className="flex items-center gap-3 font-mono text-sm text-text-primary"
                >
                  <span className="w-6 select-none text-right text-[10px] uppercase tracking-wider text-text-dim">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="tracking-widest">{c}</span>
                </li>
              ))}
            </ul>

            <button
              type="button"
              onClick={onCopyCodes}
              className="mb-4 w-full rounded-sm border border-border bg-bg-card px-3 py-2 font-mono text-xs uppercase tracking-wider text-text-secondary hover:border-border-bright hover:text-text-primary"
            >
              {copied ? "·· copied ··" : "·· copy all to clipboard ··"}
            </button>

            <label className="mb-4 flex items-start gap-2 text-xs leading-relaxed text-text-secondary">
              <input
                type="checkbox"
                checked={backupAck}
                onChange={(e) => setBackupAck(e.target.checked)}
                data-testid="setup-backup-ack"
                className="mt-0.5 accent-accent"
              />
              <span>
                I've stored these codes somewhere safe (password manager,
                printed page). I understand they won't be shown again.
              </span>
            </label>

            <div className="flex justify-end">
              <PrimaryButton
                type="button"
                onClick={onFinish}
                disabled={!backupAck}
                testId="setup-finish"
              >
                Finish setup → Dashboard
              </PrimaryButton>
            </div>
          </div>
        ) : null}
      </div>
    </main>
  );
};

/* -------------------------------------------------------------------------- */
/* Sub-components — local to this page, lifted from Design's kit visuals.     */
/* -------------------------------------------------------------------------- */

const STAGE_LABELS: Record<Exclude<Stage, "loading" | "done">, string> = {
  "set-password": "password",
  "enroll-totp": "TOTP",
  "backup-codes": "backup codes",
};

const STAGE_TITLES: Record<Stage, string> = {
  loading: "Loading…",
  "set-password": "Set your password",
  "enroll-totp": "Enroll authenticator",
  "backup-codes": "Save your backup codes",
  done: "Done",
};

const WizardHeader: FC<{ stage: Stage }> = ({ stage }) => (
  <header className="mb-6">
    <div className="mb-1 flex items-center gap-2.5">
      <span className="inline-flex h-[22px] w-[22px] text-accent">
        <AthenaMark size={22} title="Athena" />
      </span>
      <span className="font-semibold tracking-[0.12em] text-accent">ATHENA</span>
      <span className="ml-auto font-mono text-[10px] uppercase tracking-wider text-text-dim">
        ·· account setup ··
      </span>
    </div>
    <h1 className="mt-2 text-base font-semibold text-text-primary">
      {STAGE_TITLES[stage]}
    </h1>
    <StepPills stage={stage} />
  </header>
);

const STEP_ORDER: ReadonlyArray<Exclude<Stage, "loading" | "done">> = [
  "set-password",
  "enroll-totp",
  "backup-codes",
];

const StepPills: FC<{ stage: Stage }> = ({ stage }) => {
  const activeIdx = STEP_ORDER.indexOf(stage as Exclude<Stage, "loading" | "done">);
  return (
    <div className="mt-3 flex flex-wrap items-center gap-3" role="list">
      {STEP_ORDER.map((s, i) => {
        const isActive = i === activeIdx;
        const isDone = activeIdx > i;
        const tone =
          isDone ? "text-success border-success/40"
          : isActive ? "text-accent border-accent/50"
          : "text-text-dim border-border";
        return (
          <span
            key={s}
            role="listitem"
            className={[
              "inline-flex items-center gap-2 rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
              tone,
            ].join(" ")}
          >
            <span className="tabular-nums">{String(i + 1).padStart(2, "0")}</span>
            <span>{STAGE_LABELS[s]}</span>
          </span>
        );
      })}
    </div>
  );
};

const FieldLabel: FC<{
  label: string;
  hint?: string;
  children: ReactNode;
}> = ({ label, hint, children }) => (
  <label className="block">
    <span className="mb-1 flex items-baseline gap-2 text-xs text-text-secondary">
      <span>{label}</span>
      {hint && (
        <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
          {hint}
        </span>
      )}
    </span>
    {children}
  </label>
);

const CodeCard: FC<{
  eyebrow: string;
  code: string;
  accent?: boolean;
  small?: boolean;
  testId?: string;
}> = ({ eyebrow, code, accent, small, testId }) => (
  <div className="rounded-sm border border-border bg-bg-card px-3 py-2">
    <div className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
      {eyebrow}
    </div>
    <code
      data-testid={testId}
      className={[
        "mt-1 block break-all font-mono",
        small ? "text-[10px] leading-snug text-text-secondary" : "text-sm tracking-widest",
        accent ? "text-accent" : "text-text-primary",
      ].join(" ")}
    >
      {code}
    </code>
  </div>
);

const PrimaryButton: FC<{
  type?: "submit" | "button";
  onClick?: () => void;
  disabled?: boolean;
  testId?: string;
  children: ReactNode;
}> = ({ type = "button", onClick, disabled, testId, children }) => (
  <button
    type={type}
    onClick={onClick}
    disabled={disabled}
    data-testid={testId}
    className="rounded-sm border border-accent-cta bg-accent-cta px-4 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
  >
    {children}
  </button>
);

export default LoginSetupPage;
