/**
 * Step-up re-authentication modal.
 *
 * Shown when an operator hits a sensitive surface (currently /search/*)
 * without an active step-up window — OR when their window expires mid-
 * session — OR when their network prefix changes (STEP_UP_NETWORK_CHANGED).
 *
 * Same-origin, in-app — never redirects to an external SSO etc. The
 * password+TOTP go to /api/v1/search/elevate; on success the parent
 * page retries whatever request triggered the modal.
 */
import { useEffect, useRef, useState, type FC } from "react";
import { ApiError, elevateStepUp } from "@/lib/api";

export type StepUpReason = "required" | "network_changed";

interface StepUpModalProps {
  readonly open: boolean;
  readonly reason: StepUpReason;
  readonly onClose: () => void;
  readonly onSuccess: () => void;
}

const StepUpModal: FC<StepUpModalProps> = ({ open, reason, onClose, onSuccess }) => {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pwInputRef = useRef<HTMLInputElement>(null);

  // Focus the password field when the modal opens. Reset state when closed.
  useEffect(() => {
    if (open) {
      setError(null);
      setTimeout(() => pwInputRef.current?.focus(), 50);
    } else {
      setPassword(""); setTotp(""); setError(null);
    }
  }, [open]);

  if (!open) return null;

  const headline = reason === "network_changed"
    ? "Network changed — please re-authenticate"
    : "Re-authentication required";
  const subhead = reason === "network_changed"
    ? "Your step-up clearance was granted from a different network. This is a defense-in-depth check — confirm your identity to continue."
    : "This surface accesses ingested customer data. Confirm your password and TOTP to continue.";

  const submit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      await elevateStepUp(password, totp);
      onSuccess();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Re-authentication failed";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="step-up-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-bg-deep/70 backdrop-blur-sm"
    >
      <div className="w-full max-w-md rounded-lg border border-border-bright bg-bg-elevated p-6 shadow-2xl">
        <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-accent">
          [ step-up auth ]
        </div>
        <h2 id="step-up-title" className="mb-2 text-base font-semibold text-text-primary">
          {headline}
        </h2>
        <p className="mb-5 text-xs text-text-secondary">{subhead}</p>

        <form onSubmit={submit} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-[11px] uppercase tracking-wider text-text-dim">
              Password
            </span>
            <input
              ref={pwInputRef}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={submitting}
              className="rounded-sm border border-border bg-bg-card px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] uppercase tracking-wider text-text-dim">
              TOTP code
            </span>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={totp}
              onChange={(e) => setTotp(e.target.value.replace(/\D/g, ""))}
              maxLength={8}
              required
              disabled={submitting}
              className="rounded-sm border border-border bg-bg-card px-3 py-2 font-mono text-sm tracking-widest text-text-primary focus:border-accent focus:outline-none"
            />
          </label>

          {error && (
            <div role="alert" className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">
              {error}
            </div>
          )}

          <div className="mt-2 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !password || !totp}
              className="rounded-sm border border-accent bg-accent px-3 py-1.5 text-xs text-text-on-accent transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {submitting ? "Verifying…" : "Confirm"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default StepUpModal;
