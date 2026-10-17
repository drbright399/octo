/**
 * Settings → Account.
 *
 * Three live panels:
 *   1. Profile  — identity + role read-out from /auth/me
 *   2. Authentication — change password, reset TOTP, backup-codes hint
 *   3. Active sessions — list + per-session revoke + sign-out-everywhere
 *
 * Every value here is real (no hardcoded fixtures). The transient action
 * buttons surface as modals so the page itself stays scrollable + safe
 * to navigate away from. Per the dropdown/account split, this panel
 * does NOT carry "Sign out" (transient action — lives in the topbar
 * dropdown).
 */
import { type FC, type FormEvent, useEffect, useState } from "react";
import {
  changeMyPassword,
  getMe,
  listMySessions,
  regenerateBackupCodes,
  revokeMyOtherSessions,
  revokeMySession,
  totpEnrollBegin,
  totpEnrollComplete,
  updateMyProfile,
  type SessionEntry,
  type TotpEnrollBeginResponse,
} from "@/lib/api";
import {
  ROLE_LABEL,
  ROLE_TIER,
  type MeResponse,
} from "@/contracts/operator";
import TotpQr from "@/components/totp-qr";
import { AccountPreferencesPanel } from "@/components/account-preferences-panel";

const AccountTab: FC = () => {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [pwModalOpen, setPwModalOpen] = useState(false);
  const [totpModalOpen, setTotpModalOpen] = useState(false);
  const [emailModalOpen, setEmailModalOpen] = useState(false);
  const [backupRegenModalOpen, setBackupRegenModalOpen] = useState(false);

  const reloadMe = (): void => {
    getMe()
      .then((r) => {
        if (r === null) {
          setLoadError("Session expired. Refresh to sign back in.");
        } else {
          setMe(r);
        }
      })
      .catch((e: Error) => setLoadError(e.message));
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getMe()
      .then((r) => {
        if (cancelled) return;
        if (r === null) {
          setLoadError("Session expired. Refresh to sign back in.");
        } else {
          setMe(r);
        }
      })
      .catch((e: Error) => !cancelled && setLoadError(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6 text-center text-text-dim">
        Loading account…
      </section>
    );
  }
  if (loadError || !me) {
    return (
      <section
        className="rounded-lg border border-critical bg-critical/10 p-6 text-sm text-critical"
        role="alert"
      >
        {loadError ?? "Account information unavailable."}
      </section>
    );
  }

  // displayName preferred by Athena's user-facing strings; resolved via
  // friendlyName() helper below for dashboard greetings + topbar.
  const first = me.role[0];
  const primaryRole = first
    ? me.role.reduce(
        (best, r) =>
          (ROLE_TIER[r] ?? 0) > (ROLE_TIER[best] ?? 0) ? r : best,
        first,
      )
    : null;
  const roleLabel = primaryRole ? ROLE_LABEL[primaryRole] : "—";
  const tenant = me.scope_slugs.includes("*")
    ? "all tenants"
    : me.scope_slugs.join(", ");

  return (
    <div className="flex flex-col gap-4">
      <ProfilePanel
        me={me}
        roleLabel={roleLabel}
        tenant={tenant}
        onProfileChanged={reloadMe}
        onEditEmailClick={() => setEmailModalOpen(true)}
      />
      <AuthenticationPanel
        me={me}
        onChangePasswordClick={() => setPwModalOpen(true)}
        onResetTotpClick={() => setTotpModalOpen(true)}
        onRegenBackupCodesClick={() => setBackupRegenModalOpen(true)}
      />
      <AccountPreferencesPanel />
      <SessionsPanel />

      {pwModalOpen ? (
        <ChangePasswordModal
          onClose={() => setPwModalOpen(false)}
          onSuccess={() => {
            setPwModalOpen(false);
            reloadMe();
          }}
        />
      ) : null}

      {totpModalOpen ? (
        <ResetTotpModal
          onClose={() => setTotpModalOpen(false)}
          onSuccess={() => {
            setTotpModalOpen(false);
            reloadMe();
          }}
        />
      ) : null}

      {emailModalOpen ? (
        <ChangeEmailModal
          currentEmail={me.email}
          onClose={() => setEmailModalOpen(false)}
          onSuccess={() => {
            setEmailModalOpen(false);
            reloadMe();
          }}
        />
      ) : null}

      {backupRegenModalOpen ? (
        <RegenBackupCodesModal
          onClose={() => setBackupRegenModalOpen(false)}
          onSuccess={() => {
            setBackupRegenModalOpen(false);
            reloadMe();
          }}
        />
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Profile panel
// ---------------------------------------------------------------------------

const ProfilePanel: FC<{
  me: MeResponse;
  roleLabel: string;
  tenant: string;
  onProfileChanged: () => void;
  onEditEmailClick: () => void;
}> = ({ me, roleLabel, tenant, onProfileChanged, onEditEmailClick }) => {
  const [editingDisplay, setEditingDisplay] = useState(false);
  const [draftDisplay, setDraftDisplay] = useState(me.display_name ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const saveDisplayName = async (): Promise<void> => {
    setBusy(true);
    setErr(null);
    try {
      await updateMyProfile({ displayName: draftDisplay });
      setEditingDisplay(false);
      onProfileChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Update failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rounded-lg border border-border bg-bg-surface p-6">
      <h1 className="mb-1 text-lg font-semibold text-text-primary">Account</h1>
      <p className="mb-6 text-sm text-text-dim">
        Profile, authentication factors, and active sessions. Values reflect the
        live identity returned by <code className="font-mono">/auth/me</code>.
      </p>
      {err ? (
        <div role="alert" className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
          {err}
        </div>
      ) : null}
      <dl
        className="grid grid-cols-1 gap-4 md:grid-cols-2"
        data-testid="account-live-fields"
      >
        <Row label="Username" value={me.username} />
        <div className="rounded border border-border bg-bg-card px-4 py-3">
          <dt className="flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-text-dim">
            <span>Display name</span>
            {!editingDisplay ? (
              <button
                type="button"
                onClick={() => {
                  setDraftDisplay(me.display_name ?? "");
                  setEditingDisplay(true);
                }}
                className="text-text-secondary hover:text-accent"
              >
                edit
              </button>
            ) : null}
          </dt>
          <dd className="mt-1 text-sm text-text-primary">
            {editingDisplay ? (
              <div className="flex flex-col gap-2">
                <input
                  type="text"
                  autoFocus
                  maxLength={80}
                  value={draftDisplay}
                  onChange={(e) => setDraftDisplay(e.target.value)}
                  placeholder="Your friendly name (e.g., Rick)"
                  className="w-full rounded border border-border bg-bg-input px-2 py-1 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
                />
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void saveDisplayName()}
                    className="rounded-sm border border-accent-cta bg-accent-cta px-2 py-1 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
                  >
                    {busy ? "Saving…" : "Save"}
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditingDisplay(false)}
                    className="rounded-sm border border-border bg-bg-card px-2 py-1 text-xs text-text-secondary hover:text-text-primary"
                  >
                    Cancel
                  </button>
                </div>
                <p className="text-[10px] text-text-dim">
                  Leave blank to clear. Athena will fall back to your
                  username everywhere when no display name is set.
                </p>
              </div>
            ) : (
              <>
                {me.display_name ? (
                  me.display_name
                ) : (
                  <span className="text-text-dim">— not set —</span>
                )}
              </>
            )}
          </dd>
        </div>
        <div className="rounded border border-border bg-bg-card px-4 py-3">
          <dt className="flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-text-dim">
            <span>Email</span>
            <button
              type="button"
              onClick={onEditEmailClick}
              className="text-text-secondary hover:text-accent"
            >
              edit
            </button>
          </dt>
          <dd className="mt-1 text-sm text-text-primary">{me.email}</dd>
        </div>
        <Row label="Role" value={roleLabel} valueTone="accent" />
        <Row label="Tenant scope" value={tenant} />
      </dl>
    </section>
  );
};

// ---------------------------------------------------------------------------
// Authentication panel
// ---------------------------------------------------------------------------

const AuthenticationPanel: FC<{
  me: MeResponse;
  onChangePasswordClick: () => void;
  onResetTotpClick: () => void;
  onRegenBackupCodesClick: () => void;
}> = ({
  me,
  onChangePasswordClick,
  onResetTotpClick,
  onRegenBackupCodesClick,
}) => {
  const mfaText = me.mfa_enabled ? "enrolled (TOTP)" : "not enrolled";
  const backupText =
    me.backup_codes_remaining > 0
      ? `${me.backup_codes_remaining} remaining`
      : me.mfa_enabled
        ? "none generated"
        : "n/a";

  return (
    <section className="rounded-lg border border-border bg-bg-surface p-6">
      <h2 className="mb-1 text-base font-semibold text-text-primary">
        Authentication
      </h2>
      <p className="mb-4 text-sm text-text-dim">
        Manage your password and second factor.
      </p>

      <dl className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Row
          label="MFA"
          value={mfaText}
          valueTone={me.mfa_enabled ? "success" : "warning"}
        />
        <Row label="Backup codes" value={backupText} />
      </dl>

      {me.needs_setup ? (
        <div
          role="alert"
          className="mt-4 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
        >
          {me.must_change_password
            ? "Initial password setup is required."
            : "TOTP enrollment is required."}{" "}
          <a href="/login/setup" className="underline">
            Finish setup →
          </a>
        </div>
      ) : null}

      <div className="mt-6 flex flex-wrap gap-2">
        <ActionButton onClick={onChangePasswordClick}>
          Change password
        </ActionButton>
        <ActionButton onClick={onResetTotpClick}>
          {me.mfa_enabled ? "Reset TOTP" : "Enroll TOTP"}
        </ActionButton>
        {me.mfa_enabled ? (
          <ActionButton onClick={onRegenBackupCodesClick}>
            Generate new backup codes
          </ActionButton>
        ) : null}
      </div>
      <p className="mt-3 text-[11px] text-text-dim">
        Resetting TOTP rotates BOTH the authenticator secret and the
        backup-code set. Use "Generate new backup codes" when you only
        want fresh codes (e.g., you've used most of them).
      </p>
    </section>
  );
};

// ---------------------------------------------------------------------------
// Active sessions panel
// ---------------------------------------------------------------------------

const SessionsPanel: FC = () => {
  const [sessions, setSessions] = useState<SessionEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = (): void => {
    setLoading(true);
    setError(null);
    listMySessions()
      .then((s) => setSessions(s))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(reload, []);

  const onRevoke = async (id: string): Promise<void> => {
    if (!window.confirm("Revoke this session? It will be signed out immediately.")) return;
    setBusy(true);
    setError(null);
    try {
      await revokeMySession(id);
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Revoke failed");
    } finally {
      setBusy(false);
    }
  };

  const onSignOutEverywhere = async (): Promise<void> => {
    if (
      !window.confirm(
        "Sign out every other session for this account? Your current " +
          "session here stays signed in.",
      )
    )
      return;
    setBusy(true);
    setError(null);
    try {
      const n = await revokeMyOtherSessions();
      setError(null);
      reload();
      // Flash a brief status — surface via the loading row replaced.
      // Could be a toaster later; for now we just rely on the list refresh.
      void n;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign-out-everywhere failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rounded-lg border border-border bg-bg-surface p-6">
      <h2 className="mb-1 text-base font-semibold text-text-primary">
        Active sessions
      </h2>
      <p className="mb-4 text-sm text-text-dim">
        Every browser or device with a live session for this account.
      </p>
      {error ? (
        <div role="alert" className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
          {error}
        </div>
      ) : null}
      {loading ? (
        <div className="text-sm text-text-dim">Loading sessions…</div>
      ) : sessions.length === 0 ? (
        <div className="text-sm text-text-dim">No active sessions.</div>
      ) : (
        <ul role="list" className="flex flex-col divide-y divide-border/40">
          {sessions.map((s) => (
            <li
              key={s.id}
              className="flex flex-wrap items-center justify-between gap-3 py-2"
            >
              <div className="flex flex-col">
                <span className="font-mono text-xs text-text-primary">
                  {s.ip_address ?? "(no ip)"}{" "}
                  {s.is_current ? (
                    <span className="ml-1 rounded bg-accent/20 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-accent">
                      this session
                    </span>
                  ) : null}
                </span>
                <span className="text-[11px] text-text-dim">
                  {s.user_agent ? truncate(s.user_agent, 70) : "(no UA)"}
                </span>
                <span className="text-[11px] text-text-dim">
                  {s.auth_method} · last active{" "}
                  {s.last_active_at.slice(0, 19).replace("T", " ")}
                </span>
              </div>
              {!s.is_current ? (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void onRevoke(s.id)}
                  className="rounded border border-critical/40 px-2 py-1 text-xs text-critical hover:bg-critical/10 disabled:opacity-50"
                >
                  Revoke
                </button>
              ) : (
                <span className="text-[11px] text-text-dim">current</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {sessions.filter((s) => !s.is_current).length > 0 ? (
        <div className="mt-4 flex justify-end">
          <button
            type="button"
            disabled={busy}
            onClick={() => void onSignOutEverywhere()}
            className="rounded border border-critical/40 bg-critical/10 px-3 py-1.5 text-xs text-critical hover:bg-critical/20 disabled:opacity-50"
          >
            Sign out everywhere else
          </button>
        </div>
      ) : null}
    </section>
  );
};

// ---------------------------------------------------------------------------
// Change password modal
// ---------------------------------------------------------------------------

const ChangePasswordModal: FC<{
  onClose: () => void;
  onSuccess: () => void;
}> = ({ onClose, onSuccess }) => {
  const [current, setCurrent] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const submit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    setError(null);
    if (newPw.length < 12) {
      setError("New password must be at least 12 characters.");
      return;
    }
    if (newPw !== confirm) {
      setError("The two new-password fields don't match.");
      return;
    }
    setBusy(true);
    try {
      await changeMyPassword(current || null, newPw);
      setCurrent("");
      setNewPw("");
      setConfirm("");
      setDone(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Change password failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Change password" onClose={onClose}>
      {done ? (
        <div>
          <div
            role="status"
            className="mb-4 rounded border border-success/50 bg-success/10 px-3 py-2 text-xs text-success"
          >
            Password updated. Every other session for this account was
            signed out — your current session here stays signed in.
          </div>
          <div className="rounded border border-accent/30 bg-accent-soft px-3 py-2 text-[11px] text-text-secondary">
            <strong>Update your password manager now</strong> so the next
            sign-in autofills the new value instead of stomping it with the
            old one.
          </div>
          <button
            type="button"
            onClick={onSuccess}
            className="mt-4 w-full rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong"
          >
            Done
          </button>
        </div>
      ) : (
        <form onSubmit={(e) => void submit(e)}>
          {error ? (
            <div
              role="alert"
              className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              {error}
            </div>
          ) : null}
          <label className="mb-3 block">
            <span className="mb-1 block text-xs text-text-secondary">
              Current password
            </span>
            <input
              type="password"
              autoComplete="current-password"
              autoFocus
              required
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              className={inputClass}
            />
          </label>
          <label className="mb-3 block">
            <span className="mb-1 block text-xs text-text-secondary">
              New password{" "}
              <span className="ml-1 font-mono text-[10px] uppercase tracking-wider text-text-dim">
                min 12 chars
              </span>
            </span>
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              className={inputClass}
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
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className={inputClass}
            />
          </label>
          <div className="mt-2 flex gap-2">
            <button
              type="submit"
              disabled={busy}
              className="flex-1 rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
            >
              {busy ? "Updating…" : "Change password"}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-sm border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary hover:text-text-primary"
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </ModalShell>
  );
};

// ---------------------------------------------------------------------------
// Reset TOTP modal
// ---------------------------------------------------------------------------

const ResetTotpModal: FC<{
  onClose: () => void;
  onSuccess: () => void;
}> = ({ onClose, onSuccess }) => {
  const [enrollData, setEnrollData] = useState<TotpEnrollBeginResponse | null>(
    null,
  );
  const [totpCode, setTotpCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setBusy(true);
    totpEnrollBegin()
      .then((r) => setEnrollData(r))
      .catch((e: Error) => setError(e.message))
      .finally(() => setBusy(false));
  }, []);

  const verify = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    setError(null);
    if (!enrollData) return;
    if (!/^\d{6,8}$/.test(totpCode.trim())) {
      setError("Code must be 6 digits.");
      return;
    }
    setBusy(true);
    try {
      const codes = await totpEnrollComplete(
        enrollData.pending_token,
        totpCode.trim(),
      );
      setBackupCodes(codes);
      setTotpCode("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "TOTP enrollment failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Reset authenticator (TOTP)" onClose={onClose}>
      {error ? (
        <div
          role="alert"
          className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
        >
          {error}
        </div>
      ) : null}

      {!backupCodes && enrollData ? (
        <form onSubmit={(e) => void verify(e)}>
          <p className="mb-3 rounded border border-accent/30 bg-accent-soft px-3 py-2 text-xs text-text-secondary">
            Replace any existing TOTP factor with a fresh one. The old
            secret + the previous backup-code set are revoked once you
            verify the first code from the new authenticator.
          </p>
          <div className="mb-3 flex justify-center">
            <TotpQr value={enrollData.otpauth_uri} size={156} />
          </div>
          <div className="mb-3 rounded border border-border bg-bg-card px-3 py-2">
            <div className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
              base32 secret · manual entry
            </div>
            <code className="mt-1 block font-mono text-sm tracking-widest text-accent">
              {enrollData.secret_b32}
            </code>
          </div>
          <details className="mb-3 rounded border border-border bg-bg-card px-3 py-2 text-xs">
            <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-wider text-text-dim">
              show otpauth URI
            </summary>
            <code className="mt-2 block break-all font-mono text-[11px] text-text-primary">
              {enrollData.otpauth_uri}
            </code>
          </details>
          <label className="mb-3 block">
            <span className="mb-1 block text-xs text-text-secondary">
              6-digit code from your authenticator
            </span>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              required
              pattern="\d{6,8}"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              className={`${inputClass} text-center text-lg tracking-widest`}
            />
          </label>
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={busy}
              className="flex-1 rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
            >
              {busy ? "Verifying…" : "Verify & rotate"}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-sm border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary hover:text-text-primary"
            >
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      {!enrollData && !backupCodes ? (
        <div className="text-sm text-text-dim">Generating enrollment secret…</div>
      ) : null}

      {backupCodes ? (
        <div>
          <div
            role="alert"
            className="mb-3 rounded border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            <strong>Save these codes now.</strong> Each one is a single-use
            fallback if you lose access to your authenticator. They are
            shown ONCE.
          </div>
          <ul
            role="list"
            className="mb-3 grid grid-cols-2 gap-2 rounded border border-border bg-bg-card p-3 font-mono text-sm tracking-widest text-text-primary"
          >
            {backupCodes.map((c, i) => (
              <li key={i} className="text-center">
                {c}
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={() =>
              void navigator.clipboard?.writeText(backupCodes.join("\n"))
            }
            className="mb-3 w-full rounded-sm border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary hover:border-border-bright hover:text-text-primary"
          >
            Copy all to clipboard
          </button>
          <label className="mb-3 flex items-start gap-2 text-xs text-text-secondary">
            <input
              type="checkbox"
              checked={ack}
              onChange={(e) => setAck(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              I've stored these codes somewhere safe. I understand they won't
              be shown again.
            </span>
          </label>
          <button
            type="button"
            disabled={!ack}
            onClick={onSuccess}
            className="w-full rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
          >
            Done
          </button>
        </div>
      ) : null}
    </ModalShell>
  );
};

// ---------------------------------------------------------------------------
// Change email modal
// ---------------------------------------------------------------------------

const ChangeEmailModal: FC<{
  currentEmail: string;
  onClose: () => void;
  onSuccess: () => void;
}> = ({ currentEmail, onClose, onSuccess }) => {
  const [email, setEmail] = useState(currentEmail);
  const [currentPw, setCurrentPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    setError(null);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) {
      setError("That doesn't look like a valid email.");
      return;
    }
    if (!currentPw) {
      setError("Current password required to change email.");
      return;
    }
    if (email.trim() === currentEmail) {
      setError("New email must differ from the current email.");
      return;
    }
    setBusy(true);
    try {
      await updateMyProfile({
        email: email.trim(),
        currentPassword: currentPw,
      });
      setCurrentPw("");
      onSuccess();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Email change failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Change email" onClose={onClose}>
      <form onSubmit={(e) => void submit(e)}>
        {error ? (
          <div
            role="alert"
            className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            {error}
          </div>
        ) : null}
        <p className="mb-3 rounded border border-accent/30 bg-accent-soft px-3 py-2 text-xs text-text-secondary">
          Your email is where future password-reset links land. Changing
          it requires your current password — confirms it's actually you.
        </p>
        <label className="mb-3 block">
          <span className="mb-1 block text-xs text-text-secondary">
            New email
          </span>
          <input
            type="email"
            autoComplete="email"
            autoFocus
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={inputClass}
          />
        </label>
        <label className="mb-3 block">
          <span className="mb-1 block text-xs text-text-secondary">
            Current password
          </span>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={currentPw}
            onChange={(e) => setCurrentPw(e.target.value)}
            className={inputClass}
          />
        </label>
        <div className="mt-2 flex gap-2">
          <button
            type="submit"
            disabled={busy}
            className="flex-1 rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
          >
            {busy ? "Updating…" : "Change email"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary hover:text-text-primary"
          >
            Cancel
          </button>
        </div>
      </form>
    </ModalShell>
  );
};

// ---------------------------------------------------------------------------
// Regenerate backup codes modal
// ---------------------------------------------------------------------------

const RegenBackupCodesModal: FC<{
  onClose: () => void;
  onSuccess: () => void;
}> = ({ onClose, onSuccess }) => {
  const [currentPw, setCurrentPw] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    setError(null);
    if (!currentPw) {
      setError("Current password required.");
      return;
    }
    setBusy(true);
    try {
      const fresh = await regenerateBackupCodes(currentPw);
      setCurrentPw("");
      setCodes(fresh);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Regenerate failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Generate new backup codes" onClose={onClose}>
      {error ? (
        <div
          role="alert"
          className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
        >
          {error}
        </div>
      ) : null}

      {!codes ? (
        <form onSubmit={(e) => void submit(e)}>
          <p className="mb-3 rounded border border-accent/30 bg-accent-soft px-3 py-2 text-xs text-text-secondary">
            This revokes your existing backup-code set and issues a fresh
            8-code set. Your TOTP authenticator stays untouched. Confirm
            with your current password.
          </p>
          <label className="mb-3 block">
            <span className="mb-1 block text-xs text-text-secondary">
              Current password
            </span>
            <input
              type="password"
              autoComplete="current-password"
              autoFocus
              required
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              className={inputClass}
            />
          </label>
          <div className="mt-2 flex gap-2">
            <button
              type="submit"
              disabled={busy}
              className="flex-1 rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
            >
              {busy ? "Generating…" : "Generate new codes"}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-sm border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary hover:text-text-primary"
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div>
          <div
            role="alert"
            className="mb-3 rounded border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            <strong>Save these codes now.</strong> Each is a single-use
            fallback if you lose your authenticator. They are shown
            ONCE. Your previous backup-code set is no longer valid.
          </div>
          <ul
            role="list"
            className="mb-3 grid grid-cols-2 gap-2 rounded border border-border bg-bg-card p-3 font-mono text-sm tracking-widest text-text-primary"
          >
            {codes.map((c, i) => (
              <li key={i} className="text-center">
                {c}
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={() => void navigator.clipboard?.writeText(codes.join("\n"))}
            className="mb-3 w-full rounded-sm border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary hover:border-border-bright hover:text-text-primary"
          >
            Copy all to clipboard
          </button>
          <label className="mb-3 flex items-start gap-2 text-xs text-text-secondary">
            <input
              type="checkbox"
              checked={ack}
              onChange={(e) => setAck(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              I've stored these codes somewhere safe. They won't be shown
              again.
            </span>
          </label>
          <button
            type="button"
            disabled={!ack}
            onClick={onSuccess}
            className="w-full rounded-sm border border-accent-cta bg-accent-cta px-3 py-2 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
          >
            Done
          </button>
        </div>
      )}
    </ModalShell>
  );
};

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------

const ModalShell: FC<{
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}> = ({ title, onClose, children }) => (
  <>
    <div
      onClick={onClose}
      aria-hidden="true"
      className="fixed inset-0 z-40 bg-black/50"
    />
    <div
      role="dialog"
      aria-modal="true"
      aria-label={title}
      className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border-bright bg-bg-elevated p-5 shadow-xl"
    >
      <header className="mb-4 flex items-center justify-between">
        <h3 className="text-base font-semibold text-text-primary">{title}</h3>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="rounded-sm p-1 text-text-secondary hover:bg-accent-soft hover:text-accent"
        >
          ✕
        </button>
      </header>
      {children}
    </div>
  </>
);

const inputClass =
  "w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none";

const Row: FC<{
  label: string;
  value: string;
  valueTone?: "default" | "accent" | "success" | "warning";
}> = ({ label, value, valueTone = "default" }) => (
  <div className="rounded border border-border bg-bg-card px-4 py-3">
    <dt className="text-[10px] font-semibold uppercase tracking-wider text-text-dim">
      {label}
    </dt>
    <dd
      className={[
        "mt-1 text-sm",
        valueTone === "accent"
          ? "text-accent font-mono"
          : valueTone === "success"
            ? "text-success"
            : valueTone === "warning"
              ? "text-critical"
              : "text-text-primary",
      ].join(" ")}
    >
      {value}
    </dd>
  </div>
);

const ActionButton: FC<{ onClick: () => void; children: React.ReactNode }> = ({
  onClick,
  children,
}) => (
  <button
    type="button"
    onClick={onClick}
    className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary transition-colors hover:border-border-bright hover:bg-accent-soft hover:text-accent"
  >
    {children}
  </button>
);

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}

export default AccountTab;
