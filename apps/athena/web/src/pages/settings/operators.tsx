import { type FC, useEffect, useState } from "react";
import {
  ApiError,
  createOperator,
  disableOperator,
  enableOperator,
  removeOperator,
  updateOperatorEmail,
  grantRole,
  listClients,
  resetOperatorPassword,
  revokeRole,
  setLlmGrant,
  type ClientEntry,
  type ResetPasswordResult,
  listOperators,
} from "@/lib/api";
import {
  ROLE_LABEL,
  ROLE_TIER,
  canManageRole,
  type CreateOperatorResponse,
  type MeResponse,
  type OperatorListEntry,
  type RoleName,
} from "@/contracts/operator";
import HelpTooltip from "@/components/help-tooltip";

interface OperatorsTabProps {
  me: MeResponse | null;
}

const ROLE_CHOICES: RoleName[] = ["admin", "analyst", "viewer", "super_admin"];

const OperatorsTab: FC<OperatorsTabProps> = ({ me }) => {
  const [operators, setOperators] = useState<OperatorListEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [activationLink, setActivationLink] =
    useState<CreateOperatorResponse | null>(null);

  const refresh = (): void => {
    setLoading(true);
    setError(null);
    listOperators()
      .then(setOperators)
      .catch((e: ApiError) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(refresh, []);

  if (!me) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6 text-text-dim">
        Loading identity…
      </section>
    );
  }

  const callerCanCreate = canManageRole(me.role, "analyst") ||
                          canManageRole(me.role, "admin");

  return (
    <section className="flex flex-col gap-4">
      <header className="rounded-lg border border-border bg-bg-surface p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="mb-1 text-lg font-semibold text-text-primary">
              Operators
            </h1>
            <p className="text-sm text-text-dim">
              Manage who can sign in to this Athena bundle. New operators are
              created in pending state and activated by the magic-link URL
              shown after creation. The browser never sees their password.
            </p>
          </div>
          {callerCanCreate && (
            <button
              type="button"
              onClick={() => {
                setShowCreate(true);
                setActivationLink(null);
              }}
              className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:opacity-90"
            >
              + New operator
            </button>
          )}
        </div>
      </header>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-critical/40 bg-critical/10 p-3 text-sm text-critical"
        >
          {error}
        </div>
      )}

      {activationLink && (
        <ActivationLinkBanner
          response={activationLink}
          onDismiss={() => setActivationLink(null)}
        />
      )}

      {showCreate && (
        <CreateOperatorForm
          me={me}
          onCancel={() => setShowCreate(false)}
          onCreated={(resp) => {
            setShowCreate(false);
            setActivationLink(resp);
            refresh();
          }}
        />
      )}

      {loading ? (
        <section className="rounded-lg border border-border bg-bg-surface p-6 text-center text-text-dim">
          Loading operators…
        </section>
      ) : (
        <OperatorTable
          me={me}
          operators={operators}
          onChanged={refresh}
        />
      )}
    </section>
  );
};

// ---------------------------------------------------------------------------
// Operator table
// ---------------------------------------------------------------------------

const OperatorTable: FC<{
  me: MeResponse;
  operators: OperatorListEntry[];
  onChanged: () => void;
}> = ({ me, operators, onChanged }) => {
  // Load the bundle's client list once for the tenant-scope pickers.
  // Failures are non-fatal — the picker degrades to "* only" if the
  // fetch errors, and the user can still grant/revoke roles.
  const [clients, setClients] = useState<ClientEntry[]>([]);
  useEffect(() => {
    listClients()
      .then((c) => setClients(c))
      .catch(() => {
        /* silent — pickers fall back to "* only" */
      });
  }, []);

  if (operators.length === 0) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6 text-center text-text-dim">
        No operators yet.
      </section>
    );
  }
  return (
    // No overflow clipping on the wrapper: the row dropdowns
    // (role-grant + tenant-scope) absolute-position outside their
    // <td>'s bounding box, and any `overflow-x-auto` parent silently
    // also clips the y-axis (CSS spec quirk), eating the menus.
    // Settings is desktop-first; if horizontal scroll is ever needed
    // on narrow viewports, switch to a portal-rendered menu instead
    // of re-introducing overflow here.
    <section className="rounded-lg border border-border bg-bg-surface">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-border bg-bg-base/40 text-text-dim">
          <tr>
            <th className="px-4 py-2 font-normal">Username</th>
            <th className="px-4 py-2 font-normal">Email</th>
            <th className="px-4 py-2 font-normal">
              <span className="inline-flex items-center gap-1.5">
                Roles
                <HelpTooltip>
                  Role tiers (low → high): <strong>viewer</strong> (read-only
                  in scope), <strong>analyst</strong> (investigate +
                  AI-engage in scope), <strong>admin</strong> (manage
                  operators ≤ admin and all data),{" "}
                  <strong>super_admin</strong> (everything, including
                  managing other super_admins). The factory account is the
                  bundle's break-glass — see Settings → System once that
                  panel ships.
                </HelpTooltip>
              </span>
            </th>
            <th className="px-4 py-2 font-normal">
              <span className="inline-flex items-center gap-1.5">
                Tenant scope
                <HelpTooltip>
                  Which of the MSP's CUSTOMERS this operator can see.{" "}
                  <code className="font-mono">*</code> means "all tenants
                  in this bundle." Specific slugs restrict visibility.
                  Viewers are client users: they must be scoped to their
                  own tenant(s) — never <code className="font-mono">*</code>{" "}
                  or a tenant still carrying a vendor-named placeholder.
                </HelpTooltip>
              </span>
            </th>
            <th className="px-4 py-2 font-normal">
              <span className="inline-flex items-center gap-1.5">
                MFA
                <HelpTooltip>
                  Multi-factor authentication. <strong>on</strong> means
                  the operator has a TOTP authenticator enrolled (and
                  optionally a passkey). <strong>off</strong> means no
                  second factor — should never be off for super_admin or
                  admin in production.
                </HelpTooltip>
              </span>
            </th>
            <th className="px-4 py-2 font-normal">
              <span className="inline-flex items-center gap-1.5">
                State
                <HelpTooltip>
                  <strong>active</strong> — operator can sign in.{" "}
                  <strong>pending</strong> — credentials not yet set; needs
                  to redeem the activation magic link (see the row's
                  creator for the URL). <strong>disabled</strong> — sign-in
                  blocked; existing sessions revoked.
                </HelpTooltip>
              </span>
            </th>
            <th className="px-4 py-2 font-normal">
              <span className="inline-flex items-center gap-1.5">
                LLM
                <HelpTooltip>
                  Octo AI access. Admins/super_admins grant + revoke.
                  Operator's own opt-in is in Settings → Account →
                  Preferences (independent). Both must be on for
                  &ldquo;Ask Octo&rdquo; to reach the model. The factory
                  super_admin is always granted (cannot be revoked by
                  other admins).
                </HelpTooltip>
              </span>
            </th>
            <th className="px-4 py-2 font-normal">Last login</th>
            <th className="px-4 py-2 font-normal text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {operators.map((op) => (
            <OperatorRow
              key={op.id}
              me={me}
              operator={op}
              clients={clients}
              onChanged={onChanged}
            />
          ))}
        </tbody>
      </table>
    </section>
  );
};

const OperatorRow: FC<{
  me: MeResponse;
  operator: OperatorListEntry;
  clients: ClientEntry[];
  onChanged: () => void;
}> = ({ me, operator, clients, onChanged }) => {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const isSelf = operator.id === me.operator_id;
  const targetTier = Math.max(
    0,
    ...operator.roles.map((r) => ROLE_TIER[r] ?? 0),
  );
  const callerTier = Math.max(
    0,
    ...me.role.map((r) => ROLE_TIER[r] ?? 0),
  );
  const canActOnTarget = callerTier >= targetTier;
  const canDisable = canActOnTarget && !isSelf && !operator.disabled_at;
  const canEnable = canActOnTarget && !isSelf && !!operator.disabled_at;
  const canResetPassword = canActOnTarget && !isSelf && !operator.disabled_at;
  // The factory account is the platform's break-glass path; the server refuses too.
  const canRemove = canActOnTarget && !isSelf && !operator.is_factory;
  const [resetResult, setResetResult] = useState<ResetPasswordResult | null>(null);
  const [resetFormOpen, setResetFormOpen] = useState(false);

  const onDisable = async (): Promise<void> => {
    if (!window.confirm(`Disable ${operator.username}? Active sessions will be revoked.`)) return;
    setBusy(true);
    setErr(null);
    try {
      await disableOperator(operator.id, "disabled via Settings UI");
      onChanged();
    } catch (e) {
      setErr((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  };
  const onRemove = async (): Promise<void> => {
    const reason = window.prompt(
      `Remove ${operator.username}?\n\n` +
        "• Never signed in → the account is deleted.\n" +
        "• Has history → it is retired: all access is revoked and the username " +
        "and email are freed, but the record is kept so the audit trail still " +
        "shows who did what.\n\nReason (required, recorded in the audit log):",
    );
    if (!reason || reason.trim().length < 3) return;
    setBusy(true);
    setErr(null);
    try {
      await removeOperator(operator.id, reason.trim());
      onChanged();
    } catch (e) {
      setErr((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  };
  const onEnable = async (): Promise<void> => {
    setBusy(true);
    setErr(null);
    try {
      await enableOperator(operator.id);
      onChanged();
    } catch (e) {
      setErr((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  };
  const onSubmitTempPassword = async (newPassword: string): Promise<void> => {
    setBusy(true);
    setErr(null);
    try {
      const r = await resetOperatorPassword(
        operator.id,
        "reset via Settings UI",
        newPassword,
      );
      setResetResult(r);
      setResetFormOpen(false);
      onChanged();
    } catch (e) {
      setErr((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <tr className="border-b border-border/40 last:border-b-0">
      <td className="px-4 py-2 font-medium text-text-primary">
        {operator.username}
        {isSelf && (
          <span className="ml-2 rounded bg-accent/20 px-1.5 py-0.5 text-xs text-accent">
            you
          </span>
        )}
      </td>
      <td className="px-4 py-2 text-text-dim">
        {operator.email}
        {canActOnTarget ? (
          <button
            type="button"
            disabled={busy}
            title="Change this operator's email (works on disabled accounts too)"
            onClick={() => {
              const next = window.prompt(
                `New email for ${operator.username}:`,
                operator.email,
              );
              if (!next || next.trim() === operator.email) return;
              setBusy(true);
              setErr(null);
              updateOperatorEmail(operator.id, next.trim())
                .then(() => onChanged())
                .catch((e: ApiError) => setErr(e.message))
                .finally(() => setBusy(false));
            }}
            className="ml-2 text-xs text-text-dim underline decoration-dotted hover:text-accent disabled:opacity-50"
          >
            edit
          </button>
        ) : null}
      </td>
      <td className="px-4 py-2">
        <div className="flex flex-wrap items-center gap-1">
          {operator.roles.map((r) => {
            const canRevoke =
              canActOnTarget && !isSelf && operator.roles.length > 1;
            const handleRevoke = (): void => {
              if (
                !window.confirm(
                  `Revoke '${r}' from ${operator.username}?`,
                )
              )
                return;
              setBusy(true);
              setErr(null);
              revokeRole(operator.id, r)
                .then(() => onChanged())
                .catch((e: ApiError) => setErr(e.message))
                .finally(() => setBusy(false));
            };
            return (
              <RoleBadge
                key={r}
                role={r}
                {...(canRevoke ? { onRevoke: handleRevoke } : {})}
              />
            );
          })}
          {operator.roles.length === 0 && (
            <span className="text-xs text-text-dim">none</span>
          )}
          {canActOnTarget && !isSelf ? (
            <GrantRolePicker
              operator={operator}
              callerTier={callerTier}
              busy={busy}
              onGrant={(role) => {
                // A viewer is a client user: the server refuses the '*'
                // default for it. Carry over a concrete scope, or ask for one.
                const concrete = operator.scope_slugs.filter((s) => s !== "*");
                if (
                  role === "viewer" &&
                  (concrete.length === 0 || operator.scope_slugs.includes("*"))
                ) {
                  setErr(
                    "A viewer is a client user and needs specific tenants: narrow this operator's tenant scope to the client's tenant(s) first, then grant viewer.",
                  );
                  return;
                }
                setBusy(true);
                setErr(null);
                grantRole(operator.id, role, role === "viewer" ? concrete : undefined)
                  .then(() => onChanged())
                  .catch((e: ApiError) => setErr(e.message))
                  .finally(() => setBusy(false));
              }}
            />
          ) : null}
        </div>
      </td>
      <td className="px-4 py-2">
        {canActOnTarget && !isSelf && operator.roles.length > 0 ? (
          <TenantScopeEditor
            operator={operator}
            clients={clients}
            primaryRole={
              operator.roles.reduce(
                (best, r) =>
                  (ROLE_TIER[r] ?? 0) > (ROLE_TIER[best] ?? 0) ? r : best,
                operator.roles[0]!,
              )
            }
            busy={busy}
            onSave={(scope) => {
              const role = operator.roles.reduce(
                (best, r) =>
                  (ROLE_TIER[r] ?? 0) > (ROLE_TIER[best] ?? 0) ? r : best,
                operator.roles[0]!,
              );
              setBusy(true);
              setErr(null);
              grantRole(operator.id, role, scope)
                .then(() => onChanged())
                .catch((e: ApiError) => setErr(e.message))
                .finally(() => setBusy(false));
            }}
          />
        ) : (
          <ScopeBadgeList scopes={operator.scope_slugs} />
        )}
      </td>
      <td className="px-4 py-2">
        {operator.mfa_enabled ? (
          <span className="text-success">on</span>
        ) : (
          <span className="text-text-dim">off</span>
        )}
      </td>
      <td className="px-4 py-2">
        {operator.disabled_at ? (
          <span className="text-critical">disabled</span>
        ) : operator.must_change_password ? (
          <span className="text-text-dim">pending</span>
        ) : (
          <span className="text-success">active</span>
        )}
      </td>
      <td className="px-4 py-2">
        <LlmGrantCell
          operator={operator}
          canManage={canActOnTarget && !operator.is_factory}
          onChanged={onChanged}
        />
      </td>
      <td className="px-4 py-2 text-text-dim">
        {operator.last_login_at?.slice(0, 19).replace("T", " ") ?? "never"}
      </td>
      <td className="px-4 py-2">
        <div className="flex items-center justify-end gap-2">
          {err && (
            <span
              role="alert"
              className="max-w-xs text-left text-xs text-critical"
              data-testid={`operator-error-${operator.username}`}
            >
              {err}
            </span>
          )}
          {canDisable && (
            <button
              type="button"
              disabled={busy}
              onClick={onDisable}
              className="rounded border border-critical/40 px-2 py-1 text-xs text-critical hover:bg-critical/10 disabled:opacity-50"
            >
              Disable
            </button>
          )}
          {canEnable && (
            <button
              type="button"
              disabled={busy}
              onClick={onEnable}
              className="rounded border border-success/40 px-2 py-1 text-xs text-success hover:bg-success/10 disabled:opacity-50"
            >
              Enable
            </button>
          )}
          {canRemove && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void onRemove()}
              title="Delete a never-used account, or retire one with history"
              className="rounded border border-critical/40 px-2 py-1 text-xs text-critical hover:bg-critical/10 disabled:opacity-50"
            >
              Remove
            </button>
          )}
          {canResetPassword && (
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setResetResult(null);
                setResetFormOpen((v) => !v);
              }}
              data-testid={`reset-pw-${operator.username}`}
              className="rounded border border-border-bright px-2 py-1 text-xs text-text-secondary hover:bg-accent-soft hover:text-accent disabled:opacity-50"
            >
              Reset password
            </button>
          )}
          {!canActOnTarget && !isSelf && (
            <span className="text-xs text-text-dim">tier-locked</span>
          )}
        </div>
        {resetFormOpen ? (
          <ResetPasswordForm
            username={operator.username}
            busy={busy}
            onSubmit={(pw) => void onSubmitTempPassword(pw)}
            onCancel={() => setResetFormOpen(false)}
          />
        ) : null}
        {resetResult && resetResult.operator_id === operator.id ? (
          <ResetResultPanel
            result={resetResult}
            onClose={() => setResetResult(null)}
          />
        ) : null}
      </td>
    </tr>
  );
};

const ResetPasswordForm: FC<{
  username: string;
  busy: boolean;
  onSubmit: (newPassword: string) => void;
  onCancel: () => void;
}> = ({ username, busy, onSubmit, onCancel }) => {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [localErr, setLocalErr] = useState<string | null>(null);

  const submit = (ev: React.FormEvent): void => {
    ev.preventDefault();
    setLocalErr(null);
    if (pw.length < 12) {
      setLocalErr("Password must be at least 12 characters.");
      return;
    }
    if (pw !== confirm) {
      setLocalErr("The two password fields don't match.");
      return;
    }
    onSubmit(pw);
  };

  return (
    <form
      onSubmit={submit}
      data-testid={`reset-pw-form-${username}`}
      className="mt-2 rounded border border-border bg-bg-card px-3 py-2"
    >
      <div className="mb-2 text-xs text-text-secondary">
        Set a temporary password for <strong>{username}</strong>. They'll be
        forced to change it on first sign-in. Tell them the temp password
        out-of-band (DM / phone / ticket) — never paste it where their own
        account can read it.
      </div>
      <label className="mb-2 block">
        <span className="mb-1 block text-[11px] text-text-dim">
          Temporary password{" "}
          <span className="font-mono text-[10px] uppercase tracking-wider">
            min 12 chars
          </span>
        </span>
        <input
          type="password"
          autoComplete="new-password"
          autoFocus
          required
          minLength={12}
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          className="w-full rounded border border-border bg-bg-input px-2 py-1 font-mono text-xs text-text-primary focus:border-accent focus:outline-none"
        />
      </label>
      <label className="mb-2 block">
        <span className="mb-1 block text-[11px] text-text-dim">
          Confirm temporary password
        </span>
        <input
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          className="w-full rounded border border-border bg-bg-input px-2 py-1 font-mono text-xs text-text-primary focus:border-accent focus:outline-none"
        />
      </label>
      {localErr ? (
        <div className="mb-2 rounded border border-critical/40 bg-critical/10 px-2 py-1 text-[11px] text-critical">
          {localErr}
        </div>
      ) : null}
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy}
          className="rounded border border-accent-cta bg-accent-cta px-2 py-1 text-[11px] font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
        >
          {busy ? "Setting…" : "Set temporary password"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary hover:text-text-primary"
        >
          Cancel
        </button>
      </div>
    </form>
  );
};

const ResetResultPanel: FC<{
  result: ResetPasswordResult;
  onClose: () => void;
}> = ({ result, onClose }) => {
  if (result.temporary_password_set) {
    return (
      <div className="mt-2 rounded border border-success/40 bg-success/10 px-3 py-2 text-xs">
        <div className="mb-1 font-semibold text-success">
          Temporary password set for {result.username}
        </div>
        <p className="text-text-secondary">
          Their sessions have been revoked and their old password is no
          longer valid. Tell them the temporary password you typed —
          they'll be forced to pick their own at next sign-in. The temp
          password is NOT stored or shown again.
        </p>
        <button
          type="button"
          onClick={onClose}
          className="mt-2 rounded border border-border px-2 py-0.5 text-text-secondary hover:text-text-primary"
        >
          Done
        </button>
      </div>
    );
  }
  // Magic-link mode (left in for completeness; not used by the current UI)
  const expiresAt = result.magic_link_expires_at
    ? new Date(result.magic_link_expires_at).toLocaleString()
    : "—";
  return (
    <div className="mt-2 rounded border border-accent/40 bg-accent-soft px-3 py-2 text-xs">
      <div className="mb-1 font-semibold text-accent">
        One-time setup link for {result.username}
      </div>
      {result.magic_link_url ? (
        <div className="mb-2 break-all rounded border border-border bg-bg-card px-2 py-1 font-mono text-[11px] text-text-primary">
          {result.magic_link_url}
        </div>
      ) : null}
      <div className="flex flex-wrap items-center justify-between gap-2 text-text-dim">
        <span>Expires {expiresAt}</span>
        <button
          type="button"
          onClick={onClose}
          className="rounded border border-border px-2 py-0.5 text-text-secondary hover:text-text-primary"
        >
          Done
        </button>
      </div>
    </div>
  );
};

/** Slice 7f — LLM access toggle column. Admins/super_admins can flip
 * this for subordinate-tier operators per the existing tier rule (the
 * backend rejects out-of-tier writes, so we surface the toggle as
 * disabled when `canManage` is false). Factory super_admin's grant
 * is locked from modification by others; we render a static "factory"
 * indicator for that row. */
const LlmGrantCell: FC<{
  operator: OperatorListEntry;
  canManage: boolean;
  onChanged: () => void;
}> = ({ operator, canManage, onChanged }) => {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [granted, setGranted] = useState(operator.l2_llm_granted);

  // Keep local state in sync if the parent re-fetches.
  useEffect(() => {
    setGranted(operator.l2_llm_granted);
  }, [operator.l2_llm_granted]);

  if (operator.is_factory) {
    return (
      <span
        className="font-mono text-[10px] uppercase tracking-wider text-accent"
        title="Factory super_admin is always granted; cannot be revoked here."
      >
        factory
      </span>
    );
  }

  const onToggle = (): void => {
    if (!canManage || busy) return;
    const next = !granted;
    setGranted(next);  // optimistic
    setBusy(true);
    setErr(null);
    setLlmGrant(operator.id, next)
      .then(() => onChanged())
      .catch((e: Error) => {
        setGranted(!next);  // revert
        setErr(e.message);
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        role="switch"
        aria-checked={granted}
        disabled={!canManage || busy}
        onClick={onToggle}
        title={
          canManage
            ? `${granted ? "Revoke" : "Grant"} L2 LLM access`
            : "Insufficient tier to change this operator's grant"
        }
        className={[
          "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors",
          granted
            ? "border-accent bg-accent/40"
            : "border-border bg-bg-card",
          (!canManage || busy) ? "cursor-not-allowed opacity-60" : "cursor-pointer",
        ].join(" ")}
      >
        <span
          className={[
            "inline-block h-3.5 w-3.5 transform rounded-full bg-text-primary transition-transform",
            granted ? "translate-x-5" : "translate-x-1",
          ].join(" ")}
        />
      </button>
      {err && (
        <span className="text-[10px] text-critical" title={err}>
          err
        </span>
      )}
    </div>
  );
};

const ScopeBadgeList: FC<{ scopes: string[] }> = ({ scopes }) => {
  if (scopes.length === 0) {
    return <span className="text-xs text-text-dim">none</span>;
  }
  if (scopes.includes("*")) {
    return (
      <span className="inline-block rounded border border-accent/40 bg-accent/20 px-1.5 py-0.5 font-mono text-[10px] text-accent">
        * all tenants
      </span>
    );
  }
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((s) => (
        <span
          key={s}
          className="inline-block rounded border border-border bg-bg-card px-1.5 py-0.5 font-mono text-[10px] text-text-secondary"
        >
          {s}
        </span>
      ))}
    </div>
  );
};

/** Why a viewer (client user) can't be scoped to this tenant, or null. The
 *  server refuses the same tenants; this only says so before the click. */
function viewerScopeBlock(c: ClientEntry): string | null {
  if (c.placeholder_name) {
    return "placeholder name — rename it under Tenants first";
  }
  if (c.placeholder_slug) {
    return "placeholder slug — merge it into a properly named tenant first";
  }
  return null;
}

const VIEWER_SCOPE_RULE =
  "A viewer is a client user: pick the specific tenant(s) they belong to. " +
  "All tenants (*) and an empty scope are refused for viewers.";

const TenantScopeEditor: FC<{
  operator: OperatorListEntry;
  clients: ClientEntry[];
  primaryRole: RoleName;
  busy: boolean;
  onSave: (scopes: string[]) => void;
}> = ({ operator, clients, primaryRole, busy, onSave }) => {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<string[]>(operator.scope_slugs);

  useEffect(() => {
    if (open) setDraft(operator.scope_slugs);
  }, [open, operator.scope_slugs]);

  // Viewers are CLIENT users: never '*', never empty, never a tenant still
  // named after a vendor (the server refuses all three). Others keep '*'
  // and an empty pick still saves as '*'.
  const isViewer = primaryRole === "viewer";
  const allTenants = draft.includes("*");
  // A viewer's scope may still name a tenant since offboarded (they read
  // nothing there already). It isn't listed below, so it can't be unticked:
  // it is dropped on save rather than have the server refuse the scope.
  const listed = new Set(clients.map((c) => c.slug));
  const effective = isViewer && clients.length > 0
    ? draft.filter((s) => s === "*" || listed.has(s))
    : draft;
  const viewerInvalid = isViewer && (effective.includes("*") || effective.length === 0);

  const toggleAll = (): void => {
    setDraft((d) => (d.includes("*") ? [] : ["*"]));
  };
  const toggleSlug = (slug: string): void => {
    setDraft((d) => {
      const without = d.filter((s) => s !== "*");
      return without.includes(slug)
        ? without.filter((s) => s !== slug)
        : [...without, slug];
    });
  };

  const save = (): void => {
    if (viewerInvalid) return;
    const final = effective.length === 0 ? ["*"] : effective;
    onSave(final);
    setOpen(false);
  };

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={busy}
        className="flex flex-wrap items-center gap-1 rounded border border-dashed border-border-bright px-1.5 py-0.5 text-left text-xs text-text-secondary hover:bg-accent-soft hover:text-accent disabled:opacity-50"
        title="Edit tenant scope"
        data-testid={`scope-editor-${operator.username}`}
      >
        <ScopeBadgeList scopes={operator.scope_slugs} />
        <span aria-hidden="true">▾</span>
      </button>
      {open ? (
        <div
          role="menu"
          className="absolute left-0 top-full z-20 mt-1 w-64 rounded border border-border bg-bg-elevated p-2 shadow-lg"
        >
          <label
            className={[
              "mb-2 flex items-center gap-2 rounded px-2 py-1 text-xs text-text-secondary hover:bg-accent-soft hover:text-accent",
              isViewer ? "opacity-50" : "",
            ].join(" ")}
            title={isViewer ? VIEWER_SCOPE_RULE : undefined}
          >
            <input
              type="checkbox"
              checked={allTenants}
              disabled={isViewer}
              onChange={toggleAll}
              aria-label="all tenants"
            />
            <span>
              <span className="font-mono">*</span> all tenants
            </span>
          </label>
          <div className="max-h-48 overflow-y-auto border-t border-border pt-1">
            {clients.length === 0 ? (
              <div className="px-2 py-1 text-[11px] text-text-dim">
                No customers configured in this bundle yet. Add a client
                via the future Tenants tab.
              </div>
            ) : (
              clients.map((c) => {
                const checked = draft.includes(c.slug);
                const block = isViewer ? viewerScopeBlock(c) : null;
                // A blocked tenant can still be UNticked (a scope written
                // before the rule), never ticked.
                const disabled = (!isViewer && allTenants) || (block !== null && !checked);
                return (
                  <label
                    key={c.slug}
                    className={[
                      "flex items-center gap-2 rounded px-2 py-1 text-xs hover:bg-accent-soft hover:text-accent",
                      disabled ? "opacity-50" : "text-text-secondary",
                    ].join(" ")}
                    title={block ?? undefined}
                  >
                    <input
                      type="checkbox"
                      disabled={disabled}
                      checked={checked}
                      onChange={() => toggleSlug(c.slug)}
                      aria-label={`scope ${c.slug}`}
                    />
                    <span className="flex-1">
                      {c.display_name}
                      {block ? (
                        <span className="block text-[10px] text-high">{block}</span>
                      ) : null}
                    </span>
                    <span className="font-mono text-[10px] text-text-dim">
                      {c.slug}
                    </span>
                  </label>
                );
              })
            )}
          </div>
          {viewerInvalid ? (
            <div
              role="alert"
              className="mt-2 rounded border border-critical/30 bg-critical/10 px-2 py-1 text-[11px] text-critical"
            >
              {VIEWER_SCOPE_RULE}
            </div>
          ) : null}
          <div className="mt-2 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="rounded border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={save}
              disabled={viewerInvalid}
              className="rounded border border-accent-cta bg-accent-cta px-2 py-1 text-[11px] font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
            >
              Save scope
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
};

const GrantRolePicker: FC<{
  operator: OperatorListEntry;
  callerTier: number;
  busy: boolean;
  onGrant: (role: RoleName) => void;
}> = ({ operator, callerTier, busy, onGrant }) => {
  const [open, setOpen] = useState(false);
  const grantable = ROLE_CHOICES.filter((r) => {
    if (operator.roles.includes(r)) return false; // already has it
    if ((ROLE_TIER[r] ?? 0) > callerTier) return false; // tier rule
    return true;
  });
  if (grantable.length === 0) return null;
  return (
    <div className="relative">
      <button
        type="button"
        disabled={busy}
        onClick={() => setOpen((v) => !v)}
        title="Grant role"
        aria-label="Grant role"
        data-testid={`grant-role-${operator.username}`}
        className="rounded border border-dashed border-border-bright px-1.5 py-0.5 text-xs text-text-secondary hover:bg-accent-soft hover:text-accent disabled:opacity-50"
      >
        + role
      </button>
      {open ? (
        <div
          role="menu"
          className="absolute left-0 top-full z-10 mt-1 flex flex-col gap-px rounded border border-border bg-bg-elevated p-1 shadow-lg"
        >
          {grantable.map((r) => (
            <button
              key={r}
              type="button"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                onGrant(r);
              }}
              className="rounded-sm px-2 py-1 text-left text-xs text-text-secondary hover:bg-accent-soft hover:text-accent"
            >
              {ROLE_LABEL[r]}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
};

const RoleBadge: FC<{ role: RoleName; onRevoke?: () => void }> = ({
  role,
  onRevoke,
}) => {
  const tone =
    role === "super_admin"
      ? "bg-accent/20 text-accent border-accent/40"
      : role === "admin"
      ? "bg-success/20 text-success border-success/40"
      : role === "analyst"
      ? "bg-bg-base text-text-secondary border-border"
      : "bg-bg-base text-text-dim border-border";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs ${tone}`}
    >
      {ROLE_LABEL[role]}
      {onRevoke ? (
        <button
          type="button"
          onClick={onRevoke}
          title={`Revoke ${ROLE_LABEL[role]}`}
          aria-label={`Revoke ${ROLE_LABEL[role]}`}
          className="ml-0.5 leading-none text-text-dim hover:text-critical"
        >
          ×
        </button>
      ) : null}
    </span>
  );
};

// ---------------------------------------------------------------------------
// Create form
// ---------------------------------------------------------------------------

const CreateOperatorForm: FC<{
  me: MeResponse;
  onCancel: () => void;
  onCreated: (resp: CreateOperatorResponse) => void;
}> = ({ me, onCancel, onCreated }) => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<RoleName>("analyst");
  const [scopeRaw, setScopeRaw] = useState("*");
  // A viewer's tenants are PICKED from the active tenants, never typed:
  // a viewer is a client user, and '*' / empty would show them every
  // tenant (the server refuses both, and vendor-named placeholders).
  const [viewerTenants, setViewerTenants] = useState<string[]>([]);
  const [clients, setClients] = useState<ClientEntry[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const isViewer = role === "viewer";

  useEffect(() => {
    if (!isViewer || clients !== null) return;
    listClients()
      .then(setClients)
      .catch((e: ApiError) => {
        setClients([]);
        setErr(`Could not load tenants: ${e.message}`);
      });
  }, [isViewer, clients]);

  const allowedRoles = ROLE_CHOICES.filter((r) =>
    canManageRole(me.role, r),
  );

  const toggleViewerTenant = (slug: string): void => {
    setViewerTenants((d) =>
      d.includes(slug) ? d.filter((s) => s !== slug) : [...d, slug],
    );
  };

  const onSubmit = async (
    ev: React.FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    ev.preventDefault();
    setErr(null);
    if (!username.trim() || !email.trim()) {
      setErr("Username and email are required.");
      return;
    }
    let scope_slugs: string[];
    if (isViewer) {
      if (viewerTenants.length === 0) {
        setErr("Pick the tenant(s) this client user belongs to.");
        return;
      }
      scope_slugs = [...viewerTenants].sort();
    } else {
      const typed = scopeRaw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      scope_slugs = typed.length > 0 ? typed : ["*"];
    }
    setBusy(true);
    try {
      const resp = await createOperator({
        username: username.trim(),
        email: email.trim(),
        role,
        scope_slugs,
      });
      onCreated(resp);
    } catch (e) {
      setErr((e as ApiError).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={onSubmit}
      className="rounded-lg border border-border bg-bg-surface p-6"
    >
      <h2 className="mb-4 text-base font-semibold text-text-primary">
        Create operator
      </h2>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-text-dim">Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="off"
            spellCheck={false}
            pattern="[A-Za-z0-9._\-]+"
            className="rounded border border-border bg-bg-base px-2 py-1 text-text-primary"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-text-dim">Email</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="rounded border border-border bg-bg-base px-2 py-1 text-text-primary"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-text-dim">Role</span>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as RoleName)}
            className="rounded border border-border bg-bg-base px-2 py-1 text-text-primary"
          >
            {allowedRoles.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
        </label>
        {isViewer ? (
          <fieldset
            className="flex flex-col gap-1 text-sm"
            data-testid="viewer-tenant-picker"
          >
            <legend className="text-text-dim">
              Tenant(s) — a viewer is a client user and sees only these
            </legend>
            <div className="max-h-48 overflow-y-auto rounded border border-border bg-bg-base p-1">
              {clients === null ? (
                <div className="px-2 py-1 text-xs text-text-dim">Loading tenants…</div>
              ) : clients.length === 0 ? (
                <div className="px-2 py-1 text-xs text-text-dim">
                  No active tenants to invite a client user to.
                </div>
              ) : (
                clients.map((c) => {
                  const block = viewerScopeBlock(c);
                  return (
                    <label
                      key={c.slug}
                      className={[
                        "flex items-center gap-2 rounded px-2 py-1 text-xs",
                        block ? "opacity-60" : "text-text-secondary hover:bg-accent-soft",
                      ].join(" ")}
                      title={block ?? undefined}
                    >
                      <input
                        type="checkbox"
                        disabled={block !== null}
                        checked={viewerTenants.includes(c.slug)}
                        onChange={() => toggleViewerTenant(c.slug)}
                        aria-label={`invite to ${c.slug}`}
                      />
                      <span className="flex-1">
                        {c.display_name}
                        {block ? (
                          <span className="block text-[10px] text-high">{block}</span>
                        ) : null}
                      </span>
                      <span className="font-mono text-[10px] text-text-dim">{c.slug}</span>
                    </label>
                  );
                })
              )}
            </div>
          </fieldset>
        ) : (
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-text-dim">
              Scope slugs (comma-separated, * for all)
            </span>
            <input
              value={scopeRaw}
              onChange={(e) => setScopeRaw(e.target.value)}
              className="rounded border border-border bg-bg-base px-2 py-1 text-text-primary"
            />
          </label>
        )}
      </div>
      {err && (
        <p className="mt-3 text-sm text-critical" role="alert">
          {err}
        </p>
      )}
      <div className="mt-4 flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={busy}
          className="rounded border border-border px-3 py-1.5 text-sm text-text-secondary hover:text-text-primary"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={busy || (isViewer && viewerTenants.length === 0)}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:opacity-90 disabled:opacity-50"
        >
          {busy ? "Creating…" : "Create operator"}
        </button>
      </div>
    </form>
  );
};

// ---------------------------------------------------------------------------
// Activation-link banner
// ---------------------------------------------------------------------------

const ActivationLinkBanner: FC<{
  response: CreateOperatorResponse;
  onDismiss: () => void;
}> = ({ response, onDismiss }) => {
  const [copied, setCopied] = useState(false);
  const onCopy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(response.magic_link_url);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Browser denied clipboard; user can copy manually.
    }
  };
  const expires = new Date(response.magic_link_expires_at).toLocaleString();
  return (
    <section className="rounded-lg border border-accent/40 bg-accent/10 p-4 text-sm">
      <div className="mb-2 flex items-start justify-between gap-3">
        <div>
          <h3 className="font-semibold text-accent">
            Activation link generated for {response.username}
          </h3>
          <p className="text-text-secondary">
            Deliver this URL to the new operator over a trusted out-of-band
            channel (e.g., signal, encrypted email, in-person). It expires at{" "}
            <strong>{expires}</strong> and can only be used once. Athena will
            not display this link again — copy it now.
          </p>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          className="text-text-dim hover:text-text-primary"
          aria-label="Dismiss"
        >
          ×
        </button>
      </div>
      <div className="flex items-center gap-2">
        <code className="flex-1 break-all rounded border border-border bg-bg-base px-2 py-1.5 text-xs text-text-primary">
          {response.magic_link_url}
        </code>
        <button
          type="button"
          onClick={onCopy}
          className="rounded border border-border px-3 py-1.5 text-xs hover:border-accent hover:text-accent"
        >
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
    </section>
  );
};

export default OperatorsTab;
