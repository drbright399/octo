/**
 * OneTimeSecretPanel — shown once, right after an integration is created with
 * an Athena-generated webhook token.
 *
 * Tells the operator what to do NOW (store the token somewhere safe) and what
 * NOT to do yet (attach the webhook before sites are mapped — alerts from
 * unmapped sites create pending tenants or are held for review), then exactly
 * what to configure on the vendor
 * side: the header name, the header value (the token), the URL to post to and
 * the payload templates — each with a copy button. The token is masked until
 * revealed.
 *
 * Copy buttons only say "copied" once the clipboard write RESOLVES. If the
 * clipboard API is missing or the write is rejected, the token is revealed and
 * the operator is told to select and copy it by hand — a false "copied" here
 * would lose a value the backend can never show again.
 *
 * Security: the token arrives as a prop from the wizard's component state and
 * goes nowhere else — no localStorage/sessionStorage, no URL, no logging. The
 * backend cannot show it again, so when this panel unmounts it is gone; the
 * recovery path is Settings → Integrations → <vendor> → Disable, then Add
 * integration again.
 */
import { type FC, type ReactNode, useCallback, useState } from "react";
import { CodeBlock, copyButtonText } from "@/components/onboarding-guide";
import type { GeneratedWebhookSecret, OnboardingStep } from "@/contracts/integration";
import { recoveryPath } from "@/lib/integration-fields";
import { useClipboardCopy } from "@/lib/use-clipboard-copy";

interface Props {
  readonly vendorName: string;
  readonly secret: GeneratedWebhookSecret;
  /** The adapter's setup-guide steps; the ones carrying a payload template
   *  are repeated here so they are on screen when the token is. */
  readonly steps?: readonly OnboardingStep[] | undefined;
  /** Operator confirms they have stored it; the wizard drops the value. */
  readonly onContinue: () => void;
}

const MASK = "•".repeat(32);

export const OneTimeSecretPanel: FC<Props> = ({ vendorName, secret, steps, onContinue }) => {
  const [revealed, setRevealed] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const tokenLabel = secret.credential_label || "Webhook Token";
  const templates = (steps ?? []).filter((s) => s.code_sample);

  // The token could not reach the clipboard: show it so it can be selected.
  const onTokenCopyFailed = useCallback((): void => {
    setRevealed(true);
    setCopyFailed(true);
  }, []);

  return (
    <>
      <div
        data-testid="one-time-secret-panel"
        className="flex flex-1 flex-col gap-4 overflow-y-auto p-5"
      >
        <div
          role="alert"
          className="rounded border border-high/60 bg-high/10 px-3 py-2 text-xs leading-relaxed text-text-primary"
        >
          <strong className="font-semibold">Shown once</strong> — this token cannot be
          displayed again. Copy it somewhere SAFE now (a password manager).{" "}
          <strong className="font-semibold">
            Do NOT attach the webhook to a {vendorName} monitor until you have mapped
            your sites on the next screen
          </strong>{" "}
          — alerts from unmapped sites create pending tenants or are held for review.
          If the token is lost:{" "}
          {recoveryPath(vendorName)}.
        </div>

        <p className="text-xs leading-relaxed text-text-secondary">
          Athena generated this integration&apos;s {tokenLabel} and stored it encrypted.
          Once your sites are mapped, configure the {vendorName} webhook to send it as a
          custom header. The token is held in this tab only until you continue; your
          clipboard will contain it — clear it afterwards.
        </p>

        {copyFailed ? (
          <div
            role="alert"
            data-testid="token-copy-failed"
            className="rounded border border-critical bg-critical/10 px-3 py-2 text-xs leading-relaxed text-critical"
          >
            Copy failed — select it and copy manually. This browser did not allow
            clipboard access, so the token is revealed below.
          </div>
        ) : null}

        <CopyRow label="Header name" value={secret.header_name} copyLabel="Copy header name" />

        <CopyRow
          label={`Header value — the ${tokenLabel}`}
          value={secret.header_value}
          display={revealed ? secret.header_value : MASK}
          copyLabel="Copy header value"
          testId="one-time-secret-value"
          selectable={revealed}
          onCopyFailed={onTokenCopyFailed}
          extra={
            <button
              type="button"
              aria-pressed={revealed}
              onClick={() => setRevealed((v) => !v)}
              className="border border-l-0 border-border px-2 py-1.5 font-mono text-[10px] uppercase tracking-wider text-text-dim hover:bg-accent-soft hover:text-accent"
            >
              {revealed ? "hide" : "reveal"}
            </button>
          }
        />

        {secret.webhook_url ? (
          <CopyRow
            label="Webhook URL — where the vendor posts"
            value={secret.webhook_url}
            copyLabel="Copy webhook URL"
          />
        ) : (
          <div
            role="status"
            data-testid="no-ingest-host-notice"
            className="rounded border border-critical/60 bg-critical/10 px-3 py-2 text-xs leading-relaxed text-text-primary"
          >
            {secret.webhook_url_problem ??
              "No public ingest hostname is configured — real-time webhooks cannot work until one is set."}{" "}
            Keep the token: it stays valid once an ingest hostname exists.
          </div>
        )}

        {templates.length > 0 ? (
          <section data-testid="secret-panel-templates" className="flex flex-col gap-2">
            <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
              Payload templates — the {vendorName} webhook body
            </span>
            {templates.map((s) => (
              <details key={s.title} className="rounded-sm border border-border bg-bg-surface">
                <summary className="cursor-pointer px-2 py-1.5 text-xs text-text-primary">
                  {s.title}
                </summary>
                <div className="px-2 pb-2">
                  <p className="text-[11px] leading-relaxed text-text-secondary">{s.body}</p>
                  <CodeBlock
                    code={s.code_sample ?? ""}
                    copyLabel={`Copy template: ${s.title}`}
                  />
                </div>
              </details>
            ))}
            <p className="text-[11px] leading-relaxed text-text-dim">
              The URL, the header name and these templates stay available after this
              screen: Settings → Integrations → {vendorName} → Setup guide. Only the
              token is never shown again.
            </p>
          </section>
        ) : null}
      </div>

      <footer className="flex items-center justify-end gap-2 border-t border-border bg-bg-surface px-5 py-3">
        <button
          type="button"
          onClick={onContinue}
          className="rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong"
        >
          I&apos;ve stored it safely — continue
        </button>
      </footer>
    </>
  );
};

const CopyRow: FC<{
  label: string;
  value: string;
  /** What is rendered; defaults to `value`. Copy always copies `value`. */
  display?: string;
  copyLabel: string;
  testId?: string;
  extra?: ReactNode;
  /** Make the rendered value easy to select by hand (one click selects all). */
  selectable?: boolean;
  onCopyFailed?: () => void;
}> = ({ label, value, display, copyLabel, testId, extra, selectable, onCopyFailed }) => {
  // "copied" only once the clipboard write resolved — see useClipboardCopy.
  const { state, copy } = useClipboardCopy(onCopyFailed);
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
        {label}
      </span>
      <div className="flex items-stretch">
        <code
          data-testid={testId}
          className={`min-w-0 flex-1 overflow-x-auto rounded-l-sm border border-border bg-bg-input px-2 py-1.5 font-mono text-[11px] text-text-secondary${selectable ? " select-all" : ""}`}
        >
          {display ?? value}
        </code>
        {extra}
        <button
          type="button"
          aria-label={copyLabel}
          onClick={() => void copy(value)}
          className="rounded-r-sm border border-l-0 border-border px-2 py-1.5 font-mono text-[10px] uppercase tracking-wider text-text-dim hover:bg-accent-soft hover:text-accent"
        >
          {copyButtonText(state)}
        </button>
      </div>
    </div>
  );
};
