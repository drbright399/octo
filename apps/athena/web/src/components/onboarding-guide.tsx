/**
 * OnboardingGuide — the guided setup panel rendered in the integration
 * configure surface when an adapter declares `onboarding`.
 *
 * Ported from Claude Design's `integration-handoff-bundle` ConfigureDrawer
 * guide column, adapted into a STEPPED walkthrough: one step at a time with
 * a subtle game-menu "loading" transition between steps (a brief accent
 * sweep + dim, then the next step slides in). Collapses to an instant swap
 * under `prefers-reduced-motion`.
 *
 * Renders the webhook URL prominently (webhook-first) for push/hybrid
 * adapters — or, when the deployment has no public ingest hostname, the
 * backend's explicit "webhooks cannot work yet" notice instead of any URL —
 * then the steps — each with optional copy-able value (webhook
 * URL) and a monospaced payload-template block.
 */
import { type FC, useEffect, useState } from "react";
import type { Onboarding, OnboardingStep } from "@/contracts/integration";
import { type CopyState, useClipboardCopy } from "@/lib/use-clipboard-copy";

/** Button text for a copy control — "copied" only after the write resolved. */
export function copyButtonText(state: CopyState): string {
  if (state === "copied") return "copied ✓";
  if (state === "failed") return "copy failed — select it";
  return "copy";
}

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true
  );
}

interface Props {
  readonly onboarding: Onboarding;
  readonly deliveryMode: string;
}

export const OnboardingGuide: FC<Props> = ({ onboarding, deliveryMode }) => {
  const isPush = deliveryMode === "push" || deliveryMode === "hybrid";
  const steps = onboarding.steps;
  const [active, setActive] = useState(0);
  // `pending` holds the target step while the loading transition plays.
  const [pending, setPending] = useState<number | null>(null);

  useEffect(() => {
    if (pending === null) return;
    const swap = window.setTimeout(() => setActive(pending), 190);
    const done = window.setTimeout(() => setPending(null), 210);
    return () => {
      window.clearTimeout(swap);
      window.clearTimeout(done);
    };
  }, [pending]);

  const goTo = (i: number): void => {
    if (i === active || pending !== null || i < 0 || i >= steps.length) return;
    if (prefersReducedMotion()) {
      setActive(i);
      return;
    }
    setPending(i);
  };

  const step = steps[active];
  if (!step) return null;
  const transitioning = pending !== null;

  return (
    <section className="mb-5 rounded-md border border-border bg-bg-surface p-4">
      <div className="mb-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider text-text-dim">
        <span className="text-accent">·· 01 ··</span>
        <span>setup guide</span>
      </div>
      <p className="mb-3 text-xs leading-relaxed text-text-secondary">{onboarding.summary}</p>

      {isPush && onboarding.webhook_url ? (
        <CopyField
          label="Athena webhook URL — paste this into the vendor"
          value={onboarding.webhook_url}
          prominent
        />
      ) : isPush && onboarding.webhook_url_problem ? (
        // No ingest hostname → NO URL. Never substitute the console address:
        // a vendor posting there is blocked at the access gate.
        <div
          role="status"
          data-testid="no-ingest-host-notice"
          className="rounded-sm border border-critical/60 bg-critical/10 p-2 text-xs leading-relaxed text-text-primary"
        >
          {onboarding.webhook_url_problem}
        </div>
      ) : null}

      {/* Step indicator — clickable, with the loading transition on change. */}
      <div className="mb-3 mt-3 flex flex-wrap items-center gap-1.5">
        {steps.map((s, i) => (
          <button
            key={s.title}
            type="button"
            aria-label={`Step ${i + 1}: ${s.title}`}
            aria-current={i === active ? "step" : undefined}
            onClick={() => goTo(i)}
            className={[
              "nav-sweep rounded-sm border px-2 py-1 font-mono text-[10px] transition-colors",
              i === active
                ? "border-accent bg-accent-soft text-accent"
                : "border-border text-text-dim hover:text-text-secondary",
            ].join(" ")}
          >
            {String(i + 1).padStart(2, "0")}
          </button>
        ))}
      </div>

      <div className="onb-stepview relative">
        {transitioning ? <span className="onb-loadbar" aria-hidden="true" /> : null}
        <div
          key={active}
          className={`onb-step-content ${transitioning ? "onb-step-content--out" : "onb-step-content--in"}`}
        >
          <StepBody step={step} />
        </div>
      </div>

      {/* Prev / Next */}
      <div className="mt-3 flex items-center justify-between">
        <button
          type="button"
          disabled={active === 0 || transitioning}
          onClick={() => goTo(active - 1)}
          className="nav-sweep rounded-sm border border-border px-3 py-1 font-mono text-[11px] text-text-secondary disabled:cursor-default disabled:opacity-40"
        >
          ← prev
        </button>
        <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
          step {active + 1} of {steps.length}
        </span>
        <button
          type="button"
          disabled={active === steps.length - 1 || transitioning}
          onClick={() => goTo(active + 1)}
          className="nav-sweep rounded-sm border border-border px-3 py-1 font-mono text-[11px] text-text-secondary disabled:cursor-default disabled:opacity-40"
        >
          next →
        </button>
      </div>
    </section>
  );
};

const StepBody: FC<{ readonly step: OnboardingStep }> = ({ step }) => (
  <div className="flex flex-col gap-2">
    <div className="text-[13px] font-semibold text-text-primary">{step.title}</div>
    <div className="text-xs leading-relaxed text-text-secondary">{step.body}</div>
    {step.copy_value ? <CopyField label="copy" value={step.copy_value} /> : null}
    {step.code_sample ? <CodeBlock code={step.code_sample} /> : null}
  </div>
);

// ---------- Copy-to-clipboard field ----------
const CopyField: FC<{ label?: string; value: string; prominent?: boolean }> = ({
  label,
  value,
  prominent,
}) => {
  const { state, copy } = useClipboardCopy();
  return (
    <div
      className={`mt-1 flex flex-col gap-1 ${prominent ? "rounded-sm border border-accent/30 bg-accent-soft p-2" : ""}`}
    >
      {label ? (
        <span
          className={`font-mono text-[10px] uppercase tracking-wider ${prominent ? "text-accent" : "text-text-dim"}`}
        >
          {label}
        </span>
      ) : null}
      <div className="flex items-stretch">
        <code className="min-w-0 flex-1 overflow-x-auto rounded-l-sm border border-border bg-bg-input px-2 py-1.5 font-mono text-[11px] text-text-secondary">
          {value}
        </code>
        <button
          type="button"
          onClick={() => void copy(value)}
          className="rounded-r-sm border border-l-0 border-border px-2 py-1.5 font-mono text-[10px] uppercase tracking-wider text-text-dim hover:bg-accent-soft hover:text-accent"
        >
          {copyButtonText(state)}
        </button>
      </div>
    </div>
  );
};

// ---------- Payload code block ----------
export const CodeBlock: FC<{ code: string; copyLabel?: string }> = ({ code, copyLabel }) => {
  const { state, copy } = useClipboardCopy();
  return (
    <div className="mt-1 overflow-hidden rounded-sm border border-border bg-bg-deep">
      <div className="flex items-center justify-between border-b border-border px-2.5 py-1">
        <span className="font-mono text-[9px] uppercase tracking-wider text-text-dim">
          json · payload template
        </span>
        <button
          type="button"
          aria-label={copyLabel}
          onClick={() => void copy(code)}
          className="font-mono text-[10px] uppercase tracking-wider text-text-dim hover:text-accent"
        >
          {copyButtonText(state)}
        </button>
      </div>
      <pre className="m-0 overflow-x-auto px-3 py-2.5">
        <code className="font-mono text-[11px] leading-relaxed text-text-secondary">{code}</code>
      </pre>
    </div>
  );
};
