/**
 * ConfirmDialog — the in-app "Are you sure?" for an action that cannot be
 * taken back with a click (never `window.confirm`: it blocks the thread,
 * cannot say what the choice means, and looks like the browser, not Athena).
 *
 * An alertdialog portalled to <body> ABOVE the drawers that host it (a
 * drawer is z-50), labelled by its title and described by its body:
 *   - focus starts on Cancel — the safe default — and Tab stays inside;
 *   - Escape and the backdrop are Cancel;
 *   - on close focus goes to `returnFocus()` (the control that opened it, or
 *     the caller's choice when that control is gone);
 *   - while `busy` every button is disabled, the box holds the focus and
 *     Escape / the backdrop do nothing; a failure is shown inside (`error`)
 *     and the dialog stays, focus back on Cancel.
 * The caller runs the action and closes the dialog — this only asks.
 */
import { type FC, type KeyboardEvent, type ReactNode, useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";

export interface ConfirmAction {
  readonly id: string;
  readonly label: string;
  /** The label while THIS action runs ("Saving…"). */
  readonly busyLabel?: string;
  /** The recommended choice: filled. Every other choice is outlined. */
  readonly primary?: boolean;
  readonly onSelect: () => void;
}

interface Props {
  readonly title: string;
  /** What the choice means, in plain words (the dialog's description). */
  readonly children: ReactNode;
  readonly actions: readonly ConfirmAction[];
  readonly onCancel: () => void;
  /** The id of the action in flight; null when idle. */
  readonly busy?: string | null;
  readonly error?: string | null;
  readonly returnFocus?: () => HTMLElement | null | undefined;
  readonly testId?: string;
}

const FOCUSABLE = "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex='-1'])";

export const ConfirmDialog: FC<Props> = ({
  title,
  children,
  actions,
  onCancel,
  busy = null,
  error = null,
  returnFocus,
  testId = "confirm-dialog",
}) => {
  const titleId = useId();
  const bodyId = useId();
  const boxRef = useRef<HTMLDivElement | null>(null);
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  const returnRef = useRef(returnFocus);
  const working = busy !== null;

  useEffect(() => {
    returnRef.current = returnFocus;
  });
  useEffect(() => {
    cancelRef.current?.focus();
    return () => {
      const to = returnRef.current?.();
      if (to?.isConnected) to.focus();
    };
  }, []);

  // A disabled button drops focus (to <body>, where keys no longer reach the
  // box and Tab walks out to the page behind). While busy the box itself
  // holds it — Tab stays put, Escape waits; when the action fails, focus
  // goes back to the safe choice.
  useEffect(() => {
    const box = boxRef.current;
    if (!box) return;
    if (working) box.focus();
    else if (document.activeElement === box || !box.contains(document.activeElement)) cancelRef.current?.focus();
  }, [working]);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>): void => {
    if (e.key === "Escape") {
      e.stopPropagation();
      e.preventDefault();
      if (!working) onCancel();
      return;
    }
    if (e.key !== "Tab" || !boxRef.current) return;
    const items = Array.from(boxRef.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) {
      e.preventDefault();
      return;
    }
    if (e.shiftKey && (document.activeElement === first || document.activeElement === boxRef.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <>
      <div
        onClick={working ? undefined : onCancel}
        aria-hidden="true"
        data-testid={`${testId}-backdrop`}
        className="fixed inset-0 z-[60] bg-black/50"
      />
      <div
        ref={boxRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        aria-busy={working}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        data-testid={testId}
        className="fixed left-1/2 top-1/2 z-[70] w-[min(520px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border-bright bg-bg-elevated p-5 shadow-xl focus:outline-none"
      >
        <h2 id={titleId} className="text-base font-semibold text-text-primary">
          {title}
        </h2>
        <div id={bodyId} className="mt-2 flex flex-col gap-2 text-xs leading-relaxed text-text-secondary">
          {children}
        </div>
        {error ? (
          <div role="alert" className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
            {error}
          </div>
        ) : null}
        <div className="mt-4 flex flex-wrap items-center justify-end gap-2">
          <button
            ref={cancelRef}
            type="button"
            disabled={working}
            onClick={onCancel}
            className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50"
          >
            Cancel
          </button>
          {actions.map((a) => (
            <button
              key={a.id}
              type="button"
              disabled={working}
              onClick={a.onSelect}
              data-testid={`${testId}-${a.id}`}
              className={
                a.primary
                  ? "rounded-sm border border-critical bg-critical px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
                  : "rounded-sm border border-critical px-3 py-1.5 text-xs text-critical hover:bg-critical/10 disabled:opacity-50"
              }
            >
              {busy === a.id ? (a.busyLabel ?? "Saving…") : a.label}
            </button>
          ))}
        </div>
      </div>
    </>,
    document.body,
  );
};

export default ConfirmDialog;
