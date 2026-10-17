/**
 * ResolvedLinkButton — an external link whose address has to be LOOKED UP
 * when the operator asks for it.
 *
 * Used for "open device in the vendor portal": the portal addresses a device
 * by an id the console does not have, and looking it up costs a (rate-limited)
 * vendor API read — so nothing is resolved per row, only on click.
 *
 *   idle      → a button
 *   pending   → the button, disabled ("…")
 *   resolved  → the address opens in a new tab, and the control BECOMES a real
 *               <a target="_blank" rel="noopener noreferrer"> — so a blocked
 *               pop-up costs one more click, not a dead end. The window.open
 *               happens after an await, i.e. outside the click's user
 *               activation: browsers may block it, and with "noopener" the
 *               call cannot tell. So the resolved state SAYS what happened
 *               (role="status") instead of leaving a button that turned into
 *               a link and nothing else.
 *   failed    → NO navigation; the server's sentence is shown (role="alert")
 *               and the button can be pressed again
 *
 * Only an https:// address is ever opened or rendered. The caller's
 * `resolve()` decides where the address comes from; this component never
 * builds one.
 */
import { type FC, useEffect, useRef, useState } from "react";

export interface ResolvedLinkButtonProps {
  readonly label: string;
  /** Rejects with an Error whose message is shown to the operator. */
  readonly resolve: () => Promise<string>;
  /** Tooltip for the idle / resolved control. */
  readonly title?: string | undefined;
  readonly className?: string | undefined;
  readonly testId?: string | undefined;
}

type State =
  | { readonly status: "idle" | "pending" }
  | { readonly status: "resolved"; readonly url: string }
  | { readonly status: "failed"; readonly message: string };

export const ResolvedLinkButton: FC<ResolvedLinkButtonProps> = ({
  label,
  resolve,
  title,
  className,
  testId,
}) => {
  const [state, setState] = useState<State>({ status: "idle" });
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const onClick = async (): Promise<void> => {
    if (state.status === "pending") return;
    setState({ status: "pending" });
    try {
      const url = await resolve();
      if (typeof url !== "string" || !url.startsWith("https://")) {
        throw new Error("no usable address was returned");
      }
      if (!alive.current) return;
      setState({ status: "resolved", url });
      window.open(url, "_blank", "noopener,noreferrer");
    } catch (e) {
      if (!alive.current) return;
      setState({
        status: "failed",
        message: e instanceof Error && e.message ? e.message : "The link could not be looked up",
      });
    }
  };

  if (state.status === "resolved") {
    return (
      <>
        <a
          href={state.url}
          target="_blank"
          rel="noopener noreferrer"
          title={title}
          data-testid={testId}
          className={className}
        >
          {label} <span aria-hidden="true">↗</span>
        </a>
        <span
          role="status"
          data-testid={testId ? `${testId}-status` : undefined}
          className="max-w-[28rem] text-[10px] leading-snug text-text-dim"
        >
          Looked up. If a new tab did not open, click the link again.
        </span>
      </>
    );
  }

  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          void onClick();
        }}
        disabled={state.status === "pending"}
        aria-busy={state.status === "pending" ? "true" : undefined}
        title={title}
        data-testid={testId}
        className={[className ?? "", state.status === "pending" ? "cursor-wait opacity-60" : ""].join(" ")}
      >
        {state.status === "pending" ? `${label} …` : label}
      </button>
      {state.status === "failed" ? (
        <span
          role="alert"
          data-testid={testId ? `${testId}-error` : undefined}
          className="max-w-[28rem] text-[11px] text-critical"
        >
          {state.message}
        </span>
      ) : null}
    </>
  );
};

export default ResolvedLinkButton;
