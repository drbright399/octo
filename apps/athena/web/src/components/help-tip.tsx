/**
 * HelpTip — small `(?)` affordance that surfaces a one-line explanation
 * on hover/focus via the browser's native `title` tooltip + an
 * accessible `aria-label`. Click is swallowed so dropping the tip
 * inside a clickable row doesn't fire the row's onClick.
 *
 * Use sparingly — only where the control's purpose isn't already
 * obvious from its label (e.g., "step-up auth", "90-day window",
 * "severity P1-P5"). If you need long-form copy or rich content,
 * reach for a real popover component instead.
 */
import { type FC, type MouseEvent } from "react";

interface HelpTipProps {
  readonly children: string;
}

const HelpTip: FC<HelpTipProps> = ({ children }) => {
  const stop = (e: MouseEvent): void => e.stopPropagation();
  return (
    <button
      type="button"
      title={children}
      aria-label={children}
      onClick={stop}
      tabIndex={0}
      className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-border bg-bg-card font-mono text-[9px] leading-none text-text-dim transition-colors hover:border-accent hover:text-accent focus-visible:border-accent focus-visible:text-accent focus-visible:outline-none"
    >
      ?
    </button>
  );
};

export default HelpTip;
