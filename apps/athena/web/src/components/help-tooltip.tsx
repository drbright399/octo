import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type FC,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";

/**
 * Inline help tooltip — small `?` icon that reveals an explanation on
 * hover or keyboard focus.
 *
 * The tooltip body is rendered via React portal into `document.body` so
 * it escapes parent flex/overflow/transform/stacking contexts (which
 * otherwise crush it into the trigger's flex slot). Position is computed
 * from the trigger button's bounding rect at open time and re-computed
 * on scroll/resize while open. Visually treated as a top-level UI
 * bubble — appears during interaction, gone otherwise.
 *
 * Accessibility:
 *   - Trigger is a real button, focusable + keyboard-activatable
 *   - Tooltip content is `aria-describedby`-linked so screen readers
 *     associate the explanation with the trigger
 *   - Dismisses on Escape, click outside, or blur
 *   - Respects `prefers-reduced-motion` (no fade animation when set)
 */

interface HelpTooltipProps {
  /** Plain text or rich content shown when the tooltip is open */
  readonly children: ReactNode;
  /** Optional aria-label for the trigger; defaults to "More information" */
  readonly label?: string;
  /** Position the popover relative to the trigger. Default: "top" */
  readonly placement?: "top" | "bottom" | "left" | "right";
  /** Maximum tooltip width in CSS units. Default: "22rem" */
  readonly maxWidth?: string;
}

interface Coords {
  top: number;
  left: number;
}

const HelpTooltip: FC<HelpTooltipProps> = ({
  children,
  label = "More information",
  placement = "top",
  maxWidth = "22rem",
}) => {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState<Coords | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const tipRef = useRef<HTMLDivElement | null>(null);
  const tipId = useRef(
    `help-tip-${Math.random().toString(36).slice(2, 10)}`,
  );

  // Compute fixed-position coords from trigger's bounding rect.
  // Runs after the tooltip mounts so we can read its actual size for
  // proper centering (avoids the "flickers in upper-left then jumps"
  // pattern).
  useLayoutEffect(() => {
    if (!open) return;
    const trigger = triggerRef.current;
    const tip = tipRef.current;
    if (!trigger || !tip) return;
    const compute = (): void => {
      const tr = trigger.getBoundingClientRect();
      const tw = tip.offsetWidth;
      const th = tip.offsetHeight;
      const gap = 8;
      let top = 0;
      let left = 0;
      if (placement === "bottom") {
        top = tr.bottom + gap;
        left = tr.left + tr.width / 2 - tw / 2;
      } else if (placement === "left") {
        top = tr.top + tr.height / 2 - th / 2;
        left = tr.left - tw - gap;
      } else if (placement === "right") {
        top = tr.top + tr.height / 2 - th / 2;
        left = tr.right + gap;
      } else {
        // top (default)
        top = tr.top - th - gap;
        left = tr.left + tr.width / 2 - tw / 2;
      }
      // Clamp to viewport with 8px margins
      const margin = 8;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      if (left < margin) left = margin;
      if (left + tw > vw - margin) left = vw - margin - tw;
      if (top < margin) top = margin;
      if (top + th > vh - margin) top = vh - margin - th;
      setCoords({ top, left });
    };
    compute();
    window.addEventListener("scroll", compute, true);
    window.addEventListener("resize", compute);
    return () => {
      window.removeEventListener("scroll", compute, true);
      window.removeEventListener("resize", compute);
    };
  }, [open, placement]);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (ev: MouseEvent): void => {
      const trigger = triggerRef.current;
      const tip = tipRef.current;
      const target = ev.target as Node;
      if (
        trigger && !trigger.contains(target) &&
        tip && !tip.contains(target)
      ) {
        setOpen(false);
      }
    };
    const onEsc = (ev: KeyboardEvent): void => {
      if (ev.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onEsc);
    };
  }, [open]);

  const tipNode =
    open && typeof document !== "undefined"
      ? createPortal(
          <div
            ref={tipRef}
            id={tipId.current}
            role="tooltip"
            style={{
              maxWidth,
              top: coords?.top ?? -9999,
              left: coords?.left ?? -9999,
              // Hide while we don't have coords yet so the first paint
              // doesn't flash in the wrong place.
              visibility: coords ? "visible" : "hidden",
            }}
            className="pointer-events-auto fixed z-[1000] whitespace-normal rounded-md border border-border-bright bg-bg-elevated px-3.5 py-2.5 text-[12px] leading-relaxed text-text-secondary shadow-2xl ring-1 ring-accent-glow backdrop-blur"
          >
            {children}
          </div>,
          document.body,
        )
      : null;

  return (
    <span className="relative inline-flex">
      <button
        ref={triggerRef}
        type="button"
        aria-label={label}
        aria-describedby={open ? tipId.current : undefined}
        onClick={() => setOpen((v) => !v)}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-border bg-bg-card text-[10px] font-mono leading-none text-text-dim transition-colors hover:border-accent hover:text-accent focus:border-accent focus:text-accent focus:outline-none"
      >
        ?
      </button>
      {tipNode}
    </span>
  );
};

export default HelpTooltip;
