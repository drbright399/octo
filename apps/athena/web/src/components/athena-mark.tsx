/**
 * AthenaMark — the bracketed-A brand mark. Ported from Design's
 * `assets/athena-mark.svg` (concept C, 2026-05-13). Inline SVG so it
 * inherits `currentColor` from its container — per-MSP bundle accent
 * drives it automatically.
 *
 * Replaces the prior 🦉 emoji in the topbar + login surfaces. Per the
 * design-pass non-negotiable: no emoji as icons or as the brand mark.
 *
 * Default size 24px. Pass `size` for the boot splash (96-128px).
 */
import type { FC, SVGProps } from "react";

interface AthenaMarkProps extends Omit<SVGProps<SVGSVGElement>, "viewBox"> {
  readonly size?: number | string;
  readonly title?: string;
}

const AthenaMark: FC<AthenaMarkProps> = ({
  size = 24, title = "Athena", ...rest
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 40 40"
    width={size}
    height={size}
    role="img"
    aria-label={title}
    {...rest}
  >
    <g
      fill="none"
      stroke="currentColor"
      strokeWidth={2.4}
      strokeLinecap="square"
      strokeLinejoin="miter"
    >
      <polyline points="9,5 5,5 5,35 9,35" />
      <polyline points="31,5 35,5 35,35 31,35" />
      <polygon points="20,10 13,30 27,30" />
      <line x1="16" y1="24" x2="24" y2="24" strokeWidth={3} />
    </g>
  </svg>
);

export default AthenaMark;
