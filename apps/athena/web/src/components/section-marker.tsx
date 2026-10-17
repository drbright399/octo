/**
 * SectionMarker — `·· 04 ··` style label, the signature visual element
 * borrowed from Micro-IT's site (the visual-inspiration design notes).
 *
 * Used as a small, low-profile label above section titles to give the
 * page a procedural / phased rhythm. Pairs naturally with terminal-line
 * headers.
 *
 * Usage:
 *   <SectionMarker n={1} />
 *   <h2>Filters</h2>
 *
 *   <SectionMarker label="A" />
 *   <h2>Threat intel</h2>
 *
 * The `n` form auto-zero-pads to two digits to match the brand
 * formatting (01, 02, ... 04). For non-numeric labels, pass `label`
 * directly — the dot framing is consistent.
 */
import type { FC } from "react";

interface SectionMarkerProps {
  readonly n?: number;
  readonly label?: string;
  /** Optional accent override — defaults to the dim secondary text tone. */
  readonly tone?: "dim" | "accent";
}

const SectionMarker: FC<SectionMarkerProps> = ({ n, label, tone = "dim" }) => {
  const text = label !== undefined
    ? label
    : n !== undefined
      ? String(n).padStart(2, "0")
      : "";
  if (!text) return null;
  return (
    <span
      className={[
        "inline-block font-mono text-[10px] uppercase tracking-[0.2em]",
        tone === "accent" ? "text-accent" : "text-text-dim",
      ].join(" ")}
      aria-hidden="true"
    >
      ·· {text} ··
    </span>
  );
};

export default SectionMarker;
