/**
 * BootSplash — first-load welcome sequence. Ported from Design's kit
 * (2026-05-13). Plays the bracketed-A mark in 4 phases:
 *
 *   0–0.4s   brackets fade in
 *   0.4–0.8s brackets spread apart slightly
 *   0.8–1.1s A symbol blinks in between them
 *   1.1–1.6s hold
 *   1.6–2.4s shrink + translate toward the topbar position, fade out
 *
 * Runs once per browser session (sessionStorage) — page reloads during
 * the same session skip the splash. Operators reload often during
 * incident response; don't replay.
 *
 * Respects prefers-reduced-motion: collapses to a 250ms fade.
 *
 * Component CSS lives in src/index.css under the .boot-* selectors.
 */
import { useEffect, useState, type FC } from "react";

const BOOT_KEY = "athena.boot-splash-shown.v1";

type Phase = "brackets" | "spread" | "blink" | "hold" | "park" | "done";

export function shouldShowBoot(): boolean {
  try { return window.sessionStorage.getItem(BOOT_KEY) !== "1"; }
  catch { return true; }
}

interface BootSplashProps {
  readonly onDone?: () => void;
}

const BootSplash: FC<BootSplashProps> = ({ onDone }) => {
  const [phase, setPhase] = useState<Phase>("brackets");

  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const stages: ReadonlyArray<[Phase, number]> = reduce
      ? [["done", 250]]
      : [
          ["spread", 400],
          ["blink",  800],
          ["hold",  1100],
          ["park",  1600],
          ["done",  2400],
        ];
    const timers = stages.map(([name, ms]) =>
      window.setTimeout(() => setPhase(name), ms),
    );
    return () => { for (const t of timers) window.clearTimeout(t); };
  }, []);

  useEffect(() => {
    if (phase === "done") {
      try { window.sessionStorage.setItem(BOOT_KEY, "1"); } catch { /* */ }
      onDone?.();
    }
  }, [phase, onDone]);

  if (phase === "done") return null;

  return (
    <div className={`boot-splash boot-phase-${phase}`} role="status" aria-label="Loading Athena">
      <div className="boot-stage" aria-hidden="true">
        <svg className="boot-mark" viewBox="0 0 40 40">
          <polyline
            className="boot-bracket boot-bracket--l"
            points="9,5 5,5 5,35 9,35"
            fill="none" stroke="currentColor" strokeWidth="2.4"
            strokeLinecap="square" strokeLinejoin="miter"
          />
          <polyline
            className="boot-bracket boot-bracket--r"
            points="31,5 35,5 35,35 31,35"
            fill="none" stroke="currentColor" strokeWidth="2.4"
            strokeLinecap="square" strokeLinejoin="miter"
          />
          <polygon
            className="boot-a"
            points="20,10 13,30 27,30"
            fill="none" stroke="currentColor" strokeWidth="2.4"
            strokeLinejoin="miter"
          />
          <line
            className="boot-a-cross"
            x1="16" y1="24" x2="24" y2="24"
            stroke="currentColor" strokeWidth="3" strokeLinecap="square"
          />
        </svg>
        <div className="boot-wordmark">ATHENA</div>
        <div className="boot-tag">·· data plane console · booting ··</div>
      </div>
    </div>
  );
};

export default BootSplash;
