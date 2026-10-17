/**
 * Oscilloscope — CRT-style scrolling waveform. Ported from Design's
 * kit (2026-05-13). Multiple sine harmonics sum into a composite
 * signal scrolling right-to-left, mirrored around the horizontal axis.
 *
 * W8 (2026-05-14): the harmonic synthesis stays as TEXTURE, but the
 * peak ENVELOPE is now driven by real bucket counts from
 * `/dashboard/throughput`. Each x position maps to a bucket index;
 * that bucket's count normalized to the window max becomes the
 * amplitude envelope, multiplied into the harmonic noise. Peaks
 * mean "a real spike happened at that point in time." The texture
 * still flows continuously via the `t` parameter so the CRT scroll
 * feel survives.
 *
 * Color threshold matches severity (driven by current rate, not the
 * envelope):
 *   rate < 50/min   → success (quiet)
 *   50–200/min      → accent  (normal)
 *   200–500/min     → high    (busy)
 *   500+/min        → critical (spike — pulses faster)
 *
 * When `points` is empty (initial load or fetch error), falls back
 * to the original synthetic-only mode so the widget never goes blank.
 *
 * 60fps via rAF, respects `prefers-reduced-motion` (freezes scroll but
 * keeps trace).
 */
import { useEffect, useRef, type FC, type PointerEvent } from "react";

interface OscilloscopePoint {
  readonly t: string;   // bucket timestamp (ISO) — only used as identity
  readonly v: number;   // event count in this bucket
}

interface OscilloscopeProps {
  readonly rate: number;       // value used by the tier map — drives color
  readonly points?: ReadonlyArray<OscilloscopePoint>;
  /** Bucket width in seconds — drives the left-scroll speed so the
   *  waveform moves at "1 bucket per bucket duration." Defaults to
   *  60s if omitted; pass the actual bucket size for accurate scroll. */
  readonly bucketSeconds?: number;
  /** Total window in minutes — used to compute the ruler tick spacing
   *  and the "T-<delta>" hover label. Required for the ruler to draw;
   *  omitting it hides the ruler. */
  readonly windowMinutes?: number;
  /** Unit label for the hover readout (e.g., "events", "% cpu"). */
  readonly readoutLabel?: string;
  /** Override the default events/min threshold curve. Used by CPU/RAM
   *  feeds where 50/75/90 (% utilization) bucket better than
   *  50/200/500 events. Each entry: { max, token (CSS var), pulse,
   *  baseAmp }. Lowest .max first; final entry's .max should be
   *  Infinity. */
  readonly thresholds?: ReadonlyArray<Tier>;
  readonly height?: number;
  /** When true, the wrapper uses 100% height (fills parent) instead
   *  of a fixed pixel value. Caller must place the component inside
   *  a sized flex/grid parent. Useful for widget cards that resize. */
  readonly fillHeight?: boolean;
}

/** Pick a sensible tick interval (in minutes) for the time-axis ruler.
 *  Hash marks every N minutes; labels at every 3rd hash. The map
 *  keeps the on-screen density reasonable across the preset matrix. */
function pickTickIntervalMinutes(windowMinutes: number): number {
  if (windowMinutes <= 15) return 1;       // 15m → 15 hashes / labels every 3m
  if (windowMinutes <= 60) return 5;       // 1h  → 12 hashes / labels every 15m
  if (windowMinutes <= 300) return 30;     // 5h  → 10 hashes / labels every 90m
  if (windowMinutes <= 1440) return 120;   // 24h → 12 hashes / labels every 6h
  return 720;                              // 7d  → 14 hashes / labels every 36h
}

function formatRulerDelta(minutesAgo: number): string {
  if (minutesAgo < 1) return "now";
  if (minutesAgo < 60) return `-${Math.round(minutesAgo)}m`;
  if (minutesAgo < 1440) return `-${Math.round(minutesAgo / 60)}h`;
  return `-${Math.round(minutesAgo / 1440)}d`;
}

export interface Tier {
  readonly max: number;
  readonly token: string;
  readonly pulse: boolean;
  readonly baseAmp: number;
}

/** Stock thresholds for CPU/RAM-style 0-100% feeds — quiet/warm/hot/critical. */
export const PERCENT_THRESHOLDS: readonly Tier[] = [
  { max: 50,        token: "--success",  pulse: false, baseAmp: 0.32 },
  { max: 75,        token: "--accent",   pulse: false, baseAmp: 0.62 },
  { max: 90,        token: "--high",     pulse: false, baseAmp: 0.82 },
  { max: Infinity,  token: "--critical", pulse: true,  baseAmp: 1.00 },
];

const THRESHOLDS: readonly Tier[] = [
  { max: 50,        token: "--success",  pulse: false, baseAmp: 0.32 },
  { max: 200,       token: "--accent",   pulse: false, baseAmp: 0.62 },
  { max: 500,       token: "--high",     pulse: false, baseAmp: 0.82 },
  { max: Infinity,  token: "--critical", pulse: true,  baseAmp: 1.00 },
];

function tierForRate(rate: number, table: readonly Tier[] = THRESHOLDS): Tier {
  return table.find((t) => rate < t.max) ?? table[0]!;
}

const HARMONICS: ReadonlyArray<readonly [number, number, number]> = [
  // [freq (rad/px), phaseSpeed (rad/sec), amplitude weight]
  [0.018, 1.4, 0.45],
  [0.041, 2.1, 0.30],
  [0.073, 0.9, 0.18],
  [0.121, 3.3, 0.10],
  [0.205, 1.6, 0.06],
];

const REF_WIDTH = 640;

const Oscilloscope: FC<OscilloscopeProps> = ({
  rate, points, bucketSeconds = 60,
  windowMinutes, readoutLabel = "events",
  thresholds, height = 96, fillHeight = false,
}) => {
  const thresholdsRef = useRef<readonly Tier[] | undefined>(thresholds);
  useEffect(() => { thresholdsRef.current = thresholds; }, [thresholds]);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const stateRef = useRef({ t: 0, pulse: 0, ampSmoothed: 0, scroll: 0 });
  // Keep the latest points in a ref so the render loop reads the
  // freshest array without restarting the rAF every poll.
  const pointsRef = useRef<ReadonlyArray<OscilloscopePoint> | undefined>(points);
  const bucketSecRef = useRef<number>(bucketSeconds);
  // W10: cursor position for the hover scrubber. -1 = not hovering.
  const hoverXRef = useRef<number>(-1);
  const windowMinutesRef = useRef<number | undefined>(windowMinutes);
  const readoutLabelRef = useRef<string>(readoutLabel);
  useEffect(() => { pointsRef.current = points; }, [points]);
  useEffect(() => { bucketSecRef.current = bucketSeconds; }, [bucketSeconds]);
  useEffect(() => { windowMinutesRef.current = windowMinutes; }, [windowMinutes]);
  useEffect(() => { readoutLabelRef.current = readoutLabel; }, [readoutLabel]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dpr = window.devicePixelRatio || 1;

    let w = 0;
    let h = 0;
    const syncSize = (): void => {
      const r = canvas.getBoundingClientRect();
      const needW = Math.round(r.width * dpr);
      const needH = Math.round(r.height * dpr);
      if (canvas.width !== needW || canvas.height !== needH) {
        canvas.width = needW;
        canvas.height = needH;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      }
      w = r.width;
      h = r.height;
    };
    syncSize();

    const cs = getComputedStyle(document.documentElement);
    const resolveTone = (): { line: string; baseAmp: number; pulse: boolean } => {
      const tier = tierForRate(rate, thresholdsRef.current);
      return {
        line: cs.getPropertyValue(tier.token).trim() || "#a78bfa",
        baseAmp: tier.baseAmp,
        pulse: tier.pulse,
      };
    };

    const noise = (u: number, t: number): number => {
      const v = Math.sin(u * 12.9898 + t * 78.233) * 43758.5453;
      return (v - Math.floor(v)) * 2 - 1;
    };

    let raf = 0;
    let lastT = performance.now();

    const tick = (now: number): void => {
      syncSize();
      if (w === 0 || h === 0) {
        raf = requestAnimationFrame(tick);
        return;
      }

      const dt = Math.min(60, now - lastT) / 1000;
      lastT = now;
      const st = stateRef.current;
      if (!reduce) {
        st.t += dt;
        st.pulse += dt;
        // W9: left-scroll keyed to bucket duration. One bucket width
        // of pixels per bucketSeconds. The visual sample function
        // re-maps each x position to a "virtual" x that accounts for
        // scroll, so older buckets move left while new data slides
        // in from the right edge.
        const ptsLen = pointsRef.current?.length ?? 0;
        const bucketSec = bucketSecRef.current;
        if (ptsLen > 0 && bucketSec > 0 && w > 0) {
          const bucketPx = w / ptsLen;
          st.scroll += (bucketPx / bucketSec) * dt;
          // Snap modulo bucketPx so scroll doesn't accumulate
          // unbounded floating-point drift; the visual position
          // wraps naturally as new points enter on the right.
          if (st.scroll > bucketPx) st.scroll -= bucketPx;
        }
      }

      const tone = resolveTone();
      const targetAmp = tone.baseAmp;
      st.ampSmoothed += (targetAmp - st.ampSmoothed) * Math.min(1, dt * 4);
      let amp = st.ampSmoothed;
      if (tone.pulse) {
        amp *= 0.9 + 0.10 * Math.sin(st.pulse * 9);
      }

      // W10: reserve the bottom ~18px for the time-axis ruler band
      // when windowMinutes is provided. Waveform mirrors around the
      // visual center of the remaining (top) area.
      const ruler = windowMinutesRef.current;
      const rulerBand = ruler !== undefined ? 18 : 0;
      const waveTop = 0;
      const waveBottom = h - rulerBand;
      const waveHeight = waveBottom - waveTop;
      const cy = waveTop + waveHeight / 2;

      // Clear + scanlines (whole canvas)
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = "rgba(255,255,255,0.025)";
      for (let y = 0; y < h; y += 2) ctx.fillRect(0, y, w, 1);

      ctx.setLineDash([2, 4]);
      ctx.strokeStyle = "rgba(255,255,255,0.06)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, cy);
      ctx.lineTo(w, cy);
      ctx.stroke();
      ctx.setLineDash([]);

      const usableHalf = waveHeight / 2 - 4;
      const t = st.t;
      const widthScale = REF_WIDTH / Math.max(w, 1);

      // W8: compute the data envelope. Each x → bucket index → that
      // bucket's normalized count. Floor=baseline texture so quiet
      // buckets still wiggle visibly; otherwise the canvas would look
      // dead during low-traffic windows.
      const livePoints = pointsRef.current;
      const hasLiveData = livePoints && livePoints.length > 0;
      let maxV = 1;
      if (hasLiveData) {
        for (const p of livePoints) {
          if (p.v > maxV) maxV = p.v;
        }
      }
      const envelopeFloor = 0.18;  // baseline so quiet buckets still trace

      const sample = (x: number, layer: number): number => {
        const phaseOffset = layer * 0.7;
        let v = 0;
        let weight = 0;
        for (let i = 0; i < HARMONICS.length; i++) {
          const [freq, speed, wgt] = HARMONICS[i]!;
          const normFreq = freq * widthScale;
          v += wgt * Math.sin(x * normFreq + t * speed + phaseOffset + i * 0.6);
          weight += wgt;
        }
        v /= weight;
        const u = (x / Math.max(w, 1)) * REF_WIDTH;
        v += noise(u + layer * 11, t * 8) * 0.12;

        // Data envelope: shrink the texture to the real bucket count
        // at this x. When points are empty (loading / error), fall
        // through with envelope=1 → original synthetic behavior.
        if (hasLiveData) {
          const pts = livePoints!;
          // W9: add scroll offset so older buckets visibly drift left.
          // Sub-pixel offset interpolates between bucket indices.
          const effX = x + st.scroll;
          const idxF = (effX / Math.max(w, 1)) * (pts.length - 1);
          const i0 = Math.max(0, Math.min(pts.length - 1, Math.floor(idxF)));
          const i1 = Math.max(0, Math.min(pts.length - 1, Math.ceil(idxF)));
          const frac = idxF - i0;
          const v0 = pts[i0]!.v;
          const v1 = pts[i1]!.v;
          const interp = v0 + (v1 - v0) * frac;
          // Normalize to 0..1, lift by floor so quiet ≠ flat-line.
          const envelope = envelopeFloor + (1 - envelopeFloor) * (interp / maxV);
          v *= envelope;
        }
        return v;
      };

      // (W9 sparkline underlay reverted in W10 — Rick's call:
      // "looks too much like a blocky static shadow". Replaced by
      // the time-axis ruler + hover scrubber below.)

      const layerStyles = [
        { width: 1.0, alpha: 0.30, blur: 0 },
        { width: 1.2, alpha: 0.55, blur: 4 },
        { width: 1.6, alpha: 1.00, blur: tone.pulse ? 14 : 8 },
      ];

      for (let L = 0; L < 3; L++) {
        const sty = layerStyles[L]!;
        ctx.save();
        ctx.globalAlpha = sty.alpha;
        ctx.shadowColor = tone.line;
        ctx.shadowBlur = sty.blur;
        ctx.strokeStyle = tone.line;
        ctx.lineWidth = sty.width;
        ctx.lineJoin = "round";
        ctx.lineCap = "round";

        ctx.beginPath();
        for (let x = 0; x <= w; x += 1) {
          const v = sample(x, L);
          const y = cy - Math.abs(v) * amp * usableHalf;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();

        ctx.beginPath();
        for (let x = 0; x <= w; x += 1) {
          const v = sample(x, L);
          const y = cy + Math.abs(v) * amp * usableHalf;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();
        ctx.restore();
      }

      // Bright dense centerline
      ctx.save();
      ctx.shadowColor = "#ffffff";
      ctx.shadowBlur = 6;
      ctx.strokeStyle = "rgba(255,255,255,0.9)";
      ctx.lineWidth = 0.9;
      ctx.beginPath();
      for (let x = 0; x <= w; x += 1) {
        const v = sample(x, 0);
        const y = cy + v * amp * usableHalf * 0.18;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
      ctx.restore();

      // ---------- W10: time-axis ruler + hover scrubber ----------
      if (ruler !== undefined) {
        const tickIntervalMin = pickTickIntervalMinutes(ruler);
        const tickCount = Math.max(1, Math.floor(ruler / tickIntervalMin));
        const rulerY = waveBottom + 2;
        ctx.save();
        ctx.strokeStyle = "rgba(255,255,255,0.18)";
        ctx.lineWidth = 1;
        ctx.fillStyle = "rgba(255,255,255,0.45)";
        ctx.font = "8px ui-monospace, monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        for (let i = 0; i <= tickCount; i++) {
          const minsBack = ruler - i * tickIntervalMin;
          const x = (i / tickCount) * w;
          const major = i % 3 === 0 || i === tickCount;
          ctx.beginPath();
          ctx.moveTo(x, rulerY);
          ctx.lineTo(x, rulerY + (major ? 5 : 3));
          ctx.stroke();
          if (major) {
            ctx.fillText(formatRulerDelta(minsBack), x, rulerY + 6);
          }
        }
        ctx.restore();

        // Hover scrubber — vertical guide + tooltip with bucket
        // time + value at the cursor position.
        const hx = hoverXRef.current;
        if (hx >= 0 && hx <= w && hasLiveData) {
          ctx.save();
          ctx.strokeStyle = "rgba(255,255,255,0.45)";
          ctx.setLineDash([3, 3]);
          ctx.beginPath();
          ctx.moveTo(hx, 0);
          ctx.lineTo(hx, waveBottom);
          ctx.stroke();
          ctx.setLineDash([]);
          // Compute bucket count at hover + the minutes-ago delta.
          const pts = livePoints!;
          const effX = hx + st.scroll;
          const idxF = (effX / Math.max(w, 1)) * (pts.length - 1);
          const i0 = Math.max(0, Math.min(pts.length - 1, Math.round(idxF)));
          const val = pts[i0]!.v;
          const minsBack = ruler * (1 - hx / Math.max(w, 1));
          const label = `${formatRulerDelta(minsBack)} · ${val.toLocaleString()} ${readoutLabelRef.current}`;

          // Tooltip pill anchored above the cursor.
          ctx.font = "10px ui-monospace, monospace";
          const textW = ctx.measureText(label).width;
          const padX = 6;
          const boxW = textW + padX * 2;
          const boxH = 16;
          let boxX = hx - boxW / 2;
          if (boxX < 2) boxX = 2;
          if (boxX + boxW > w - 2) boxX = w - 2 - boxW;
          const boxY = 4;
          ctx.fillStyle = "rgba(0,0,0,0.75)";
          ctx.strokeStyle = tone.line;
          ctx.lineWidth = 1;
          ctx.fillRect(boxX, boxY, boxW, boxH);
          ctx.strokeRect(boxX, boxY, boxW, boxH);
          ctx.fillStyle = "rgba(255,255,255,0.95)";
          ctx.textAlign = "left";
          ctx.textBaseline = "middle";
          ctx.fillText(label, boxX + padX, boxY + boxH / 2);
          ctx.restore();
        }
      }
      // ----------------------------------------------------------

      raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); };
  }, [rate]);

  // W10: pointer handlers track cursor x for the scrubber. The rAF
  // loop reads hoverXRef on every frame, so no React re-render is
  // needed to repaint the guide / tooltip — it's smooth at 60fps.
  const onPointerMove = (e: PointerEvent<HTMLCanvasElement>): void => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    hoverXRef.current = e.clientX - rect.left;
  };
  const onPointerLeave = (): void => {
    hoverXRef.current = -1;
  };

  return (
    <div
      style={
        fillHeight
          ? { height: "100%", width: "100%", minHeight: height }
          : { height, width: "100%" }
      }
    >
      <canvas
        ref={canvasRef}
        onPointerMove={onPointerMove}
        onPointerLeave={onPointerLeave}
        style={{
          width: "100%",
          height: "100%",
          display: "block",
          cursor: windowMinutes !== undefined ? "crosshair" : "default",
        }}
        aria-label="Event throughput waveform"
        role="img"
      />
    </div>
  );
};

export default Oscilloscope;
