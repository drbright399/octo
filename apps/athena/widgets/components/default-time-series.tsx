/**
 * `default-time-series` — minimal sparkline. SVG-rendered so it scales
 * cleanly and stays accessible (text fallback in title).
 */

import { type FC, useMemo } from "react";

export interface TimeSeriesPoint {
  readonly t: string;
  readonly v: number;
}

export interface DefaultTimeSeriesProps {
  readonly title?: string;
  readonly unit?: string;
  readonly points: readonly TimeSeriesPoint[];
  readonly height?: number;
}

export const DefaultTimeSeries: FC<DefaultTimeSeriesProps> = ({
  title,
  unit = "",
  points,
  height = 72,
}) => {
  const { path, areaPath, min, max, last } = useMemo(() => {
    if (points.length === 0) {
      return { path: "", areaPath: "", min: 0, max: 0, last: 0 };
    }
    const values = points.map((p) => p.v);
    const minV = Math.min(...values);
    const maxV = Math.max(...values);
    const range = maxV - minV || 1;

    const w = 100;
    const h = 40;
    const stepX = points.length > 1 ? w / (points.length - 1) : 0;

    const coords = points.map((p, i) => {
      const x = i * stepX;
      const y = h - ((p.v - minV) / range) * h;
      return { x, y };
    });

    const linePath = coords
      .map((c, i) => (i === 0 ? `M ${c.x} ${c.y}` : `L ${c.x} ${c.y}`))
      .join(" ");
    const fillPath = `${linePath} L ${w} ${h} L 0 ${h} Z`;

    return {
      path: linePath,
      areaPath: fillPath,
      min: minV,
      max: maxV,
      last: values[values.length - 1] ?? 0,
    };
  }, [points]);

  if (points.length === 0) {
    return (
      <div className="px-4 py-6 text-center text-sm italic text-text-dim">
        No data.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {title ? (
        <div className="flex items-baseline justify-between text-[11px] text-text-dim">
          <span className="uppercase tracking-wider">{title}</span>
          <span className="font-mono text-text-secondary">
            {last}
            {unit}
          </span>
        </div>
      ) : null}
      <svg
        viewBox="0 0 100 40"
        preserveAspectRatio="none"
        className="w-full"
        style={{ height: `${height}px` }}
        role="img"
        aria-label={`Time series chart, range ${min} to ${max}${unit}`}
      >
        <path d={areaPath} fill="var(--accent-soft)" />
        <path
          d={path}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <div className="flex justify-between font-mono text-[10px] text-text-dim">
        <span>min {min}{unit}</span>
        <span>max {max}{unit}</span>
      </div>
    </div>
  );
};

export default DefaultTimeSeries;
