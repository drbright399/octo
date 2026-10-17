import { useEffect, useRef, type FC } from "react";

/**
 * Animated network-of-nodes background, ported from the V2 dashboard's
 * `network-bg.js`. Runs in a fixed-position canvas behind the app shell.
 *
 * Theme-reactive: reads `--bg-gradient-1` / `--bg-gradient-2` CSS custom
 * props for the gradient fill, and uses different node/line palettes
 * depending on `data-theme` (deeper violet on light backgrounds so the
 * mesh reads as signal not haze).
 *
 * Respects `prefers-reduced-motion` — falls back to a static frame for
 * users who'd find the animation distracting.
 */

interface ColorRGB {
  r: number;
  g: number;
  b: number;
}

interface PaletteConfig {
  nodeColor: ColorRGB;
  nodeGlow: ColorRGB;
  lineColor: ColorRGB;
  lineAlphaScale: number;
  nodeAlphaScale: number;
  glowAlphaScale: number;
}

// Default palette tints — used as fallback if --accent doesn't parse.
// The runtime now resolves nodeColor/lineColor from the live CSS
// var so per-bundle accent shifts (Theme v2 Appearance) propagate
// to the background mesh without rebuild.
const DARK_FALLBACK = { r: 167, g: 139, b: 250 };  // violet
const LIGHT_FALLBACK = { r: 109, g: 40, b: 217 };

const DARK_PALETTE: PaletteConfig = {
  nodeColor: DARK_FALLBACK,
  nodeGlow:  DARK_FALLBACK,
  lineColor: DARK_FALLBACK,
  lineAlphaScale: 0.10,
  nodeAlphaScale: 0.7,
  glowAlphaScale: 0.22,
};

const LIGHT_PALETTE: PaletteConfig = {
  nodeColor: LIGHT_FALLBACK,
  nodeGlow:  LIGHT_FALLBACK,
  lineColor: LIGHT_FALLBACK,
  lineAlphaScale: 0.16,
  nodeAlphaScale: 0.8,
  glowAlphaScale: 0.28,
};

/** Parse a CSS color (hex 3/6, rgb()) into ColorRGB. Returns fallback
 * on any parse failure — the network-bg never renders black mesh on
 * a typo. */
function parseColor(raw: string, fallback: ColorRGB): ColorRGB {
  const v = raw.trim();
  if (!v) return fallback;
  // #rgb / #rrggbb
  const hex = v.startsWith("#") ? v.slice(1) : v;
  if (/^[0-9a-f]{3}$/i.test(hex)) {
    return {
      r: parseInt(hex[0]! + hex[0], 16),
      g: parseInt(hex[1]! + hex[1], 16),
      b: parseInt(hex[2]! + hex[2], 16),
    };
  }
  if (/^[0-9a-f]{6}$/i.test(hex)) {
    return {
      r: parseInt(hex.slice(0, 2), 16),
      g: parseInt(hex.slice(2, 4), 16),
      b: parseInt(hex.slice(4, 6), 16),
    };
  }
  // rgb(r, g, b) / rgba(r, g, b, a)
  const m = v.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
  if (m) {
    return { r: +m[1]!, g: +m[2]!, b: +m[3]! };
  }
  return fallback;
}

const NetworkBg: FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduceMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches;

    const NODE_COUNT = 70;
    const NODE_MIN_SIZE = 1;
    const NODE_MAX_SIZE = 2.4;
    const CONNECTION_DISTANCE = 180;
    const MOUSE_INFLUENCE = 200;
    const SPEED = 0.22;
    const CURRENT_X = 0.06;
    const CURRENT_Y = 0.015;

    interface Node {
      x: number; y: number; vx: number; vy: number;
      size: number; brightness: number; phase: number;
      type: "bright" | "normal";
    }

    let width = 0, height = 0;
    let nodes: Node[] = [];
    const mouse = { x: -1000, y: -1000 };
    let palette: PaletteConfig = DARK_PALETTE;
    let bgTop = "#0a0414";
    let bgBottom = "#1a0f3a";

    const readTheme = (): void => {
      const cs = getComputedStyle(document.documentElement);
      const t1 = cs.getPropertyValue("--bg-gradient-1").trim();
      const t2 = cs.getPropertyValue("--bg-gradient-2").trim();
      if (t1) bgTop = t1;
      if (t2) bgBottom = t2;
      const ds = document.documentElement.getAttribute("data-theme");
      const isLight = ds === "light";
      // Per-bundle accent — parse from --accent and apply to the mesh
      // so Theme v2 Appearance shifts cascade into the background.
      // Falls back to the historic violet on parse failure.
      const accentRaw = cs.getPropertyValue("--accent").trim();
      const accent = parseColor(accentRaw, isLight ? LIGHT_FALLBACK : DARK_FALLBACK);
      const glowRaw = cs.getPropertyValue("--accent-strong").trim();
      const glow = parseColor(glowRaw, accent);
      // Mutate the shared palette object (not the const itself) so the
      // running animation loop picks up the new values on its next frame.
      palette = isLight ? LIGHT_PALETTE : DARK_PALETTE;
      palette.nodeColor = accent;
      palette.lineColor = accent;
      palette.nodeGlow = glow;
    };

    const resize = (): void => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    const createNodes = (): void => {
      nodes = [];
      for (let i = 0; i < NODE_COUNT; i++) {
        nodes.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * SPEED,
          vy: (Math.random() - 0.5) * SPEED,
          size: NODE_MIN_SIZE + Math.random() * (NODE_MAX_SIZE - NODE_MIN_SIZE),
          brightness: 0.3 + Math.random() * 0.6,
          phase: Math.random() * Math.PI * 2,
          type: Math.random() > 0.88 ? "bright" : "normal",
        });
      }
    };

    const update = (): void => {
      for (const node of nodes) {
        node.vx += CURRENT_X * 0.01;
        node.vy += CURRENT_Y * 0.01;
        node.vx *= 0.999;
        node.vy *= 0.999;
        node.x += node.vx;
        node.y += node.vy;
        node.phase += 0.012;

        const margin = 50;
        if (node.x < -margin) node.x = width + margin;
        if (node.x > width + margin) node.x = -margin;
        if (node.y < -margin) node.y = height + margin;
        if (node.y > height + margin) node.y = -margin;

        const dx = node.x - mouse.x;
        const dy = node.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < MOUSE_INFLUENCE && dist > 0) {
          const force = ((MOUSE_INFLUENCE - dist) / MOUSE_INFLUENCE) * 0.018;
          node.vx += (dx / dist) * force;
          node.vy += (dy / dist) * force;
        }
      }
    };

    const draw = (): void => {
      const grad = ctx.createLinearGradient(0, 0, 0, height);
      grad.addColorStop(0, bgTop);
      grad.addColorStop(1, bgBottom);
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, width, height);

      // connections
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        if (!a) continue;
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          if (!b) continue;
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < CONNECTION_DISTANCE) {
            const alpha = (1 - dist / CONNECTION_DISTANCE) * palette.lineAlphaScale;
            const { r, g, b: bl } = palette.lineColor;
            ctx.strokeStyle = `rgba(${r}, ${g}, ${bl}, ${alpha})`;
            ctx.lineWidth = 0.5;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // nodes
      for (const node of nodes) {
        const twinkle = 0.5 + 0.5 * Math.sin(node.phase);
        const alpha = node.brightness * twinkle;

        if (node.type === "bright") {
          const { r, g, b } = palette.nodeGlow;
          const glowGrad = ctx.createRadialGradient(
            node.x, node.y, 0, node.x, node.y, node.size * 6,
          );
          glowGrad.addColorStop(0, `rgba(${r}, ${g}, ${b}, ${alpha * palette.glowAlphaScale})`);
          glowGrad.addColorStop(1, `rgba(${r}, ${g}, ${b}, 0)`);
          ctx.fillStyle = glowGrad;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.size * 6, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alpha * 0.85})`;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.size * 1.4, 0, Math.PI * 2);
          ctx.fill();
        } else {
          const { r, g, b } = palette.nodeColor;
          ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alpha * palette.nodeAlphaScale})`;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    };

    let rafId = 0;
    const animate = (): void => {
      update();
      draw();
      rafId = requestAnimationFrame(animate);
    };

    const onMouse = (e: MouseEvent): void => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    };
    const onMouseLeave = (): void => {
      mouse.x = -1000;
      mouse.y = -1000;
    };
    const onResize = (): void => {
      resize();
      if (nodes.length !== NODE_COUNT) createNodes();
    };

    resize();
    createNodes();
    readTheme();

    const themeObserver = new MutationObserver(readTheme);
    themeObserver.observe(document.documentElement, {
      attributes: true,
      // data-scheme swaps --bg-gradient-1/2 (Appearance → Background).
      attributeFilter: ["data-theme", "data-bundle", "data-scheme"],
    });

    document.addEventListener("mousemove", onMouse);
    document.addEventListener("mouseleave", onMouseLeave);
    window.addEventListener("resize", onResize);

    if (reduceMotion) {
      // Single static frame instead of continuous animation
      draw();
    } else {
      animate();
    }

    return () => {
      cancelAnimationFrame(rafId);
      themeObserver.disconnect();
      document.removeEventListener("mousemove", onMouse);
      document.removeEventListener("mouseleave", onMouseLeave);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 h-full w-full"
    />
  );
};

export default NetworkBg;
