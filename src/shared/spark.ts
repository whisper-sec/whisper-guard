// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Two small drawing primitives, shared by every surface.
//
// Both are inline SVG built from real numbers, drawn in `currentColor` so
// they inherit the reader's colour scheme instead of carrying a palette of
// their own, and both refuse to draw at all rather than draw a flat line
// out of no data. A chart of nothing that looks like a chart of something
// is the visual form of the error that renders as an empty state.

/** Build an SVG element in the right namespace (document.createElement will
 *  silently produce an unrendered HTML element with the same tag name). */
function svgEl<K extends keyof SVGElementTagNameMap>(name: K): SVGElementTagNameMap[K] {
  return document.createElementNS("http://www.w3.org/2000/svg", name);
}

export interface SparkOptions {
  width?: number;
  height?: number;
  /** Fill the area under the line at this opacity. 0 draws the line alone. */
  fill?: number;
  /** Mark the most recent sample with a dot. */
  head?: boolean;
  /** Accessible one-line description of what the shape is. */
  title?: string;
}

/**
 * A sparkline over `values`, oldest first. Returns null when there is not
 * enough signal to be honest about: fewer than two samples, or every
 * sample identical (a flat line implies a measured steady state, and we
 * have not measured one).
 */
export function sparkline(values: number[], opts: SparkOptions = {}): SVGSVGElement | null {
  const w = opts.width ?? 96;
  const h = opts.height ?? 20;
  const pts = values.filter((v) => Number.isFinite(v));
  if (pts.length < 2) return null;
  let min = Infinity;
  let max = -Infinity;
  for (const v of pts) {
    if (v < min) min = v;
    if (v > max) max = v;
  }
  if (max === min) return null;

  const pad = 1.5;
  const span = max - min;
  const stepX = (w - pad * 2) / (pts.length - 1);
  const y = (v: number): number => h - pad - ((v - min) / span) * (h - pad * 2);

  const coords = pts.map((v, i) => [pad + i * stepX, y(v)] as const);
  const line = coords.map(([x, yy], i) => `${i === 0 ? "M" : "L"}${x.toFixed(2)},${yy.toFixed(2)}`).join(" ");

  const svg = svgEl("svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("width", String(w));
  svg.setAttribute("height", String(h));
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("aria-hidden", opts.title ? "false" : "true");
  svg.setAttribute("focusable", "false");
  if (opts.title) {
    svg.setAttribute("role", "img");
    const t = svgEl("title");
    t.textContent = opts.title;
    svg.appendChild(t);
  }

  if (opts.fill && opts.fill > 0) {
    const area = svgEl("path");
    const last = coords[coords.length - 1];
    const first = coords[0];
    if (last && first) {
      area.setAttribute("d", `${line} L${last[0].toFixed(2)},${h} L${first[0].toFixed(2)},${h} Z`);
      area.setAttribute("fill", "currentColor");
      area.setAttribute("opacity", String(opts.fill));
      svg.appendChild(area);
    }
  }

  const path = svgEl("path");
  path.setAttribute("d", line);
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.25");
  path.setAttribute("stroke-linejoin", "round");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("vector-effect", "non-scaling-stroke");
  svg.appendChild(path);

  const last = coords[coords.length - 1];
  if (opts.head && last) {
    const dot = svgEl("circle");
    dot.setAttribute("cx", last[0].toFixed(2));
    dot.setAttribute("cy", last[1].toFixed(2));
    dot.setAttribute("r", "1.6");
    dot.setAttribute("fill", "currentColor");
    svg.appendChild(dot);
  }
  return svg;
}

/**
 * A number that counts up to its value once, on first paint. Motion is the
 * cheapest way to say "this was measured just now" rather than "this was
 * typed into the page", and it costs the reader nothing: the final text is
 * written immediately when the reader has asked for reduced motion, and the
 * element always ends on the exact string, never on a rounding artefact.
 */
export function countUp(el: HTMLElement, to: number, format: (n: number) => string, ms = 650): void {
  const final = format(to);
  const reduced =
    typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced || !Number.isFinite(to) || to <= 0 || ms <= 0) {
    el.textContent = final;
    return;
  }
  const start = performance.now();
  const tick = (now: number): void => {
    const t = Math.min(1, (now - start) / ms);
    // easeOutCubic: fast first, settling rather than stopping.
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = t >= 1 ? final : format(to * eased);
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/** Big counts, said the way a person says them. */
export function compact(n: number): string {
  if (!Number.isFinite(n)) return "-";
  const abs = Math.abs(n);
  if (abs >= 1e12) return `${(n / 1e12).toFixed(2)}T`;
  if (abs >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (abs >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(Math.round(n));
}
