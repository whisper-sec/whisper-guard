// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE DRAWN PRIMITIVES.
//
// Every label-and-value pair on a security surface is a question the page
// declined to answer: what is the PICTURE of that fact? These are the
// answers. Nine primitives, each one a shape whose geometry carries a real
// measurement, so a reader sees the size of a thing before reading its
// number.
//
// Four rules every primitive here holds to.
//
//   1. REFUSE RATHER THAN LIE. Each returns null when the data cannot
//      honestly support the shape: fewer samples than the shape implies,
//      a whole of zero, every value identical. A chart of nothing that
//      looks like a chart of something is the visual form of the error
//      that renders as an empty state, and this codebase has been bitten
//      by that class of defect more than any other.
//   2. NO PALETTE OF THEIR OWN. Ink is `currentColor`; anything else names
//      a theme token (var(--w-...)). A primitive that hardcodes a hex is a
//      primitive that is wrong in one of the two themes, and nobody sees
//      both at once.
//   3. GEOMETRY IS THE MESSAGE. Where a value is too small to see, it is
//      drawn at a hairline floor so it reads as TINY rather than as
//      ABSENT. Those are different facts.
//   4. AA OR IT IS NOT A LABEL. Every word drawn inside a mark - a column
//      head, an axis end, a caption in a donut hole - uses --w-muted or
//      stronger, never --w-faint. --w-faint is the token for a hairline or
//      a separator; used on 7px axis text it measured 2.95:1 against the
//      card, which is a label a reader is asked to read and cannot.
//   5. SPEAK. Every primitive carries a <title> saying in words what the
//      shape says in pixels, so a screen reader and a hover both get the
//      measurement.

const NS = "http://www.w3.org/2000/svg";

function svgEl<K extends keyof SVGElementTagNameMap>(name: K): SVGElementTagNameMap[K] {
  return document.createElementNS(NS, name);
}

/**
 * The SVG shell.
 *
 * A title is given ONLY when the shape is the sole carrier of its fact.
 * Where a mark sits directly beside the words for the same measurement, it
 * takes no title and is marked decorative instead, for two reasons that
 * turn out to be the same reason: a screen reader would otherwise announce
 * the same sentence twice, and `textContent` would return it twice, which
 * silently doubled every caption the mark was placed under. The second
 * symptom is what caught it, and it is the visible half of the first.
 */
function frame(w: number, h: number, title?: string): SVGSVGElement {
  const svg = svgEl("svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("width", String(w));
  svg.setAttribute("height", String(h));
  svg.setAttribute("focusable", "false");
  if (title === undefined || title === "") {
    svg.setAttribute("aria-hidden", "true");
    return svg;
  }
  svg.setAttribute("role", "img");
  const t = svgEl("title");
  t.textContent = title;
  svg.appendChild(t);
  return svg;
}

function attrs(el: Element, map: Record<string, string | number>): void {
  for (const [k, v] of Object.entries(map)) el.setAttribute(k, String(v));
}

/** Reduced motion, asked once per call rather than cached: a reader can
 *  change it while a surface is open. */
function reduced(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export type Tone = "neutral" | "ok" | "warn" | "hot" | "accent";

const TONE_VAR: Record<Tone, string> = {
  neutral: "var(--w-muted)",
  ok: "var(--w-ok)",
  warn: "var(--w-v-low)",
  hot: "var(--w-v-high)",
  accent: "var(--w-accent)",
};

// ===========================================================================
// 1. ratioBar - a part of a whole, with a floor so small is not nothing
// ===========================================================================

export interface RatioBarOptions {
  width?: number;
  height?: number;
  tone?: Tone;
  /** Words for the measurement, used as the accessible title. */
  title?: string;
  /** Draw a faint tick at this fraction, e.g. a threshold. */
  marker?: number;
}

/**
 * `part` of `whole`, drawn. The bar exists because "5 listed of 9,216
 * announced" is a sentence and the difference between a huge clean network
 * and a small dirty one is a shape.
 *
 * Returns null when `whole` is not a positive number, because a proportion
 * of nothing is not a proportion.
 */
export function ratioBar(part: number, whole: number, opts: RatioBarOptions = {}): SVGSVGElement | null {
  if (!Number.isFinite(part) || !Number.isFinite(whole) || whole <= 0 || part < 0) return null;
  const w = opts.width ?? 120;
  const h = opts.height ?? 6;
  const frac = Math.min(1, part / whole);
  const pct = (frac * 100).toFixed(3);
  const svg = frame(w, h, opts.title);
  svg.setAttribute("preserveAspectRatio", "none");

  const track = svgEl("rect");
  attrs(track, { x: 0, y: 0, width: w, height: h, rx: h / 2, fill: "var(--w-line)" });
  svg.appendChild(track);

  // The floor. A real 0.05% must be visible AS 0.05% and not vanish into
  // the track, because "too small to draw" and "zero" are different facts.
  const drawn = Math.max(frac * w, part > 0 ? Math.min(2, w) : 0);
  if (drawn > 0) {
    const fill = svgEl("rect");
    attrs(fill, {
      x: 0, y: 0, width: drawn.toFixed(2), height: h, rx: h / 2,
      fill: TONE_VAR[opts.tone ?? "accent"],
    });
    svg.appendChild(fill);
  }

  if (opts.marker !== undefined && opts.marker > 0 && opts.marker < 1) {
    const tick = svgEl("rect");
    attrs(tick, {
      x: (opts.marker * w).toFixed(2), y: -1, width: 1, height: h + 2,
      fill: "var(--w-line-strong)",
    });
    svg.appendChild(tick);
  }
  svg.dataset["pct"] = pct;
  return svg;
}

// ===========================================================================
// 2. arcGauge - a score on an arc, with the band it falls in
// ===========================================================================

export interface ArcGaugeOptions {
  size?: number;
  /** 0..1. */
  value: number;
  /** Centre text. */
  center?: string;
  /** Small text under the centre. */
  caption?: string;
  tone?: Tone;
  title?: string;
  /** Thickness of the ring as a fraction of the diameter. Around 0.1 reads
   *  as a scale; much thicker and it reads as a pie chart with the middle
   *  cut out, which is a different figure making a different claim. */
  weight?: number;
}

/**
 * A fraction on a 270-degree arc. Used for identity health and for the
 * graph's threat score, both of which are "how far along a scale" facts
 * that a bare integer refuses to place.
 *
 * Returns null for a value outside 0..1, rather than clamping: a caller
 * passing 1.4 has a bug, and drawing a full ring would hide it.
 */
export function arcGauge(opts: ArcGaugeOptions): SVGSVGElement | null {
  const v = opts.value;
  if (!Number.isFinite(v) || v < 0 || v > 1) return null;
  const size = opts.size ?? 96;
  const svg = frame(size, size, opts.title);
  const cx = size / 2;
  const cy = size / 2;
  const weight = opts.weight ?? 0.1;
  const r = size / 2 - (size * weight) / 2 - 2;
  const stroke = size * weight;

  // 270 degrees, opening at the bottom: the gap reads as a scale with ends
  // rather than as a pie with a slice missing.
  const START = 135;
  const SWEEP = 270;
  const pt = (deg: number): [number, number] => {
    const rad = (deg * Math.PI) / 180;
    return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
  };
  const arcPath = (fromDeg: number, toDeg: number): string => {
    const [x0, y0] = pt(fromDeg);
    const [x1, y1] = pt(toDeg);
    const large = Math.abs(toDeg - fromDeg) > 180 ? 1 : 0;
    return `M${x0.toFixed(2)},${y0.toFixed(2)} A${r},${r} 0 ${large} 1 ${x1.toFixed(2)},${y1.toFixed(2)}`;
  };

  const track = svgEl("path");
  attrs(track, {
    d: arcPath(START, START + SWEEP), fill: "none", stroke: "var(--w-line)",
    "stroke-width": stroke, "stroke-linecap": "round",
  });
  svg.appendChild(track);

  if (v > 0) {
    const val = svgEl("path");
    // A hairline floor again: a real 1% must show as a nub.
    const sweep = Math.max(SWEEP * v, 2);
    attrs(val, {
      d: arcPath(START, START + sweep), fill: "none",
      stroke: TONE_VAR[opts.tone ?? "accent"],
      "stroke-width": stroke, "stroke-linecap": "round",
    });
    svg.appendChild(val);
  }

  if (opts.center) {
    const t = svgEl("text");
    attrs(t, {
      x: cx, y: cy + (opts.caption ? -1 : 5), "text-anchor": "middle",
      fill: "var(--w-text)", "font-size": (size * 0.24).toFixed(1),
      "font-weight": "600", "font-family": "var(--w-mono)",
    });
    t.textContent = opts.center;
    svg.appendChild(t);
  }
  if (opts.caption) {
    const c = svgEl("text");
    attrs(c, {
      x: cx, y: cy + size * 0.14, "text-anchor": "middle",
      fill: "var(--w-muted)", "font-size": (size * 0.072).toFixed(1),
      "letter-spacing": "0.1em",
    });
    c.textContent = opts.caption;
    svg.appendChild(c);
  }
  return svg;
}

// ===========================================================================
// 3. donut - a categorical breakdown, as SVG rather than canvas
// ===========================================================================

export interface Slice {
  label: string;
  value: number;
  /** A CSS colour; a theme token is expected. */
  color: string;
}

export interface DonutOptions {
  size?: number;
  center?: string;
  caption?: string;
  title?: string;
}

/**
 * Returns null when every slice is zero, or when there are no slices. A
 * donut of one slice is drawn (it is a true statement: everything is one
 * thing) but a donut of nothing is not.
 */
export function donut(slices: Slice[], opts: DonutOptions = {}): SVGSVGElement | null {
  const live = slices.filter((s) => Number.isFinite(s.value) && s.value > 0);
  const total = live.reduce((a, s) => a + s.value, 0);
  if (total <= 0) return null;

  const size = opts.size ?? 128;
  const svg = frame(size, size, opts.title);
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 4;
  const inner = r * 0.62;

  let angle = -Math.PI / 2;
  for (const s of live) {
    const sweep = (s.value / total) * Math.PI * 2;
    // A full-circle slice cannot be drawn as an arc (start equals end), so
    // the single-slice case is a ring, not a degenerate wedge.
    if (live.length === 1) {
      const ring = svgEl("circle");
      attrs(ring, {
        cx, cy, r: (r + inner) / 2, fill: "none",
        stroke: s.color, "stroke-width": r - inner,
      });
      svg.appendChild(ring);
      break;
    }
    const x0 = cx + r * Math.cos(angle);
    const y0 = cy + r * Math.sin(angle);
    const x1 = cx + r * Math.cos(angle + sweep);
    const y1 = cy + r * Math.sin(angle + sweep);
    const xi1 = cx + inner * Math.cos(angle + sweep);
    const yi1 = cy + inner * Math.sin(angle + sweep);
    const xi0 = cx + inner * Math.cos(angle);
    const yi0 = cy + inner * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    const p = svgEl("path");
    attrs(p, {
      d:
        `M${x0.toFixed(2)},${y0.toFixed(2)} A${r},${r} 0 ${large} 1 ${x1.toFixed(2)},${y1.toFixed(2)} ` +
        `L${xi1.toFixed(2)},${yi1.toFixed(2)} A${inner},${inner} 0 ${large} 0 ${xi0.toFixed(2)},${yi0.toFixed(2)} Z`,
      fill: s.color,
    });
    const tt = svgEl("title");
    tt.textContent = `${s.label}: ${s.value}`;
    p.appendChild(tt);
    svg.appendChild(p);
    angle += sweep;
  }

  if (opts.center) {
    const t = svgEl("text");
    attrs(t, {
      x: cx, y: cy + 2, "text-anchor": "middle", fill: "var(--w-text)",
      "font-size": (size * 0.22).toFixed(1), "font-weight": "600",
      "font-family": "var(--w-mono)",
    });
    t.textContent = opts.center;
    svg.appendChild(t);
  }
  if (opts.caption) {
    const c = svgEl("text");
    // The caption has to FIT INSIDE THE HOLE. Sized as a fraction of the
    // donut it overflowed the inner radius and was painted over by the ring
    // itself, so the word "DESTINATIONS" came out clipped at both ends
    // under a number it was supposed to be labelling. Size it from the hole
    // and the caption's own length instead, and let a caption that still
    // cannot fit be dropped rather than drawn broken.
    const holeW = inner * 2 - 6;
    // 0.78 em per uppercase character including the letter-spacing below,
    // measured against the rendered caption rather than guessed: the first
    // attempt used 1.72 and still overran the hole by a fifth.
    const fs = Math.min(size * 0.07, holeW / (Math.max(1, opts.caption.length) * 0.78));
    if (fs >= 5) {
      attrs(c, {
        x: cx, y: cy + size * 0.135, "text-anchor": "middle", fill: "var(--w-muted)",
        "font-size": fs.toFixed(2), "letter-spacing": "0.08em",
      });
      c.textContent = opts.caption;
      svg.appendChild(c);
    }
  }
  return svg;
}

// ===========================================================================
// 4. stackShare - one bar, whole width, showing concentration
// ===========================================================================

export interface StackShareOptions {
  width?: number;
  height?: number;
  title?: string;
  /** Label the largest segment inline when it is wide enough to hold text. */
  labelLargest?: boolean;
}

/**
 * A single 100%-wide stacked bar. This is the concentration primitive: it
 * answers "how much of this is in how few hands" at a glance, which a list
 * of counts sorted descending never does.
 */
export function stackShare(slices: Slice[], opts: StackShareOptions = {}): SVGSVGElement | null {
  const live = slices.filter((s) => Number.isFinite(s.value) && s.value > 0);
  const total = live.reduce((a, s) => a + s.value, 0);
  if (total <= 0) return null;
  const w = opts.width ?? 240;
  const h = opts.height ?? 12;
  const svg = frame(w, h, opts.title);
  svg.setAttribute("preserveAspectRatio", "none");

  let x = 0;
  live.forEach((s, i) => {
    const raw = (s.value / total) * w;
    // Floor at a visible sliver so a real minority holder is not erased,
    // then let the last segment absorb the rounding so the bar is exactly
    // full and never shows a gap that means nothing.
    const width = i === live.length - 1 ? Math.max(0, w - x) : Math.max(raw, 1.5);
    const rect = svgEl("rect");
    attrs(rect, {
      x: x.toFixed(2), y: 0, width: width.toFixed(2), height: h, fill: s.color,
    });
    const tt = svgEl("title");
    tt.textContent = `${s.label}: ${s.value} of ${total} (${((s.value / total) * 100).toFixed(0)}%)`;
    rect.appendChild(tt);
    svg.appendChild(rect);
    x += width;
  });
  return svg;
}

// ===========================================================================
// 5. timeStrip - a real time axis, with events at their real times
// ===========================================================================

export interface TimeEvent {
  at: number;
  tone: Tone;
  label: string;
}

export interface TimeStripOptions {
  width?: number;
  height?: number;
  /** Window end; defaults to now. */
  until?: number;
  /** Window length in hours. */
  hours?: number;
  title?: string;
}

/**
 * Events plotted on a genuine time axis over a trailing window, with hour
 * ticks and a marked midnight.
 *
 * A list "newest first" tells a reader the ORDER of events. It cannot tell
 * them that eleven of the twelve happened inside four minutes, which is the
 * shape that means something. This is the only primitive here whose whole
 * value is the horizontal position of a mark.
 *
 * Returns null with no events in the window: an empty axis is furniture.
 */
export function timeStrip(events: TimeEvent[], opts: TimeStripOptions = {}): SVGSVGElement | null {
  const until = opts.until ?? Date.now();
  const hours = opts.hours ?? 24;
  const since = until - hours * 3_600_000;
  const inWindow = events.filter((e) => Number.isFinite(e.at) && e.at >= since && e.at <= until);
  if (inWindow.length === 0) return null;

  const w = opts.width ?? 240;
  const h = opts.height ?? 34;
  // NOT preserveAspectRatio="none", unlike the bars.
  //
  // A bar has no text in it, so stretching one to fill its container is
  // free. This strip carries "24h ago" and "now", and a card wider than the
  // viewBox stretches those horizontally without stretching them
  // vertically, which is the specific ugly that makes a chart look
  // home-made. Uniform scaling costs a little height and keeps the
  // lettering the shape lettering is.
  const svg = frame(w, h, opts.title);
  const axisY = h - 9;

  const base = svgEl("rect");
  attrs(base, { x: 0, y: axisY, width: w, height: 1, fill: "var(--w-line)" });
  svg.appendChild(base);

  // An hour tick every three hours, and a taller one at each local midnight,
  // so the strip reads as a clock rather than as a ruler.
  const step = 3_600_000;
  for (let t = Math.ceil(since / step) * step; t <= until; t += step) {
    const d = new Date(t);
    const isMidnight = d.getHours() === 0;
    if (!isMidnight && d.getHours() % 3 !== 0) continue;
    const x = ((t - since) / (until - since)) * w;
    const tick = svgEl("rect");
    attrs(tick, {
      x: x.toFixed(2), y: isMidnight ? axisY - 3 : axisY - 1.5,
      width: isMidnight ? 1 : 0.75, height: isMidnight ? 4 : 2.5,
      fill: isMidnight ? "var(--w-line-strong)" : "var(--w-line)",
    });
    svg.appendChild(tick);
  }

  // Marks, hot ones last so a single flagged event is never painted over
  // by the ordinary traffic around it.
  const order: Tone[] = ["neutral", "ok", "accent", "warn", "hot"];
  const sorted = [...inWindow].sort((a, b) => order.indexOf(a.tone) - order.indexOf(b.tone));
  for (const e of sorted) {
    const x = ((e.at - since) / (until - since)) * w;
    const hot = e.tone === "hot" || e.tone === "warn";
    const mark = svgEl("rect");
    attrs(mark, {
      x: Math.min(w - 1.6, Math.max(0, x - 0.8)).toFixed(2),
      y: hot ? 1 : axisY - 12, width: 1.6,
      height: hot ? axisY - 1 : 12,
      fill: TONE_VAR[e.tone], rx: 0.8, opacity: hot ? 1 : 0.75,
    });
    const tt = svgEl("title");
    tt.textContent = `${new Date(e.at).toLocaleTimeString()} ${e.label}`;
    mark.appendChild(tt);
    svg.appendChild(mark);
  }

  const cap = (x: number, anchor: string, text: string): void => {
    const t = svgEl("text");
    attrs(t, { x, y: h - 1, "text-anchor": anchor, fill: "var(--w-muted)", "font-size": 7 });
    t.textContent = text;
    svg.appendChild(t);
  };
  cap(0, "start", `${hours}h ago`);
  cap(w, "end", "now");
  return svg;
}

// ===========================================================================
// 6. flowJoin - THE JOIN. Destinations converging on shared infrastructure.
// ===========================================================================

export interface FlowNode {
  id: string;
  label: string;
  weight: number;
  tone?: Tone;
}

export interface FlowColumn {
  label: string;
  nodes: FlowNode[];
}

export interface FlowLink {
  from: string;
  to: string;
  weight: number;
  tone?: Tone;
}

export interface FlowJoinOptions {
  width?: number;
  /** Height per row of the tallest column. */
  rowHeight?: number;
  title?: string;
}

/**
 * The moat, drawn.
 *
 * Columns of nodes with weighted ribbons between them. Anyone can list the
 * companies a browser talked to. What needs a graph is the observation that
 * nine of those destinations resolve into two networks held by one operator
 * that is present in one building: the CONVERGENCE is the finding, and a
 * convergence is a shape, not a row in a table.
 *
 * The three flat bar-lists this replaces showed the same three rows grouped
 * three different ways and drew no relationship between them at all.
 *
 * Returns null unless there are at least two columns with nodes and at
 * least one link: a flow with nothing flowing is a legend.
 */
export function flowJoin(
  columns: FlowColumn[],
  links: FlowLink[],
  opts: FlowJoinOptions = {},
): SVGSVGElement | null {
  const cols = columns.filter((c) => c.nodes.length > 0);
  if (cols.length < 2 || links.length === 0) return null;

  const w = opts.width ?? 300;
  const rowH = opts.rowHeight ?? 22;
  const tallest = Math.max(...cols.map((c) => c.nodes.length));
  const headH = 13;
  const h = headH + tallest * rowH + 4;

  const svg = frame(w, h, opts.title);

  const colW = w / cols.length;
  const NODE_W = 5;
  const LABEL_PAD = 4;
  /* The label gutter. Every node's name is written to the RIGHT of its bar,
     and ribbons are only ever drawn in the space AFTER the widest label and
     BEFORE the next column's bar. Without this the ribbons ran the full
     column width and struck straight through the text they were connecting,
     which made the one picture whose whole job is legibility the least
     legible thing on the page. */
  const labelZone = Math.max(40, colW * 0.56);
  /* Where a ribbon leaving column ci may start, and where one arriving at
     column ci must end. */
  const outX = (ci: number): number => ci * colW + NODE_W + LABEL_PAD + labelZone;
  const inX = (ci: number): number => ci * colW;

  // Lay every node out first: a link cannot be drawn before both of its
  // ends have a position, and a second pass is cheaper than a lookup that
  // can fail halfway through drawing.
  const pos = new Map<string, { x: number; y: number; h: number; tone: Tone; col: number }>();
  cols.forEach((col, ci) => {
    const total = col.nodes.reduce((a, n) => a + Math.max(n.weight, 0), 0);
    const avail = tallest * rowH - 6;
    let y = headH + 3;
    // Proportional heights when the weights differ, equal heights when they
    // do not: a column of identical weights drawn proportionally is a
    // column of identical boxes, which reads as a fact about the data
    // rather than an absence of one.
    const equal = total <= 0 || col.nodes.every((n) => n.weight === col.nodes[0]?.weight);
    for (const n of col.nodes) {
      const nh = equal
        ? avail / col.nodes.length - 3
        : Math.max(4, (Math.max(n.weight, 0) / total) * avail - 3);
      pos.set(n.id, { x: ci * colW, y, h: nh, tone: n.tone ?? "neutral", col: ci });
      y += nh + 3;
    }
  });

  // Ribbons first, so nodes and text sit on top of them.
  let drawn = 0;
  for (const l of links) {
    const a = pos.get(l.from);
    const b = pos.get(l.to);
    if (!a || !b) continue;
    const x0 = outX(a.col);
    const x1 = inX(b.col);
    if (x1 <= x0) continue;
    const y0 = a.y + a.h / 2;
    const y1 = b.y + b.h / 2;
    const mid = (x0 + x1) / 2;
    const path = svgEl("path");
    attrs(path, {
      d: `M${x0.toFixed(2)},${y0.toFixed(2)} C${mid.toFixed(2)},${y0.toFixed(2)} ${mid.toFixed(2)},${y1.toFixed(2)} ${x1.toFixed(2)},${y1.toFixed(2)}`,
      fill: "none",
      stroke: TONE_VAR[l.tone ?? "accent"],
      "stroke-width": Math.max(0.8, Math.min(6, l.weight * 1.6)).toFixed(2),
      opacity: l.tone === "hot" ? 0.75 : 0.3,
      "stroke-linecap": "round",
    });
    svg.appendChild(path);
    drawn++;
  }
  // Every link named a node that does not exist: the caller built the
  // columns and the links from different data, and a picture of nodes with
  // no ribbons would hide that.
  if (drawn === 0) return null;

  cols.forEach((col, ci) => {
    const head = svgEl("text");
    attrs(head, {
      x: ci * colW, y: 8,
      "text-anchor": "start", fill: "var(--w-muted)",
      "font-size": 7.5, "letter-spacing": "0.1em",
    });
    head.textContent = col.label.toUpperCase();
    svg.appendChild(head);

    for (const n of col.nodes) {
      const p = pos.get(n.id);
      if (!p) continue;
      const bar = svgEl("rect");
      attrs(bar, {
        x: p.x, y: p.y.toFixed(2), width: NODE_W, height: p.h.toFixed(2),
        rx: 2, fill: TONE_VAR[p.tone],
      });
      const tt = svgEl("title");
      tt.textContent = `${n.label} (${n.weight})`;
      bar.appendChild(tt);
      svg.appendChild(bar);

      const label = svgEl("text");
      attrs(label, {
        x: (p.x + NODE_W + LABEL_PAD).toFixed(2), y: (p.y + p.h / 2 + 3).toFixed(2),
        "text-anchor": "start",
        fill: p.tone === "hot" ? TONE_VAR.hot : "var(--w-text)",
        "font-size": 9,
      });
      // Truncated to the label gutter, so a long hostname can never grow
      // into the ribbons. The full string stays on the node's tooltip.
      const room = Math.floor(labelZone / 5.1);
      label.textContent = n.label.length > room ? `${n.label.slice(0, Math.max(3, room - 1))}…` : n.label;
      svg.appendChild(label);
    }
  });
  return svg;
}

// ===========================================================================
// 7. chainSpine - the seven-rung join path as a drawn path
// ===========================================================================

export interface SpineRung {
  label: string;
  /** live | empty | unavailable, drawn as three different marks. */
  state: "live" | "empty" | "unavailable";
  tone?: Tone;
  /** Set on the rung that carries the finding, drawn larger. */
  pivotal?: boolean;
}

export interface ChainSpineOptions {
  width?: number;
  title?: string;
  /** Draw horizontally (the wide surfaces) rather than vertically. */
  horizontal?: boolean;
}

/**
 * The seven rungs as a graphic, distinct from the row list that carries the
 * values. It exists for the surfaces where the whole chain must land in one
 * glance and there is no room for seven rows: a reader sees how far the
 * walk got, where it broke, and which rung carries the risk, before reading
 * a single word.
 *
 * The three states get three MARKS, not three colours: a filled node, a
 * hollow node, and a cross. Colour alone cannot carry a distinction this
 * load-bearing, because roughly one reader in twelve will not see it.
 */
export function chainSpine(rungs: SpineRung[], opts: ChainSpineOptions = {}): SVGSVGElement | null {
  if (rungs.length < 2) return null;
  const w = opts.width ?? 280;
  const h = opts.horizontal === false ? rungs.length * 20 : 40;
  const svg = frame(w, h, opts.title);

  const padX = 10;
  const y = 14;
  const step = (w - padX * 2) / (rungs.length - 1);

  rungs.forEach((r, i) => {
    if (i === rungs.length - 1) return;
    const next = rungs[i + 1];
    const broken = r.state !== "live" || next?.state !== "live";
    const seg = svgEl("line");
    attrs(seg, {
      x1: padX + i * step, y1: y, x2: padX + (i + 1) * step, y2: y,
      stroke: broken ? "var(--w-line)" : "var(--w-accent-line)",
      "stroke-width": broken ? 1 : 1.75,
      ...(broken ? { "stroke-dasharray": "2 2" } : {}),
    });
    svg.appendChild(seg);
  });

  rungs.forEach((r, i) => {
    const x = padX + i * step;
    const tone = TONE_VAR[r.tone ?? "accent"];
    const rad = r.pivotal ? 5.5 : 3.75;
    // The element the tooltip belongs to, tracked explicitly. It used to be
    // taken as svg.lastElementChild, which on a pivotal live rung is the
    // HALO drawn after the node, so the hover target and the mark the
    // reader is pointing at were different elements.
    let node: SVGElement;
    if (r.state === "unavailable") {
      // A cross, because "we could not read this" must never look like a
      // quiet node. This is the state that becomes an outage rendering as
      // safety when it is drawn the same as a value.
      const g = svgEl("g");
      for (const [dx, dy] of [[-3, -3], [-3, 3]] as const) {
        const l = svgEl("line");
        attrs(l, {
          x1: x + dx, y1: y + dy, x2: x - dx, y2: y - dy,
          stroke: "var(--w-v-low)", "stroke-width": 1.5, "stroke-linecap": "round",
        });
        g.appendChild(l);
      }
      svg.appendChild(g);
      node = g;
    } else {
      const c = svgEl("circle");
      attrs(c, {
        cx: x, cy: y, r: rad,
        fill: r.state === "live" ? tone : "var(--w-bg)",
        stroke: r.state === "live" ? "none" : "var(--w-line-strong)",
        "stroke-width": 1.25,
      });
      svg.appendChild(c);
      node = c;
      if (r.pivotal && r.state === "live") {
        const halo = svgEl("circle");
        attrs(halo, {
          cx: x, cy: y, r: rad + 3, fill: "none", stroke: tone,
          "stroke-width": 1, opacity: 0.45,
        });
        svg.appendChild(halo);
      }
    }
    const tt = svgEl("title");
    tt.textContent = `${r.label}: ${r.state}`;
    node.appendChild(tt);

    const t = svgEl("text");
    // The end labels anchor to their own edge rather than to their node.
    // Centred, the first and last labels run off the viewBox and are
    // silently clipped, which turned "PRESENT AT" into "PRESENT" - a
    // shortened label that still reads as a whole word is the worst kind
    // of truncation, because nothing about it looks wrong.
    const first = i === 0;
    const last = i === rungs.length - 1;
    attrs(t, {
      x: first ? 0 : last ? w : x,
      y: h - 8,
      "text-anchor": first ? "start" : last ? "end" : "middle",
      fill: r.pivotal ? "var(--w-text)" : "var(--w-muted)",
      "font-size": 6.5, "letter-spacing": "0.06em",
    });
    t.textContent = r.label.toUpperCase();
    svg.appendChild(t);
  });
  return svg;
}

// ===========================================================================
// 8. countMarks - a small count drawn as the count, one mark per thing
// ===========================================================================

/** Past this many marks the eye stops counting and the picture starts
 *  implying a precision it cannot deliver. */
const MAX_MARKS = 60;

export interface CountMarksOptions {
  /** Marks per row before wrapping. */
  perRow?: number;
  size?: number;
  gap?: number;
  tone?: Tone;
  /** Draw this many additional marks in muted ink behind the counted ones. */
  outOf?: number;
  title?: string;
}

/**
 * A count, drawn as that many marks.
 *
 * "9 flagged neighbours" is a number a reader skims past. Nine marks is a
 * quantity they see. This is the right instrument only for small counts,
 * so it refuses above 60: past that the marks stop being countable and the
 * picture starts implying a precision the eye cannot recover, which is a
 * chart lying politely.
 */
export function countMarks(n: number, opts: CountMarksOptions = {}): SVGSVGElement | null {
  if (!Number.isFinite(n) || n < 0 || n > MAX_MARKS) return null;
  // A denominator past the cap cannot be drawn, and clamping it would draw
  // "9 of 60" for a measurement of 9 of 400. Refuse instead: a wrong ratio
  // drawn confidently is worse than no picture at all.
  if (opts.outOf !== undefined && (!Number.isFinite(opts.outOf) || opts.outOf > MAX_MARKS)) return null;
  const total = opts.outOf !== undefined && opts.outOf > n ? opts.outOf : n;
  if (total === 0) return null;
  const perRow = opts.perRow ?? 20;
  const s = opts.size ?? 5;
  const gap = opts.gap ?? 2.5;
  const rows = Math.ceil(total / perRow);
  const w = Math.min(total, perRow) * (s + gap) - gap;
  const h = rows * (s + gap) - gap;
  const svg = frame(w, h, opts.title);
  for (let i = 0; i < total; i++) {
    const r = svgEl("rect");
    attrs(r, {
      x: ((i % perRow) * (s + gap)).toFixed(2),
      y: (Math.floor(i / perRow) * (s + gap)).toFixed(2),
      width: s, height: s, rx: 1.25,
      fill: i < n ? TONE_VAR[opts.tone ?? "hot"] : "var(--w-line)",
    });
    svg.appendChild(r);
  }
  return svg;
}

// ===========================================================================
// 9. pulseTrack - the live one, and honest when nothing is arriving
// ===========================================================================

export interface PulseTrackOptions {
  width?: number;
  height?: number;
  title?: string;
}

export interface PulseHandle {
  el: SVGSVGElement;
  /** Push one real arrival. Returns false once the track is detached. */
  push(tone?: Tone): boolean;
  /** Say, in the mark itself, that nothing has arrived. */
  idle(): void;
  stop(): void;
}

/**
 * A track that moves when data actually arrives, and says so when it does
 * not.
 *
 * This is the only self-animating primitive, and it carries a rule the rest
 * of the product now depends on: MOTION MEANS AN EVENT HAPPENED. A spinner
 * that turns while nothing is happening teaches a reader that motion here
 * is decoration, and after that no motion on the surface can mean anything.
 * `push()` is called from the real arrival path; `idle()` dims the track and
 * stops it, so a quiet product looks quiet rather than looking busy.
 */
export function pulseTrack(opts: PulseTrackOptions = {}): PulseHandle {
  const w = opts.width ?? 64;
  const h = opts.height ?? 14;
  const svg = frame(w, h, opts.title);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.classList.add("w-pulse");

  const base = svgEl("rect");
  attrs(base, { x: 0, y: h / 2 - 0.5, width: w, height: 1, fill: "var(--w-line)" });
  svg.appendChild(base);

  const marks: SVGRectElement[] = [];
  let stopped = false;

  const shift = (): void => {
    for (let i = marks.length - 1; i >= 0; i--) {
      const m = marks[i];
      if (!m) continue;
      const x = Number(m.getAttribute("x")) - 5;
      if (x < -2) {
        m.remove();
        marks.splice(i, 1);
        continue;
      }
      m.setAttribute("x", x.toFixed(2));
      m.setAttribute("opacity", Math.max(0.15, x / w).toFixed(2));
    }
  };

  return {
    el: svg,
    push(tone: Tone = "accent"): boolean {
      if (stopped || !svg.isConnected) return false;
      svg.classList.remove("w-pulse-idle");
      shift();
      const m = svgEl("rect");
      const tall = tone === "hot" || tone === "warn";
      attrs(m, {
        x: w - 2, y: tall ? 1 : h / 2 - 3, width: 2,
        height: tall ? h - 2 : 6, rx: 1, fill: TONE_VAR[tone],
      });
      // The newest mark fades in rather than appearing, which is what makes
      // the track read as arriving rather than as redrawing.
      if (!reduced()) {
        m.setAttribute("opacity", "0");
        requestAnimationFrame(() => m.setAttribute("opacity", "1"));
      }
      svg.appendChild(m);
      marks.push(m);
      return true;
    },
    idle(): void {
      svg.classList.add("w-pulse-idle");
    },
    stop(): void {
      stopped = true;
    },
  };
}

// ===========================================================================
// re-exports, so a surface imports its drawing from one place
// ===========================================================================

export { sparkline, countUp, compact } from "./spark";
export type { SparkOptions } from "./spark";
