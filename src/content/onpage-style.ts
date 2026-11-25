// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The look the content script's on-page warnings share. These warnings draw
// inside a closed shadow root on someone else's page, which cannot read the
// extension's stylesheet, so the palette lives here as constants. It is one
// fixed dark look: it does not follow the theme choice. Translucent values
// are composited to solid colours over their ground, because the warnings
// draw over arbitrary pages. Everything is applied through CSSOM
// (element.style), which a page's Content-Security-Policy cannot refuse.

import { MARK_DATAURI } from "../shared/brand";

export const ONPAGE = {
  card: "#0d0d1a",
  well: "#06060c",
  text: "#eeeef0",
  text2: "#c3c3cd",
  muted: "#8888a0",
  line: "#252531",
  lineStrong: "#34343f",
  wellLine: "#121218",
  accent: "#b49cf5",
  accentLine: "#7d5ce0",
  onAccent: "#ffffff",
  pillFill: "#1b1631",
  pillLine: "#2e2550",
  high: "#ef4444",
  critical: "#b8202a",
  headingDanger: "#fecaca",
  scrim: "rgba(1,1,3,0.78)",
  cardShadow: "0 24px 80px rgba(0,0,0,0.6), 0 0 60px -24px rgba(122,92,224,0.55)",
} as const;

/**
 * Generic families only: the card renders in faces the browser picks, never
 * one a page supplies.
 */
export const FONT_SANS = "system-ui, sans-serif";
export const FONT_MONO = "ui-monospace, monospace";

/** A styled element: tag, optional id (scoped to the closed root), inline css, optional text. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  id: string | null,
  css: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (id) e.id = id;
  e.style.cssText = css;
  if (text !== undefined) e.textContent = text;
  return e;
}

/** The knot mark as an image of the given CSS size. */
export function markImg(sizePx: number): HTMLImageElement {
  const img = document.createElement("img");
  img.src = MARK_DATAURI;
  img.alt = "";
  img.style.cssText = `width:${sizePx}px;height:${sizePx}px;flex:none;display:block`;
  return img;
}

/**
 * Inline styles cannot use :focus-visible, so the ring is drawn on every
 * focus (which also marks the default button when a card opens).
 */
export function focusRing(el: HTMLElement): void {
  el.addEventListener("focus", () => {
    el.style.outline = `2px solid ${ONPAGE.accent}`;
    el.style.outlineOffset = "2px";
  });
  el.addEventListener("blur", () => {
    el.style.outline = "";
    el.style.outlineOffset = "";
  });
}

/**
 * Edges and fills of the field caution card, one tone per case. Each value is
 * a translucent colour composited over the card ground, written as the solid
 * result because the card draws over arbitrary pages.
 */
export const CAUTION_TONE = {
  /** rgba(245,158,11,0.55) over #0d0d1a */
  amberEdge: "#8d5d12",
  /** the kind named inside a flagged-site sentence */
  amberText: "#fbbf24",
  /** the neutral edge used after a click-through (same as ONPAGE.lineStrong) */
  neutralEdge: "#34343f",
  /** rgba(239,68,68,0.10) over #0d0d1a: the fill of the recovery-phrase card and its caret */
  dangerFill: "#24121e",
} as const;

/** The SVG namespace, for the close icon (built with createElementNS, never markup). */
const SVG_NS = "http://www.w3.org/2000/svg";

/** A 14 px X icon in `currentColor`, hidden from assistive technology. */
export function closeIcon(): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "14");
  svg.setAttribute("height", "14");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.4");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", "M6 6l12 12M18 6L6 18");
  svg.appendChild(path);
  return svg;
}
