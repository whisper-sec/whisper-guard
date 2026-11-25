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
