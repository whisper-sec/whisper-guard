// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Canvas drawings read the SAME tokens the stylesheets do.
//
// A <canvas> gets no cascade, so every chart in the extension used to
// carry its own hard-coded hex - which is exactly how the dashboard's
// donut, gauge and constellation stayed dark-only long after the panel
// learned to follow the reader's colour scheme: nothing in CSS could
// reach them. Reading the custom property off the document root instead
// means a chart is themed by the same file as everything else, and a
// palette change cannot leave a canvas behind.
//
// The fallback is the dark value, so a chart still draws if a stylesheet
// has not landed yet, and it is never the source of truth.

import { CATEGORY_HEX, type ReportCategory } from "./report";

const cache = new Map<string, string>();

// A resolved token is cached because categoryColor() is called once per
// row on a busy chart. The cache is dropped the moment the reader's
// colour scheme flips, so it can never hold a stale palette.
const schemeQuery =
  typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: light)") : null;
const themeListeners = new Set<() => void>();
schemeQuery?.addEventListener("change", () => {
  cache.clear();
  for (const fn of themeListeners) {
    try {
      fn();
    } catch {
      // one bad repaint never stops the others
    }
  }
});

/** Repaint hook: run `fn` whenever the reader's colour scheme flips. */
export function onThemeChange(fn: () => void): void {
  themeListeners.add(fn);
}

/** Read a theme custom property, with the dark value as the fallback. */
export function themeColor(name: string, fallback: string): string {
  const hit = cache.get(name);
  if (hit !== undefined) return hit;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const out = v === "" ? fallback : v;
  cache.set(name, out);
  return out;
}

/** The category hue for a canvas fill, themed. */
export function categoryColor(cat: ReportCategory): string {
  return themeColor(`--w-cat-${cat}`, CATEGORY_HEX[cat]);
}

/**
 * The palette a chart needs, resolved once per draw. Grouped rather than
 * fetched one at a time so a drawing routine reads as a drawing routine.
 */
export interface ChartInk {
  text: string;
  muted: string;
  line: string;
  /** The unfilled part of a gauge: a hairline fill is invisible on a card
   *  in either theme, so a track is drawn in the strong edge, not a
   *  surface. Caught by looking at the rendered gauge, not by reading it. */
  track: string;
  accent: string;
  ok: string;
  warn: string;
  crit: string;
}

export function chartInk(): ChartInk {
  return {
    text: themeColor("--w-text", "#ececf1"),
    muted: themeColor("--w-muted", "#9a9aae"),
    line: themeColor("--w-line-strong", "#2c2c3c"),
    track: themeColor("--w-line-strong", "#2c2c3c"),
    accent: themeColor("--w-accent", "#6ea8ff"),
    ok: themeColor("--w-ok", "#34d399"),
    warn: themeColor("--w-v-low", "#fbbf24"),
    crit: themeColor("--w-v-high", "#f87171"),
  };
}

/** The document's font stacks, for canvas `ctx.font`. */
export const CANVAS_SANS = "ui-sans-serif, system-ui, sans-serif";
export const CANVAS_MONO = "ui-monospace, monospace";
