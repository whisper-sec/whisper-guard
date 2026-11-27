// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Contrast as a page really draws it, shared by the specs that measure it.

import type { Page } from "@playwright/test";

export interface TextSample {
  /** A short description of the element, for the failure message. */
  what: string;
  /** The rendered ink, composited over its ground. */
  ratio: number;
  /** The AA floor this sample has to clear (3.0 for large text). */
  floor: number;
  /** The id of the popup part (This site, This page, This browser) the element sits in, or null. */
  panel: string | null;
}

/**
 * Walk everything the page actually PAINTS and measure it.
 *
 * This runs in the page because contrast is a property of what rendered,
 * not of what was written: the ink may be translucent, the ground may be
 * three ancestors up or a color-mix(), and either may come from a token
 * that has just flipped. Composite both and compare.
 */
export async function measureContrast(tab: Page): Promise<TextSample[]> {
  // Controls carry a 120ms colour transition, so a sample taken too soon
  // after a scheme flip reads an ink part-way between the two palettes on a
  // ground that has already snapped - which measured as 2.30:1 on a button
  // that is 5.80:1 at rest. Ask for reduced motion, which the product's own
  // stylesheet answers by switching every transition off, and measure the
  // resting state on purpose rather than whatever the clock happened to
  // catch.
  await tab.emulateMedia({ reducedMotion: "reduce" });
  return tab.evaluate(() => {
    const px = (c: string): number[] => {
      const m = c.match(/-?[\d.]+/g);
      if (!m) return [0, 0, 0, 1];
      const raw = m.map(Number);
      // Chromium serialises a computed colour on two DIFFERENT scales:
      // `rgb(233, 204, 207)` is 0-255 while a color-mix() result comes back
      // as `color(srgb 0.913725 0.8 0.812549)`, 0-1.
      const scale = c.startsWith("color(") ? 255 : 1;
      return [raw[0]! * scale, raw[1]! * scale, raw[2]! * scale, raw[3] ?? 1];
    };
    const over = (fg: number[], bg: number[]): number[] => {
      const a = fg[3]!;
      return [0, 1, 2].map((i) => fg[i]! * a + bg[i]! * (1 - a)).concat(1);
    };
    const lum = (c: number[]): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * f(c[0]!) + 0.7152 * f(c[1]!) + 0.0722 * f(c[2]!);
    };

    /** The first opaque ground behind `el`, composited down from the page. */
    const groundOf = (el: Element): number[] => {
      const stack: number[][] = [];
      for (let n: Element | null = el; n; n = n.parentElement) {
        const c = px(getComputedStyle(n).backgroundColor);
        if (c[3]! > 0) stack.push(c);
        if (c[3] === 1) break;
      }
      // Nothing opaque anywhere: the browser paints white behind the page.
      let out = [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i]!, out);
      return out;
    };

    const out: { what: string; ratio: number; floor: number; panel: string | null }[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("body *"))) {
      // Only elements with their OWN visible text; a container's colour is
      // measured on whichever child actually paints the glyphs.
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? "")
        .join("")
        .trim();
      if (own === "") continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;
      // A disabled control is allowed to look disabled.
      if ((el as HTMLButtonElement).disabled) continue;
      if (el.closest("[disabled]")) continue;

      // Element opacity multiplies the ink's alpha.
      let alpha = 1;
      for (let n: Element | null = el; n; n = n.parentElement) alpha *= Number(getComputedStyle(n).opacity);
      const fg = px(cs.color);
      fg[3] = fg[3]! * alpha;

      const ground = groundOf(el);
      const ink = over(fg, ground);
      const [hi, lo] = [lum(ink), lum(ground)].sort((a, b) => b - a);
      const ratio = (hi! + 0.05) / (lo! + 0.05);

      const size = parseFloat(cs.fontSize);
      const weight = Number(cs.fontWeight) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      out.push({
        what: `<${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${
          el.className && typeof el.className === "string" ? `.${el.className.trim().split(/\s+/).join(".")}` : ""
        }> "${own.slice(0, 40)}"`,
        ratio,
        floor: large ? 3 : 4.5,
        panel: el.closest("#popup-scroll > section")?.id ?? null,
      });
    }
    return out;
  });
}
