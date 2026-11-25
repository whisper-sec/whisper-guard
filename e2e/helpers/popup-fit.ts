// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// What the popup's layout checks share: the second, wider-glyph measure and the
// routed card's lines, which hold on any page that renders the popup (the real
// extension, or the shimmed file in Gecko).

import { expect, test, type Page } from "@playwright/test";

/**
 * How much wider every glyph is drawn for the second measure, in em of its own
 * font size: about 9% on Lato text and 6.7% on mono. Renderers do not all set
 * text alike. Linux headless Chromium, which runs the Gecko and Blink
 * comparison in CI, rounds each glyph's advance to a whole pixel, which at
 * 11px JetBrains Mono is 0.036em a glyph. A layout that holds only with no room
 * at its line ends passes on one machine and wraps a line on the next, so a fit
 * is measured twice, as drawn and with every glyph this much wider, and must
 * hold both times. What that is meant to cover: a layout that holds widened on
 * one renderer should hold as drawn on a renderer that differs only in setting
 * text up to 0.04em a glyph wider; other differences, such as line heights or
 * fonts, are not covered. In CI's headless Blink the widening comes on top of
 * its own rounding.
 * On the routed card, with a name of a real one's length, every line held up
 * to 0.06em in Chromium and Firefox on macOS and in Linux headless Chromium.
 */
export const WIDER_EM = 0.04;

/**
 * The letter spacing WCAG 1.4.12 lets a reader set with their own style
 * (0.12 times the font size). The routed card's layout must survive it: the
 * popup may scroll then, but the Name keeps to one line with its zone whole, and
 * the limits still start under the dot.
 */
export const TEXT_SPACING_EM = 0.12;

/** Resolves after two animation frames: layout has run, and whatever watches a
 *  size (a ResizeObserver, the fade) has seen the result. */
export function twoFrames(page: Page): Promise<void> {
  return page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
}

/** The page's fonts are loaded and the layout they give has been drawn. */
export async function settledLayout(page: Page): Promise<void> {
  await page.evaluate(() => document.fonts.ready.then(() => undefined));
  await twoFrames(page);
}

/**
 * Run `measure` with every element's own letter spacing raised by `em` of its
 * font size, the whole popup included (a footer that wraps takes room from the
 * region too), then put the spacing back as it was.
 */
export async function withWiderGlyphs<T>(page: Page, em: number, measure: () => Promise<T>): Promise<T> {
  await page.evaluate((em) => {
    const els = [document.documentElement, ...document.querySelectorAll<HTMLElement | SVGElement>("body, body *")];
    // Read every spacing before any is changed: a child inherits its parent's.
    const was = els.map((e) => {
      const cs = getComputedStyle(e);
      const base = cs.letterSpacing === "normal" ? 0 : parseFloat(cs.letterSpacing);
      return { e, base, size: parseFloat(cs.fontSize), inline: e.style.getPropertyValue("letter-spacing"), prio: e.style.getPropertyPriority("letter-spacing") };
    });
    for (const w of was) w.e.style.setProperty("letter-spacing", `${w.base + em * w.size}px`, "important");
    (window as unknown as { __fitRestore?: () => void }).__fitRestore = () => {
      for (const w of was) {
        if (w.inline) w.e.style.setProperty("letter-spacing", w.inline, w.prio);
        else w.e.style.removeProperty("letter-spacing");
      }
    };
  }, em);
  // Two frames, so whatever watches a size (the fade, the Name's zone) has seen it.
  const frames = (): Promise<void> => twoFrames(page);
  try {
    await frames();
    return await measure();
  } finally {
    await page.evaluate(() => {
      const w = window as unknown as { __fitRestore?: () => void };
      w.__fitRestore?.();
      delete w.__fitRestore;
    });
    await frames();
  }
}

/**
 * The two parts of the routed card's layout that its fit depends on. The Name
 * takes one line: a selection of it is the whole name, which is also its
 * title; a name of a real one's length has its start trimmed with an ellipsis,
 * and the start fills the line up to the zone (the last three labels), which
 * ends at the cell's right edge. The routing limits start under the dot. Checked as drawn,
 * with every glyph WIDER_EM wider, and at the text spacing a reader may set
 * (TEXT_SPACING_EM), where the zone must still be whole.
 */
export async function expectRoutedCardLayout(page: Page, label: string): Promise<void> {
  const read = (): Promise<{
    lines: number; title: string; selected: string; zone: string | null; clips: boolean; ellipsis: boolean;
    startFromCell: number; zoneFromStart: number; zoneFromEdge: number; limitsFromDot: number;
  }> =>
    page.evaluate(() => {
      const name = document.querySelector<HTMLElement>("#identity-detail .pc-name")!;
      const start = name.querySelector<HTMLElement>(".pc-name-start")!;
      const zone = name.querySelector<HTMLElement>(".pc-name-zone");
      const cell = name.closest(".v")!.getBoundingClientRect();
      const sb = start.getBoundingClientRect();
      const zb = zone?.getBoundingClientRect();
      const cs = getComputedStyle(start);
      const range = document.createRange();
      range.selectNodeContents(name);
      const sel = getSelection()!;
      sel.removeAllRanges();
      sel.addRange(range);
      const selected = sel.toString();
      sel.removeAllRanges();
      const dot = document.querySelector("#route-line .w-dot")!.getBoundingClientRect();
      const more = document.querySelector("#route-line .pc-route-more")!.getBoundingClientRect();
      return {
        lines: name.getBoundingClientRect().height / parseFloat(getComputedStyle(name).lineHeight),
        title: name.title,
        selected,
        zone: zone?.textContent ?? null,
        clips: start.scrollWidth > start.clientWidth,
        ellipsis: cs.overflowX !== "visible" && cs.textOverflow === "ellipsis",
        startFromCell: sb.left - cell.left,
        zoneFromStart: zb ? zb.left - sb.right : NaN,
        zoneFromEdge: zb ? cell.right - zb.right : NaN,
        limitsFromDot: more.left - dot.left,
      };
    });
  for (const [em, how] of [[0, "as drawn"], [WIDER_EM, `${WIDER_EM}em wider`], [TEXT_SPACING_EM, `${TEXT_SPACING_EM}em wider`]] as const) {
    const m = em === 0 ? await read() : await withWiderGlyphs(page, em, read);
    const at = `${label}, ${how}`;
    expect(m.lines, `${at}: the Name takes one line`).toBeCloseTo(1, 1);
    expect(m.title.length, `${at}: the test name is as long as a real one`).toBeGreaterThanOrEqual(73);
    expect(m.selected, `${at}: a selection of the Name is the whole name, its title`).toBe(m.title);
    expect(m.zone, `${at}: the zone is a part of its own`).toBe(m.title.split(".").slice(-3).join("."));
    expect(m.clips && m.ellipsis, `${at}: the start of the long name is trimmed with an ellipsis`).toBe(true);
    expect(m.startFromCell, `${at}: the start begins at the cell's left edge`).toBeCloseTo(0, 0);
    expect(m.zoneFromStart, `${at}: the zone follows the start with no gap`).toBeCloseTo(0, 0);
    expect(m.zoneFromEdge, `${at}: the zone ends at the cell's right edge, whole`).toBeCloseTo(0, 0);
    expect(m.limitsFromDot, `${at}: the routing limits start under the dot`).toBeCloseTo(0, 0);
  }
}

/** How the first screen of a checked site sits against the fade over the region's foot. */
export interface FirstScreen {
  /** Where the fade starts, read from the element itself, in page pixels. */
  fadeTop: number;
  /** The fade's own height. */
  fadeHeight: number;
  /** Pixels between the lowest block that must be clear of the fade and the fade's top. */
  margin: number;
  /** The block that sits lowest of those that must be clear. */
  lowest: string;
  /** Pixels between the facts card's own foot and the fade's top (for the record, not asserted). */
  cardMargin: number;
  /** Facts rows drawn. */
  rungs: number;
  scrollTop: number;
}

/**
 * Where the first screen of a clean site ends. The verdict card, its chips and
 * every facts row must end above the top of the fade, which is read from the
 * element (never a constant: its height is a design value that can move). Read
 * once everything is drawn, at the top of the scroll, with the fade shown: a
 * fade that is not shown would mean the popup has nothing below it, and the
 * measurement would not be of this layout.
 */
export async function measureFirstScreen(page: Page): Promise<FirstScreen> {
  await page.evaluate(() => document.fonts.ready);
  await expect
    .poll(() => page.evaluate(() => document.fonts.check("12.5px Lato") && document.fonts.check("12px 'JetBrains Mono'")))
    .toBe(true);
  await expect(page.locator("#popup-fade")).toBeVisible();
  return page.evaluate(() => {
    const region = document.getElementById("popup-scroll") as HTMLElement;
    const fade = document.getElementById("popup-fade") as HTMLElement;
    const fadeBox = fade.getBoundingClientRect();
    const blocks: [string, Element][] = [
      ["verdict card", document.getElementById("host-row")!],
      ...(document.getElementById("site-chips")!.hidden ? [] : ([["chips", document.getElementById("site-chips")!]] as [string, Element][])),
      ...[...document.querySelectorAll("#chain-mount .ch-rung")].map((e, i): [string, Element] => [`fact ${i + 1}`, e]),
    ];
    let lowest = "";
    let bottom = -Infinity;
    for (const [name, e] of blocks) {
      const b = e.getBoundingClientRect().bottom;
      if (b > bottom) {
        bottom = b;
        lowest = name;
      }
    }
    return {
      fadeTop: fadeBox.top,
      fadeHeight: fadeBox.height,
      margin: fadeBox.top - bottom,
      lowest,
      cardMargin: fadeBox.top - document.getElementById("chain-card")!.getBoundingClientRect().bottom,
      rungs: document.querySelectorAll("#chain-mount .ch-rung").length,
      scrollTop: region.scrollTop,
    };
  });
}

/**
 * The first screen of a clean site holds the verdict card, its chips and all
 * seven facts clear of the fade, as drawn and with every glyph WIDER_EM wider.
 * Both margins go into the test's annotations, and a failure names them.
 */
export async function expectFirstScreen(page: Page, label: string): Promise<{ plain: FirstScreen; wider: FirstScreen }> {
  const plain = await measureFirstScreen(page);
  const wider = await withWiderGlyphs(page, WIDER_EM, () => measureFirstScreen(page));
  const say = (m: FirstScreen): string =>
    `${m.margin.toFixed(1)} px under ${m.lowest} (the whole facts card ${m.cardMargin.toFixed(1)} px; fade ${m.fadeHeight} px from ${m.fadeTop.toFixed(1)})`;
  test.info().annotations.push({ type: label, description: `as drawn ${say(plain)} | ${WIDER_EM}em wider ${say(wider)}` });
  for (const [how, m] of [["as drawn", plain], [`${WIDER_EM}em wider`, wider]] as const) {
    expect(m.scrollTop, `${label}, ${how}: the popup is at the top`).toBe(0);
    expect(m.rungs, `${label}, ${how}: all seven facts are drawn`).toBe(7);
    expect(m.margin, `${label}, ${how}: the ${m.lowest} runs into the fade (${say(m)})`).toBeGreaterThanOrEqual(0);
  }
  return { plain, wider };
}
