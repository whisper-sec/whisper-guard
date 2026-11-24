// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// How much of the popup's 600 px the This browser tab uses, measured on any
// page that renders it (the real extension, or the shimmed file in Gecko).

import { expect, test, type Page } from "@playwright/test";

export interface TabFit {
  /** scrollHeight - clientHeight of the content region: above 0 the tab scrolls. */
  over: number;
  /** Pixels left under the last block inside the region's padding (negative when it scrolls). */
  spare: number;
  scroll: number;
  client: number;
  width: number;
  identity: number;
  activity: number;
  footer: number;
  sentenceLines: number;
  moreLines: number;
  fade: boolean;
}

/**
 * Measured only once everything the tab holds has been drawn: the fonts are
 * loaded and the footer's readout is on screen (it is drawn after an
 * asynchronous permission read and takes part of the region, so a read before
 * it would pass for the wrong reason). A caller measuring the routed state
 * also waits for the card to be complete (the chip VERIFIED and its three
 * rows) before calling.
 */
export async function measureBrowserTab(page: Page): Promise<TabFit> {
  await page.evaluate(() => document.fonts.ready);
  await expect
    .poll(() => page.evaluate(() => document.fonts.check("12.5px Lato") && document.fonts.check("12px 'JetBrains Mono'")))
    .toBe(true);
  await expect(page.locator("#shield-readout")).toBeVisible();
  const m = await page.locator("#tab-content").evaluate((r) => {
    const box = (id: string): number => document.getElementById(id)?.getBoundingClientRect().height ?? 0;
    const last = [...document.getElementById("panel-browser")!.children].filter((e) => !(e as HTMLElement).hidden).pop()!;
    const end = last.getBoundingClientRect().bottom - r.getBoundingClientRect().top;
    const text = document.querySelector("#route-line .pc-route-text") as HTMLElement | null;
    const more = document.querySelector("#route-line .pc-route-more") as HTMLElement | null;
    const lh = (e: HTMLElement): number => parseFloat(getComputedStyle(e).lineHeight);
    const moreBox = more?.getBoundingClientRect().height ?? 0;
    return {
      s: r.scrollHeight,
      c: r.clientHeight,
      w: r.clientWidth,
      spare: r.clientHeight - end - parseFloat(getComputedStyle(r).paddingBottom),
      identity: box("identity-card") || box("signin-pitch"),
      activity: box("activity-card"),
      footer: document.querySelector(".pp-footer")?.getBoundingClientRect().height ?? 0,
      sentenceLines: text ? Math.round((text.getBoundingClientRect().height - moreBox) / lh(text)) : 0,
      moreLines: more ? Math.round(moreBox / lh(more)) : 0,
    };
  });
  return {
    over: m.s - m.c,
    spare: m.spare,
    scroll: m.s,
    client: m.c,
    width: m.w,
    identity: m.identity,
    activity: m.activity,
    footer: m.footer,
    sentenceLines: m.sentenceLines,
    moreLines: m.moreLines,
    fade: await page.locator("#tab-fade").isVisible(),
  };
}

export function describeFit(f: TabFit): string {
  return (
    `over ${f.over} spare ${f.spare.toFixed(1)} scroll ${f.scroll} client ${f.client} width ${f.width} ` +
    `identity ${f.identity.toFixed(1)} activity ${f.activity.toFixed(1)} footer ${f.footer.toFixed(1)} ` +
    `sentence-lines ${f.sentenceLines} second-line-lines ${f.moreLines}`
  );
}

/**
 * How much wider every glyph is drawn for the second measure, in em of its own
 * font size: about 9% on Lato text and 6.7% on mono. Renderers do not all set
 * text alike. Linux headless Chromium, which runs the Gecko and Blink
 * comparison in CI, rounds each glyph's advance to a whole pixel, which at
 * 11px JetBrains Mono is 0.036em a glyph. A tab that fits only with no room at
 * its line ends passes on one machine and wraps a line on the next, so a fit
 * is measured twice, as drawn and with every glyph this much wider, and must
 * hold both times. What that is meant to cover: a tab that holds widened on
 * one renderer should fit as drawn on a renderer that differs only in setting
 * text up to 0.04em a glyph wider; other differences, such as line heights or
 * fonts, are not covered. In CI's headless Blink the widening comes on top of
 * its own rounding.
 * On the routed tab, with a name of a real one's length, every line held up
 * to 0.06em in Chromium and Firefox on macOS and in Linux headless Chromium.
 */
export const WIDER_EM = 0.04;

/**
 * The letter spacing WCAG 1.4.12 lets a reader set with their own style
 * (0.12 times the font size). The routed card's layout must survive it: the
 * tab may scroll then, but the Name keeps to one line with its zone whole, and
 * the limits still start under the dot.
 */
export const TEXT_SPACING_EM = 0.12;

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
  const frames = (): Promise<void> => page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
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

/** The tab's fit with every glyph `em` wider. */
export async function measureBrowserTabWider(page: Page, em = WIDER_EM): Promise<TabFit> {
  return withWiderGlyphs(page, em, () => measureBrowserTab(page));
}

/**
 * The tab fits its region as drawn and with every glyph WIDER_EM wider: no
 * scrolling and no fade, both times. Both measures go into the test's
 * annotations, and a failure of the room names the numbers.
 */
export async function expectBrowserTabFits(page: Page, label: string): Promise<void> {
  const plain = await measureBrowserTab(page);
  const wider = await measureBrowserTabWider(page);
  test.info().annotations.push({ type: label, description: `${describeFit(plain)} | ${WIDER_EM}em wider: ${describeFit(wider)}` });
  expect(plain.over, `${label}: the tab runs ${plain.over}px past the region (${describeFit(plain)})`).toBeLessThanOrEqual(0);
  expect(plain.fade, `${label}: the fade shows`).toBe(false);
  expect(
    wider.over,
    `${label}: with every glyph ${WIDER_EM}em wider, the tab runs ${wider.over}px past the region (${describeFit(wider)})`,
  ).toBeLessThanOrEqual(0);
  expect(wider.fade, `${label}: with every glyph ${WIDER_EM}em wider, the fade shows`).toBe(false);
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
