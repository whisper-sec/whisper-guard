// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// How much of the popup's 600 px the This browser tab uses, measured on any
// page that renders it (the real extension, or the shimmed file in Gecko).

import { expect, type Page } from "@playwright/test";

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
