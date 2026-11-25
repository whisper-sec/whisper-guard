// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// What the theme specs share: choosing a theme without going through the
// popup, and reading what a page actually draws.

import { expect, type Page } from "@playwright/test";
import type { Extension } from "./extension";

/** The key the pages keep their first-frame copy of the choice under. */
export const MIRROR_KEY = "guard.theme";

export type Choice = "auto" | "light" | "dark";
export type Scheme = "dark" | "light";

/**
 * Set the choice the way the popup leaves it: in `storage.local` with the
 * other settings, and in the extension origin's copy the pages read first.
 * Pages that are already open follow the storage change.
 */
export async function choose(ext: Extension, choice: Choice | string): Promise<void> {
  await ext.sw.evaluate(async (c: string) => {
    const cur = (await chrome.storage.local.get("settings"))["settings"] ?? {};
    await chrome.storage.local.set({ settings: { ...(cur as object), theme: c } });
  }, choice);
  // A file of the extension is a document of its origin, so it can reach the
  // origin's local storage without loading a page that runs any script.
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/theme.css`);
  await page.evaluate(([k, c]) => localStorage.setItem(k!, c!), [MIRROR_KEY, choice]);
  await page.close();
}

/** The scheme a page has applied to its root. */
export function schemeOf(page: Page): Promise<string | undefined> {
  return page.evaluate(() => document.documentElement.dataset["scheme"]);
}

/** The scheme the stylesheet draws, whatever the attribute says: the page's background token. */
export function backgroundToken(page: Page): Promise<string> {
  return page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--w-bg").trim());
}

/** The page's applied scheme is `scheme`, and a frame has been drawn since. */
export async function expectScheme(page: Page, scheme: Scheme, message?: string): Promise<void> {
  await expect.poll(() => schemeOf(page), { message }).toBe(scheme);
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
}

/**
 * Every custom property of the theme as one page computes it. A palette is the
 * whole set, so two pages that agree on it draw the same colours.
 */
export function palette(page: Page): Promise<Record<string, string>> {
  return page.evaluate(() => {
    const names = new Set<string>();
    for (const sheet of Array.from(document.styleSheets)) {
      for (const rule of Array.from(sheet.cssRules)) {
        if (!(rule instanceof CSSStyleRule)) continue;
        for (const n of Array.from(rule.style)) if (n.startsWith("--w-")) names.add(n);
      }
    }
    const cs = getComputedStyle(document.documentElement);
    const out: Record<string, string> = {};
    for (const n of [...names].sort()) out[n] = cs.getPropertyValue(n).trim();
    return out;
  });
}
