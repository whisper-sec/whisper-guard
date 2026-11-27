// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: the look-alike bar (board 4a). The bar is drawn inside Guard's closed
// shadow root, so every reading goes through the DevTools protocol helpers.
// Covers the wording with and without a brand, the graph line, the drawn
// values, contrast, keyboard use with a visible focus ring, dismissal (this
// host, this tab) and a narrow window.

import { readFileSync } from "node:fs";
import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { BAR_FN, ClosedShadow, DISMISS_CENTRE_FN, type BarSnapshot } from "./helpers/closed-shadow";
import { launchExtension, makeShieldDist, setKey, setSettings, visit, waitForIcon, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const OVERLAY = "div[style*='2147483647']";
function fontDataUri(file: string): string {
  return `data:font/woff2;base64,${readFileSync(new URL(`../assets/fonts/${file}`, import.meta.url)).toString("base64")}`;
}
// A page that declares its own faces under the names the bar might ask for.
const HOSTILE_FONTS = `<style>
    @font-face { font-family: Lato; font-weight: 100 900; src: url(${fontDataUri("lato-latin-900-normal.woff2")}) format("woff2"); }
    @font-face { font-family: "JetBrains Mono"; font-weight: 100 900; src: url(${fontDataUri("jetbrains-mono-latin-400-normal.woff2")}) format("woff2"); }
    @font-face { font-family: Arial; src: url(${fontDataUri("lato-latin-900-normal.woff2")}) format("woff2"); }
  </style>`;
const PAGE = (host: string, head = ""): string =>
  `<!doctype html><html><head><title>${host}</title>${head}</head><body><h1>${host}</h1>
<form><input id="pw" type="password" name="pw"></form></body></html>`;

// A look-alike with no graph verdict, one the graph rates, and a flagged host
// that imitates no brand. Each test that dismisses uses its own host.
const PLAIN = "paypa1-bar-plain-e2e.com";
const RATED = "paypa1-bar-rated-e2e.com";
const NO_BRAND = "bar-no-brand-e2e.com";
const NARROW = "paypa1-bar-narrow-e2e.com";
const FONTS = "paypa1-bar-fonts-e2e.com";
const KEY_ENTER = "paypa1-bar-enter-e2e.com";
const KEY_SPACE = "paypa1-bar-space-e2e.com";
const CLICK = "paypa1-bar-click-e2e.com";
// A look-alike of the longest brand domain in the detector corpus.
const LONG = "canadapost-bar-long-e2e.com";
const LONG_BRAND = "canadapost-postescanada.ca";
const BRAND_DOMAIN = "paypal.com";
const TAIL = " Be careful with passwords and payment details.";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const h of [PLAIN, RATED, NO_BRAND, NARROW, KEY_ENTER, KEY_SPACE, CLICK, LONG]) net.setPage(h, PAGE(h));
  net.setPage(FONTS, PAGE(FONTS, HOSTILE_FONTS));
  net.setVerdict(RATED, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setVerdict(NO_BRAND, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, MOCK_KEY);
  await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function openBar(host: string): Promise<{ page: Page; shadow: ClosedShadow; snap: BarSnapshot }> {
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  return readBar(page);
}

async function readBar(page: Page): Promise<{ page: Page; shadow: ClosedShadow; snap: BarSnapshot }> {
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 15_000 }).toBeGreaterThan(0);
  const shadow = await ClosedShadow.open(ext.context, page);
  let snap: BarSnapshot | null = null;
  await expect.poll(async () => (snap = await shadow.call<BarSnapshot>(BAR_FN)) !== null, { timeout: 10_000 }).toBe(true);
  return { page, shadow, snap: snap! };
}

const read = async (shadow: ClosedShadow): Promise<BarSnapshot> => (await shadow.call<BarSnapshot>(BAR_FN))!;

function channels(css: string): [number, number, number] {
  const m = /^rgba?\((\d+), (\d+), (\d+)(?:, ([\d.]+))?\)$/.exec(css);
  if (!m) throw new Error(`not an opaque colour: ${css}`);
  if (m[4] !== undefined && Number(m[4]) !== 1) throw new Error(`translucent colour: ${css}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}
function luminance(css: string): number {
  const [r, g, b] = channels(css).map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** Press Tab (a trusted key) until the closed root's focus lands on `id`. */
async function tabTo(page: Page, shadow: ClosedShadow, id: string): Promise<void> {
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press("Tab");
    if ((await read(shadow)).focusedId === id) return;
  }
  throw new Error(`Tab never reached ${id}`);
}

test("look-alike with no graph verdict: tag LOOK-ALIKE, brand in a strong, exact sentence, link and Dismiss button", async () => {
  const { page, shadow, snap } = await openBar(PLAIN);
  expect(snap.role).toBe("alert");
  expect(snap.tag!.text).toBe("LOOK-ALIKE");
  expect(snap.sentence!.text).toBe(`This site looks like ${BRAND_DOMAIN} but is not it.${TAIL}`);
  expect(snap.sentence!.strongTag).toBe("strong");
  expect(snap.sentence!.strongText).toBe(BRAND_DOMAIN);
  expect(snap.go!.text).toBe(`Go to the real ${BRAND_DOMAIN}`);
  expect(snap.go!.href).toBe(`https://${BRAND_DOMAIN}/`);
  expect(snap.go!.tag).toBe("a");
  expect(snap.dismiss!.text).toBe("Dismiss");
  expect(snap.dismiss!.tag).toBe("button");
  expect(snap.mark!.alt).toBe("Whisper Guard");
  const cdp = await ext.context.newCDPSession(page);
  const tree = JSON.stringify(await cdp.send("Accessibility.getFullAXTree"));
  await cdp.detach();
  expect(tree).toContain('"alert"');
  for (const piece of ["This site looks like", BRAND_DOMAIN, "but is not it."]) expect(tree).toContain(piece);
  await shadow.close();
  await page.close();
});

test("look-alike the graph rates MEDIUM: the graph line with its label sits between the two sentences", async () => {
  const { page, shadow, snap } = await openBar(RATED);
  expect(snap.tag!.text).toBe("LOOK-ALIKE");
  expect(snap.sentence!.text).toBe(
    `This site looks like ${BRAND_DOMAIN} but is not it. The Whisper graph rates it MEDIUM (suspicious).${TAIL}`,
  );
  expect(snap.sentence!.strongText).toBe(BRAND_DOMAIN);
  await shadow.close();
  await page.close();
});

test("flagged host that imitates no brand: tag SUSPICIOUS, flagged sentence with the graph line, no real-site link", async () => {
  const { page, shadow, snap } = await openBar(NO_BRAND);
  expect(snap.tag!.text).toBe("SUSPICIOUS");
  expect(snap.sentence!.text).toBe(
    `This site is flagged as suspicious. The Whisper graph rates it MEDIUM (suspicious).${TAIL}`,
  );
  expect(snap.sentence!.strongText).toBeNull();
  expect(snap.go).toBeNull();
  expect(snap.dismiss!.text).toBe("Dismiss");
  await shadow.close();
  await page.close();
});

test("bar is drawn with the board values: ground, 2 px amber edge, amber tag and link, 22 px mark, pill tag, 6 px link and Dismiss radius", async () => {
  const { page, shadow, snap } = await openBar(PLAIN);
  expect(snap.bar.position).toBe("fixed");
  expect(snap.bar.backgroundColor).toBe("rgb(26, 18, 6)");
  expect(snap.bar.borderBottomWidth).toBe("2px");
  expect(snap.bar.borderBottomColor).toBe("rgb(245, 158, 11)");
  expect(snap.bar.rect.t).toBe(0);
  expect(snap.mark!.w).toBe(22);
  expect(snap.mark!.h).toBe(22);
  expect(snap.tag!.backgroundColor).toBe("rgb(245, 158, 11)");
  expect(snap.tag!.color).toBe("rgb(28, 25, 23)");
  expect(snap.tag!.fontWeight).toBe("700");
  expect(snap.tag!.fontSize).toBe("11px");
  expect(parseFloat(snap.tag!.borderRadius)).toBeGreaterThanOrEqual(snap.tag!.rect.h / 2);
  expect(snap.sentence!.fontSize).toBe("14.5px");
  expect(snap.go!.backgroundColor).toBe("rgb(245, 158, 11)");
  expect(snap.go!.color).toBe("rgb(28, 25, 23)");
  expect(snap.go!.fontWeight).toBe("700");
  expect(snap.go!.borderRadius).toBe("6px");
  expect(snap.go!.textDecorationLine).toBe("none");
  expect(snap.dismiss!.color).toBe("rgb(253, 230, 138)");
  expect(snap.dismiss!.backgroundColor).toBe("rgba(0, 0, 0, 0)");
  expect(snap.dismiss!.borderRadius).toBe("6px");
  expect(snap.dismiss!.fontWeight).toBe("700");
  expect(snap.dismiss!.borderColor).toBe("rgb(146, 95, 9)");
  expect(snap.dismiss!.minHeight).toBe("40px");
  await shadow.close();
  await page.close();
});

test("bar text is drawn in generic faces only: no page-supplied web font reaches the sentence, tag, link or Dismiss", async () => {
  const { page, shadow, snap } = await openBar(FONTS);
  for (const id of ["w-bar-text", "w-bar-tag", "w-bar-go", "w-bar-dismiss"]) {
    const fonts = await shadow.platformFonts(id);
    expect(fonts, `${id} has drawn text`).not.toBeNull();
    for (const f of fonts!) expect(f.isCustomFont, `${f.familyName} must not be a page-supplied font`).toBe(false);
  }
  for (const el of [snap.sentence, snap.tag, snap.go, snap.dismiss]) {
    expect(el!.fontFamily).not.toMatch(/["']|lato|jetbrains|arial|helvetica|menlo|consolas|sfmono/i);
  }
  await shadow.close();
  await page.close();
});

test("contrast is at least 4.5:1 for the sentence, tag, link text, Dismiss text and the focus ring", async () => {
  const { page, shadow, snap } = await openBar(PLAIN);
  const ground = snap.bar.backgroundColor;
  expect(contrast(snap.sentence!.color, ground)).toBeGreaterThanOrEqual(4.5);
  expect(contrast(snap.tag!.color, snap.tag!.backgroundColor)).toBeGreaterThanOrEqual(4.5);
  expect(contrast(snap.go!.color, snap.go!.backgroundColor)).toBeGreaterThanOrEqual(4.5);
  expect(contrast(snap.dismiss!.color, ground)).toBeGreaterThanOrEqual(4.5);
  await tabTo(page, shadow, "w-bar-dismiss");
  const focused = await read(shadow);
  expect(contrast(focused.dismiss!.outlineColor, ground)).toBeGreaterThanOrEqual(4.5);
  await shadow.close();
  await page.close();
});

test("keyboard: Tab reaches the link and then Dismiss, each with a 2 px solid focus ring", async () => {
  const { page, shadow } = await openBar(PLAIN);
  await tabTo(page, shadow, "w-bar-go");
  let s = await read(shadow);
  expect(s.go!.outlineWidth).toBe("2px");
  expect(s.go!.outlineStyle).toBe("solid");
  expect(s.dismiss!.outlineStyle).toBe("none");
  await page.keyboard.press("Tab");
  s = await read(shadow);
  expect(s.focusedId).toBe("w-bar-dismiss");
  expect(s.dismiss!.outlineWidth).toBe("2px");
  expect(s.dismiss!.outlineStyle).toBe("solid");
  expect(s.dismiss!.outlineColor).toBe("rgb(180, 156, 245)");
  expect(s.go!.outlineStyle).toBe("none");
  await shadow.close();
  await page.close();
});

test("keyboard: Enter on Dismiss removes the bar and Guard's host element", async () => {
  const { page, shadow } = await openBar(KEY_ENTER);
  await tabTo(page, shadow, "w-bar-dismiss");
  await page.keyboard.press("Enter");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBe(0);
  expect(await page.evaluate(() => sessionStorage.getItem("whisper-guard-dismissed"))).toBe(KEY_ENTER);
  await shadow.close();
  await page.close();
});

test("keyboard: Space on Dismiss removes the bar and Guard's host element", async () => {
  const { page, shadow } = await openBar(KEY_SPACE);
  await tabTo(page, shadow, "w-bar-dismiss");
  await page.keyboard.press("Space");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBe(0);
  await shadow.close();
  await page.close();
});

test("a script-made click on Dismiss does nothing; a real click removes the bar, sticks on reload in this tab, and a new tab shows the bar again", async () => {
  const { page, shadow } = await openBar(CLICK);

  // The page cannot dismiss the bar for the reader: only a trusted event does.
  await shadow.call<void>(`function () { this.getElementById("w-bar-dismiss").click(); }`);
  expect((await read(shadow)).dismiss).not.toBeNull();
  expect(await page.locator(OVERLAY).count()).toBeGreaterThan(0);

  const at = (await shadow.call<{ x: number; y: number }>(DISMISS_CENTRE_FN))!;
  await page.mouse.click(at.x, at.y);
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBe(0);
  expect(await page.evaluate(() => sessionStorage.getItem("whisper-guard-dismissed"))).toBe(CLICK);
  await shadow.close();

  // Same tab, after a reload: no bar. The password caution still speaks,
  // which also proves Guard was injected again and chose not to draw the bar.
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect
    .poll(
      async () => {
        await page.locator("#pw").evaluate((e) => {
          (e as HTMLInputElement).blur();
          (e as HTMLInputElement).focus();
        });
        return page.locator(OVERLAY).count();
      },
      { timeout: 20_000 },
    )
    .toBeGreaterThan(0);
  const after = await ClosedShadow.open(ext.context, page);
  expect(await after.call<BarSnapshot>(BAR_FN)).toBeNull();
  await after.close();

  // A new tab on the same host: sessionStorage is per tab, so the bar shows.
  const second = await openBar(CLICK);
  expect(second.snap.dismiss!.text).toBe("Dismiss");
  await second.shadow.close();
  await second.page.close();
  await page.close();
});

test("at a 375 px wide window the bar stays inside the window and both controls are fully visible", async () => {
  const { page, shadow } = await openBar(NARROW);
  await page.setViewportSize({ width: 375, height: 700 });
  await expect.poll(async () => (await read(shadow)).vw, { timeout: 10_000 }).toBeLessThanOrEqual(375);
  const s = await read(shadow);
  expect(s.bar.rect.l).toBeGreaterThanOrEqual(0);
  expect(s.bar.rect.r).toBeLessThanOrEqual(s.vw);
  expect(s.bar.scrollWidth).toBeLessThanOrEqual(s.bar.clientWidth);
  for (const c of [s.go!, s.dismiss!]) {
    expect(c.rect.l).toBeGreaterThanOrEqual(0);
    expect(c.rect.r).toBeLessThanOrEqual(s.vw);
    expect(c.rect.b).toBeLessThanOrEqual(s.bar.rect.b);
    expect(c.rect.w).toBeGreaterThan(40);
  }
  expect(s.sentence!.rect.r).toBeLessThanOrEqual(s.vw);
  await shadow.close();
  await page.close();
});

test("at a 375 px wide window a look-alike of the longest corpus brand keeps the link and Dismiss fully inside the window and the bar", async () => {
  const { page, shadow } = await openBar(LONG);
  await page.setViewportSize({ width: 375, height: 700 });
  await expect.poll(async () => (await read(shadow)).vw, { timeout: 10_000 }).toBeLessThanOrEqual(375);
  const s = await read(shadow);
  expect(s.go!.text).toBe(`Go to the real ${LONG_BRAND}`);
  expect(s.bar.scrollWidth).toBeLessThanOrEqual(s.bar.clientWidth);
  for (const c of [s.go!, s.dismiss!]) {
    expect(c.rect.l).toBeGreaterThanOrEqual(s.bar.rect.l);
    expect(c.rect.r).toBeLessThanOrEqual(Math.min(s.vw, s.bar.rect.r));
    expect(c.rect.b).toBeLessThanOrEqual(s.bar.rect.b);
  }
  await shadow.close();
  await page.close();
});
