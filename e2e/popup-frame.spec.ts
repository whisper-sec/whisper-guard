// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE POPUP FRAME AND ITS ONE SCROLL.
//
// The popup is a fixed 400 x 600 frame: a header with a line under it, one
// scrolling region and a footer pinned to the bottom edge. The region holds
// three parts one after the other (This site, This page, This browser). Each
// claim is measured against the built extension:
//
//   - the frame holds its size and only the content region scrolls;
//   - the popup opens at the top, and again at the top after Re-check;
//   - no tab role of any kind is left, and each part has a heading;
//   - every block still exists, in the part that holds it, with no id twice;
//   - one footer, the same wherever the reader has scrolled;
//   - "Open in console" for a signed-in reader, whatever the page;
//   - the page part says why it is empty, or is not shown, never echoing the
//     site's own sentence;
//   - the frame holds in the dark and the light scheme;
//   - the header is one row, and Re-check, Theme and Settings fit beside the widest figure;
//   - a soft fade above the footer shows while content runs on below.
//
// The popup is opened here as a page of the extension, not as a toolbar
// window, so the sizes are those of its own box. That scrolling sends nothing
// is proved at the message layer in firefox-render.spec.ts.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY } from "./helpers/servers";
import {
  launchExtension,
  openGraphDrawers,
  openPopup,
  scrollPopupTo,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";
import { settledLayout, WIDER_EM, withWiderGlyphs } from "./helpers/popup-fit";
import { CONSOLE_URL, GRAPH_HOST } from "../src/shared/config";
import { compact3 } from "../src/shared/spark";

let net: E2ENetwork;
let ext: Extension;

const HOST = "frame-full-guard-e2e.com";
const SLOW = "frame-slow-guard-e2e.com";
// A site with a threat factor, so "Why this verdict" has something to show.
const FLAGGED = "frame-flagged-guard-e2e.com";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(HOST, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setEnrich(HOST, {
    ip: "198.51.100.40",
    city: "London, GB",
    country: "GB",
    asn: "AS64540",
    owner: "MediaCo plc",
    asnName: "MEDIACO - MediaCo plc",
    prefix: "198.51.100.0/24",
    threatNeighbors: 0,
    prevalence: 812,
    verdict: "NONE",
  });
  net.setIdentify(HOST, [
    {
      host: HOST,
      canonical_name: "MediaCo",
      category: "media",
      roles: ["DNS_OPERATOR", "ORIGIN_AS"],
      confidence: 0.85,
      host_class: "single_tenant",
      evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco"],
    },
  ]);
  net.setPresence("AS64540", {
    facilities: ["Example Carrier Hotel LON1", "Example Colo LON2"],
    exchanges: ["Example Exchange LON"],
    facilityCount: 14,
    exchangeCount: 4,
  });
  net.setVerdict(SLOW, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict(FLAGGED, { band: "MEDIUM", coverage: "malicious-evidenced", label: "suspicious" });
  net.setExplain(FLAGGED, [{ score: 16.9, sources: [{ feedId: "e2e-feed" }] }]);
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.graphMode = "mock";
  net.graphDelayMs = 0;
  net.clearLog();
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

// -------------------------------------------------------------- the helpers

const LIVE_RUNG = "#chain-mount .ch-rung.ch-live";

/** A popup on a clean host with the chain drawn, at the top. */
async function openSite(opts: { colorScheme?: "dark" | "light" } = {}): Promise<{ popup: Page; page: Page; tabId: number }> {
  const { page, tabId } = await visit(ext, `https://${HOST}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  const popup = await openPopup(ext, tabId);
  if (opts.colorScheme) await popup.emulateMedia({ colorScheme: opts.colorScheme });
  await popup.locator(LIVE_RUNG).first().waitFor({ timeout: 20_000 });
  return { popup, page, tabId };
}

/** A popup for a page it cannot check: one of the extension's own pages. */
async function openUncheckable(): Promise<{ popup: Page; page: Page }> {
  // The extension has no tabs permission, so the tab is found by creation.
  const { page, tabId } = await visit(ext, `chrome-extension://${ext.id}/options.html`);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#ineligible")).toBeVisible();
  return { popup, page };
}

interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
  bottom: number;
}

async function box(popup: Page, selector: string): Promise<Box> {
  return popup.locator(selector).evaluate((e) => {
    const r = e.getBoundingClientRect();
    return { x: r.x, y: r.y, width: r.width, height: r.height, bottom: r.bottom };
  });
}

async function frame(popup: Page): Promise<{ body: Box; header: Box; footer: Box; region: Box }> {
  return {
    body: await box(popup, "body"),
    header: await box(popup, ".pp-header"),
    footer: await box(popup, ".pp-footer"),
    region: await box(popup, "#popup-scroll"),
  };
}

/** Scroll the region to `y` (or its end), wait two frames, return where it stopped. */
async function scrollRegion(popup: Page, y: number | "end"): Promise<number> {
  return popup.locator("#popup-scroll").evaluate(async (r, to) => {
    r.scrollTop = to === "end" ? r.scrollHeight : to;
    await new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done())));
    return r.scrollTop;
  }, y);
}

const scrollTopOf = (popup: Page): Promise<number> => popup.locator("#popup-scroll").evaluate((r) => r.scrollTop);

/** How often a sentence is on the popup as text a reader can see. */
async function timesShown(popup: Page, sentence: string): Promise<number> {
  const body = await popup.locator("body").innerText();
  return body.split(sentence).length - 1;
}

// ------------------------------------------------------------------------ T1

test("the popup is a fixed 400 x 600 frame and only the content region scrolls", async () => {
  const { popup, page } = await openUncheckable();

  for (const size of [null, { width: 400, height: 600 }]) {
    if (size) await popup.setViewportSize(size);
    const f = await frame(popup);
    expect([f.body.width, f.body.height]).toEqual([400, 600]);
    expect(f.header.height).toBe(52);
    expect(f.header.y).toBe(0);
    expect(f.region.y, "the region starts right under the header").toBe(f.header.bottom);
    expect(f.footer.bottom).toBe(600);
  }

  // The line under the header is the header's own bottom border, inside its 52 px.
  const line = await popup.locator(".pp-header").evaluate((h) => {
    const cs = getComputedStyle(h);
    return { width: cs.borderBottomWidth, style: cs.borderBottomStyle, color: cs.borderBottomColor };
  });
  expect(line.width).toBe("1px");
  expect(line.style).toBe("solid");
  expect(line.color).toBe(await token(popup, "--w-line", "backgroundColor"));

  // Make it overflow, by a device of the test: one tall element.
  await popup.locator("#panel-site").evaluate((p) => {
    const tall = document.createElement("div");
    tall.style.height = "1000px";
    tall.id = "test-tall";
    p.appendChild(tall);
  });
  const before = await frame(popup);
  const overflow = await popup.locator("#popup-scroll").evaluate((r) => ({
    scrollable: r.scrollHeight > r.clientHeight,
    overflowY: getComputedStyle(r).overflowY,
  }));
  expect(overflow.scrollable, "control: the region really overflows").toBe(true);
  expect(overflow.overflowY).toBe("auto");

  // A real wheel over the region scrolls it (a copy of an `overflow: hidden`
  // frame would not, though a click would still scroll its target into view).
  await popup.mouse.move(200, 300);
  await popup.mouse.wheel(0, 300);
  await expect.poll(() => scrollTopOf(popup)).toBeGreaterThan(0);

  const after = await frame(popup);
  for (const part of ["header", "footer"] as const) expect(after[part]).toEqual(before[part]);
  expect(await popup.evaluate(() => window.scrollY)).toBe(0);
  expect(await popup.evaluate(() => document.scrollingElement!.scrollTop)).toBe(0);

  await popup.close();
  await page.close();
});

test("the popup opens at the top of the scroll, and again at the top after Re-check", async () => {
  const { popup, page } = await openSite();
  const room = await popup.locator("#popup-scroll").evaluate((r) => r.scrollHeight - r.clientHeight);
  expect(room, "control: there is something to scroll").toBeGreaterThan(200);
  expect(await scrollTopOf(popup), "it opened at the top").toBe(0);

  await scrollPopupTo(popup, "browser");
  expect(await scrollTopOf(popup), "control: the test really scrolled down").toBeGreaterThan(100);

  await Promise.all([popup.waitForEvent("load"), popup.locator("#btn-refresh").click()]);
  await popup.locator(LIVE_RUNG).first().waitFor({ timeout: 20_000 });
  expect(await scrollTopOf(popup), "after Re-check it is at the top again").toBe(0);
  // Content that arrives later does not carry the view away from the top:
  // read again once the graph size and the last 24 hours have been drawn.
  await expect(popup.locator("#scale")).toBeVisible();
  await expect(popup.locator("#fig-destinations")).toBeVisible();
  await settledLayout(popup);
  expect(await scrollTopOf(popup)).toBe(0);

  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T2

test("no tab role of any kind is left, and the three parts are in no tab order of their own", async () => {
  const { popup, page } = await openSite();
  // Every role that starts with "tab": the tab, its list and its panel.
  await expect(popup.locator('[role^="tab"]'), "an element still has a tab role").toHaveCount(0);
  for (const role of ["tab", "tablist"] as const) {
    await expect(popup.getByRole(role, { includeHidden: true }), role).toHaveCount(0);
  }
  // Nothing of the old tab bar, its dot or its keyboard wiring is left in the markup.
  const old = await popup.evaluate(() => [...document.querySelectorAll("[id]")].map((e) => e.id).filter((id) => /^tab-/.test(id)));
  expect(old).toEqual([]);

  // The three parts are in no tab order of their own.
  const stops = await popup.evaluate(() =>
    ["panel-site", "panel-page", "panel-browser"].map((id) => (document.getElementById(id) as HTMLElement).tabIndex),
  );
  expect(stops).toEqual([-1, -1, -1]);
  await popup.close();
  await page.close();
});

// Block id -> the part that holds it (header and footer ids are in none).
const HOMES: Record<string, string | null> = {
  "host-row": "panel-site",
  "checking-view": "panel-site",
  "not-checked-view": "panel-site",
  lookalike: "panel-site",
  "blocked-card": "panel-site",
  "graph-error": "panel-site",
  "site-chips": "panel-site",
  "chain-card": "panel-site",
  "graph-path": "panel-site",
  "neighbours-note": "panel-site",
  "protect-card": "panel-site",
  expanders: "panel-site",
  "exp-why": "panel-site",
  "exp-who": "panel-site",
  "exp-neighborhood": "panel-site",
  "exp-session": "panel-site",
  ineligible: "panel-site",
  "linkscan-card": "panel-page",
  "iocscan-card": "panel-page",
  "page-empty": "panel-page",
  "cookie-line": "panel-page",
  "identity-card": "panel-browser",
  "signin-pitch": "panel-browser",
  "tier-meter": "panel-browser",
  "btn-dashboard": "panel-browser",
  "activity-card": "panel-browser",
  "activity-destinations": "panel-browser",
  "activity-flagged": "panel-browser",
  "today-row": "panel-browser",
  "footer-actions": null,
  "btn-console": null,
  "btn-dossier": null,
  "privacy-line": null,
  scale: null,
  "btn-refresh": null,
  "btn-theme": null,
  "theme-live": null,
  "btn-settings": null,
};

test("three parts follow one another, each with a heading, every block is in its part and no id occurs twice", async () => {
  const { popup, page } = await openSite();

  // The parts are the region's direct children, in this order, with a heading each.
  const parts = await popup.locator("#popup-scroll").evaluate((r) =>
    [...r.children].map((c) => {
      const h = document.getElementById(c.getAttribute("aria-labelledby") ?? "");
      return {
        id: c.id,
        tag: c.tagName.toLowerCase(),
        heading: h?.tagName.toLowerCase() ?? null,
        words: h?.textContent ?? null,
        role: c.getAttribute("role"),
        hidden: c.hasAttribute("hidden"),
        tabindex: c.getAttribute("tabindex"),
      };
    }),
  );
  expect(parts.map((p) => [p.id, p.tag, p.heading, p.words])).toEqual([
    ["panel-site", "section", "h2", "This site"],
    ["panel-page", "section", "h2", "This page"],
    ["panel-browser", "section", "h2", "This browser"],
  ]);
  expect(parts.map((p) => p.role)).toEqual([null, null, null]);
  // The site part is the one the popup moves focus to after a press: -1, never in the tab order.
  expect(parts.map((p) => p.tabindex)).toEqual(["-1", null, null]);

  // Each heading is read by a screen reader and takes no room on screen.
  const headings = await popup.locator("#popup-scroll > section > h2").evaluateAll((hs) =>
    hs.map((h) => {
      const r = h.getBoundingClientRect();
      return { w: r.width, h: r.height, shown: getComputedStyle(h).display !== "none" && getComputedStyle(h).visibility !== "hidden" };
    }),
  );
  expect(headings).toHaveLength(3);
  for (const h of headings) {
    expect(h.shown).toBe(true);
    expect(h.w * h.h, "a heading for screen readers takes no room on screen").toBeLessThanOrEqual(1);
  }
  await expect(popup.getByRole("heading", { name: "This site", level: 2 })).toHaveCount(1);
  await expect(popup.getByRole("heading", { name: "This page", level: 2 })).toHaveCount(1);
  await expect(popup.getByRole("heading", { name: "This browser", level: 2 })).toHaveCount(1);

  // The parts sit one under another, 10 px apart, in the region's own padding.
  const stack = await popup.evaluate(() =>
    ["panel-site", "panel-page", "panel-browser"].map((id) => {
      const r = document.getElementById(id)!.getBoundingClientRect();
      return { top: r.top, bottom: r.bottom };
    }),
  );
  expect(stack[0]!.bottom, "This site ends before This page starts").toBeLessThanOrEqual(stack[1]!.top);
  expect(stack[1]!.top - stack[0]!.bottom).toBe(10);
  expect(stack[2]!.top - stack[1]!.bottom).toBe(10);

  const homes = await popup.evaluate((ids) => {
    const out: Record<string, string | null> = {};
    for (const id of ids) {
      const node = document.getElementById(id);
      out[id] = node ? (node.closest("#popup-scroll > section")?.id ?? null) : "MISSING";
    }
    return out;
  }, Object.keys(HOMES));
  expect(homes).toEqual(HOMES);

  const twice = await popup.evaluate(() => {
    const seen = new Map<string, number>();
    for (const e of document.querySelectorAll("[id]")) seen.set(e.id, (seen.get(e.id) ?? 0) + 1);
    return [...seen].filter(([, n]) => n > 1).map(([id]) => id);
  });
  expect(twice).toEqual([]);

  // "Why this verdict" shows only for a threat factor or a score above zero,
  // so it is asserted on a flagged site below, not on this clean one.
  for (const id of ["host-row", "chain-card", "expanders", "linkscan-card", "iocscan-card", "signin-pitch", "btn-dashboard"]) {
    await expect(popup.locator(`#${id}`), `#${id} is drawn`).toBeVisible();
  }
  await popup.close();
  await page.close();

  const flagged = await visit(ext, `https://${FLAGGED}/`);
  await waitForIcon(ext, flagged.tabId, ["suspicious"]);
  const popupB = await openPopup(ext, flagged.tabId);
  await expect(popupB.locator("#protect-card"), "#protect-card on This site").toBeVisible();
  await popupB.close();
  await flagged.page.close();
});

test("the three parts are on the popup in the order this site, this page, this browser, signed in too", async () => {
  await setKey(ext, MOCK_API_KEY);
  const { popup, page } = await openSite();
  await expect(popup.locator("#identity-card")).toBeVisible({ timeout: 15_000 });
  await expect(popup.locator("#signin-pitch")).toBeHidden();
  await expect(popup.locator("#btn-dashboard")).toBeVisible();
  const tops = await popup.evaluate(() =>
    ["host-row", "linkscan-card", "iocscan-card", "identity-card", "activity-card"].map((id) => ({
      id,
      top: document.getElementById(id)!.getBoundingClientRect().top + (document.getElementById("popup-scroll") as HTMLElement).scrollTop,
    })),
  );
  const sorted = [...tops].sort((a, b) => a.top - b.top).map((t) => t.id);
  expect(sorted).toEqual(["host-row", "linkscan-card", "iocscan-card", "identity-card", "activity-card"]);
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T3

interface FooterNow {
  box: Box;
  text: string;
  shown: string[];
}

async function footerNow(popup: Page): Promise<FooterNow> {
  return popup.locator(".pp-footer").evaluate((f) => {
    const r = f.getBoundingClientRect();
    const visible = (e: Element): boolean => {
      const b = e.getBoundingClientRect();
      return b.width > 0 && b.height > 0 && getComputedStyle(e).visibility !== "hidden";
    };
    return {
      box: { x: r.x, y: r.y, width: r.width, height: r.height, bottom: r.bottom },
      text: (f as HTMLElement).innerText.replace(/\s+/g, " ").trim(),
      shown: [...f.querySelectorAll("[id]")].filter(visible).map((e) => e.id),
    };
  });
}

for (const signedIn of [false, true]) {
  test(`the footer is the same at the top, the middle and the end of the scroll (${signedIn ? "signed in" : "signed out"})`, async () => {
    await setKey(ext, signedIn ? MOCK_API_KEY : null);
    const { popup, page } = await openSite();
    await expect(popup.locator("#privacy-line")).toBeVisible();
    const end = await popup.locator("#popup-scroll").evaluate((r) => r.scrollHeight - r.clientHeight);
    expect(end, "control: there is a middle to stop at").toBeGreaterThan(200);

    const at: FooterNow[] = [];
    for (const y of [0, Math.round(end / 2), "end"] as const) {
      await scrollRegion(popup, y);
      at.push(await footerNow(popup));
    }
    expect(at[0]!.box.bottom).toBe(600);
    expect(at[1], "the footer in the middle of the scroll").toEqual(at[0]);
    expect(at[2], "the footer at the end of the scroll").toEqual(at[0]);

    // What it holds: the sent-line always; the two buttons only signed in.
    expect(at[0]!.shown).toContain("privacy-line");
    expect(at[0]!.shown.includes("btn-console")).toBe(signedIn);
    expect(at[0]!.shown.includes("btn-dossier")).toBe(signedIn);
    // The sent-line names the hostname that was sent and where it went.
    const line = (await popup.locator("#privacy-line").textContent()) ?? "";
    expect(line).toContain(`“${HOST}”`);
    expect(line).toContain(GRAPH_HOST);
    expect(line).toContain("path");
    // Nothing of the old per-part footers is left.
    const gone = await popup.evaluate(() =>
      [...document.querySelectorAll("[id]")].map((e) => e.id).filter((id) => /^(footer-(page|browser)|shield-|browser-console)/.test(id)),
    );
    expect(gone, "an id of a per-part footer is still in the markup").toEqual([]);
    expect(at[0]!.text).not.toContain("Active Shield");
    expect(at[0]!.text).not.toContain("Open console");
    // The buttons keep their 32 px.
    if (signedIn) {
      for (const id of ["btn-console", "btn-dossier"]) expect((await box(popup, `#${id}`)).height, id).toBe(32);
    }
    await popup.close();
    await page.close();
  });
}

test("Open in console is there for a signed-in reader on a checked page and on a page that cannot be checked, never signed out", async () => {
  // Signed in, checked page: both buttons, and the console button opens the console.
  await setKey(ext, MOCK_API_KEY);
  const checked = await openSite();
  await expect(checked.popup.locator("#btn-console")).toBeVisible({ timeout: 15_000 });
  await expect(checked.popup.locator("#btn-console")).toHaveText("Open in console");
  await expect(checked.popup.locator("#btn-dossier")).toBeVisible();
  const opened = ext.context.waitForEvent("page", { timeout: 20_000 });
  await checked.popup.locator("#btn-console").click();
  const tab = await opened;
  await expect.poll(() => tab.url(), { timeout: 20_000 }).not.toBe("about:blank");
  expect(new URL(tab.url()).origin).toBe(new URL(CONSOLE_URL).origin);
  await tab.close().catch(() => undefined);
  await checked.popup.close();
  await checked.page.close();

  // Signed in, a page Guard cannot check: the console button, no dossier to copy.
  const odd = await openUncheckable();
  await expect(odd.popup.locator("#btn-console")).toBeVisible({ timeout: 15_000 });
  await expect(odd.popup.locator("#btn-dossier")).toBeHidden();
  await expect(odd.popup.locator("#footer-actions")).toBeVisible();
  await odd.popup.close();
  await odd.page.close();

  // Signed out: neither, on either kind of page.
  await setKey(ext, null);
  const out = await openSite();
  await expect(out.popup.locator("#privacy-line")).toBeVisible();
  await expect(out.popup.locator("#btn-console")).toBeHidden();
  await expect(out.popup.locator("#btn-dossier")).toBeHidden();
  await out.popup.close();
  await out.page.close();
  const outOdd = await openUncheckable();
  await expect(outOdd.popup.locator("#btn-console")).toBeHidden();
  await expect(outOdd.popup.locator("#footer-actions")).toBeHidden();
  await outOdd.popup.close();
  await outOdd.page.close();
});

// ------------------------------------------------------------------------ T4

const NEEDS_LIVE_CHECK = "The link check and the indicator scan need the live check. Turn it on in settings.";

test("with the live check off, This page says why in one sentence and shows no card", async () => {
  await setSettings(ext, { cloudCheck: false });
  const { page, tabId } = await visit(ext, `https://${SLOW}/`);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#panel-page")).toBeVisible();
  await expect(popup.locator("#page-empty")).toHaveText(NEEDS_LIVE_CHECK);
  await expect(popup.locator("#linkscan-card")).toBeHidden();
  await expect(popup.locator("#iocscan-card")).toBeHidden();
  expect(await timesShown(popup, NEEDS_LIVE_CHECK)).toBe(1);
  // The footer still says what was sent (nothing), at the foot of every position.
  await expect(popup.locator("#privacy-line")).toBeVisible();
  await expect(popup.locator("#btn-console")).toBeHidden();
  await popup.close();
  await page.close();
});

test("on a page that cannot be checked, the site's message is on the popup once and This page is not shown", async () => {
  const { popup, page } = await openUncheckable();
  const words = ((await popup.locator("#ineligible").textContent()) ?? "").trim();
  expect(words.length).toBeGreaterThan(0);
  await expect(popup.locator("#panel-page")).toBeHidden();
  await expect(popup.locator("#page-empty")).toBeHidden();
  await expect(popup.locator("#linkscan-card")).toBeHidden();
  expect(await timesShown(popup, words), "the site's sentence is repeated").toBe(1);
  await expect(popup.locator("#privacy-line")).toBeVisible();
  await expect(popup.locator("#panel-browser")).toBeVisible();
  await popup.close();
  await page.close();
});

test("with the live check on, This page shows both cards and no sentence of its own", async () => {
  const { popup, page } = await openSite();
  await expect(popup.locator("#panel-page")).toBeVisible();
  await expect(popup.locator("#page-empty")).toBeHidden();
  await expect(popup.locator("#linkscan-card")).toBeVisible();
  await expect(popup.locator("#iocscan-card")).toBeVisible();
  expect(await timesShown(popup, NEEDS_LIVE_CHECK)).toBe(0);
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T5

test("while a check is in flight This page is not shown and the checking sentence is on the popup once, then both cards show", async () => {
  net.assessDelayMs.set(SLOW, 60_000);
  const { page, tabId } = await visit(ext, `https://${SLOW}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#checking-view")).toBeVisible();
  const note = ((await popup.locator("#checking-text").textContent()) ?? "").trim();
  expect(note.length).toBeGreaterThan(0);
  await expect(popup.locator("#panel-page")).toBeHidden();
  await expect(popup.locator("#linkscan-card")).toBeHidden();
  expect(await timesShown(popup, note), "the checking sentence is repeated").toBe(1);

  // The checking view fills the first screen: the browser part waits below it.
  const view = await popup.evaluate(() => {
    const region = document.getElementById("popup-scroll")!.getBoundingClientRect();
    const site = document.getElementById("panel-site")!.getBoundingClientRect();
    const browser = document.getElementById("panel-browser")!.getBoundingClientRect();
    return { siteBottom: site.bottom, browserTop: browser.top, regionBottom: region.bottom };
  });
  expect(view.siteBottom, "the checking view fills the first screen").toBeGreaterThanOrEqual(view.regionBottom - 1);
  expect(view.browserTop, "the browser part waits below the first screen").toBeGreaterThanOrEqual(view.regionBottom);

  await expect(popup.locator("#band-chip")).toHaveText("COULD NOT CHECK", { timeout: 15_000 });
  await expect(popup.locator("#panel-page")).toBeVisible();
  await expect(popup.locator("#linkscan-card")).toBeVisible();
  await expect(popup.locator("#iocscan-card")).toBeVisible();
  await popup.close();
  await page.close();
  net.assessDelayMs.delete(SLOW);
});

// ------------------------------------------------------------------------ T6

async function token(popup: Page, name: string, prop: "color" | "backgroundColor"): Promise<string> {
  return popup.evaluate(
    ([n, p]) => {
      const probe = document.createElement("div");
      probe.style.setProperty(p === "color" ? "color" : "background-color", `var(${n})`);
      document.body.appendChild(probe);
      const v = getComputedStyle(probe)[p as "color"];
      probe.remove();
      return v;
    },
    [name, prop] as const,
  );
}

test("the frame holds in the dark and the light scheme, at every scroll position", async () => {
  const boxes: Record<string, Awaited<ReturnType<typeof frame>>> = {};
  const grounds: Record<string, string> = {};
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite({ colorScheme: scheme });
    await expect(popup.locator(".pp-footer")).toBeVisible();
    const first = await frame(popup);
    for (const where of ["top", "page", "end"] as const) {
      if (where === "top") await scrollRegion(popup, 0);
      else if (where === "page") await scrollPopupTo(popup, "page");
      else await scrollRegion(popup, "end");
      const f = await frame(popup);
      boxes[`${scheme}-${where}`] = f;
      expect([f.body.width, f.body.height]).toEqual([400, 600]);
      expect(f.header.height).toBe(52);
      expect(f.header.y).toBe(0);
      expect(f.header, `${where}: the header does not move`).toEqual(first.header);
      expect(f.footer, `${where}: the footer does not move`).toEqual(first.footer);
      expect(f.region, `${where}: the region does not move`).toEqual(first.region);
      expect(f.footer.bottom, `${where}: the footer is pinned to the frame`).toBe(600);
    }

    await scrollRegion(popup, 0);
    const ink = await popup.evaluate(() => {
      const c = (s: string, p: "backgroundColor" | "borderBottomColor" | "borderTopColor"): string =>
        getComputedStyle(document.querySelector(s) as Element)[p];
      return {
        body: c("body", "backgroundColor"),
        header: c(".pp-header", "backgroundColor"),
        headerLine: c(".pp-header", "borderBottomColor"),
        footer: c(".pp-footer", "backgroundColor"),
        footerLine: c(".pp-footer", "borderTopColor"),
      };
    });
    expect(ink.body).toBe(await token(popup, "--w-bg", "backgroundColor"));
    expect(ink.header).toBe(await token(popup, "--w-surface", "backgroundColor"));
    expect(ink.headerLine).toBe(await token(popup, "--w-line", "backgroundColor"));
    expect(ink.footer).toBe(await token(popup, "--w-surface", "backgroundColor"));
    expect(ink.footerLine).toBe(await token(popup, "--w-line", "backgroundColor"));
    grounds[scheme] = ink.body;
    await popup.close();
    await page.close();
  }
  expect(grounds.dark).not.toBe(grounds.light);
  for (const where of ["top", "page", "end"]) {
    expect(boxes[`dark-${where}`], `${where}: the same boxes in both schemes`).toEqual(boxes[`light-${where}`]);
  }
});

// ------------------------------------------------------------------------ T7

test("one header at every scroll position: its parts sit on one row and Re-check and Settings work", async () => {
  const { popup, page } = await openSite();
  await expect(popup.locator("#scale")).toBeVisible({ timeout: 15_000 });
  await expect(popup.locator("#scale-nodes")).toHaveText(/^\d/);

  const read = (): Promise<{ box: Box; text: string; fits: boolean; row: boolean }> =>
    popup.locator(".pp-header").evaluate((h) => {
      const hb = h.getBoundingClientRect();
      const kids = [...h.children].filter((k) => getComputedStyle(k).display !== "none" && k.getBoundingClientRect().width > 0);
      const mids = kids.map((k) => {
        const r = k.getBoundingClientRect();
        return r.top + r.height / 2;
      });
      return {
        box: { x: hb.x, y: hb.y, width: hb.width, height: hb.height, bottom: hb.bottom },
        // The figure counts up as it arrives; the rest of the text is stable.
        text: (h as HTMLElement).innerText.replace(/[\d.]+[KMBT]?\s*\n?nodes/, "# nodes"),
        fits: h.scrollWidth <= h.clientWidth,
        row:
          kids.every((k) => {
            const r = k.getBoundingClientRect();
            return r.left >= hb.left - 0.5 && r.right <= hb.right + 0.5 && r.top >= hb.top && r.bottom <= hb.bottom;
          }) && Math.max(...mids) - Math.min(...mids) <= 2,
      };
    });
  // The graph size is a dot and a figure: no line graph, and the dot is a
  // 6 px circle centred on the figure's line.
  await expect(popup.locator("#scale svg"), "a line graph is still drawn in the header").toHaveCount(0);
  await expect(popup.locator("#scale-pulse"), "the old pulse element is still in the header").toHaveCount(0);
  await expect(popup.locator("#scale .scale-dot")).toBeVisible();
  const dot = await popup.evaluate(() => {
    const d = document.querySelector("#scale .scale-dot")!.getBoundingClientRect();
    const f = document.querySelector("#scale .scale-figures")!.getBoundingClientRect();
    return { w: d.width, h: d.height, off: Math.abs(d.top + d.height / 2 - (f.top + f.height / 2)) };
  });
  expect([dot.w, dot.h], "the dot is not 6 x 6").toEqual([6, 6]);
  expect(dot.off, "the dot is not centred on the figure").toBeLessThanOrEqual(1);

  const site = await read();
  expect(site.fits, "the header overflows sideways").toBe(true);
  expect(site.row, "the header's parts are not on one row inside its box").toBe(true);
  expect(site.box.height).toBe(52);
  for (const part of ["page", "browser"] as const) {
    await scrollPopupTo(popup, part);
    expect(await read()).toEqual(site);
  }

  // Settings opens the options page.
  await popup.evaluate(() => {
    (window as unknown as { __opened: number }).__opened = 0;
    chrome.runtime.openOptionsPage = (): Promise<void> => {
      (window as unknown as { __opened: number }).__opened++;
      return Promise.resolve();
    };
  });
  await popup.locator("#btn-settings").click();
  expect(await popup.evaluate(() => (window as unknown as { __opened: number }).__opened)).toBe(1);

  await popup.close();
  await page.close();
});

/** What the header measures: the room left, and where its buttons sit in its content box. */
interface HeaderFit {
  spacer: number;
  height: number;
  fits: boolean;
  row: boolean;
  text: string;
  buttons: { id: string; width: number; height: number; left: number; right: number }[];
  contentLeft: number;
  contentRight: number;
}

// The popup opened with its graph-size answer replaced, so a test can pick
// the figure, hold the answer, or make the read fail. Everything else goes to
// the worker as usual.
type ScaleStub = { nodes?: number; mode?: "figure" | "held" | "failed" };

async function openSiteWithScale(
  stub: ScaleStub,
  colorScheme: "dark" | "light" = "dark",
): Promise<{ popup: Page; page: Page }> {
  const { page, tabId } = await visit(ext, `https://${HOST}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  const popup = await ext.context.newPage();
  await popup.emulateMedia({ colorScheme });
  await popup.addInitScript((s: ScaleStub) => {
    const w = window as unknown as { __releaseScale: () => void; __scaleAsked: number };
    w.__scaleAsked = 0;
    const orig = chrome.runtime.sendMessage.bind(chrome.runtime) as (m: unknown) => Promise<unknown>;
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    w.__releaseScale = release;
    (chrome.runtime as unknown as { sendMessage: (m: { kind?: string }) => Promise<unknown> }).sendMessage = async (m) => {
      if (m?.kind !== "getScale") return orig(m);
      w.__scaleAsked++;
      if (s.mode === "failed") return { ok: false };
      if (s.mode === "held") await gate;
      const res = (await orig(m)) as { ok: boolean; scale?: { nodes: number } };
      if (s.nodes !== undefined && res.ok && res.scale) res.scale.nodes = s.nodes;
      return res;
    };
  }, stub);
  await popup.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
  await popup.locator(LIVE_RUNG).first().waitFor({ timeout: 20_000 });
  return { popup, page };
}

// The popup has asked for the graph size once: what is shown (or not) after
// this is the answer to that ask, with no fixed wait.
async function scaleAsked(popup: Page): Promise<void> {
  await expect
    .poll(() => popup.evaluate(() => (window as unknown as { __scaleAsked: number }).__scaleAsked))
    .toBe(1);
}

test("the header figure is three significant digits, never more than five characters", () => {
  const cases: [number, string][] = [
    [Number.NaN, "-"],
    [0, "0"],
    [999, "999"],
    [999.4, "999"],
    [999.6, "1.00k"],
    [12_345, "12.3k"],
    [1_234_000, "1.23M"],
    [7_482_240_523, "7.48B"],
    [9_999_000_000, "10.0B"],
    [12_340_000_000, "12.3B"],
    [99_950_000_000, "100B"],
    [123_456_789_012, "123B"],
    [999_600_000_000, "1.00T"],
    [-0.4, "0"],
    [-7_482_240_523, "-7.48B"],
  ];
  for (const [n, text] of cases) expect(compact3(n), `${n}`).toBe(text);
  // Every count below 1000T, at each power of ten and at each place where
  // rounding carries into the next digit or the next letter.
  for (let e = 0; e < 15; e++) {
    for (const m of [1, 1.005, 2.5, 4.4449, 9.9949, 9.995, 9.999, 9.9999]) {
      const n = m * 10 ** e;
      expect(compact3(n).length, `${n} is drawn as "${compact3(n)}"`).toBeLessThanOrEqual(5);
    }
  }
});

for (const scheme of ["dark", "light"] as const) {
  test(`the header draws Re-check, Theme and Settings on one row beside the widest figure, inside its padding, as drawn and with wider glyphs (${scheme})`, async () => {
    const { popup, page } = await openSiteWithScale({ nodes: 12_340_000_000 }, scheme);
    await expect(popup.locator("#scale-nodes")).toHaveText("12.3B", { timeout: 15_000 });
    await settledLayout(popup);
    const read = (): Promise<HeaderFit> =>
      popup.locator(".pp-header").evaluate((h): HeaderFit => {
        const hb = h.getBoundingClientRect();
        const cs = getComputedStyle(h);
        const kids = [...h.children].filter((k) => k.getBoundingClientRect().width > 0);
        const mids = kids.map((k) => k.getBoundingClientRect().top + k.getBoundingClientRect().height / 2);
        const buttons = ["btn-refresh", "btn-theme", "btn-settings"].map((id) => {
          const r = document.getElementById(id)!.getBoundingClientRect();
          return { id, width: r.width, height: r.height, left: r.left, right: r.right };
        });
        return {
          spacer: h.querySelector(".spacer")!.getBoundingClientRect().width,
          height: hb.height,
          fits: h.scrollWidth <= h.clientWidth,
          row: Math.max(...mids) - Math.min(...mids) <= 2,
          text: (h as HTMLElement).innerText.replace(/\s+/g, " "),
          buttons,
          contentLeft: hb.left + parseFloat(cs.paddingLeft) + parseFloat(cs.borderLeftWidth),
          contentRight: hb.right - parseFloat(cs.paddingRight) - parseFloat(cs.borderRightWidth),
        };
      });
    const plain = await read();
    const wider = await withWiderGlyphs(popup, WIDER_EM, read);
    test.info().annotations.push({
      type: "room",
      description: `spacer ${plain.spacer.toFixed(2)} px as drawn, ${wider.spacer.toFixed(2)} px ${WIDER_EM}em wider`,
    });
    // Ten billion and more is drawn in three digits: five characters, as
    // wide as any figure the header draws, since the figure is monospaced.
    expect(plain.text, "the figure read is not the widest one").toContain("12.3B nodes");
    for (const [how, m] of [["as drawn", plain], [`${WIDER_EM}em wider`, wider]] as const) {
      expect(m.buttons.map((b) => b.id), `${how}: the three buttons are drawn, in order`).toEqual(["btn-refresh", "btn-theme", "btn-settings"]);
      for (const b of m.buttons) {
        expect([b.width, b.height], `${how}: ${b.id} is not 30 x 30`).toEqual([30, 30]);
        expect(b.left, `${how}: ${b.id} starts left of the header's content box`).toBeGreaterThanOrEqual(m.contentLeft - 0.01);
        expect(b.right, `${how}: ${b.id} runs into the header's right padding`).toBeLessThanOrEqual(m.contentRight + 0.01);
      }
      expect(m.height, `${how}: the header is not 52 px tall`).toBe(52);
      expect(m.fits, `${how}: the header overflows sideways`).toBe(true);
      expect(m.row, `${how}: the header wrapped onto a second row`).toBe(true);
    }
    await popup.close();
    await page.close();
  });
}

test("the dot shows only once the graph size was read", async () => {
  // Read fails: nothing shows, so neither does the dot.
  {
    const { popup, page } = await openSiteWithScale({ mode: "failed" });
    await scaleAsked(popup);
    await expect(popup.locator("#scale")).toBeHidden();
    await expect(popup.locator("#scale .scale-dot")).toBeHidden();
    await popup.close();
    await page.close();
  }
  // Read not yet answered: still nothing. Once it answers, both show.
  const { popup, page } = await openSiteWithScale({ mode: "held" });
  await scaleAsked(popup);
  await expect(popup.locator("#scale")).toBeHidden();
  await expect(popup.locator("#scale .scale-dot")).toBeHidden();
  await popup.evaluate(() => (window as unknown as { __releaseScale: () => void }).__releaseScale());
  await expect(popup.locator("#scale")).toBeVisible({ timeout: 15_000 });
  await expect(popup.locator("#scale .scale-dot")).toBeVisible();
  await popup.close();
  await page.close();
});

// ----------------------------------------------------------------- the fade

const fadeShown = (popup: Page): Promise<boolean> => popup.locator("#popup-fade").isVisible();

test("a soft fade above the footer shows while the content runs on, is gone at the end, and comes back", async () => {
  const { popup, page } = await openSite();
  await openGraphDrawers(popup);

  // On open, at the top of a popup that runs on below, the fade shows over the region's foot.
  await expect(popup.locator("#popup-fade")).toBeVisible();
  const fade = await popup.locator("#popup-fade").evaluate((f) => {
    const cs = getComputedStyle(f);
    const r = f.getBoundingClientRect();
    const scroller = document.getElementById("popup-scroll") as HTMLElement;
    const region = scroller.getBoundingClientRect();
    const foot = (document.querySelector(".pp-footer") as HTMLElement).getBoundingClientRect();
    return {
      pointer: cs.pointerEvents,
      hidden: f.getAttribute("aria-hidden"),
      text: f.textContent,
      focusable: (f as HTMLElement).tabIndex,
      inside: scroller.contains(f),
      bottomGap: Math.abs(r.bottom - region.bottom),
      aboveFooter: r.bottom <= foot.top + 0.5,
      height: r.height,
      image: cs.backgroundImage,
    };
  });
  expect(fade.pointer).toBe("none");
  expect(fade.hidden).toBe("true");
  expect(fade.text).toBe("");
  expect(fade.focusable).toBe(-1);
  expect(fade.inside, "the fade is outside the scroller, so it stays put while content moves").toBe(false);
  expect(fade.bottomGap).toBeLessThanOrEqual(1);
  expect(fade.aboveFooter).toBe(true);
  expect(fade.height).toBe(56);
  expect(fade.image).toContain("gradient");

  // Scrolled to the end, it is gone, and the last line is fully in view and not covered.
  await scrollRegion(popup, "end");
  await expect(popup.locator("#popup-fade")).toBeHidden();
  // The last visible leaf of the popup's content: the one lowest on the page.
  const last = await popup.locator("#popup-scroll").evaluate((scroller) => {
    const region = scroller.getBoundingClientRect();
    let end: Element | null = null;
    let low = -Infinity;
    for (const e of scroller.querySelectorAll("*")) {
      if (e.children.length > 0) continue;
      // Content of a closed drawer is not drawn; only its summary is.
      const drawer = e.closest("details");
      if (drawer && !drawer.open && !e.closest("summary")) continue;
      const r = e.getBoundingClientRect();
      if (r.width === 0 || r.height === 0 || getComputedStyle(e).visibility === "hidden") continue;
      if (r.bottom >= low) {
        low = r.bottom;
        end = e;
      }
    }
    if (!end) return { found: false, inside: false, hit: false, what: "" };
    const r = end.getBoundingClientRect();
    const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
    return {
      found: true,
      inside: r.bottom <= region.bottom + 0.5 && r.top >= region.top,
      hit: !!hit && (end.contains(hit) || hit.contains(end)),
      what: `${end.tagName.toLowerCase()}${end.id ? `#${end.id}` : ""}`,
    };
  });
  expect(last.found, "control: the popup has a last visible element").toBe(true);
  expect(last.inside, `the last element (${last.what}) is cut off at the end of the scroll`).toBe(true);
  expect(last.hit, `the last element (${last.what}) is covered at the end of the scroll`).toBe(true);

  // Scrolling back up brings it back.
  await scrollRegion(popup, 0);
  await expect(popup.locator("#popup-fade")).toBeVisible();
  await popup.close();
  await page.close();
});

test("content that fits shows no fade, and content made to overflow shows it", async () => {
  const { popup, page } = await openUncheckable();
  await popup.setViewportSize({ width: 400, height: 600 });
  // Made to fit by a device of the test: the other two parts are taken out.
  await popup.evaluate(() => {
    for (const id of ["panel-page", "panel-browser"]) (document.getElementById(id) as HTMLElement).style.display = "none";
  });
  const fits = await popup.locator("#popup-scroll").evaluate((r) => r.scrollHeight - r.clientHeight);
  expect(fits, "control: the content fits the region").toBeLessThanOrEqual(0);
  await expect(popup.locator("#popup-fade")).toBeHidden();

  await popup.locator("#panel-site").evaluate((p) => {
    const tall = document.createElement("div");
    tall.style.height = "1000px";
    tall.id = "test-tall";
    p.appendChild(tall);
  });
  await expect(popup.locator("#popup-fade")).toBeVisible();
  await popup.locator("#test-tall").evaluate((e) => e.remove());
  await expect(popup.locator("#popup-fade")).toBeHidden();
  expect(await fadeShown(popup)).toBe(false);
  await popup.close();
  await page.close();
});

test("the scroller draws a thin scrollbar from tokens and keeps its gutter stable", async () => {
  const { popup, page } = await openUncheckable();
  const bar = await popup.locator("#popup-scroll").evaluate((r) => {
    const cs = getComputedStyle(r);
    return { width: cs.scrollbarWidth, gutter: cs.scrollbarGutter, color: cs.scrollbarColor };
  });
  expect(bar.width).toBe("thin");
  expect(bar.gutter).toContain("stable");
  expect(bar.color).not.toBe("auto");
  await popup.close();
  await page.close();
});
