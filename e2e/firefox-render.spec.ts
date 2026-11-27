// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// CROSS-ENGINE RENDER: the panel and the dashboard drawn by Gecko, and by
// Blink, from the same built files, and compared.
//
// `npm run e2e:firefox` proves the add-on LINTS and INSTALLS. Neither of
// those looks at a pixel. Everything else in this suite runs in Chromium,
// so a layout that only Blink can draw would ship to Firefox with every
// gate green and nobody the wiser - and the panel now leans on `color-mix`,
// custom-property-driven animation, inline SVG and a grid-based spine, all
// of which are places engines actually differ.
//
// Firefox cannot side-load an MV3 extension under Playwright, so this
// mounts the REAL built page with a small `chrome` shim in front of it: the
// same HTML, the same CSS, the same bundled script, answering the same
// messages. What it proves is the rendering, which is the half no other
// gate covers.
//
// The assertions are geometric rather than visual: how many rungs the spine
// laid out, whether the verdict mark actually has height, whether anything
// overflows the 400-pixel panel sideways. Those are the failures that
// happen, and they are the ones a screenshot diff would report as "1200
// pixels changed" without saying why.

import { test, expect, chromium, firefox, type Browser, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scrollPopupTo } from "./helpers/extension";
import { expectFirstScreen, expectRoutedCardLayout, settledLayout, WIDER_EM, withWiderGlyphs } from "./helpers/popup-fit";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(HERE, "../dist/firefox");

/** A hostname whose chain has something on every rung. */
const HOST = "news.mediaco-vendor.com";

/**
 * The shim. It answers exactly the messages the panel sends on open, with
 * fixtures, so the page under test is the real one and only the transport
 * is stubbed. Injected before any page script runs.
 */
const SHIM = `
window.__sent = [];
const CHAIN = {
  host: ${JSON.stringify(HOST)},
  live: 7,
  unavailable: 0,
  evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco"],
  facilities: ["Example Carrier Hotel LON1"],
  exchanges: ["Example Exchange LON"],
  owner: "MediaCo plc", country: "GB", city: "London", asn: "AS64540", asnOk: true,
  ip: "198.51.100.40", vendor: "MediaCo", vendorCategory: "single_tenant",
  identifyCategory: "media", roles: ["DNS_OPERATOR"], ageDays: 900,
  prefix: "198.51.100.0/24", threatNeighbors: 0, at: Date.now(),
  rungs: [
    { kind: "name", label: "NAME", value: ${JSON.stringify(HOST)}, fact: "registered 2 years ago", state: "live", tone: "neutral", detail: [], drillable: false },
    { kind: "vendor", label: "RUNS ON", value: "MediaCo", fact: "media - 85% sure", state: "live", tone: "neutral", detail: ["observed as dns operator"], drillable: false },
    { kind: "address", label: "ADDRESS", value: "198.51.100.40", fact: "London", state: "live", tone: "neutral", detail: ["1 A record"], drillable: true },
    { kind: "prefix", label: "PREFIX", value: "198.51.100.0/24", fact: "no flagged neighbours", state: "live", tone: "neutral", detail: [], drillable: true },
    { kind: "network", label: "NETWORK", value: "AS64540", fact: "top-1k rank 812", state: "live", tone: "neutral", detail: [], drillable: true },
    { kind: "operator", label: "OPERATOR", value: "MediaCo plc", fact: "GB", state: "live", tone: "neutral", detail: [], drillable: false },
    { kind: "presence", label: "PRESENT AT", value: "Example Carrier Hotel LON1", fact: "14 facilities", state: "live", tone: "neutral", detail: ["Example Carrier Hotel LON1"], drillable: false },
  ],
};
const REPLIES = {
  getTabState: { ok: true, tabState: {
    hostname: ${JSON.stringify(HOST)}, registrable: "mediaco-vendor.com", eligible: true,
    signedIn: false, icon: "benign", graphError: null, detector: null, shieldOn: false,
    verdict: { host: ${JSON.stringify(HOST)}, band: "NONE", coverage: "known-clean", label: "clean", at: Date.now() },
  } },
  getSettings: { ok: true, settings: { shield: false, amberBanner: true, fieldGuard: true, nearMiss: false, corpusAutoUpdate: true, allowlist: [], cookieDecline: true, cloudCheck: true }, signedIn: false, corpusVersion: 1, corpusUpdated: "" },
  getChain: { ok: true, chain: CHAIN },
  getScale: { ok: true, scale: { nodes: window.__nodes ?? 7482240523, edges: 39546784832, objects: 47029025355, identities: 649, queries: 5699066, windowHours: 24, p50Us: 30, p99Us: 76083, pulse: Array.from({length: 48}, (_, i) => 18000 + Math.round(6000 * Math.sin(i / 7))), updated: Date.now(), degraded: false } },
  getQuota: { ok: true, quota: { plan: "ANONYMOUS", anonymous: true, hourlyLimit: 100, hourlyRemaining: 94, dailyLimit: 500, dailyRemaining: 466, maxDepth: 2 } },
  takeSigninAsk: { ok: true, ask: null },
  getWins: { ok: true, wins: { date: "2026-09-02", total: 3, counts: { preemptBlock: 1, identityVerified: 1, cookieDecline: 1, lookalikeCaught: 0 } } },
  getBrowserReport: { ok: true, report: { hosts: [], totals: { destinations: 4, companies: 4, countries: 2, networks: 2, lookups: 8, flagged: 1 }, generatedAt: Date.now() } },
  getProtection: { ok: true, protection: {
    host: ${JSON.stringify(HOST)}, band: "NONE", blocking: false, label: "clean", coverage: "known-clean",
    who: "MediaCo plc", category: "media", where: { city: "London", country: "GB", ip: "198.51.100.40" },
    ageDays: 900, why: [], score: 0, whyFactors: [{ name: "tranco", weight: null, kind: "good" }],
    variants: [], partial: false } },
  listBlocked: { ok: true, hosts: [] },
  getSession: { ok: true, session: [] },
};
window.chrome = {
  runtime: {
    id: "shim",
    sendMessage: (msg) => { window.__sent.push(msg.kind); return Promise.resolve(REPLIES[msg.kind] ?? { ok: true }); },
    connect: () => ({ onMessage: { addListener() {} }, postMessage() {}, disconnect() {} }),
    getURL: (p) => p,
  },
  tabs: { query: () => Promise.resolve([{ id: 1 }]), update: () => Promise.resolve(), create: () => Promise.resolve() },
  storage: { local: { get: () => Promise.resolve({}), set: () => Promise.resolve(), remove: () => Promise.resolve() } },
  permissions: { contains: () => Promise.resolve(false), request: () => Promise.resolve(false) },
};
`;

interface Geometry {
  rungs: number;
  liveRungs: number;
  discHeight: number;
  bodyScrollWidth: number;
  bodyClientWidth: number;
  /** Sideways overflow of the one scrolling content region. */
  regionOverflow: { scrollWidth: number; clientWidth: number };
  scaleVisible: boolean;
  dotBox: [number, number];
  /** The header as drawn, and again with every glyph WIDER_EM wider. */
  header: HeaderRoom;
  headerWider: HeaderRoom;
  scaleText: string;
  tierWidthPct: number;
  chainLabels: string[];
}

interface HeaderRoom {
  /** Width of the free space beside the graph size, with all three buttons drawn. */
  spacer: number;
  height: number;
  overflow: boolean;
  oneRow: boolean;
  /** Each button's box, and where the header's content box (inside its padding) ends. */
  buttons: { id: string; width: number; height: number; left: number; right: number }[];
  contentLeft: number;
  contentRight: number;
}

function readHeader(page: Page): Promise<HeaderRoom> {
  return page.evaluate((): HeaderRoom => {
    const h = document.querySelector(".pp-header") as HTMLElement;
    const mids = [...h.children]
      .filter((k) => k.getBoundingClientRect().width > 0)
      .map((k) => k.getBoundingClientRect().top + k.getBoundingClientRect().height / 2);
    const hb = h.getBoundingClientRect();
    const cs = getComputedStyle(h);
    return {
      spacer: h.querySelector(".spacer")!.getBoundingClientRect().width,
      height: hb.height,
      overflow: h.scrollWidth > h.clientWidth,
      oneRow: Math.max(...mids) - Math.min(...mids) <= 2,
      buttons: ["btn-refresh", "btn-theme", "btn-settings"].map((id) => {
        const r = document.getElementById(id)!.getBoundingClientRect();
        return { id, width: r.width, height: r.height, left: r.left, right: r.right };
      }),
      contentLeft: hb.left + parseFloat(cs.paddingLeft) + parseFloat(cs.borderLeftWidth),
      contentRight: hb.right - parseFloat(cs.paddingRight) - parseFloat(cs.borderRightWidth),
    };
  });
}

async function measure(browser: Browser, scheme: "dark" | "light", nodes?: number): Promise<Geometry> {
  const page: Page = await browser.newPage({
    viewport: { width: 400, height: 900 },
    colorScheme: scheme,
    reducedMotion: "reduce",
  });
  if (nodes !== undefined) await page.addInitScript(`window.__nodes = ${nodes};`);
  await page.addInitScript(SHIM);
  await page.goto(`file://${join(DIST, "popup.html")}`);
  await page.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 15_000 });
  await settledLayout(page);

  const g = await page.evaluate((): Geometry => {
    const disc = document.getElementById("band-glyph");
    const scale = document.getElementById("scale");
    return {
      rungs: document.querySelectorAll("#chain-mount .ch-rung").length,
      liveRungs: document.querySelectorAll("#chain-mount .ch-rung.ch-live").length,
      discHeight: disc ? disc.getBoundingClientRect().height : 0,
      bodyScrollWidth: document.body.scrollWidth,
      bodyClientWidth: document.body.clientWidth,
      scaleVisible: scale ? !scale.hasAttribute("hidden") : false,
      dotBox: (() => {
        const d = document.querySelector("#scale .scale-dot")?.getBoundingClientRect();
        return [d ? d.width : 0, d ? d.height : 0] as [number, number];
      })(),
      header: { spacer: -1, height: -1, overflow: true, oneRow: false, buttons: [], contentLeft: 0, contentRight: 0 },
      headerWider: { spacer: -1, height: -1, overflow: true, oneRow: false, buttons: [], contentLeft: 0, contentRight: 0 },
      scaleText: document.getElementById("scale-nodes")?.textContent ?? "",
      tierWidthPct: -1,
      regionOverflow: { scrollWidth: -1, clientWidth: -1 },
      chainLabels: [...document.querySelectorAll("#chain-mount .ch-label")].map(
        (e) => e.textContent ?? "",
      ),
    };
  });
  // The header is the same at every scroll position: read it as drawn and with wider
  // glyphs (Linux Chromium, which runs this comparison in CI, already sets
  // each glyph wider than macOS does, by rounding its advance).
  g.header = await readHeader(page);
  g.headerWider = await withWiderGlyphs(page, WIDER_EM, () => readHeader(page));
  // The three parts follow one another in one region, so its sideways
  // overflow is read once. The tier meter sits in This browser, at the end of
  // the scroll, and is read once that part is in view.
  g.regionOverflow = await page.evaluate(() => {
    const r = document.getElementById("popup-scroll") as HTMLElement;
    return { scrollWidth: r.scrollWidth, clientWidth: r.clientWidth };
  });
  await scrollPopupTo(page, "browser");
  g.tierWidthPct = await page.evaluate(() => {
    const fill = document.getElementById("tier-fill");
    return fill ? (fill.getBoundingClientRect().width / 340) * 100 : -1;
  });
  await page.close();
  return g;
}

test("the panel renders the same shape in Gecko and in Blink", async () => {
  test.setTimeout(120_000);
  const ff = await firefox.launch();
  const cr = await chromium.launch();
  try {
    const gecko = await measure(ff, "dark");
    const blink = await measure(cr, "dark");

    // CONTROL: the measurement is real. A shim that never rendered would
    // report zeroes and every equality below would still hold.
    expect(blink.rungs, "the Blink render produced no spine at all").toBe(7);
    expect(blink.discHeight, "the verdict mark has no height in Blink").toBeGreaterThan(20);

    // The spine: same count, same rungs, same order, in both engines.
    expect(gecko.rungs, "Gecko laid out a different number of rungs").toBe(blink.rungs);
    expect(gecko.liveRungs).toBe(blink.liveRungs);
    expect(gecko.chainLabels).toEqual(blink.chainLabels);
    expect(gecko.chainLabels).toEqual([
      "Name",
      "Runs on",
      "Address",
      "Prefix",
      "Network",
      "Operator",
      "Present at",
    ]);

    // The verdict mark is a fixed-size flex child inside a centred row, which
    // is exactly the kind of thing that collapses to zero in one engine and
    // not the other.
    expect(gecko.discHeight, "the verdict mark collapsed in Gecko").toBeGreaterThan(20);

    // The live readouts really drew: an inline SVG path and a filled meter.
    expect(gecko.scaleVisible && blink.scaleVisible, "the scale readout did not appear").toBe(true);
    expect(gecko.dotBox, "the dot is not 6 x 6 in Gecko").toEqual([6, 6]);
    expect(blink.dotBox, "the dot is not 6 x 6 in Blink").toEqual([6, 6]);
    expect(gecko.tierWidthPct, "the tier meter did not fill in Gecko").toBeGreaterThan(50);
    expect(blink.tierWidthPct, "the tier meter did not fill in Blink").toBeGreaterThan(50);

    // NOTHING overflows sideways. A 400-pixel panel with a horizontal
    // scrollbar is the single most obvious way a cross-engine layout bug
    // shows up, and it is invisible in a full-page capture.
    for (const [engine, g] of [["Gecko", gecko], ["Blink", blink]] as const) {
      expect(
        g.bodyScrollWidth,
        `${engine} overflows the panel horizontally (${g.bodyScrollWidth} > ${g.bodyClientWidth})`,
      ).toBeLessThanOrEqual(g.bodyClientWidth + 1);
      // The content region keeps its own overflow, so a block that is too wide
      // scrolls inside it rather than widening the body: check the one region.
      expect(
        g.regionOverflow.scrollWidth,
        `${engine} overflows the scrolling region horizontally (${g.regionOverflow.scrollWidth} > ${g.regionOverflow.clientWidth})`,
      ).toBeLessThanOrEqual(g.regionOverflow.clientWidth + 1);
    }
  } finally {
    await ff.close();
    await cr.close();
  }
});

test("the header draws Re-check, Theme and Settings on one row beside the widest figure, inside its padding, in Gecko and in Blink, in both schemes, as drawn and with wider glyphs", async () => {
  test.setTimeout(120_000);
  const ff = await firefox.launch();
  const cr = await chromium.launch();
  try {
    for (const [engine, browser] of [["Gecko", ff], ["Blink", cr]] as const) {
      for (const scheme of ["dark", "light"] as const) {
        // Ten billion and more is drawn in three digits, five characters: as
        // wide as any figure the header draws (the figure is monospaced).
        const g = await measure(browser, scheme, 12_340_000_000);
        expect(g.scaleVisible, `${engine} ${scheme}: the readout did not appear`).toBe(true);
        expect(g.scaleText, `${engine} ${scheme}: the figure is not three digits`).toBe("12.3B");
        test.info().annotations.push({
          type: `${engine} ${scheme}`,
          description: `spacer ${g.header.spacer.toFixed(2)} px as drawn, ${g.headerWider.spacer.toFixed(2)} px ${WIDER_EM}em wider`,
        });
        for (const [how, h] of [["as drawn", g.header], [`${WIDER_EM}em wider`, g.headerWider]] as const) {
          const at = `${engine} ${scheme}, ${how}`;
          expect(h.buttons.map((b) => b.id), `${at}: the three buttons are drawn, in order`).toEqual(["btn-refresh", "btn-theme", "btn-settings"]);
          for (const b of h.buttons) {
            expect([b.width, b.height], `${at}: ${b.id} is not 30 x 30`).toEqual([30, 30]);
            expect(b.left, `${at}: ${b.id} starts left of the header's content box`).toBeGreaterThanOrEqual(h.contentLeft - 0.01);
            expect(b.right, `${at}: ${b.id} runs into the header's right padding`).toBeLessThanOrEqual(h.contentRight + 0.01);
          }
          expect(h.height, `${at}: the header is not 52 px tall`).toBe(52);
          expect(h.overflow, `${at}: the header overflows sideways`).toBe(false);
          expect(h.oneRow, `${at}: the header's parts are not on one row`).toBe(true);
        }
      }
    }
  } finally {
    await ff.close();
    await cr.close();
  }
});

/** The lowest visible leaf of the scrolling region: is it fully in view, and is it what a click there would hit? */
function lastLine(page: Page): Promise<{ found: boolean; inside: boolean; hit: boolean; what: string }> {
  return page.locator("#popup-scroll").evaluate((scroller) => {
    const region = scroller.getBoundingClientRect();
    let end: Element | null = null;
    let low = -Infinity;
    for (const e of scroller.querySelectorAll("*")) {
      if (e.children.length > 0) continue;
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
}

test("scrolling the whole content top to bottom and back sends nothing, in both engines, and no tab role is left", async () => {
  test.setTimeout(120_000);
  const ff = await firefox.launch();
  const cr = await chromium.launch();
  try {
    for (const [engine, browser] of [["Gecko", ff], ["Blink", cr]] as const) {
      const page = await browser.newPage({ viewport: { width: 400, height: 600 }, reducedMotion: "reduce" });
      await page.addInitScript(SHIM);
      await page.goto(`file://${join(DIST, "popup.html")}`);
      await page.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 15_000 });

      await expect(page.locator('[role^="tab"]'), `${engine}: an element still has a tab role`).toHaveCount(0);
      await expect(page.getByRole("tab", { includeHidden: true }), engine).toHaveCount(0);
      await expect(page.getByRole("heading", { name: "This site", level: 2 }), engine).toHaveCount(1);
      await expect(page.getByRole("heading", { name: "This page", level: 2 }), engine).toHaveCount(1);
      await expect(page.getByRole("heading", { name: "This browser", level: 2 }), engine).toHaveCount(1);

      // The render has no session storage, so the cookie line's record is
      // unknown and the line stays hidden, in both engines.
      await expect(page.locator("#cookie-line"), engine).toHaveCount(1);
      await expect(page.locator("#cookie-line"), engine).toBeHidden();

      // The count of messages the page has sent, once opening has settled:
      // equal on two reads in a row, no timer.
      const sent = (): Promise<number> =>
        page.evaluate(() => (window as unknown as { __sent: string[] }).__sent.length);
      let last = -1;
      await expect
        .poll(
          async () => {
            const n = await sent();
            const same = n === last;
            last = n;
            return same;
          },
          { message: `${engine}: the open never settled` },
        )
        .toBe(true);
      const opened = last;

      // Top to bottom and back, a part at a time and then the whole way.
      expect(await page.locator("#popup-scroll").evaluate((r) => r.scrollTop), `${engine}: it opens at the top`).toBe(0);
      for (const part of ["page", "browser", "page", "site"] as const) {
        await scrollPopupTo(page, part);
        expect(await sent(), `${engine}: scrolling to ${part} sent a message`).toBe(opened);
      }
      const room = await page.locator("#popup-scroll").evaluate((r) => r.scrollHeight - r.clientHeight);
      expect(room, `${engine}: control: there is something to scroll`).toBeGreaterThan(200);
      await page.mouse.move(200, 300);
      for (let i = 0; i < 12; i++) await page.mouse.wheel(0, 120);
      await expect.poll(() => page.locator("#popup-scroll").evaluate((r) => r.scrollTop), { message: engine }).toBeGreaterThan(room - 2);
      await expect(page.locator("#popup-fade"), `${engine}: the fade is gone at the end`).toBeHidden();
      const end = await lastLine(page);
      expect(end.found, `${engine}: control: there is a last line`).toBe(true);
      expect(end.inside, `${engine}: the last line (${end.what}) is cut off at the end`).toBe(true);
      expect(end.hit, `${engine}: the last line (${end.what}) is covered at the end`).toBe(true);
      for (let i = 0; i < 12; i++) await page.mouse.wheel(0, -120);
      await expect.poll(() => page.locator("#popup-scroll").evaluate((r) => r.scrollTop), { message: engine }).toBe(0);
      await expect(page.locator("#popup-fade"), `${engine}: the fade is back at the top`).toBeVisible();
      expect(await sent(), `${engine}: scrolling top to bottom and back sent a message`).toBe(opened);

      // A reload (what Re-check does) after scrolling down lands at the top.
      await page.locator("#popup-scroll").evaluate((r) => r.scrollTo(0, r.scrollHeight));
      expect(await page.locator("#popup-scroll").evaluate((r) => r.scrollTop), `${engine}: control: scrolled down`).toBeGreaterThan(100);
      await page.reload();
      await page.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 15_000 });
      await settledLayout(page);
      expect(await page.locator("#popup-scroll").evaluate((r) => r.scrollTop), `${engine}: a reload did not land at the top`).toBe(0);
      await page.close();
    }
  } finally {
    await ff.close();
    await cr.close();
  }
});

/** The shim for a signed-in reader: two buttons in the footer, the least room the first screen ever has. */
const SIGNED_IN_SHIM = `${SHIM}
Object.assign(REPLIES, {
  getTabState: { ok: true, tabState: { ...REPLIES.getTabState.tabState, signedIn: true } },
  getSettings: { ...REPLIES.getSettings, signedIn: true },
});
`;

test("while a check runs the checking view fills the first screen and the browser part waits below, in Gecko and Blink", async () => {
  test.setTimeout(120_000);
  const ff = await firefox.launch();
  const cr = await chromium.launch();
  try {
    for (const [engine, browser] of [["Gecko", ff], ["Blink", cr]] as const) {
      const page = await browser.newPage({ viewport: { width: 400, height: 600 }, reducedMotion: "reduce" });
      // The worker keeps answering that the check is still running.
      await page.addInitScript(`${SHIM}
Object.assign(REPLIES, { getTabState: { ok: true, tabState: { ...REPLIES.getTabState.tabState, icon: "checking", verdict: null } } });`);
      await page.goto(`file://${join(DIST, "popup.html")}`);
      await expect(page.locator("#checking-view"), engine).toBeVisible();
      await expect(page.locator("#panel-page"), engine).toBeHidden();
      const where = await page.evaluate(() => ({
        siteBottom: document.getElementById("panel-site")!.getBoundingClientRect().bottom,
        browserTop: document.getElementById("panel-browser")!.getBoundingClientRect().top,
        regionBottom: document.getElementById("popup-scroll")!.getBoundingClientRect().bottom,
      }));
      expect(where.siteBottom, `${engine}: the checking view stops short of the first screen's foot`).toBeGreaterThanOrEqual(where.regionBottom - 1);
      expect(where.browserTop, `${engine}: the browser part shows on the first screen`).toBeGreaterThanOrEqual(where.regionBottom);
      await page.close();
    }
  } finally {
    await ff.close();
    await cr.close();
  }
});

test("the first screen of a clean site holds the verdict card, its chips and all seven facts clear of the fade, in Gecko and Blink, both schemes, as drawn and wider", async () => {
  test.setTimeout(120_000);
  const ff = await firefox.launch();
  const cr = await chromium.launch();
  try {
    for (const [engine, browser] of [["Gecko", ff], ["Blink", cr]] as const) {
      for (const scheme of ["dark", "light"] as const) {
        const page = await browser.newPage({ viewport: { width: 400, height: 600 }, colorScheme: scheme, reducedMotion: "reduce" });
        await page.addInitScript(SIGNED_IN_SHIM);
        await page.goto(`file://${join(DIST, "popup.html")}`);
        await page.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 15_000 });
        await expect(page.locator("#btn-dossier"), engine).toBeVisible();
        await expect(page.locator("#band-chip"), engine).toHaveText("NO KNOWN THREAT");
        await expectFirstScreen(page, `${engine}-${scheme}`);
        await page.close();
      }
    }
  } finally {
    await ff.close();
    await cr.close();
  }
});

test("the light theme flips in Gecko too, and does not just inherit dark", async () => {
  test.setTimeout(120_000);
  const ff = await firefox.launch();
  try {
    const page = await ff.newPage({ viewport: { width: 400, height: 900 }, reducedMotion: "reduce" });
    await page.addInitScript(SHIM);

    const grounds: Record<string, string> = {};
    for (const scheme of ["dark", "light"] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto(`file://${join(DIST, "popup.html")}`);
      await page.locator("#chain-mount .ch-rung").first().waitFor({ timeout: 15_000 });
      grounds[scheme] = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    }
    // The whole palette flips, or it flips nowhere. Two identical grounds
    // means Gecko ignored the media query and the light theme is a fiction
    // in the one engine nothing else in this suite exercises.
    expect(grounds["dark"], "Gecko rendered both schemes identically").not.toBe(grounds["light"]);
    await page.close();
  } finally {
    await ff.close();
  }
});

// ------------------------------------------- the drawn evidence, in Gecko

/**
 * The interstitial's shim. Its own fixtures, deliberately not shared with
 * the panel's: this page needs a flagged name with a fresh registration, a
 * populated neighbourhood and cited reasons, and bending the panel's
 * fixtures to carry all that would change what the panel test measures.
 */
const WARNING_SHIM = `
const WHOST = "warn-render-guard-e2e.com";
const CHAIN = {
  host: WHOST, live: 7, unavailable: 0,
  evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:badhosting"],
  facilities: ["Example Colo MTL1"], exchanges: [],
  owner: "Bad Hosting LLC", country: "CA", city: "Example City", asn: "AS64550", asnOk: true,
  ip: "192.0.2.66", vendor: null, vendorCategory: null, identifyCategory: null,
  roles: [], ageDays: 16, prefix: "192.0.2.0/24", threatNeighbors: 9, at: Date.now(),
  rungs: [
    { kind: "name", label: "NAME", value: WHOST, fact: "registered 16 days ago", state: "live", tone: "warn", detail: [], drillable: false },
    { kind: "vendor", label: "RUNS ON", value: null, fact: null, state: "empty", tone: "neutral", detail: [], drillable: false },
    { kind: "address", label: "ADDRESS", value: "192.0.2.66", fact: "Example City", state: "live", tone: "neutral", detail: [], drillable: true },
    { kind: "prefix", label: "PREFIX", value: "192.0.2.0/24", fact: "9 flagged neighbours", state: "live", tone: "hot", detail: [], drillable: true },
    { kind: "network", label: "NETWORK", value: "AS64550", fact: null, state: "live", tone: "neutral", detail: [], drillable: true },
    { kind: "operator", label: "OPERATOR", value: "Bad Hosting LLC", fact: "CA", state: "live", tone: "neutral", detail: [], drillable: false },
    { kind: "presence", label: "PRESENT AT", value: "Example Colo MTL1", fact: "1 facility", state: "live", tone: "neutral", detail: [], drillable: false },
  ],
};
const REPLIES = {
  getBlock: { ok: true, block: { blocked: true, brand: null, brandDomain: null, beforeLoad: false } },
  getChain: { ok: true, chain: CHAIN },
  getProtection: { ok: true, protection: {
    host: WHOST, band: "CRITICAL", blocking: true, label: "credential-phishing suspect",
    coverage: "malicious-evidenced", who: "Bad Hosting LLC", category: null,
    where: { city: "Example City", country: "CA", ip: "192.0.2.66" },
    ageDays: 16, why: ["Listed in 1 threat feed: openphish", "listed in 2 threat feed(s)"],
    score: 17.2, whyFactors: [], variants: [], partial: false } },
};
window.chrome = {
  runtime: {
    id: "shim",
    sendMessage: (msg) => Promise.resolve(REPLIES[msg.kind] ?? { ok: true }),
    getURL: (p) => p,
  },
  tabs: { query: () => Promise.resolve([{ id: 1 }]), update: () => Promise.resolve() },
  storage: { local: { get: () => Promise.resolve({}), set: () => Promise.resolve() } },
};
`;

interface EvidenceGeometry {
  bars: number;
  barFills: string[];
  spineLabels: string[];
  rungs: number;
  counter: string;
  age: string;
  neighbours: string;
  reasons: string;
  stopSize: [number, number];
  bandInk: string;
  bandShown: boolean;
  bodyScrollWidth: number;
  bodyClientWidth: number;
}

async function measureWarning(browser: Browser, scheme: "dark" | "light"): Promise<EvidenceGeometry> {
  const page: Page = await browser.newPage({
    viewport: { width: 1000, height: 900 },
    colorScheme: scheme,
    reducedMotion: "reduce",
  });
  await page.addInitScript(WARNING_SHIM);
  await page.goto(`file://${join(DIST, "warning.html")}?host=warn-render-guard-e2e.com`);
  await page.locator("#ev-chain .ch-rung").first().waitFor({ timeout: 15_000 });
  await page.locator("#ev-feeds .ev-figure").waitFor({ timeout: 15_000 });

  const g = await page.evaluate((): EvidenceGeometry => {
    const text = (sel: string): string => (document.querySelector(sel)?.textContent ?? "").trim();
    const stop = document.querySelector("#glyph svg")?.getBoundingClientRect();
    return {
      bars: document.querySelectorAll("#ev-spine .ev-bar").length,
      barFills: [...document.querySelectorAll("#ev-spine .ev-bar")].map((b) => getComputedStyle(b).backgroundColor),
      spineLabels: [...document.querySelectorAll("#ev-spine .ev-bar-label")].map((t) => t.textContent ?? ""),
      rungs: document.querySelectorAll("#ev-chain .ch-rung").length,
      counter: text("#ev-completeness"),
      age: text("#ev-age .ev-figure"),
      neighbours: text("#ev-neighbours .ev-figure"),
      reasons: text("#ev-feeds .ev-figure"),
      stopSize: [stop?.width ?? 0, stop?.height ?? 0],
      bandInk: getComputedStyle(document.querySelector("#band") as Element).backgroundColor,
      bandShown: (() => {
        const band = document.querySelector("#band") as HTMLElement;
        const box = band.getBoundingClientRect();
        return !band.hidden && getComputedStyle(band).display !== "none" && box.width > 0 && box.height > 0;
      })(),
      bodyScrollWidth: document.body.scrollWidth,
      bodyClientWidth: document.body.clientWidth,
    };
  });
  await page.close();
  return g;
}

test("the interstitial's evidence renders the same in Gecko and Blink", async () => {
  // The most consequential surface in the product draws its spine, its stop
  // sign and its figures with colours that come from CSS custom properties.
  // That is exactly the kind of thing that works in one engine and silently
  // paints black in the other, and no other gate looks at this page in Gecko.
  test.setTimeout(120_000);
  const ff = await firefox.launch();
  const cr = await chromium.launch();
  try {
    const gecko = await measureWarning(ff, "dark");
    const blink = await measureWarning(cr, "dark");

    // CONTROL: the Blink render really produced the evidence. Without this,
    // two engines drawing nothing would agree perfectly.
    expect(blink.rungs, "Blink drew no chain on the interstitial").toBe(7);
    expect(blink.bars, "Blink drew no spine").toBe(7);
    expect(blink.counter).toBe("7 of 7 joins read");
    expect(blink.neighbours, "Blink drew no neighbour figure").toBe("9");
    expect(blink.reasons, "Blink drew no reason figure").toBe("2 reasons");
    expect(blink.age).toBe("16 days");

    // And Gecko agrees, figure for figure and bar for bar.
    expect(gecko.rungs).toBe(blink.rungs);
    expect(gecko.bars).toBe(blink.bars);
    expect(gecko.spineLabels).toEqual(blink.spineLabels);
    expect(gecko.spineLabels).toEqual([
      "NAME", "RUNS ON", "ADDRESS", "PREFIX", "NETWORK", "OPERATOR", "PRESENT AT",
    ]);
    expect(gecko.counter).toBe(blink.counter);
    expect(gecko.age).toBe(blink.age);
    expect(gecko.neighbours, "Gecko drew a different neighbour figure").toBe(blink.neighbours);
    expect(gecko.reasons).toBe(blink.reasons);
    // The bars take their colour from the tone of each join, in both engines.
    expect(gecko.barFills).toEqual(blink.barFills);
    expect(new Set(blink.barFills).size, "the bars are not all one colour").toBeGreaterThan(1);
    // The stop sign is a 96 px drawing in both, and the band plate is the same red.
    expect(blink.stopSize).toEqual([96, 96]);
    expect(gecko.stopSize).toEqual(blink.stopSize);
    expect(gecko.bandInk).toBe(blink.bandInk);
    expect(blink.bandShown, "Blink did not show the band line").toBe(true);
    expect(gecko.bandShown, "Gecko did not show the band line").toBe(true);

    // Nothing runs off the side.
    for (const [engine, g] of [["Gecko", gecko], ["Blink", blink]] as const) {
      expect(
        g.bodyScrollWidth,
        `${engine} overflows the interstitial horizontally`,
      ).toBeLessThanOrEqual(g.bodyClientWidth + 1);
    }
  } finally {
    await ff.close();
    await cr.close();
  }
});

// ------------------------------------------- This browser, signed in and routed

/**
 * A second reply set: signed in, routed, verified, with the destinations seen
 * inside the last day so the strip is drawn. The address and name are fictional.
 * The name has a real one's shape and length: "a" and 16 hex digits, "t" and
 * 32 hex digits for the account, then a stand-in zone as long as the agents
 * zone (agents.guard-e2e.test), 73 characters in all.
 * The popup draws it on one line, the start trimmed and the zone in view.
 * The categories argument is how many of today's four tallies are above zero.
 */
function routedShim(categories: 1 | 4): string {
  const counts =
    categories === 1
      ? { preemptBlock: 1, identityVerified: 0, cookieDecline: 0, lookalikeCaught: 0 }
      : { preemptBlock: 2, identityVerified: 1, cookieDecline: 3, lookalikeCaught: 2 };
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return `${SHIM}
const ADDRESS = "2001:db8:aa:bb:cc:dd:ee:ff";
const AGENT = "a5e7a1c0d9b2f4301";
const FQDN = AGENT + ".t0123456789abcdef0123456789abcdef.agents.guard-e2e.test";
Object.assign(REPLIES, {
  getTabState: { ok: true, tabState: { ...REPLIES.getTabState.tabState, signedIn: true } },
  getSettings: { ...REPLIES.getSettings, signedIn: true },
  getWins: { ok: true, wins: { date: "2026-09-02", total: ${total}, counts: ${JSON.stringify(counts)} } },
  getBrowserReport: { ok: true, report: {
    hosts: [1, 2, 3, 4].map((n) => ({
      host: "dest-" + n + "-guard-e2e.com", owner: "MediaCo", category: "work", verdict: "NONE",
      q: n, lastAt: Date.now() - n * 3_600_000,
    })),
    totals: { destinations: 4, companies: 1, countries: 1, networks: 1, lookups: 10, flagged: 0 },
    generatedAt: Date.now() } },
  egressStatus: { ok: true, egress: {
    on: true, enrolled: true, agent: AGENT, address: ADDRESS,
    label: "This browser (Whisper Guard)", fqdn: FQDN,
    rdapUrl: "https://rdap.example.test/ip/" + ADDRESS,
    controlledByOther: false, webrtcHardened: null, privateWindowsRouted: false,
    error: null, reserving: null, reserveFailed: false } },
  verifyIdentity: { ok: true, verification: { isWhisperAgent: true, fqdn: FQDN, daneOk: true, jwsOk: true, posture: null, detail: null } },
});
`;
}

for (const categories of [1, 4] as const) {
  test(`This browser, signed in and routed with ${categories} categor${categories === 1 ? "y" : "ies"} today, is measured at 400 x 600 in Gecko and Blink`, async () => {
    test.setTimeout(120_000);
    const ff = await firefox.launch();
    const cr = await chromium.launch();
    try {
      for (const [engine, browser] of [["Gecko", ff], ["Blink", cr]] as const) {
        for (const scheme of ["dark", "light"] as const) {
          const page = await browser.newPage({
            viewport: { width: 400, height: 600 },
            colorScheme: scheme,
            reducedMotion: "reduce",
          });
          await page.addInitScript(routedShim(categories));
          await page.goto(`file://${join(DIST, "popup.html")}`);
          await scrollPopupTo(page, "browser");
          await expect(page.locator("#identity-control"), engine).toHaveAttribute("data-state", "routed");
          // The card is complete before it is measured: verified, with all three rows.
          await expect(page.locator("#identity-state"), engine).toHaveText("VERIFIED");
          await expect(page.locator("#identity-detail .w-kv .k"), engine).toHaveText(["Address", "Name", "Proof"]);
          await expect(page.locator("#browser-strip svg"), engine).toBeVisible();
          await expect(page.locator("#today-row"), engine).toBeVisible();
          await expectRoutedCardLayout(page, `${engine}-${scheme}-${categories}`);
          await page.close();
        }
      }
    } finally {
      await ff.close();
      await cr.close();
    }
  });
}

test("the built Firefox manifest is the one under test", () => {
  // The shim renders dist/firefox, so this pins that the tree it renders is
  // the Firefox build and not a stale copy of the Chromium one.
  const m = JSON.parse(readFileSync(join(DIST, "manifest.json"), "utf8")) as Record<string, unknown>;
  expect(m["manifest_version"]).toBe(3);
  expect(JSON.stringify(m["optional_permissions"])).toContain("proxy");
});
