// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE RISKY VERDICTS AT THE TOP OF THE POPUP. A suspicious site, a look-alike
// and an UNKNOWN one, each measured on the built extension at 400 x 600.
//
//   - a suspicious site shows its verdict, its level and its first factor on the
//     first screen, in both colour schemes, even with hosts blocked this session;
//   - a look-alike shows its card and "Go to the real site" on the first screen,
//     also when the site is suspicious as well;
//   - the factor weights are drawn only when they add up to the score shown, and
//     the list is never cut while they are;
//   - a fact that could not be read is labelled and the counter drops with it;
//   - an UNKNOWN verdict is never drawn green, in either scheme, and the same
//     check does find green on a clean site.
//
// Every case uses its own host: the composed picture is kept per name.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY } from "./helpers/servers";
import {
  launchExtension,
  markHostBlocked,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";
import { WIDER_EM, withWiderGlyphs } from "./helpers/popup-fit";

let net: E2ENetwork;
let ext: Extension;

const DAY = 86_400_000;
const SUSPICIOUS = "risky-medium-guard-e2e.com";
const UNKNOWN_LOOKALIKE = "www.dr0pbox.com";
const SUSPICIOUS_LOOKALIKE = "www.yah0o.com";
const COMBOSQUAT = "dropbox-login-guard-e2e.com";
const CLEAN = "risky-clean-guard-e2e.com";

/** Three weighted threat sources whose weights add up to the score. */
const WEIGHTED = [
  {
    score: 47.5,
    sources: [
      { feedId: "e2e-newreg-feed", weight: 10 },
      { feedId: "e2e-typo-feed", weight: 20 },
      { feedId: "e2e-young-feed", weight: 17.5 },
    ],
  },
];

interface SeedOptions {
  band?: string;
  label?: string;
  coverage?: string;
  explain?: Record<string, unknown>[];
  ageDays?: number;
}

// The mock answers the route read by address, so each host gets its own.
let nextAddress = 120;

function seed(host: string, o: SeedOptions = {}): void {
  net.setVerdict(host, { band: o.band ?? "NONE", coverage: o.coverage ?? "known-clean", label: o.label ?? "clean" });
  net.setEnrich(host, {
    ip: `198.51.100.${nextAddress++}`,
    city: "London, GB",
    country: "GB",
    asn: "AS64540",
    owner: "MediaCo plc",
    asnName: "MEDIACO - MediaCo plc",
    prefix: "198.51.100.0/24",
    threatNeighbors: 0,
    prevalence: 812,
    verdict: o.band ?? "NONE",
  });
  net.setIdentify(host, [
    {
      host,
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
  if (o.explain) net.setExplain(host, o.explain);
  if (o.ageDays !== undefined) {
    const created = new Date(Date.now() - o.ageDays * DAY).toISOString();
    net.setHistory(host, [{ createDate: created, updateDate: created }]);
  }
}

function seedSuspicious(host: string, explain: Record<string, unknown>[] = WEIGHTED): void {
  seed(host, { band: "MEDIUM", coverage: "partial", label: "suspicious", explain, ageDays: 5 });
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  seedSuspicious(SUSPICIOUS);
  seedSuspicious(SUSPICIOUS_LOOKALIKE);
  seed(CLEAN, { explain: [{ score: 0, sources: [{ feedId: "tranco" }] }], ageDays: 800 });
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.graphMode = "mock";
  net.failQueries.clear();
  net.clearLog();
  await setKey(ext, MOCK_API_KEY);
  await setSettings(ext, { cloudCheck: true, allowlist: [] });
});

test.afterEach(async () => {
  net.failQueries.clear();
  await ext.sw.evaluate(() => chrome.storage.session.remove("blocked"));
});

// -------------------------------------------------------------- the helpers

type Scheme = "dark" | "light";

/** The popup for a site, once the facts card has drawn. */
async function openSite(
  url: string,
  opts: { colorScheme?: Scheme; icon: Parameters<typeof waitForIcon>[2] },
): Promise<{ popup: Page; page: Page }> {
  const { page, tabId } = await visit(ext, url);
  await waitForIcon(ext, tabId, opts.icon);
  const popup = await openPopup(ext, tabId);
  if (opts.colorScheme) await popup.emulateMedia({ colorScheme: opts.colorScheme });
  await popup.locator("#facts-count").waitFor({ timeout: 20_000 });
  await fontsReady(popup);
  return { popup, page };
}

async function fontsReady(popup: Page): Promise<void> {
  await popup.evaluate(() => document.fonts.ready);
  await expect
    .poll(() => popup.evaluate(() => document.fonts.check("12.5px Lato") && document.fonts.check("12px 'JetBrains Mono'")))
    .toBe(true);
}

/** One more round trip to the worker for the same protection answer: by the time it
 *  returns, the popup's own read of it has been drawn. */
async function protectionDrawn(popup: Page, host: string): Promise<void> {
  await popup.evaluate((h) => chrome.runtime.sendMessage({ kind: "getProtection", host: h }), host);
}

interface Fit {
  top: number;
  bottom: number;
  limit: number;
  spare: number;
  fade: boolean;
  scrollTop: number;
}

/**
 * Where an element sits in the content region at the first screen. Whatever the
 * reader must read or press, a card included, has to end above the fade's own
 * top while the fade shows (its height is read from the element, never a
 * constant), and inside the region when it does not.
 */
async function firstScreen(popup: Page, selector: string): Promise<Fit> {
  return popup.evaluate((sel) => {
    const region = document.getElementById("popup-scroll")!;
    const r = region.getBoundingClientRect();
    const e = document.querySelector(sel)!.getBoundingClientRect();
    const fadeEl = document.getElementById("popup-fade")!;
    const fade = !fadeEl.hidden;
    const limit = fade ? fadeEl.getBoundingClientRect().top : r.bottom;
    return { top: e.top - r.top, bottom: e.bottom, limit, spare: limit - e.bottom, fade, scrollTop: region.scrollTop };
  }, selector);
}

/** On the first screen, clear of the fade, as drawn and with every glyph WIDER_EM wider: both must hold. */
async function expectOnFirstScreen(popup: Page, selector: string, label: string): Promise<void> {
  const plain = await firstScreen(popup, selector);
  const wider = await withWiderGlyphs(popup, WIDER_EM, () => firstScreen(popup, selector));
  test.info().annotations.push({
    type: `fit ${label}`,
    description: `spare ${plain.spare.toFixed(1)} px as drawn, ${wider.spare.toFixed(1)} px ${WIDER_EM}em wider`,
  });
  for (const [how, fit] of [["as drawn", plain], [`${WIDER_EM}em wider`, wider]] as const) {
    expect(fit.scrollTop, `${label}, ${how}: the region is scrolled`).toBe(0);
    expect(fit.top, `${label}, ${how}: starts above the region`).toBeGreaterThanOrEqual(0);
    expect(fit.spare, `${label}, ${how}: ends ${(-fit.spare).toFixed(1)}px past the first screen`).toBeGreaterThanOrEqual(0);
  }
}

/** The colour a token resolves to on the page, as the browser computes a colour. */
async function tokenColor(popup: Page, token: string, property: "color" | "background-color"): Promise<string> {
  return popup.evaluate(
    ({ t, p }) => {
      const probe = document.createElement("span");
      probe.style.setProperty(p, `var(${t})`);
      document.body.appendChild(probe);
      const value = getComputedStyle(probe).getPropertyValue(p);
      probe.remove();
      return value;
    },
    { t: token, p: property },
  );
}

/**
 * Every colour drawn on an element and its descendants (SVG included) that is a
 * visible green: hue 90 to 170 degrees, saturation at least 0.25, lightness 0.15
 * to 0.85. A fully transparent colour is skipped.
 */
async function greens(popup: Page, selector: string): Promise<string[]> {
  return popup.evaluate((sel) => {
    const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
    const props = [
      "color",
      "background-color",
      "border-top-color",
      "border-right-color",
      "border-bottom-color",
      "border-left-color",
      "fill",
      "stroke",
    ];
    const found: string[] = [];
    const root = document.querySelector(sel)!;
    for (const el of [root, ...root.querySelectorAll("*")]) {
      const cs = getComputedStyle(el);
      for (const p of props) {
        const v = cs.getPropertyValue(p);
        if (!v || v === "none") continue;
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillStyle = "#000000";
        ctx.fillStyle = v;
        ctx.fillRect(0, 0, 1, 1);
        const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data as unknown as number[];
        if (a === 0) continue;
        const [rn, gn, bn] = [r! / 255, g! / 255, b! / 255];
        const max = Math.max(rn, gn, bn);
        const min = Math.min(rn, gn, bn);
        const l = (max + min) / 2;
        if (max === min) continue;
        const d = max - min;
        const s = d / (1 - Math.abs(2 * l - 1));
        let h: number;
        if (max === rn) h = ((gn - bn) / d) % 6;
        else if (max === gn) h = (bn - rn) / d + 2;
        else h = (rn - gn) / d + 4;
        h = (h * 60 + 360) % 360;
        if (h >= 90 && h <= 170 && s >= 0.25 && l >= 0.15 && l <= 0.85) {
          found.push(`${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""} ${p}: ${v}`);
        }
      }
    }
    return found;
  }, selector);
}

// -------------------------------------------------------------------- R1

test("on a suspicious site the verdict, its level and the first factor are on the first screen, in the dark and the light scheme", async () => {
  // Another host is blocked this session, so the ledger card is on the tab: the
  // first factor still has to be on the first screen.
  await markHostBlocked(ext, "risky-other-guard-e2e.com");
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite(`https://${SUSPICIOUS}/`, { colorScheme: scheme, icon: ["suspicious"] });
    await expect(popup.locator("#band-chip")).toHaveText("SUSPICIOUS · MEDIUM");
    await expect(popup.locator("#band-note")).toHaveText("Some risk signals in the graph.");
    await expect(popup.locator("#band-advice")).toHaveText("Be careful with passwords and payment details.");
    await expect(popup.locator("#band-age")).toBeVisible();
    // Not vacuous: the session ledger is on the popup, and Why sits above it.
    await expect(popup.locator("#blocked-card")).toBeVisible();
    await expect(popup.locator("#why-factors .why-factor").first()).toBeVisible();
    const why = await popup.locator("#protect-card").boundingBox();
    const blocked = await popup.locator("#blocked-card").boundingBox();
    expect(why!.y, `${scheme}: Why this verdict sits under the session ledger`).toBeLessThan(blocked!.y);

    await expectOnFirstScreen(popup, "#band-chip", `suspicious chip ${scheme}`);
    await expectOnFirstScreen(popup, "#why-factors .why-factor", `suspicious first factor ${scheme}`);
    await popup.close();
    await page.close();
  }
});

// -------------------------------------------------------------------- R2

test("on a look-alike the card and Go to the real site are on the first screen, also on a site that is suspicious too", async () => {
  // (a) a look-alike the graph knows nothing about.
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite(`https://${UNKNOWN_LOOKALIKE}/`, { colorScheme: scheme, icon: ["suspicious"] });
    await expect(popup.locator("#lookalike")).toBeVisible();
    await expect(popup.locator("#lookalike-head")).toHaveText("Look-alike caught on this device");
    await expect(popup.locator("#lookalike-text")).toHaveText("This site looks like dropbox.com but is not it.");
    await expect(popup.locator("#lookalike-on")).toHaveText(UNKNOWN_LOOKALIKE);
    await expect(popup.locator("#lookalike-real")).toHaveText("dropbox.com");
    await expect(popup.locator("#lookalike-trick")).toHaveText("Trick: homoglyph, the digit “0” in place of “o”.");
    await expect(popup.locator("#hostname")).toHaveText(UNKNOWN_LOOKALIKE);
    await expect(popup.locator("#hostname .pp-swap")).toHaveText("0");
    await expect(popup.locator("#lookalike-on .pp-swap")).toHaveText("0");
    await expect(popup.locator("#btn-goto")).toHaveText("Go to the real site");
    await expect(popup.locator("#btn-report")).toBeVisible();
    await expectOnFirstScreen(popup, "#lookalike", `look-alike card ${scheme}`);
    await expectOnFirstScreen(popup, "#btn-goto", `Go to the real site ${scheme}`);
    await popup.close();
    await page.close();
  }

  // (b) a look-alike that is suspicious as well: the card leads, Why follows.
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite(`https://${SUSPICIOUS_LOOKALIKE}/`, { colorScheme: scheme, icon: ["suspicious"] });
    await expect(popup.locator("#band-chip")).toHaveText("SUSPICIOUS · MEDIUM");
    await expect(popup.locator("#lookalike")).toBeVisible();
    await expect(popup.locator("#protect-card")).toBeVisible();
    await expectOnFirstScreen(popup, "#lookalike", `suspicious look-alike card ${scheme}`);
    await expectOnFirstScreen(popup, "#btn-goto", `suspicious look-alike Go to the real site ${scheme}`);
    const card = await popup.locator("#lookalike").boundingBox();
    const why = await popup.locator("#protect-card").boundingBox();
    expect(card!.y, `${scheme}: the look-alike card does not lead`).toBeLessThan(why!.y);
    await popup.close();
    await page.close();
  }

  // (c) a name that embeds a brand: no character is singled out.
  {
    const { popup, page } = await openSite(`https://${COMBOSQUAT}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#lookalike-trick")).toHaveText("Trick: this site embeds the name of dropbox.com.");
    await expect(popup.locator(".pp-swap")).toHaveCount(0);
    await popup.close();
    await page.close();
  }
});

// -------------------------------------------------------------------- R3

/** The shown weights, as numbers (U+2212 is a minus). */
async function shownWeights(popup: Page): Promise<number[]> {
  const texts = await popup.locator("#why-factors .wf-weight").allTextContents();
  return texts.map((t) => Number(t.trim().replace("−", "-")));
}

test("the factor weights add up to the score shown, and the list is never cut while they show", async () => {
  // (a) weights that add up: weights and bars show.
  {
    const { popup, page } = await openSite(`https://${SUSPICIOUS}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#why-score")).toHaveText("score 47.5");
    await expect(popup.locator("#why-factors .wf-weight")).toHaveText(["+20", "+17.5", "+10"]);
    const score = Number((await popup.locator("#why-score").innerText()).replace("score ", ""));
    const sum = (await shownWeights(popup)).reduce((a, b) => a + b, 0);
    expect(Math.round(sum * 10) / 10).toBe(score);
    const widths = await popup
      .locator("#why-factors .wf-fill")
      .evaluateAll((els) => els.map((e) => parseFloat((e as HTMLElement).style.width)));
    const weights = await shownWeights(popup);
    expect(widths).toHaveLength(3);
    widths.forEach((w, i) => expect(Math.abs(w - (weights[i]! / score) * 100)).toBeLessThan(0.5));
    await expect(popup.locator("#score-chip")).toBeHidden();
    await popup.close();
    await page.close();
  }

  // (b) seven weighted sources: all seven are listed, and no "more" line.
  {
    const host = "risky-seven-guard-e2e.com";
    seedSuspicious(host, [
      { score: 42, sources: [9, 8, 7, 6, 5, 4, 3].map((weight, i) => ({ feedId: `e2e-seven-feed-${i + 1}`, weight })) },
    ]);
    const { popup, page } = await openSite(`https://${host}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#why-score")).toHaveText("score 42");
    await expect(popup.locator("#why-factors .why-factor")).toHaveCount(7);
    await expect(popup.locator("#why-factors .why-factor.more")).toHaveCount(0);
    await expect(popup.locator("#why-factors .wf-weight")).toHaveCount(7);
    await popup.close();
    await page.close();
  }

  // (c) weights that do not add up to the score: names alone, no weight, no bar.
  {
    const host = "risky-short-guard-e2e.com";
    seedSuspicious(host, [
      { score: 30, sources: [{ feedId: "e2e-short-feed-a", weight: 10 }, { feedId: "e2e-short-feed-b", weight: 5 }] },
    ]);
    const { popup, page } = await openSite(`https://${host}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#why-score")).toHaveText("score 30");
    await expect(popup.locator("#why-factors .wf-name")).toHaveText(["e2e-short-feed-a", "e2e-short-feed-b"]);
    await expect(popup.locator("#why-factors .wf-weight")).toHaveCount(0);
    await expect(popup.locator("#why-factors .wf-bar")).toHaveCount(0);
    await popup.close();
    await page.close();
  }

  // (e) a negative weight on a half: the weights as written still add up to the
  // score as written, because the text of a negative weight rounds as the sum does.
  {
    const host = "risky-negative-guard-e2e.com";
    seedSuspicious(host, [
      {
        score: 35.25,
        sources: [
          { feedId: "e2e-neg-feed-a", weight: 20 },
          { feedId: "e2e-neg-feed-b", weight: 17.5 },
          { feedId: "e2e-neg-feed-c", weight: -2.25 },
        ],
      },
    ]);
    const { popup, page } = await openSite(`https://${host}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#why-factors .wf-weight")).toHaveCount(3);
    const score = Number((await popup.locator("#why-score").innerText()).replace("score ", ""));
    const sum = (await shownWeights(popup)).reduce((a, b) => a + b, 0);
    expect(Math.round(sum * 10) / 10, "the shown weights do not add up to the score shown").toBe(score);
    await popup.close();
    await page.close();
  }

  // (f) one weight larger than the score and one negative: no bar runs past its
  // track and the popup never scrolls sideways.
  {
    const host = "risky-overshoot-guard-e2e.com";
    seedSuspicious(host, [
      { score: 50, sources: [{ feedId: "e2e-over-feed-a", weight: 60 }, { feedId: "e2e-over-feed-b", weight: -10 }] },
    ]);
    const { popup, page } = await openSite(`https://${host}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#why-factors .wf-fill")).toHaveCount(2);
    const m = await popup.evaluate(() => {
      const region = document.getElementById("popup-scroll")!;
      const bars = [...document.querySelectorAll<HTMLElement>("#why-factors .wf-bar")].map((bar) => {
        const fill = bar.querySelector<HTMLElement>(".wf-fill")!;
        return {
          track: bar.getBoundingClientRect().width,
          fill: fill.getBoundingClientRect().width,
          set: parseFloat(fill.style.width),
          clips: getComputedStyle(bar).overflowX !== "visible",
        };
      });
      return { bars, over: region.scrollWidth - region.clientWidth };
    });
    for (const b of m.bars) {
      expect(b.set).toBeLessThanOrEqual(100);
      expect(b.fill).toBeLessThanOrEqual(b.track + 0.5);
      expect(b.clips, "the track does not clip its fill").toBe(true);
    }
    expect(m.over, "the popup scrolls sideways").toBeLessThanOrEqual(0);
    await popup.close();
    await page.close();
  }

  // (d) one source carries no weight: names alone.
  {
    const host = "risky-unweighted-guard-e2e.com";
    seedSuspicious(host, [
      { score: 12, sources: [{ feedId: "e2e-weighted-feed", weight: 12 }, { feedId: "e2e-bare-feed" }] },
    ]);
    const { popup, page } = await openSite(`https://${host}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#why-score")).toHaveText("score 12");
    await expect(popup.locator("#why-factors .why-factor.threat")).toHaveCount(2);
    await expect(popup.locator("#why-factors .wf-weight")).toHaveCount(0);
    await popup.close();
    await page.close();
  }
});

// -------------------------------------------------------------------- R4

test("on a suspicious site a fact that could not be read is labelled and the counter drops with it", async () => {
  const host = "risky-unread-guard-e2e.com";
  seedSuspicious(host);
  net.failQueries.add("AS_PRESENT_AT");
  const { popup, page } = await openSite(`https://${host}/`, { icon: ["suspicious"] });
  await expect(popup.locator("#facts-count")).toHaveText("6/7 facts read");
  const lost = popup.locator("#chain-mount .ch-rung.ch-lost");
  await expect(lost).toHaveCount(1);
  await expect(lost).toContainText("Present at");
  await expect(lost).toContainText("could not be read");
  await popup.close();
  await page.close();
});

test("an unread fact turns the counter amber whatever the verdict, proved where the verdict alone would not", async () => {
  // An UNKNOWN verdict draws the counter in secondary text, so amber here can
  // only come from the unread fact.
  const host = "risky-unknown-unread-guard-e2e.com";
  seed(host, { band: "UNKNOWN", coverage: "no-data", label: "unknown", ageDays: 5 });
  net.failQueries.add("AS_PRESENT_AT");
  const { popup, page } = await openSite(`https://${host}/`, { icon: ["unknown"] });
  await protectionDrawn(popup, host);
  await expect(popup.locator("#band-chip")).toHaveText("UNKNOWN");
  await expect(popup.locator("#facts-count")).toHaveText("6/7 facts read");
  const drawn = await popup.locator("#facts-count .pp-count-n").evaluate((e) => getComputedStyle(e).color);
  expect(drawn, "the unread fact did not turn the figure amber").toBe(await tokenColor(popup, "--w-v-low", "color"));
  expect(drawn).not.toBe(await tokenColor(popup, "--w-text-2", "color"));
  await popup.close();
  await page.close();
});

// -------------------------------------------------------------------- hover

/** The contrast of an element's ink on its own fill as drawn, with a brightness
 *  filter applied the way the browser applies it. */
async function inkOnFill(popup: Page, selector: string): Promise<number> {
  return popup.evaluate((sel) => {
    const el = document.querySelector<HTMLElement>(sel)!;
    const cs = getComputedStyle(el);
    const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
    const rgb = (v: string): number[] => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = "#000000";
      ctx.fillStyle = v;
      ctx.fillRect(0, 0, 1, 1);
      return [...ctx.getImageData(0, 0, 1, 1).data].slice(0, 3);
    };
    const k = /brightness\(([\d.]+)\)/.exec(cs.filter)?.[1];
    const factor = k ? Number(k) : 1;
    const lum = (c: number[]): number => {
      const [r, g, b] = c.map((x) => {
        const v = Math.min(255, x * factor) / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
    };
    const bg = lum(rgb(cs.backgroundColor));
    const ink = lum(rgb(cs.color));
    const [hi, lo] = bg > ink ? [bg, ink] : [ink, bg];
    return (hi + 0.05) / (lo + 0.05);
  }, selector);
}

test("Go to the real site keeps its text at 4.5:1 or better at rest and on hover, in the dark and the light scheme", async () => {
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite(`https://${UNKNOWN_LOOKALIKE}/`, { colorScheme: scheme, icon: ["suspicious"] });
    const rest = await inkOnFill(popup, "#btn-goto");
    await popup.locator("#btn-goto").hover();
    const hover = await inkOnFill(popup, "#btn-goto");
    test.info().annotations.push({ type: `goto ${scheme}`, description: `rest ${rest.toFixed(2)} hover ${hover.toFixed(2)}` });
    expect(rest, `${scheme}: at rest`).toBeGreaterThanOrEqual(4.5);
    expect(hover, `${scheme}: on hover`).toBeGreaterThanOrEqual(4.5);
    await popup.close();
    await page.close();
  }
});

// -------------------------------------------------------------------- R4b

test("the facts counter is green only on a clean verdict: amber on a suspicious one, secondary text on an UNKNOWN one", async () => {
  const figure = (popup: Page): Promise<string> =>
    popup.locator("#facts-count .pp-count-n").evaluate((e) => getComputedStyle(e).color);

  for (const scheme of ["dark", "light"] as const) {
    // Clean: the one place the figure is green.
    {
      const { popup, page } = await openSite(`https://${CLEAN}/`, { colorScheme: scheme, icon: ["benign", "unknown"] });
      await expect(popup.locator("#facts-count")).toHaveText("7/7 facts read");
      expect(await figure(popup), `${scheme}: clean`).toBe(await tokenColor(popup, "--w-ok", "color"));
      await popup.close();
      await page.close();
    }
    // Suspicious: the verdict's amber.
    {
      const { popup, page } = await openSite(`https://${SUSPICIOUS}/`, { colorScheme: scheme, icon: ["suspicious"] });
      await expect(popup.locator("#facts-count")).toHaveText("7/7 facts read");
      expect(await figure(popup), `${scheme}: suspicious`).toBe(await tokenColor(popup, "--w-v-low", "color"));
      await popup.close();
      await page.close();
    }
    // UNKNOWN: secondary text, never green.
    {
      const { popup, page } = await openSite(`https://${UNKNOWN_LOOKALIKE}/`, { colorScheme: scheme, icon: ["suspicious"] });
      await protectionDrawn(popup, UNKNOWN_LOOKALIKE);
      await expect(popup.locator("#band-chip")).toHaveText("UNKNOWN");
      expect(await figure(popup), `${scheme}: unknown`).toBe(await tokenColor(popup, "--w-text-2", "color"));
      expect(await greens(popup, "#chain-card"), `${scheme}: green in the facts card of an UNKNOWN verdict`).toEqual([]);
      await popup.close();
      await page.close();
    }
  }
});

// -------------------------------------------------------------------- R5

test("an UNKNOWN live verdict is never drawn green, in the dark and the light scheme", async () => {
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite(`https://${UNKNOWN_LOOKALIKE}/`, { colorScheme: scheme, icon: ["suspicious"] });
    await protectionDrawn(popup, UNKNOWN_LOOKALIKE);
    await expect(popup.locator("#band-chip")).toHaveText("UNKNOWN");
    await expect(popup.locator("#band-note")).toHaveText(
      "The graph has no evidence on this name yet. Absence of evidence is not safety.",
    );
    expect(await greens(popup, "#host-row"), `${scheme}: green on an UNKNOWN verdict`).toEqual([]);
    await popup.close();
    await page.close();
  }

  // CONTROL: the same walk does find green on a clean site, so it can fail.
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite(`https://${CLEAN}/`, { colorScheme: scheme, icon: ["benign", "unknown"] });
    await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
    expect((await greens(popup, "#host-row")).length, `${scheme}: the check cannot find green on a clean site`).toBeGreaterThan(0);
    await popup.close();
    await page.close();
  }
});
