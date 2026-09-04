// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE SURVEY. Not a gallery and not a gate: a census.
//
// Before a surface is redesigned it gets photographed as it stands, at the
// real popup width, in a real browser, against the hermetic mock network.
// Every capture is full-page, and every one is measured: content height
// against the viewport a reader actually gets, so "the page runs out of
// content" is a number rather than an impression.
//
//   npx playwright test e2e/survey.spec.ts
//
// Output: docs/survey/*.png plus docs/survey/measurements.json.
//
// The measurements file is the point. A screenshot shows what a surface
// looks like; the numbers beside it say how much of the viewport it filled
// and how many of its facts were drawn rather than written as a sentence.

import { test, expect } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openDashboard,
  openPopup,
  setKey,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, "../docs/survey");

const EVIL = "paypa1-secure-login.com";
const GOOD = "news.mediaco-vendor.com";
const NEW = "news-blog-example.com";

/** The height Chrome actually gives a popup before it starts scrolling. */
const POPUP_VIEWPORT = 600;
const POPUP_WIDTH = 400;

let net: E2ENetwork;
let ext: Extension;

interface Measurement {
  surface: string;
  file: string;
  /** Full rendered height of the document. */
  contentHeight: number;
  /** Height a reader gets without scrolling. */
  viewportHeight: number;
  /** Fraction of the first viewport that carries no drawn mark. */
  deadFractionFirstViewport: number;
  /** Elements that draw a value as a mark: svg, canvas, meter tracks, rails. */
  drawnMarks: number;
  /** Text nodes carrying a number the reader has to parse from prose. */
  narratedFacts: number;
  /** Elements that change on their own after load, without an input. */
  selfAnimating: number;
}

const measurements: Measurement[] = [];

/**
 * Count what a surface DRAWS versus what it NARRATES.
 *
 * A drawn mark is any element whose geometry encodes a value: an svg, a
 * canvas, a fill whose width is a percentage of a track, a rail whose colour
 * is the verdict. A narrated fact is a number that arrives as text inside a
 * sentence and has no mark beside it. The ratio is the whole argument of
 * this survey, so it is measured rather than asserted.
 */
async function census(page: Page): Promise<{
  drawnMarks: number;
  narratedFacts: number;
  selfAnimating: number;
  contentHeight: number;
  deadFractionFirstViewport: number;
}> {
  return page.evaluate((viewport: number) => {
    const visible = (el: Element): boolean => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) return false;
      const s = getComputedStyle(el);
      return s.display !== "none" && s.visibility !== "hidden" && Number(s.opacity) > 0.05;
    };

    const marks = [...document.querySelectorAll("svg, canvas, [data-mark], .tier-fill, .band-rail, .ch-rail, .spark, .ratio-bar, .ch-ratio")]
      .filter(visible).length;

    // Numbers living in text with no mark inside the same block.
    let narrated = 0;
    const numRe = /\b\d[\d,.]*\s*(%|B|M|K|nodes|edges|of|listed|announced|queries|blocked|days?|hours?|ago)?/i;
    for (const el of document.querySelectorAll("p, span, div, li, td")) {
      if (!visible(el)) continue;
      if (el.children.length > 0) continue; // leaf text only
      const t = (el.textContent ?? "").trim();
      if (t.length === 0 || t.length > 120) continue;
      if (!numRe.test(t)) continue;
      if (!/\d/.test(t)) continue;
      const block = el.closest("section, .w-card, .panel, .ch-rung, .tier, li") ?? el;
      if (block.querySelector("svg, canvas, .tier-fill, .band-rail, .ch-rail, .spark, .ratio-bar, .ch-ratio")) continue;
      narrated++;
    }

    // Anything with a running CSS animation or transition at census time.
    let animating = 0;
    for (const el of document.querySelectorAll("*")) {
      if (!visible(el)) continue;
      const anims = (el as HTMLElement).getAnimations?.() ?? [];
      if (anims.some((a) => a.playState === "running")) animating++;
    }

    const contentHeight = Math.max(
      document.documentElement.scrollHeight,
      document.body.scrollHeight,
    );

    // Dead space in the FIRST viewport: sample a grid and ask whether any
    // painted element covers each point. A point covered only by <body> or
    // <html> is dead.
    const cols = 8;
    const rows = 24;
    let dead = 0;
    let total = 0;
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const x = ((c + 0.5) / cols) * window.innerWidth;
        const y = ((r + 0.5) / rows) * Math.min(viewport, contentHeight);
        if (y > contentHeight) continue;
        total++;
        const el = document.elementFromPoint(x, y);
        if (!el || el === document.body || el === document.documentElement) {
          dead++;
          continue;
        }
        // A container with no text and no mark of its own at this point is
        // padding, which reads as dead to the eye even though it hit an
        // element.
        const hasInk =
          (el.textContent ?? "").trim().length > 0 ||
          el.matches("svg, canvas, img, input, button, .tier-fill, .band-rail, .ch-rail") ||
          el.querySelector("svg, canvas, img") !== null;
        if (!hasInk) dead++;
      }
    }

    return {
      drawnMarks: marks,
      narratedFacts: narrated,
      selfAnimating: animating,
      contentHeight,
      deadFractionFirstViewport: total === 0 ? 0 : dead / total,
    };
  }, POPUP_VIEWPORT);
}

async function record(page: Page, surface: string, file: string, viewportHeight: number): Promise<void> {
  const c = await census(page);
  measurements.push({
    surface,
    file,
    contentHeight: c.contentHeight,
    viewportHeight,
    deadFractionFirstViewport: Number(c.deadFractionFirstViewport.toFixed(3)),
    drawnMarks: c.drawnMarks,
    narratedFacts: c.narratedFacts,
    selfAnimating: c.selfAnimating,
  });
  await page.screenshot({ path: join(OUT, file), fullPage: true });
}

async function surveyPopup(
  tabId: number,
  surface: string,
  file: string,
  scheme: "dark" | "light" = "dark",
): Promise<void> {
  const popup = await openPopup(ext, tabId);
  await popup.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
  await popup.setViewportSize({ width: POPUP_WIDTH, height: POPUP_VIEWPORT });
  await popup.reload();
  await popup.locator("#chain-mount .ch-rung").first().waitFor({ timeout: 15_000 }).catch(() => undefined);
  await popup.waitForTimeout(900);
  await popup.addStyleTag({ content: "header { position: static !important; }" });
  await record(popup, surface, file, POPUP_VIEWPORT);
  await popup.close();
}

async function surveyPage(
  url: string,
  surface: string,
  file: string,
  height = 900,
  width = 1280,
): Promise<void> {
  const page = await ext.context.newPage();
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.setViewportSize({ width, height });
  await page.goto(url);
  await page.waitForTimeout(1500);
  await record(page, surface, file, height);
  await page.close();
}

// ------------------------------------------------------------------ fixture

test.beforeAll(async () => {
  mkdirSync(OUT, { recursive: true });
  net = new E2ENetwork();
  await net.start();

  // The bulletproof marker rides the ASSESS verdict, because that is where
  // the resolver looks for it.
  net.setVerdict(EVIL, {
    band: "CRITICAL", coverage: "partial", label: "credential-phishing suspect",
    subLabels: ["bulletproof-hosting"],
  });
  net.setEnrich(EVIL, {
    ip: "192.0.2.66", city: "Montreal, CA", country: "CA", asn: "AS64550",
    owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC",
    prefix: "192.0.2.0/24", threatNeighbors: 9, verdict: "CRITICAL",
  });
  net.setPresence("AS64550", { facilities: ["Example Colo MTL1"], exchanges: [], facilityCount: 1 });
  net.setIdentify(EVIL, []);
  net.setExplain(EVIL, [{
    indicator: EVIL, type: "domain", found: true, level: "CRITICAL", score: 17.2,
    explanation: `${EVIL} is listed in 2 threat feed(s).`,
    sources: [{ feedId: "openphish", firstSeen: "2026-07-02T00:00:00Z" }],
  }]);
  net.setHistory(EVIL, [{ createDate: "2026-08-19T00:00:00Z", updateDate: "2026-08-19T00:00:00Z" }]);

  net.setVerdict(GOOD, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setEnrich(GOOD, {
    ip: "198.51.100.40", city: "London, GB", country: "GB", asn: "AS64540",
    owner: "MediaCo plc", asnName: "MEDIACO - MediaCo plc",
    prefix: "198.51.100.0/24", threatNeighbors: 0, prevalence: 812, verdict: "NONE",
  });
  net.setIdentify(GOOD, [{
    host: GOOD, canonical_name: "MediaCo", category: "media",
    roles: ["DNS_OPERATOR", "ORIGIN_AS"], confidence: 0.85, host_class: "single_tenant",
    evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco", "band=DERIVED"],
  }]);
  net.setDensity("AS64540", { listedIps: 5, announcedIpv4: 9216, routedPrefixes: 24 });
  net.setPresence("AS64540", {
    facilities: ["Example Carrier Hotel LON1", "Example Colo LON2", "Example Halls LON3"],
    exchanges: ["Example Exchange LON", "Example Peering Point"],
    facilityCount: 14, exchangeCount: 4,
  });
  net.setVerdict(NEW, { band: "UNKNOWN", coverage: "no-data", label: null });

  // The facts the protection presets key on. EVIL is on the graph's own
  // blocking verdict and sits on a network classed as bulletproof; GOOD is
  // answered for and matches nothing; NEW is deliberately absent, so the
  // governor has a real "not in the graph" count to draw rather than a
  // capture in which every destination happens to be known.
  net.setPolicyFacts(EVIL, { band: "CRITICAL", sanctioned: true, countries: ["CA"] });
  net.setPolicyFacts(GOOD, { band: "NONE", countries: ["GB"] });

  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  writeFileSync(join(OUT, "measurements.json"), JSON.stringify(measurements, null, 2) + "\n");
  await ext?.close();
  await net?.stop();
});

// ------------------------------------------------------------------ captures

test("survey: the popup, signed out, on a flagged site", async () => {
  const { page, tabId } = await visit(ext, `https://${EVIL}/signin`);
  await waitForIcon(ext, tabId, ["malicious"]);
  await surveyPopup(tabId, "popup / signed out / flagged site", "popup-signedout-flagged.png");
  await page.close();
});

test("survey: the popup, signed out, on an ordinary site", async () => {
  const { page, tabId } = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await surveyPopup(tabId, "popup / signed out / ordinary site", "popup-signedout-ordinary.png");
  await surveyPopup(tabId, "popup / signed out / ordinary site / light", "popup-signedout-ordinary-light.png", "light");
  await page.close();
});

test("survey: the popup, signed out, on a name the graph has never seen", async () => {
  const { page, tabId } = await visit(ext, `https://${NEW}/`);
  await waitForIcon(ext, tabId, ["unknown"]);
  await surveyPopup(tabId, "popup / signed out / unknown name", "popup-signedout-unknown.png");
  await page.close();
});

test("survey: the popup, signed in", async () => {
  const now = Date.now();
  net.addEndpoint({
    agent: "agent-surveylaptop", address: "2a04:2a01:5ec5:2::b2", label: "This browser",
    device: true, created: now - 6 * 86_400_000,
    counters: {
      dns_queries: 2210, dns_blocked: 18, dns_nxdomain: 47, connections_total: 30,
      bytes_up: 3_407_872, bytes_down: 48_234_496, last_seen: now - 4 * 60_000,
    },
    // The endpoint view is a picture of an endpoint that GOES somewhere. It
    // used to be captured with an empty log, so the census measured a page
    // whose whole subject - where this endpoint went and what the settings
    // would do about it - was absent from the frame.
    logs: [
      { ts: now - 60_000, kind: "dns", qname: `${GOOD}.`, qtype: "A", decision: "allow", agent: "agent-surveylaptop" },
      { ts: now - 120_000, kind: "dns", qname: `${GOOD}.`, qtype: "AAAA", decision: "allow", agent: "agent-surveylaptop" },
      { ts: now - 180_000, kind: "dns", qname: `${EVIL}.`, qtype: "A", decision: "block", agent: "agent-surveylaptop" },
      { ts: now - 240_000, kind: "dns", qname: `${NEW}.`, qtype: "A", decision: "allow", agent: "agent-surveylaptop" },
      { ts: now - 300_000, kind: "conn", peer: GOOD, agent: "agent-surveylaptop", bytes_up: 91_000, bytes_down: 1_200_000 },
    ],
  });
  await setKey(ext, MOCK_KEY);
  const { page, tabId } = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await surveyPopup(tabId, "popup / signed in / not enrolled", "popup-signedin.png");
  await page.close();
});

test("survey: the dashboard, all three views", async () => {
  await setKey(ext, MOCK_KEY);
  for (const [view, surface, file] of [
    ["", "dashboard / this browser", "dashboard-this-browser.png"],
    ["fleet", "dashboard / fleet", "dashboard-fleet.png"],
    ["endpoint", "dashboard / endpoint", "dashboard-endpoint.png"],
  ] as const) {
    const page = await openDashboard(ext, view);
    await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.waitForTimeout(2000);
    await record(page, surface, file, 900);
    await page.close();
  }
});

test("survey: the standalone pages", async () => {
  await surveyPage(`chrome-extension://${ext.id}/options.html`, "options", "options.png");
  await surveyPage(`chrome-extension://${ext.id}/firstrun.html`, "first run", "firstrun.png");
  await surveyPage(
    `chrome-extension://${ext.id}/warning.html?host=${EVIL}&band=CRITICAL`,
    "warning interstitial",
    "warning.png",
  );
  // Its REAL geometry: context-menu opens it as a 420x560 popup window, so
  // capturing it at 1280x900 measures a window nobody ever sees and
  // reports dead space the product does not have.
  await surveyPage(
    `chrome-extension://${ext.id}/check-link.html?host=${EVIL}`,
    "check a link",
    "check-link.png",
    560,
    420,
  );
});

test("survey: the census found real surfaces", async () => {
  // A survey that measured nothing would still write a file. Control.
  expect(measurements.length).toBeGreaterThanOrEqual(10);
  expect(measurements.every((m) => m.contentHeight > 100)).toBe(true);
});
