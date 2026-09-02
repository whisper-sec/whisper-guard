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
// laid out, whether the verdict rail actually has height, whether anything
// overflows the 400-pixel panel sideways. Those are the failures that
// happen, and they are the ones a screenshot diff would report as "1200
// pixels changed" without saying why.

import { test, expect, chromium, firefox, type Browser, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
  getScale: { ok: true, scale: { nodes: 7482240523, edges: 39546784832, objects: 47029025355, identities: 649, queries: 5699066, windowHours: 24, p50Us: 30, p99Us: 76083, pulse: Array.from({length: 48}, (_, i) => 18000 + Math.round(6000 * Math.sin(i / 7))), updated: Date.now(), degraded: false } },
  getQuota: { ok: true, quota: { plan: "ANONYMOUS", anonymous: true, hourlyLimit: 100, hourlyRemaining: 94, dailyLimit: 500, dailyRemaining: 466, maxDepth: 2 } },
  getWins: { ok: true, wins: { date: "2026-09-02", total: 3, counts: { preemptBlock: 1, identityVerified: 1, cookieDecline: 1 } } },
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
  railHeight: number;
  bodyScrollWidth: number;
  bodyClientWidth: number;
  scaleVisible: boolean;
  sparkPaths: number;
  tierWidthPct: number;
  chainLabels: string[];
}

async function measure(browser: Browser, scheme: "dark" | "light"): Promise<Geometry> {
  const page: Page = await browser.newPage({
    viewport: { width: 400, height: 900 },
    colorScheme: scheme,
    reducedMotion: "reduce",
  });
  await page.addInitScript(SHIM);
  await page.goto(`file://${join(DIST, "popup.html")}`);
  await page.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 15_000 });
  await page.waitForTimeout(600);

  const g = await page.evaluate((): Geometry => {
    const rail = document.getElementById("band-rail");
    const fill = document.getElementById("tier-fill");
    const scale = document.getElementById("scale");
    return {
      rungs: document.querySelectorAll("#chain-mount .ch-rung").length,
      liveRungs: document.querySelectorAll("#chain-mount .ch-rung.ch-live").length,
      railHeight: rail ? rail.getBoundingClientRect().height : 0,
      bodyScrollWidth: document.body.scrollWidth,
      bodyClientWidth: document.body.clientWidth,
      scaleVisible: scale ? !scale.hasAttribute("hidden") : false,
      sparkPaths: document.querySelectorAll("#scale-pulse svg path").length,
      tierWidthPct: fill ? (fill.getBoundingClientRect().width / 340) * 100 : -1,
      chainLabels: [...document.querySelectorAll("#chain-mount .ch-label")].map(
        (e) => e.textContent ?? "",
      ),
    };
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
    expect(blink.railHeight, "the verdict rail has no height in Blink").toBeGreaterThan(20);

    // The spine: same count, same rungs, same order, in both engines.
    expect(gecko.rungs, "Gecko laid out a different number of rungs").toBe(blink.rungs);
    expect(gecko.liveRungs).toBe(blink.liveRungs);
    expect(gecko.chainLabels).toEqual(blink.chainLabels);
    expect(gecko.chainLabels).toEqual([
      "NAME",
      "RUNS ON",
      "ADDRESS",
      "PREFIX",
      "NETWORK",
      "OPERATOR",
      "PRESENT AT",
    ]);

    // The verdict rail is a stretched flex child, which is exactly the kind
    // of thing that collapses to zero in one engine and not the other.
    expect(gecko.railHeight, "the verdict rail collapsed in Gecko").toBeGreaterThan(20);

    // The live readouts really drew: an inline SVG path and a filled meter.
    expect(gecko.scaleVisible && blink.scaleVisible, "the scale readout did not appear").toBe(true);
    expect(gecko.sparkPaths, "Gecko drew no pulse").toBeGreaterThan(0);
    expect(blink.sparkPaths, "Blink drew no pulse").toBeGreaterThan(0);
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

test("the built Firefox manifest is the one under test", () => {
  // The shim renders dist/firefox, so this pins that the tree it renders is
  // the Firefox build and not a stale copy of the Chromium one.
  const m = JSON.parse(readFileSync(join(DIST, "manifest.json"), "utf8")) as Record<string, unknown>;
  expect(m["manifest_version"]).toBe(3);
  expect(JSON.stringify(m["optional_permissions"])).toContain("proxy");
});
