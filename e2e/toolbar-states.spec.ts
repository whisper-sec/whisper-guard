// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Each toolbar state is a tile with its symbol drawn in; the badge text stays
// empty and the title names the state in words. The badge is read back through
// the extension API and the tile through the shipped PNG files. A browser
// toolbar cannot be read.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { E2ENetwork, MOCK_API_KEY } from "./helpers/servers";
import {
  badgeText,
  DIST_CHROMIUM,
  extensionPage,
  iconState,
  launchExtension,
  navigateInTab,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
  type IconState,
} from "./helpers/extension";

const DIST_FIREFOX = join(DIST_CHROMIUM, "..", "firefox");

let net: E2ENetwork;
let ext: Extension;

const CASES: { host: string; state: IconState }[] = [
  { host: "badge-clean-guard-e2e.com", state: "benign" },
  { host: "badge-medium-guard-e2e.com", state: "suspicious" },
  { host: "badge-critical-guard-e2e.com", state: "malicious" },
  { host: "badge-norow-guard-e2e.com", state: "unknown" },
];

const SLOW_HOST = "badge-slow-guard-e2e.com";
const MOVING_HOST = "badge-moving-guard-e2e.com";
const SWITCH_HOST = "badge-switch-guard-e2e.com";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("github.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict(CASES[0]!.host, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict(CASES[1]!.host, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setVerdict(CASES[2]!.host, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  for (const h of [SLOW_HOST, MOVING_HOST, SWITCH_HOST]) {
    net.setVerdict(h, { band: "NONE", coverage: "known-clean", label: "clean" });
  }
  ext = await launchExtension({ proxyPort: net.proxyPort });
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

test.afterEach(() => {
  net.assessDelayMs.clear();
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

for (const c of CASES) {
  test(`the ${c.state} tile shows no badge text, also on a second page of the same site`, async () => {
    const { page, tabId } = await visit(ext, `https://${c.host}/`);
    await waitForIcon(ext, tabId, [c.state]);
    expect(await badgeText(ext, tabId)).toBe("");

    await navigateInTab(page, `https://${c.host}/second`);
    await waitForIcon(ext, tabId, [c.state]);
    // Past the navigation debounce, so a stale read of the first page cannot pass.
    await page.waitForTimeout(600);
    expect(await iconState(ext, tabId)).toBe(c.state);
    expect(await badgeText(ext, tabId)).toBe("");
    await page.close();
  });
}

test("a tab being checked shows the checking tile and then its verdict's tile, with no badge text", async () => {
  net.assessDelayMs.set(SLOW_HOST, 2000);
  const { page, tabId } = await visit(ext, `https://${SLOW_HOST}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  expect(await badgeText(ext, tabId)).toBe("");

  await waitForIcon(ext, tabId, ["benign"]);
  expect(await badgeText(ext, tabId)).toBe("");
  await page.close();
});

test("a page that is not checked has no badge", async () => {
  const { page, tabId } = await visit(ext, `https://${MOVING_HOST}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  await navigateInTab(page, `chrome-extension://${ext.id}/options.html`);
  await waitForIcon(ext, tabId, ["neutral"]);
  // Sampled past the debounce: the default title equals this state's title,
  // so only samples taken after the paint prove it.
  const seen = new Set<string>();
  const until = Date.now() + 1500;
  while (Date.now() < until) {
    seen.add(`${await badgeText(ext, tabId)}|${await iconState(ext, tabId)}`);
    await new Promise((r) => setTimeout(r, 50));
  }
  expect([...seen]).toEqual(["|neutral"]);
  await page.close();
});

test("the badge text stays empty when a tab moves to another state and no page loads", async () => {
  const { page, tabId } = await visit(ext, `https://${SWITCH_HOST}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  expect(await badgeText(ext, tabId)).toBe("");

  const via = await extensionPage(ext);
  try {
    await setSettings(ext, { cloudCheck: false });
    await via.evaluate((key) => chrome.runtime.sendMessage({ kind: "saveKey", key }), MOCK_API_KEY);
    await waitForIcon(ext, tabId, ["signedout"]);
    expect(await badgeText(ext, tabId)).toBe("");
  } finally {
    await via.evaluate(() => chrome.runtime.sendMessage({ kind: "signOut" }));
    await setSettings(ext, { cloudCheck: true });
    await page.close();
  }
});

// ------------------------------------------------------------ tile pixels

interface Px {
  r: number;
  g: number;
  b: number;
  a: number;
}

/** Read pixels of a shipped tile from an extension page, by drawing it on a canvas. */
async function readTile(file: string, points: [number, number][]): Promise<Px[]> {
  const via = await extensionPage(ext);
  return via.evaluate(
    async ([path, pts]) => {
      const img = new Image();
      img.src = chrome.runtime.getURL(path as string);
      await img.decode();
      const cv = document.createElement("canvas");
      cv.width = img.naturalWidth;
      cv.height = img.naturalHeight;
      const cx = cv.getContext("2d")!;
      cx.drawImage(img, 0, 0);
      return (pts as [number, number][]).map(([x, y]) => {
        const d = cx.getImageData(x, y, 1, 1).data;
        return { r: d[0]!, g: d[1]!, b: d[2]!, a: d[3]! };
      });
    },
    [file, points] as const,
  );
}

const rgb = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as [number, number, number];

function expectColour(px: Px, hex: string, tol: number, what: string): void {
  const [r, g, b] = rgb(hex);
  expect(px.a, `${what}: alpha`).toBe(255);
  expect(Math.abs(px.r - r), `${what}: red (${px.r})`).toBeLessThanOrEqual(tol);
  expect(Math.abs(px.g - g), `${what}: green (${px.g})`).toBeLessThanOrEqual(tol);
  expect(Math.abs(px.b - b), `${what}: blue (${px.b})`).toBeLessThanOrEqual(tol);
}

// The five verdict tiles are inset: column 0 of the 32 px tile (and of the 16 px
// tile, half) is transparent, the rim starts at column 2, and the ground sits
// inside it. Coordinates were read from the shipped files. `ink` is the mark
// colour and `badge` the ground of the drawn symbol in the tile's corner.
interface Tile {
  state: IconState;
  ground: string;
  /** The ring (rim) colour read at 32 px (2, 16); equal to the ground where there is none. */
  rim: string;
  /** Ground of the drawn symbol, at 32 px. */
  badge: { at: [number, number]; hex: string };
  /** Mark colour at 128 px (52, 40). */
  ink: string;
}

const TILES: Tile[] = [
  { state: "benign", ground: "#0b2a22", rim: "#10b981", badge: { at: [22, 22], hex: "#34d399" }, ink: "#9b7cf0" },
  { state: "suspicious", ground: "#4a3105", rim: "#f59e0b", badge: { at: [22, 22], hex: "#f59e0b" }, ink: "#9b7cf0" },
  { state: "malicious", ground: "#b8202a", rim: "#b8202a", badge: { at: [22, 22], hex: "#ef4444" }, ink: "#ffffff" },
  { state: "unknown", ground: "#1a1a2e", rim: "#8888a0", badge: { at: [23, 26], hex: "#c3c3cd" }, ink: "#ffffff" },
  { state: "checking", ground: "#1d1240", rim: "#7d5ce0", badge: { at: [22, 22], hex: "#7d5ce0" }, ink: "#9b7cf0" },
];

for (const t of TILES) {
  test(`the ${t.state} tile carries its ground, rim, drawn symbol and mark at 16 and 32 px`, async () => {
    const [outside32, rim32, ground32, badge32] = await readTile(`icons/${t.state}-32.png`, [[0, 16], [2, 16], [5, 16], t.badge.at]);
    expect(outside32!.a, "32 px, column 0 is transparent").toBe(0);
    expectColour(rim32!, t.rim, 20, "32 px, rim");
    expectColour(ground32!, t.ground, 20, "32 px, inside the rim");
    expectColour(badge32!, t.badge.hex, 20, "32 px, drawn symbol ground");
    const [ground16] = await readTile(`icons/${t.state}-16.png`, [[2, 8]]);
    expectColour(ground16!, t.ground, 32, "16 px, inside the rim");
    const [mark128] = await readTile(`icons/${t.state}-128.png`, [[52, 40]]);
    expectColour(mark128!, t.ink, 20, "128 px, mark");
  });
}

test("the not-checked tile carries its ground to the edge at 16 and 32 px", async () => {
  const [edge32, ground32] = await readTile("icons/neutral-32.png", [[0, 16], [3, 16]]);
  expectColour(edge32!, "#1a1a2e", 20, "32 px, left edge");
  expectColour(ground32!, "#1a1a2e", 20, "32 px, inside");
  const [ground16] = await readTile("icons/neutral-16.png", [[1, 8]]);
  expectColour(ground16!, "#1a1a2e", 32, "16 px, inside");
});

test("the unknown outline is dashed: a dash on the top rim, ground in the gap", async () => {
  const [dash, gap] = await readTile("icons/unknown-32.png", [[9, 2], [13, 2]]);
  expectColour(dash!, "#8888a0", 20, "row 2, in a dash");
  expectColour(gap!, "#1a1a2e", 20, "row 2, in a gap");
});

test("the not-checked tile is not the listing icon", () => {
  const a = readFileSync(join(DIST_CHROMIUM, "icons", "neutral-32.png"));
  const b = readFileSync(join(DIST_CHROMIUM, "icons", "base-32.png"));
  expect(a.equals(b)).toBe(false);
});

test("both packages ship the same tile for every state and size", () => {
  const states = ["benign", "suspicious", "malicious", "unknown", "checking", "signedout", "neutral"];
  for (const s of states) {
    for (const size of [16, 32, 48, 128]) {
      const f = join("icons", `${s}-${size}.png`);
      const chromium = readFileSync(join(DIST_CHROMIUM, f));
      const firefox = readFileSync(join(DIST_FIREFOX, f));
      expect(chromium.equals(firefox), f).toBe(true);
    }
  }
});
