// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Each toolbar state is a tile plus a short text badge, set in one paint with
// the title last. The expected texts and colours are typed here on purpose:
// the spec pins what a person sees, not what the product's own table says.
// A browser toolbar cannot be read, so the badge is read back through the
// extension API and the tile through the shipped PNG files.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { E2ENetwork, MOCK_API_KEY } from "./helpers/servers";
import {
  badgeColors,
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

const WHITE = [255, 255, 255, 255];
const DARK_INK = [6, 6, 12, 255];

const CASES: { host: string; state: IconState; text: string; ground: number[]; ink: number[] }[] = [
  { host: "badge-clean-guard-e2e.com", state: "benign", text: "✓", ground: [52, 211, 153, 255], ink: DARK_INK },
  { host: "badge-medium-guard-e2e.com", state: "suspicious", text: "!", ground: [245, 158, 11, 255], ink: [28, 25, 23, 255] },
  { host: "badge-critical-guard-e2e.com", state: "malicious", text: "STOP", ground: [184, 32, 42, 255], ink: WHITE },
  { host: "badge-norow-guard-e2e.com", state: "unknown", text: "?", ground: [195, 195, 205, 255], ink: DARK_INK },
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
  test(`the ${c.state} badge stays with its tile, also on a second page of the same site`, async () => {
    const { page, tabId } = await visit(ext, `https://${c.host}/`);
    await waitForIcon(ext, tabId, [c.state]);
    expect(await badgeText(ext, tabId)).toBe(c.text);
    expect(await badgeColors(ext, tabId)).toEqual({ ground: c.ground, ink: c.ink });

    await navigateInTab(page, `https://${c.host}/second`);
    await waitForIcon(ext, tabId, [c.state]);
    // Past the navigation debounce, so a stale read of the first page cannot pass.
    await page.waitForTimeout(600);
    expect(await iconState(ext, tabId)).toBe(c.state);
    expect(await badgeText(ext, tabId)).toBe(c.text);
    expect(await badgeColors(ext, tabId)).toEqual({ ground: c.ground, ink: c.ink });
    await page.close();
  });
}

test("a tab being checked shows the checking badge and then its verdict's badge", async () => {
  net.assessDelayMs.set(SLOW_HOST, 2000);
  const { page, tabId } = await visit(ext, `https://${SLOW_HOST}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  expect(await badgeText(ext, tabId)).toBe("…");
  expect((await badgeColors(ext, tabId)).ground).toEqual([125, 92, 224, 255]);

  await waitForIcon(ext, tabId, ["benign"]);
  expect(await badgeText(ext, tabId)).toBe("✓");
  await page.close();
});

test("a page that is not checked has no badge", async () => {
  const { page, tabId } = await visit(ext, `https://${MOVING_HOST}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  expect(await badgeText(ext, tabId)).toBe("✓");

  await navigateInTab(page, `chrome-extension://${ext.id}/options.html`);
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if ((await badgeText(ext, tabId)) === "" && (await iconState(ext, tabId)) === "neutral") break;
    await new Promise((r) => setTimeout(r, 100));
  }
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

test("the badge is cleared when a tab moves to a state without one and no page loads", async () => {
  const { page, tabId } = await visit(ext, `https://${SWITCH_HOST}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  expect(await badgeText(ext, tabId)).toBe("✓");

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

const TILES: { state: IconState; ground: string; edge: string }[] = [
  { state: "benign", ground: "#0c3d2e", edge: "#10b981" },
  { state: "suspicious", ground: "#4a3105", edge: "#f59e0b" },
  { state: "malicious", ground: "#b8202a", edge: "#b8202a" },
  { state: "unknown", ground: "#1a1a2e", edge: "#8888a0" },
  { state: "checking", ground: "#1d1240", edge: "#7d5ce0" },
  { state: "neutral", ground: "#1a1a2e", edge: "#1a1a2e" },
];

for (const t of TILES) {
  test(`the ${t.state} tile carries its ground and its outline at 16 and 32 px`, async () => {
    const [edge32, ground32] = await readTile(`icons/${t.state}-32.png`, [[0, 16], [3, 16]]);
    expectColour(edge32!, t.edge, 20, "32 px, left edge");
    expectColour(ground32!, t.ground, 20, "32 px, inside the outline");
    const [ground16] = await readTile(`icons/${t.state}-16.png`, [[1, 8]]);
    expectColour(ground16!, t.ground, 32, "16 px, inside the outline");
  });
}

test("the unknown outline is dashed: a dash on the top edge, ground in the gap", async () => {
  const [dash, gap] = await readTile("icons/unknown-32.png", [[16, 0], [10, 0]]);
  expectColour(dash!, "#8888a0", 20, "top edge, middle");
  expectColour(gap!, "#1a1a2e", 20, "top edge, in a gap");
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
