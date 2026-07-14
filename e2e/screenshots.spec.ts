// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Phase C: the screenshot gallery, captured from the REAL built extension
// against the hermetic mock network (no real hosts are contacted and no
// key appears anywhere). Run on demand:
//
//   npx playwright test e2e/screenshots.spec.ts
//
// Output: shots/*.png plus the composed toolbar-state strip. The gallery
// page (shots/index.html) references these files.

import { test, expect } from "@playwright/test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(HERE, "../shots");
const ICONS = resolve(HERE, "../icons");

const MOCK_KEY = "whisper_e2e_mock_key_0000000000000000";
const LOOKALIKE = "paypa1-secure-login.com";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  mkdirSync(SHOTS, { recursive: true });
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(LOOKALIKE, { band: "CRITICAL", coverage: "partial", label: "credential-phishing suspect" });
  net.setVerdict("news-blog-example.com", { band: "UNKNOWN", coverage: "no-data", label: null });
  net.setVerdict("intranet-tools-vendor.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict("paypa1-secure-login.net", { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  net.setVerdict("paypa1-secure-login.org", { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setExplain(LOOKALIKE, [
    {
      indicator: LOOKALIKE,
      type: "domain",
      level: "CRITICAL",
      score: 17.2,
      explanation: `${LOOKALIKE} is listed in 5 threat feed(s).`,
      sources: [
        { feedId: "openphish", firstSeen: "2026-07-02T00:00:00Z" },
        { feedId: "phishtank", firstSeen: "2026-07-01T00:00:00Z" },
      ],
    },
  ]);
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function popupShot(tabId: number, file: string, prep?: (p: import("@playwright/test").Page) => Promise<void>) {
  const popup = await openPopup(ext, tabId);
  await popup.setViewportSize({ width: 380, height: 650 });
  await popup.waitForTimeout(400);
  if (prep) await prep(popup);
  await popup.screenshot({ path: join(SHOTS, file), fullPage: true });
  await popup.close();
}

test("toolbar icon states strip", async () => {
  const states = [
    ["benign", "BENIGN: green ring, check", "no known threat (not a warranty)"],
    ["suspicious", "SUSPICIOUS: amber ring, triangle", "be careful; look-alikes land here"],
    ["malicious", "MALICIOUS: filled red plate, octagon", "evidenced threat; STOP"],
    ["unknown", "UNKNOWN: dashed slate ring", "the honest common state"],
    ["checking", "CHECKING: breathing ring", "verdict in flight (<300ms typical)"],
    ["signedout", "SIGNED OUT: dim mark, lock", "on-device protection still active"],
  ];
  const rows = states
    .map(
      ([s, label, sub]) => `
    <div class="cell">
      <img src="file://${ICONS}/${s}-128.png" width="96" height="96" alt="${s}">
      <img src="file://${ICONS}/${s}-16.png" width="16" height="16" class="tiny" alt="${s} 16px">
      <div class="label">${label}</div>
      <div class="sub">${sub}</div>
    </div>`,
    )
    .join("");
  const html = `<!doctype html><meta charset="utf-8"><style>
    body{background:#0b1220;color:#e5e7eb;font:14px system-ui;margin:0;padding:28px}
    h1{font-size:18px;margin:0 0 20px}
    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px;max-width:900px}
    .cell{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px;text-align:center;position:relative}
    .tiny{position:absolute;top:12px;right:12px}
    .label{font-weight:600;margin-top:10px}
    .sub{color:#9ca3af;font-size:12px;margin-top:4px}
  </style><h1>Whisper Guard: toolbar states (128px, with the 16px form top-right)</h1><div class="grid">${rows}</div>`;
  const tmp = join(mkdtempSync(join(tmpdir(), "whisper-guard-shots-")), "toolbar.html");
  writeFileSync(tmp, html);
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 980, height: 620 });
  await page.goto(`file://${tmp}`);
  await page.screenshot({ path: join(SHOTS, "toolbar-states.png"), fullPage: true });
  await page.close();
});

test("popup: keyless look-alike (the on-device hero)", async () => {
  await setKey(ext, null);
  const { page, tabId } = await visit(ext, `https://${LOOKALIKE}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  await popupShot(tabId, "popup-keyless-lookalike.png");
  await page.close();
});

test("popup: keyed evidenced-malicious with explain expanded", async () => {
  await setKey(ext, MOCK_KEY);
  const { page, tabId } = await visit(ext, `https://${LOOKALIKE}/`);
  await waitForIcon(ext, tabId, ["malicious"]);
  await popupShot(tabId, "popup-keyed-malicious.png");
  await popupShot(tabId, "popup-keyed-explain.png", async (p) => {
    await p.locator("#exp-why summary").click();
    await expect(p.locator("#why-body")).toContainText("CRITICAL");
    await p.setViewportSize({ width: 380, height: 780 });
  });
  await popupShot(tabId, "popup-keyed-neighborhood.png", async (p) => {
    await p.locator("#exp-neighborhood summary").click();
    await expect(p.locator("#neighborhood-note")).toContainText("flagged in the graph", { timeout: 20_000 });
    await p.setViewportSize({ width: 380, height: 800 });
  });
  await page.close();
});

test("popup: keyed benign and honest UNKNOWN", async () => {
  await setKey(ext, MOCK_KEY);
  const clean = await visit(ext, "https://intranet-tools-vendor.com/");
  await waitForIcon(ext, clean.tabId, ["benign"]);
  await popupShot(clean.tabId, "popup-keyed-benign.png");
  await clean.page.close();

  const unk = await visit(ext, "https://news-blog-example.com/");
  await waitForIcon(ext, unk.tabId, ["unknown"]);
  await popupShot(unk.tabId, "popup-keyed-unknown.png");
  await unk.page.close();
});

test("pre-click check window, keyless and keyed", async () => {
  await setKey(ext, null);
  const w1 = await ext.context.newPage();
  await w1.setViewportSize({ width: 420, height: 560 });
  await w1.goto(`chrome-extension://${ext.id}/check-link.html?host=${LOOKALIKE}`);
  await expect(w1.locator("#detector-text")).toContainText("paypal.com");
  await w1.screenshot({ path: join(SHOTS, "precheck-keyless.png"), fullPage: true });
  await w1.close();

  await setKey(ext, MOCK_KEY);
  const w2 = await ext.context.newPage();
  await w2.setViewportSize({ width: 420, height: 560 });
  await w2.goto(`chrome-extension://${ext.id}/check-link.html?host=${LOOKALIKE}`);
  await expect(w2.locator("#band-tag")).toHaveText("CRITICAL");
  await w2.screenshot({ path: join(SHOTS, "precheck-keyed.png"), fullPage: true });
  await w2.close();
});

test("full-page warning", async () => {
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 1100, height: 720 });
  await page.goto(
    `chrome-extension://${ext.id}/warning.html?host=${LOOKALIKE}&brand=PayPal&brandDomain=paypal.com`,
  );
  await expect(page.locator("h1")).toContainText("Whisper stopped a dangerous page");
  await page.screenshot({ path: join(SHOTS, "warning.png"), fullPage: true });
  await page.close();
});

test("first-run", async () => {
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 900, height: 860 });
  await page.goto(`chrome-extension://${ext.id}/firstrun.html`);
  await page.screenshot({ path: join(SHOTS, "firstrun.png"), fullPage: true });
  await page.close();
});

test("settings (no key anywhere on screen)", async () => {
  await setKey(ext, null);
  await setSettings(ext, { shield: false });
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 900, height: 1100 });
  await page.goto(`chrome-extension://${ext.id}/options.html`);
  await page.waitForTimeout(300);
  const content = await page.content();
  expect(content).not.toContain(MOCK_KEY);
  await page.screenshot({ path: join(SHOTS, "settings.png"), fullPage: true });
  await page.close();
});

test("on-page amber banner and password-field caution (Active Shield)", async () => {
  await setKey(ext, null);
  await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true });
  const { page, tabId } = await visit(ext, "https://paypa1-checkout-secure.com/");
  await waitForIcon(ext, tabId, ["suspicious"]);
  await page.setViewportSize({ width: 1100, height: 500 });
  await expect
    .poll(async () => page.locator("div[style*='2147483647']").count(), { timeout: 10_000 })
    .toBeGreaterThan(0);
  await page.screenshot({ path: join(SHOTS, "amber-banner.png") });
  await page.locator("input[type=password]").focus();
  await page.waitForTimeout(500);
  await page.screenshot({ path: join(SHOTS, "field-guard.png") });
  await page.close();
  await setSettings(ext, { shield: false });
});
