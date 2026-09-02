// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The DESIGN REVIEW pass: every surface, every state, in BOTH colour
// schemes, captured from the real built extension against the hermetic
// mock network. It ships nothing; it exists so a design can be LOOKED at
// rather than reasoned about, which is the only way the last round's
// contrast regression, vanished logo and tofu glyph were ever going to be
// found.
//
// Run on demand:  npx playwright test e2e/review.spec.ts
// Output:         shots-review/<surface>-<state>-<scheme>.png

import { test } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeEgressDist,
  makeProxyHolderExt,
  openDashboard,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";
import type { Page } from "@playwright/test";

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), "../shots-review");
const SCHEMES = ["dark", "light"] as const;
const LOOKALIKE = "paypa1-secure-login.com";
const CLEAN = "intranet-tools-vendor.com";

function seed(net: E2ENetwork): void {
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setIdentify(CLEAN, [{ host: CLEAN, canonical_name: "Intranet Tools", category: "work", roles: [] }]);
  net.setEnrich(CLEAN, {
    ip: "203.0.113.12", city: "Amsterdam, NL", country: "NL", asn: "AS64500",
    owner: "Intranet Tools B.V.", asnName: "INTRANET - Intranet Tools B.V.",
    verdict: "NONE", prefix: "203.0.113.0/24",
  });
  net.setVerdict(LOOKALIKE, { band: "CRITICAL", coverage: "malicious-evidenced", label: "credential-phishing suspect" });
  net.setEnrich(LOOKALIKE, {
    ip: "192.0.2.66", city: "Montreal, CA", country: "CA", asn: "AS64550",
    owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC",
    verdict: "CRITICAL", prefix: "192.0.2.0/24",
  });
  net.setIdentify(LOOKALIKE, [{ host: LOOKALIKE, canonical_name: "Bad Hosting", category: "unresolved", roles: [] }]);
  net.setVerdict("news-blog-example.com", { band: "UNKNOWN", coverage: "no-data", label: null });
  net.setExplain(LOOKALIKE, [
    {
      indicator: LOOKALIKE, type: "domain", found: true, level: "CRITICAL", score: 17.2,
      explanation: `${LOOKALIKE} is listed in 2 threat feed(s).`,
      sources: [
        { feedId: "openphish", firstSeen: "2026-07-02T00:00:00Z" },
        { feedId: "phishtank", firstSeen: "2026-07-01T00:00:00Z" },
      ],
    },
  ]);
  net.setCohost(LOOKALIKE, { ip: "192.0.2.66", cohosted: 37, prefix: "192.0.2.0/24", threatNeighbors: 9 });
}

function fleet(net: E2ENetwork): void {
  const now = Date.now();
  net.addEndpoint({
    agent: "agent-shotphone", address: "2a04:2a01:5ec5:1::a1", label: "My iPhone", device: true,
    created: now - 3 * 86400000,
    counters: { dns_queries: 4821, dns_blocked: 132, dns_nxdomain: 44, connections_total: 61, bytes_up: 1_800_000, bytes_down: 24_500_000, last_seen: now - 40_000 },
    logs: [
      { ts: now - 5000, kind: "dns", qname: `${CLEAN}.`, qtype: "A", decision: "allow", agent: "agent-shotphone" },
      { ts: now - 12000, kind: "dns", qname: `${LOOKALIKE}.`, qtype: "A", decision: "block", agent: "agent-shotphone" },
      { ts: now - 16000, kind: "conn", peer: LOOKALIKE, agent: "agent-shotphone" },
    ],
  });
  net.addEndpoint({
    agent: "agent-shotlaptop", address: "2a04:2a01:5ec5:2::b2", label: "Work laptop", created: now - 6 * 86400000,
    counters: { dns_queries: 2210, dns_blocked: 18, connections_total: 30, last_seen: now - 120_000 },
    logs: [{ ts: now - 7000, kind: "dns", qname: "news-blog-example.com.", qtype: "A", decision: "allow", agent: "agent-shotlaptop" }],
  });
}

async function shot(page: Page, name: string, scheme: "dark" | "light", w = 390, h = 760): Promise<void> {
  mkdirSync(OUT, { recursive: true });
  await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
  // Same reason as settlePopup: a sticky masthead stitches into the middle
  // of a full-page capture of a page taller than the viewport, which is
  // every panel with its drawers open.
  await page.addStyleTag({ content: "header { position: static !important; }" }).catch(() => undefined);
  await page.setViewportSize({ width: w, height: h });
  await page.waitForTimeout(350);
  await page.screenshot({ path: join(OUT, `${name}-${scheme}.png`), fullPage: true });
}

// ------------------------------------------------------- panel + pages

test.describe("panel, pages", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seed(net);
    fleet(net);
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("panel: signed out, benign, malicious, unknown", async () => {
    await setKey(ext, null);
    for (const [host, icons, name] of [
      [CLEAN, ["benign", "signedout", "unknown"], "panel-signedout"],
      [LOOKALIKE, ["malicious", "suspicious"], "panel-malicious-keyless"],
    ] as const) {
      const { page, tabId } = await visit(ext, `https://${host}/`);
      await waitForIcon(ext, tabId, [...icons]);
      const popup = await openPopup(ext, tabId);
      for (const s of SCHEMES) await shot(popup, name, s);
      await popup.close();
      await page.close();
    }

    await setKey(ext, MOCK_KEY);
    for (const [host, icons, name] of [
      [CLEAN, ["benign"], "panel-benign"],
      [LOOKALIKE, ["malicious"], "panel-malicious"],
      ["news-blog-example.com", ["unknown"], "panel-unknown"],
    ] as const) {
      const { page, tabId } = await visit(ext, `https://${host}/`);
      await waitForIcon(ext, tabId, [...icons]);
      const popup = await openPopup(ext, tabId);
      for (const s of SCHEMES) await shot(popup, name, s);
      await popup.close();
      await page.close();
    }
  });

  test("panel: the explain drawer open", async () => {
    await setKey(ext, MOCK_KEY);
    const { page, tabId } = await visit(ext, `https://${LOOKALIKE}/`);
    await waitForIcon(ext, tabId, ["malicious"]);
    const popup = await openPopup(ext, tabId);
    await popup.locator("#exp-why summary").click();
    await popup.locator("#exp-neighborhood summary").click();
    await popup.waitForTimeout(1500);
    for (const s of SCHEMES) await shot(popup, "panel-drawers", s, 390, 900);
    await popup.close();
    await page.close();
  });

  test("pages: warning, check-link, firstrun, settings", async () => {
    await setKey(ext, MOCK_KEY);
    const warn = await ext.context.newPage();
    await warn.goto(`chrome-extension://${ext.id}/warning.html?host=${LOOKALIKE}&brand=PayPal&brandDomain=paypal.com`);
    await warn.waitForTimeout(800);
    for (const s of SCHEMES) await shot(warn, "page-warning", s, 1100, 760);
    await warn.close();

    const chk = await ext.context.newPage();
    await chk.goto(`chrome-extension://${ext.id}/check-link.html?host=${LOOKALIKE}`);
    await chk.waitForTimeout(800);
    for (const s of SCHEMES) await shot(chk, "page-check-link", s, 420, 560);
    await chk.close();

    const first = await ext.context.newPage();
    await first.goto(`chrome-extension://${ext.id}/firstrun.html`);
    await first.waitForTimeout(1200);
    for (const s of SCHEMES) await shot(first, "page-firstrun", s, 900, 900);
    await first.close();

    const opt = await ext.context.newPage();
    await opt.goto(`chrome-extension://${ext.id}/options.html`);
    await opt.waitForTimeout(600);
    for (const s of SCHEMES) await shot(opt, "page-settings", s, 900, 1200);
    await opt.close();
  });

  test("dashboard: this browser, fleet, endpoint", async () => {
    await setKey(ext, null);
    await setSettings(ext, { cloudCheck: true });
    for (const host of [CLEAN, LOOKALIKE, "news-blog-example.com"]) {
      const v = await visit(ext, `https://${host}/`);
      await waitForIcon(ext, v.tabId, ["benign", "unknown", "suspicious", "malicious", "signedout"]);
      await v.page.close();
    }
    const keyless = await openDashboard(ext, "browser");
    await keyless.waitForTimeout(2500);
    for (const s of SCHEMES) await shot(keyless, "dash-browser-keyless", s, 1180, 1500);
    await keyless.close();

    await setKey(ext, MOCK_KEY);
    const fl = await openDashboard(ext, "fleet");
    await fl.waitForTimeout(2500);
    for (const s of SCHEMES) await shot(fl, "dash-fleet", s, 1180, 1500);
    await fl.close();

    const ep = await openDashboard(ext, "endpoint");
    await ep.waitForTimeout(3000);
    for (const s of SCHEMES) await shot(ep, "dash-endpoint", s, 1180, 1700);
    await ep.close();
  });
});

// --------------------------------- the one control, in all four states

test.describe("the one control: offered and refused", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seed(net);
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("offered, then refused, in the panel AND on the dashboard", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);

    const popup = await openPopup(ext, tabId);
    await popup.locator("#btn-protect").waitFor({ state: "visible", timeout: 15_000 });
    for (const s of SCHEMES) await shot(popup, "control-panel-offered", s);
    await popup.locator("#btn-protect").click();
    await popup.locator("#route-line").filter({ hasText: "Not routed" }).waitFor({ timeout: 30_000 });
    for (const s of SCHEMES) await shot(popup, "control-panel-refused", s);
    await popup.close();

    const dash = await openDashboard(ext, "browser");
    await dash.locator("#btn-protect").waitFor({ state: "visible", timeout: 15_000 });
    await dash.locator("#egress-card").scrollIntoViewIfNeeded();
    await dash.waitForTimeout(1500);
    for (const s of SCHEMES) {
      await dash.emulateMedia({ colorScheme: s });
      await dash.setViewportSize({ width: 1180, height: 900 });
      await dash.waitForTimeout(350);
      mkdirSync(OUT, { recursive: true });
      await dash.locator("#egress-card").screenshot({ path: join(OUT, `control-dashboard-card-${s}.png`) });
    }
    for (const s of SCHEMES) await shot(dash, "dash-browser-keyed", s, 1180, 1500);
    await dash.close();
    await page.close();
  });
});

test.describe("the one control: granted", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seed(net);
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeEgressDist() });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("protected, in the panel AND on the dashboard", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId);
    await popup.locator("#btn-protect").waitFor({ state: "visible", timeout: 15_000 });
    await popup.locator("#btn-protect").click();
    await popup.locator("#route-line").filter({ hasText: "Protected" }).waitFor({ timeout: 30_000 });
    await popup.waitForTimeout(1200);
    for (const s of SCHEMES) await shot(popup, "control-panel-protected", s);
    await popup.close();

    const dash = await openDashboard(ext, "browser");
    await dash.locator("#btn-protect").waitFor({ state: "visible", timeout: 15_000 });
    await dash.waitForTimeout(2500);
    for (const s of SCHEMES) {
      await dash.emulateMedia({ colorScheme: s });
      await dash.setViewportSize({ width: 1180, height: 900 });
      await dash.waitForTimeout(350);
      mkdirSync(OUT, { recursive: true });
      await dash.locator("#egress-card").screenshot({ path: join(OUT, `control-dashboard-protected-${s}.png`) });
    }
    await dash.close();
    await page.close();
  });
});

test.describe("the one control: another extension owns the proxy", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seed(net);
    ext = await launchExtension({
      proxyPort: net.proxyPort,
      dist: makeEgressDist(),
      extraExtensions: [makeProxyHolderExt(net.proxyPort)],
    });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("the conflict, named", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId);
    await popup.locator("#btn-protect").waitFor({ state: "visible", timeout: 15_000 });
    await popup.locator("#btn-protect").click();
    await popup.locator("#route-line").filter({ hasText: "Another extension" }).waitFor({ timeout: 30_000 });
    await popup.waitForTimeout(800);
    for (const s of SCHEMES) await shot(popup, "control-panel-conflict", s);
    await popup.close();
    await page.close();
  });
});
