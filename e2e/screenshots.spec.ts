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
  openDashboard,
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
      found: true,
      level: "CRITICAL",
      score: 17.2,
      explanation: `${LOOKALIKE} is listed in 5 threat feed(s).`,
      sources: [
        { feedId: "openphish", firstSeen: "2026-07-02T00:00:00Z" },
        { feedId: "phishtank", firstSeen: "2026-07-01T00:00:00Z" },
      ],
    },
  ]);
  // A believable "where my devices go" spread for the dashboard gallery.
  const dests: [string, Parameters<typeof net.setEnrich>[1], string, string][] = [
    ["mail.workmail-vendor.com", { ip: "203.0.113.5", city: "Frankfurt am Main, DE", country: "DE", asn: "AS64500", owner: "WorkMail Cloud GmbH", asnName: "WORKMAIL - WorkMail Cloud GmbH", verdict: "NONE", prefix: "203.0.113.0/24" }, "saas", "WorkMail Cloud"],
    ["cdn.mediastream-vendor.com", { ip: "198.51.100.7", city: "Amsterdam, NL", country: "NL", asn: "AS64510", owner: "Fastly, Inc.", asnName: "FASTLY - Fastly, Inc.", verdict: "NONE", prefix: "198.51.100.0/24" }, "cdn", "Fastly"],
    ["ads.tracker-vendor.com", { ip: "192.0.2.9", city: "Ashburn, US", country: "US", asn: "AS64520", owner: "Tracky Ads Inc.", asnName: "TRACKY - Tracky Ads Inc.", verdict: "NONE", prefix: "192.0.2.0/24" }, "ads", "Tracky Ads"],
    ["search-vendor.com", { ip: "203.0.113.30", city: "Dublin, IE", country: "IE", asn: "AS64530", owner: "Searchy Ltd.", asnName: "SEARCHY - Searchy Ltd.", verdict: "NONE", prefix: "203.0.113.0/24" }, "search", "Searchy"],
    ["news.mediaco-vendor.com", { ip: "198.51.100.40", city: "London, GB", country: "GB", asn: "AS64540", owner: "MediaCo plc", asnName: "MEDIACO - MediaCo plc", verdict: "NONE", prefix: "198.51.100.0/24" }, "media", "MediaCo"],
    [LOOKALIKE, { ip: "192.0.2.66", city: "Montreal, CA", country: "CA", asn: "AS64550", owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC", verdict: "CRITICAL", prefix: "192.0.2.0/24" }, "unresolved", "Bad Hosting"],
  ];
  for (const [host, enrich, cat, name] of dests) {
    net.setEnrich(host, enrich);
    net.setIdentify(host, [{ host, canonical_name: name, category: cat, roles: [] }]);
    if (host !== LOOKALIKE) {
      net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
    }
  }

  // A small fleet for the keyed views.
  const now = Date.now();
  net.addEndpoint({
    agent: "agent-shotphone", address: "2a04:2a01:5ec5:1::a1", label: "My iPhone", device: true, created: now - 3 * 86400000,
    counters: { dns_queries: 4821, dns_blocked: 132, dns_nxdomain: 44, connections_total: 61, bytes_up: 1_800_000, bytes_down: 24_500_000, last_seen: now - 40_000 },
    logs: [
      { ts: now - 5000, kind: "dns", qname: "mail.workmail-vendor.com.", qtype: "A", decision: "allow", agent: "agent-shotphone" },
      { ts: now - 9000, kind: "dns", qname: "cdn.mediastream-vendor.com.", qtype: "AAAA", decision: "allow", agent: "agent-shotphone" },
      { ts: now - 12000, kind: "dns", qname: "ads.tracker-vendor.com.", qtype: "A", decision: "block", agent: "agent-shotphone" },
      { ts: now - 16000, kind: "conn", peer: LOOKALIKE, agent: "agent-shotphone" },
    ],
  });
  net.addEndpoint({
    agent: "agent-shotlaptop", address: "2a04:2a01:5ec5:2::b2", label: "Work laptop", created: now - 6 * 86400000,
    counters: { dns_queries: 2210, dns_blocked: 18, connections_total: 30, last_seen: now - 120_000 },
    logs: [
      { ts: now - 7000, kind: "dns", qname: "search-vendor.com.", qtype: "A", decision: "allow", agent: "agent-shotlaptop" },
      { ts: now - 11000, kind: "dns", qname: "news-blog-example.com.", qtype: "A", decision: "allow", agent: "agent-shotlaptop" },
    ],
  });
  net.setCohost(LOOKALIKE, { ip: "192.0.2.66", cohosted: 37, prefix: "192.0.2.0/24", threatNeighbors: 9 });
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
    body{background:#010103;color:#e8e8f2;font:14px system-ui;margin:0;padding:28px}
    h1{font-size:18px;margin:0 0 20px;font-weight:300}
    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px;max-width:900px}
    .cell{background:#0d0d1a;border:1px solid #1e1e33;border-radius:12px;padding:18px;text-align:center;position:relative}
    .tiny{position:absolute;top:12px;right:12px}
    .label{font-weight:600;margin-top:10px}
    .sub{color:#9a9ab0;font-size:12px;margin-top:4px}
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
  // The pure on-device hero: live check off so the look-alike detector is
  // the whole story (its own honest surface).
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: false });
  const { page, tabId } = await visit(ext, `https://${LOOKALIKE}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  await popupShot(tabId, "popup-keyless-lookalike.png");
  await page.close();
  await setSettings(ext, { cloudCheck: true });
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

test("dashboard: This browser (keyless keystone), graph-enriched destinations", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  // Drive the browser so the on-device destination log has a real spread.
  for (const host of [
    "mail.workmail-vendor.com", "cdn.mediastream-vendor.com", "ads.tracker-vendor.com",
    "search-vendor.com", "news.mediaco-vendor.com", `${LOOKALIKE}`,
  ]) {
    const v = await visit(ext, `https://${host}/`);
    await waitForIcon(ext, v.tabId, ["benign", "unknown", "suspicious", "malicious", "signedout"]);
    await v.page.close();
  }
  const dash = await openDashboard(ext, "browser");
  await dash.setViewportSize({ width: 1180, height: 1500 });
  await expect(dash.locator("#b-ledger")).toContainText("WorkMail", { timeout: 15_000 });
  await dash.waitForTimeout(700);
  await dash.screenshot({ path: join(SHOTS, "dashboard-this-browser.png"), fullPage: true });
  await dash.close();
});

test("dashboard: Fleet total (keyed) and Per-endpoint drill (keyed)", async () => {
  await setKey(ext, MOCK_KEY);
  const fleet = await openDashboard(ext, "fleet");
  await fleet.setViewportSize({ width: 1180, height: 1500 });
  await expect(fleet.locator("#f-roster")).toContainText("My iPhone", { timeout: 15_000 });
  await fleet.waitForTimeout(700);
  await fleet.screenshot({ path: join(SHOTS, "dashboard-fleet.png"), fullPage: true });
  await fleet.close();

  const ep = await openDashboard(ext, "endpoint");
  await ep.setViewportSize({ width: 1180, height: 1600 });
  await expect(ep.locator("#e-address")).not.toBeEmpty({ timeout: 15_000 });
  // Open a destination's receipts (co-hosting from the graph) for the shot.
  await ep.locator("#e-hosts .w-ledger-row", { hasText: LOOKALIKE }).first().click().catch(() => undefined);
  await ep.waitForTimeout(800);
  await ep.screenshot({ path: join(SHOTS, "dashboard-endpoint.png"), fullPage: true });
  await ep.close();
});

test("dashboard: Protect this browser (egress toggle, off by default)", async () => {
  await setKey(ext, MOCK_KEY);
  const dash = await openDashboard(ext, "browser");
  await dash.setViewportSize({ width: 1180, height: 900 });
  await expect(dash.locator("#egress-card")).toBeVisible();
  await dash.locator("#egress-card").scrollIntoViewIfNeeded();
  await dash.waitForTimeout(400);
  await dash.locator("#egress-card").screenshot({ path: join(SHOTS, "dashboard-egress.png") });
  await dash.close();
});

test("popup: mini-dashboard summary of this browser", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  const { page, tabId } = await visit(ext, "https://intranet-tools-vendor.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  await popupShot(tabId, "popup-mini-dashboard.png", async (p) => {
    await p.setViewportSize({ width: 390, height: 720 });
  });
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
