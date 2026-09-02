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
// page (shots/index.html) references these files. The panel's own
// protection states (offered, protected, refused, proxy taken) and its
// light rendering are captured by e2e/protect.spec.ts, which proves them.

import { test, expect } from "@playwright/test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openDashboard,
  openPopup,
  setKey,
  settlePopup,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(HERE, "../shots");
const ICONS = resolve(HERE, "../icons");

const LOOKALIKE = "paypa1-secure-login.com";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  mkdirSync(SHOTS, { recursive: true });
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(LOOKALIKE, { band: "CRITICAL", coverage: "partial", label: "credential-phishing suspect" });
  net.setVerdict("news-blog-example.com", { band: "UNKNOWN", coverage: "no-data", label: null });
  // The first-run page fetches one real verdict for github.com to show the
  // check working. Unseeded, the hermetic mock answers UNKNOWN/no-data and the
  // published figure reads as the product not knowing a top-1000 site - true
  // of the fixture, false of the product. Seeded like every other host here.
  net.setVerdict("github.com", { band: "NONE", coverage: "known-clean", label: "clean" });
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
      explanation: `${LOOKALIKE} is listed in 2 threat feed(s).`,
      sources: [
        { feedId: "openphish", firstSeen: "2026-07-02T00:00:00Z" },
        { feedId: "phishtank", firstSeen: "2026-07-01T00:00:00Z" },
      ],
    },
  ]);
  // A believable "where my devices go" spread for the dashboard gallery.
  //
  // Every hostname here is verified unregistered over RDAP and every vendor
  // invented, BEFORE use rather than after: a published screenshot from a
  // security product must not carry a verdict about a real party we have
  // never assessed, whichever way the verdict points. The rule is about this
  // fixture and nothing else - the squat patterns quoted as examples in
  // README.md and the store listing are a separate matter, and none of them
  // is ever shown carrying a verdict.
  const dests: [string, Parameters<typeof net.setEnrich>[1], string, string][] = [
    ["mail.workmail-vendor.com", { ip: "203.0.113.5", city: "Frankfurt am Main, DE", country: "DE", asn: "AS64500", owner: "WorkMail Cloud GmbH", asnName: "WORKMAIL - WorkMail Cloud GmbH", verdict: "NONE", prefix: "203.0.113.0/24" }, "saas", "WorkMail Cloud"],
    ["cdn.mediastream-vendor.com", { ip: "198.51.100.7", city: "Amsterdam, NL", country: "NL", asn: "AS64510", owner: "Swiftpipe Edge B.V.", asnName: "SWIFTPIPE - Swiftpipe Edge B.V.", verdict: "NONE", prefix: "198.51.100.0/24" }, "cdn", "Swiftpipe Edge"],
    ["ads.tracker-vendor.com", { ip: "192.0.2.9", city: "Ashburn, US", country: "US", asn: "AS64520", owner: "Tracky Ads Inc.", asnName: "TRACKY - Tracky Ads Inc.", verdict: "NONE", prefix: "192.0.2.0/24" }, "ads", "Tracky Ads"],
    ["searchy-vendor.com", { ip: "203.0.113.30", city: "Dublin, IE", country: "IE", asn: "AS64530", owner: "Searchy Ltd.", asnName: "SEARCHY - Searchy Ltd.", verdict: "NONE", prefix: "203.0.113.0/24" }, "search", "Searchy"],
    ["news.mediaco-vendor.com", { ip: "198.51.100.40", city: "London, GB", country: "GB", asn: "AS64540", owner: "MediaCo plc", asnName: "MEDIACO - MediaCo plc", verdict: "NONE", prefix: "198.51.100.0/24" }, "media", "MediaCo"],
    [LOOKALIKE, { ip: "192.0.2.66", city: "Montreal, CA", country: "CA", asn: "AS64550", owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC", verdict: "CRITICAL", prefix: "192.0.2.0/24", threatNeighbors: 9 }, "unresolved", "Bad Hosting"],
  ];
  for (const [host, enrich, cat, name] of dests) {
    net.setEnrich(host, enrich);
    net.setIdentify(host, [{ host, canonical_name: name, category: cat, roles: [] }]);
    if (host !== LOOKALIKE) {
      net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
    }
  }

  // A small fleet for the keyed views. Ages are MINUTES, not seconds: these
  // render as relative labels ("6m ago") in published figures, and a
  // seconds-scale age re-renders on every run, so the committed captures
  // could never settle. Minutes read just as recent and survive the drift
  // between two runs.
  const now = Date.now();
  net.addEndpoint({
    agent: "agent-shotphone", address: "2a04:2a01:5ec5:1::a1", label: "My iPhone", device: true, created: now - 3 * 86400000,
    counters: { dns_queries: 4821, dns_blocked: 132, dns_nxdomain: 44, connections_total: 61, bytes_up: 1_800_000, bytes_down: 24_500_000, last_seen: now - 5 * 60_000 },
    logs: [
      { ts: now - 6 * 60_000, kind: "dns", qname: "mail.workmail-vendor.com.", qtype: "A", decision: "allow", agent: "agent-shotphone" },
      { ts: now - 7 * 60_000, kind: "dns", qname: "cdn.mediastream-vendor.com.", qtype: "AAAA", decision: "allow", agent: "agent-shotphone" },
      { ts: now - 8 * 60_000, kind: "dns", qname: "ads.tracker-vendor.com.", qtype: "A", decision: "block", agent: "agent-shotphone" },
      { ts: now - 11 * 60_000, kind: "conn", peer: LOOKALIKE, agent: "agent-shotphone" },
    ],
  });
  net.addEndpoint({
    agent: "agent-shotlaptop", address: "2a04:2a01:5ec5:2::b2", label: "Work laptop", created: now - 6 * 86400000,
    counters: { dns_queries: 2210, dns_blocked: 18, connections_total: 30, last_seen: now - 9 * 60_000 },
    logs: [
      { ts: now - 12 * 60_000, kind: "dns", qname: "searchy-vendor.com.", qtype: "A", decision: "allow", agent: "agent-shotlaptop" },
      { ts: now - 14 * 60_000, kind: "dns", qname: "news-blog-example.com.", qtype: "A", decision: "allow", agent: "agent-shotlaptop" },
    ],
  });
  net.setCohost(LOOKALIKE, { ip: "192.0.2.66", cohosted: 37, prefix: "192.0.2.0/24", threatNeighbors: 9 });
  // The chain's own inputs for the gallery. Without these the published
  // figure shows a walk that stops three rungs early, which is a picture of
  // the fixture rather than of the product.
  net.setPresence("AS64550", { facilities: ["Example Colo MTL1"], exchanges: [], facilityCount: 1 });
  net.setPresence("AS64540", { facilities: ["Example Carrier Hotel LON1", "Example Colo LON2"], exchanges: ["Example Exchange LON"], facilityCount: 14, exchangeCount: 4 });
  net.setDensity("AS64550", { listedIps: 412, announcedIpv4: 1024, routedPrefixes: 4 });
  net.setHistory(LOOKALIKE, [{ createDate: "2026-08-19T00:00:00Z", updateDate: "2026-08-19T00:00:00Z" }]);
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});


/**
 * NOTE on determinism: mock identities are counter-minted and fixture ages
 * are minutes-scale, so a re-run reproduces 34 of the 35 captures byte for
 * byte. The exception is dashboard-this-browser.png, whose activity card's
 * bottom edge can land ~3px apart between runs; the content is identical.
 * Not worth chasing, but worth knowing before assuming a diff means change.
 *
 * Capture a full page in BOTH schemes. Nothing here may rely on a default:
 * these pages follow the reader's colour scheme now, and headless Chromium
 * prefers light, so a capture that does not say which scheme it wants is a
 * capture of whichever one the browser happened to pick. That is exactly how
 * the "dark" gallery shots came back light the first time this ran.
 */
async function pageShots(
  page: import("@playwright/test").Page,
  name: string,
  size: { width: number; height: number },
): Promise<void> {
  for (const [scheme, file] of [
    ["dark", `${name}.png`],
    ["light", `${name}-light.png`],
  ] as const) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.setViewportSize(size);
    await page.waitForTimeout(350);
    await assertScheme(page, scheme, file);
    await page.screenshot({ path: join(SHOTS, file), fullPage: true });
  }
}

/**
 * The store canvas is 1280x800. A capture meant for it is taken at that
 * aspect and NOT full-page, so the framed result fills the canvas instead
 * of shrinking a tall page into an illegible strip.
 */
async function storeShot(page: import("@playwright/test").Page, name: string): Promise<void> {
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(400);
  await assertScheme(page, "dark", `${name}.png`);
  await page.screenshot({ path: join(SHOTS, `${name}.png`) });
}

/**
 * A capture named "dark" that came out light is a published figure lying
 * about the product, and it is invisible to every other assertion in this
 * file. Read the ground the page actually painted and refuse to save a shot
 * that does not match the scheme it is filed under.
 */
async function assertScheme(
  page: import("@playwright/test").Page,
  scheme: "dark" | "light",
  file: string,
): Promise<void> {
  const luminance = await page.evaluate(() => {
    const c = getComputedStyle(document.body).backgroundColor;
    const m = c.match(/-?[\d.]+/g) ?? ["255", "255", "255"];
    const scale = c.startsWith("color(") ? 255 : 1;
    const [r, g, b] = m.slice(0, 3).map((v) => Number(v) * scale);
    const f = (v: number): number => {
      const x = v / 255;
      return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * f(r!) + 0.7152 * f(g!) + 0.0722 * f(b!);
  });
  if (scheme === "dark") {
    expect(luminance, `${file} is filed as dark but its ground is light`).toBeLessThan(0.15);
  } else {
    expect(luminance, `${file} is filed as light but its ground is dark`).toBeGreaterThan(0.3);
  }
}

async function popupShot(tabId: number, file: string, prep?: (p: import("@playwright/test").Page) => Promise<void>) {
  const popup = await openPopup(ext, tabId);
  // reducedMotion: the live-feed dot and the CHECKING ring breathe, so a
  // still capture otherwise freezes a random animation phase and every run
  // rewrites the file. The product's own prefers-reduced-motion rule turns
  // every animation off, so this captures the resting state deliberately.
  // Every surface follows the reader's colour scheme now. The gallery leads
  // dark and carries a light capture of each surface beside it, so the claim
  // is shown rather than asserted; the panel's own protection states are
  // captured in both by e2e/protect.spec.ts.
  await settlePopup(popup, { colorScheme: "dark", width: 400, height: 700 });
  if (prep) await prep(popup);
  await assertScheme(popup, "dark", file);
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
  await w1.emulateMedia({ colorScheme: "dark" });
  await w1.setViewportSize({ width: 420, height: 560 });
  await w1.goto(`chrome-extension://${ext.id}/check-link.html?host=${LOOKALIKE}`);
  await expect(w1.locator("#detector-text")).toContainText("paypal.com");
  // The graph band on this surface is KEYLESS, so it lands here too - and the
  // byte-compare below is only meaningful once BOTH captures have it. Waiting
  // only for the detector row raced the band under load and produced two
  // shots that differed by a row nobody had asked to differ.
  await expect(w1.locator("#band-tag")).toHaveText("CRITICAL");
  // The graph band on this surface is KEYLESS, so it lands here too - and the
  // comparison below is only meaningful once BOTH renders have it. Waiting
  // only for the detector row raced the band under load.
  const keyless = await w1.evaluate(() => document.body.innerHTML);
  await w1.screenshot({ path: join(SHOTS, "precheck-keyless.png"), fullPage: true });
  await w1.emulateMedia({ colorScheme: "light" });
  await w1.waitForTimeout(250);
  await w1.screenshot({ path: join(SHOTS, "precheck-keyless-light.png"), fullPage: true });
  await w1.close();

  await setKey(ext, MOCK_KEY);
  const w2 = await ext.context.newPage();
  await w2.emulateMedia({ colorScheme: "dark" });
  await w2.setViewportSize({ width: 420, height: 560 });
  await w2.goto(`chrome-extension://${ext.id}/check-link.html?host=${LOOKALIKE}`);
  await expect(w2.locator("#band-tag")).toHaveText("CRITICAL");
  const keyed = await w2.evaluate(() => document.body.innerHTML);
  await w2.close();

  // The gallery used to ship this twice, captioned "keyless" and "signed in,
  // the live band joins the on-device verdict". The two were always the same
  // view, because the band on this surface is KEYLESS: signing in adds
  // nothing here. That was a documented sample claiming a difference it never
  // had. The gallery now shows one shot and says so, and this asserts the
  // reason, so if the keyed view ever does diverge the caption goes red
  // instead of quietly becoming true again.
  //
  // The claim is about what the surface RENDERS, so that is what is compared.
  // This was a byte-compare of the two PNGs, which measured the claim plus
  // the rasteriser: the two renders were proved identical in the DOM
  // (innerText and innerHTML both equal, measured) while the encoded images
  // still differed intermittently under load. A test that goes red for a
  // reason its own message cannot explain is worse than no test.
  //
  // CONTROL: an empty or error-only body would compare equal to itself, so
  // pin that the render being compared is the real one.
  expect(keyless, "the keyless render must carry the verdict, or equality proves nothing").toContain("CRITICAL");
  expect(keyless).toContain("paypal.com");
  expect(
    keyed,
    "the keyed pre-click view now differs from the keyless one; the gallery caption says they are identical and needs updating",
  ).toBe(keyless);
});

test("full-page warning", async () => {
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 1100, height: 720 });
  await page.goto(
    `chrome-extension://${ext.id}/warning.html?host=${LOOKALIKE}&brand=PayPal&brandDomain=paypal.com`,
  );
  await expect(page.locator("h1")).toContainText("Whisper stopped a dangerous page");
  await pageShots(page, "warning", { width: 1100, height: 720 });
  await storeShot(page, "warning-store");
  await page.close();
});

test("first-run", async () => {
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 900, height: 860 });
  await page.goto(`chrome-extension://${ext.id}/firstrun.html`);
  await page.waitForTimeout(600);
  await pageShots(page, "firstrun", { width: 900, height: 860 });
  await page.close();
});

test("settings (no key anywhere on screen)", async () => {
  await setSettings(ext, { shield: false });

  // The claim is that the options page never PUTS the credential on screen,
  // so it has to be asserted while a credential exists. Clearing the key
  // first and then asserting its absence proves nothing at all: there was
  // nothing to render, and the assertion would survive the deletion of every
  // masking guarantee in the page.
  await setKey(ext, MOCK_KEY);
  const keyed = await ext.context.newPage();
  await keyed.goto(`chrome-extension://${ext.id}/options.html`);
  // CONTROL: the signed-in branch really rendered, so "the key is absent" is
  // a statement about a page that had one to show.
  await expect(keyed.locator("#account-signedin")).toBeVisible({ timeout: 10_000 });
  expect(await keyed.content()).not.toContain(MOCK_KEY);
  await keyed.close();

  // The shot itself is of the signed-out page, which is what a new user sees.
  await setKey(ext, null);
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 900, height: 1100 });
  await page.goto(`chrome-extension://${ext.id}/options.html`);
  await page.waitForTimeout(300);
  expect(await page.content()).not.toContain(MOCK_KEY);
  await pageShots(page, "settings", { width: 900, height: 1100 });
  await page.close();
});

test("dashboard: This browser (keyless keystone), graph-enriched destinations", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  // Drive the browser so the on-device destination log has a real spread.
  for (const host of [
    "mail.workmail-vendor.com", "cdn.mediastream-vendor.com", "ads.tracker-vendor.com",
    "searchy-vendor.com", "news.mediaco-vendor.com", `${LOOKALIKE}`,
  ]) {
    const v = await visit(ext, `https://${host}/`);
    await waitForIcon(ext, v.tabId, ["benign", "unknown", "suspicious", "malicious", "signedout"]);
    await v.page.close();
  }
  const dash = await openDashboard(ext, "browser");
  await dash.emulateMedia({ colorScheme: "dark" });
  await dash.setViewportSize({ width: 1180, height: 1500 });
  await expect(dash.locator("#b-ledger")).toContainText("WorkMail", { timeout: 15_000 });
  await dash.waitForTimeout(700);
  await pageShots(dash, "dashboard-this-browser", { width: 1180, height: 1500 });
  // A store screenshot is 1280x800, so a 1180x1500 full-page capture scales
  // to a 531px-wide thumbnail with black either side and nothing legible in
  // it. Capture the viewport instead: it fills the store canvas and a reader
  // can actually read it. (Only visible by looking at the framed result.)
  await storeShot(dash, "dashboard-this-browser-store");
  await dash.close();
});

test("dashboard: Fleet total (keyed) and Per-endpoint drill (keyed)", async () => {
  await setKey(ext, MOCK_KEY);
  const fleet = await openDashboard(ext, "fleet");
  await fleet.emulateMedia({ colorScheme: "dark" });
  await fleet.setViewportSize({ width: 1180, height: 1500 });
  await expect(fleet.locator("#f-roster")).toContainText("My iPhone", { timeout: 15_000 });
  await fleet.waitForTimeout(700);
  await fleet.screenshot({ path: join(SHOTS, "dashboard-fleet.png"), fullPage: true });
  await fleet.close();

  const ep = await openDashboard(ext, "endpoint");
  await ep.emulateMedia({ colorScheme: "dark" });
  await ep.setViewportSize({ width: 1180, height: 1600 });
  // A negated matcher is satisfied by an element that is not there, and this
  // capture becomes a published figure: an empty or missing address would ship
  // a screenshot of a blank identity with nothing going red. Pin the value's
  // SHAPE instead, which only a real /128 has.
  await expect(ep.locator("#e-address")).toHaveText(/^[0-9a-f]{1,4}:[0-9a-f:]+$/i, { timeout: 15_000 });
  // Open a destination's receipts (co-hosting from the graph) for the shot.
  // No swallowed failure here: this capture becomes a published figure, so a
  // click that silently missed would ship a screenshot without the receipts
  // panel and nothing would go red. Assert the panel actually filled.
  await ep.locator("#e-hosts .w-ledger-row", { hasText: LOOKALIKE }).first().click();
  await expect(ep.locator("#e-drill-body")).toContainText("Co-hosted", { timeout: 15_000 });
  await ep.waitForTimeout(800);
  await pageShots(ep, "dashboard-endpoint", { width: 1180, height: 1600 });
  await storeShot(ep, "dashboard-endpoint-store");
  await ep.close();
});

test("dashboard: the ONE control, the same one the panel offers", async () => {
  await setKey(ext, MOCK_KEY);
  const dash = await openDashboard(ext, "browser");
  await dash.emulateMedia({ colorScheme: "dark" });
  await dash.setViewportSize({ width: 1180, height: 900 });
  await expect(dash.locator("#egress-card")).toBeVisible();
  // The capture is only worth anything if it is the control: pin that the
  // one button is on screen and the two-step idiom it replaced is not.
  await expect(dash.locator("#btn-protect")).toBeVisible({ timeout: 15_000 });
  await expect(dash.locator("#enroll-btn")).toHaveCount(0);
  await expect(dash.locator("#egress-toggle")).toHaveCount(0);
  await dash.locator("#egress-card").scrollIntoViewIfNeeded();
  await dash.waitForTimeout(400);
  await dash.locator("#egress-card").screenshot({ path: join(SHOTS, "dashboard-egress.png") });
  await dash.emulateMedia({ colorScheme: "light" });
  await dash.waitForTimeout(400);
  await dash.locator("#egress-card").screenshot({ path: join(SHOTS, "dashboard-egress-light.png") });
  await dash.close();
});

test("popup: the activity line for this browser", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  const { page, tabId } = await visit(ext, "https://intranet-tools-vendor.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  await popupShot(tabId, "popup-activity.png", async (p) => {
    await p.setViewportSize({ width: 390, height: 720 });
    // The four-tile grid became one line, and the only number in it that a
    // reader can act on is the flagged one. Pin the line rather than merely
    // capturing it, so a caption quoting it cannot go stale in silence.
    await expect(p.locator("#browser-24h")).toContainText("in the last 24h");
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

test("pre-emptive interruption: the inline interstitial that holds a click", async () => {
  // The flagship of E4: a real capture of a real held click. The page is
  // served by the hermetic mock, the target verdict comes from the mock
  // graph, and the overlay in the shot is the extension's own closed
  // shadow root - nothing here is drawn for the camera.
  await setKey(ext, null);
  await setSettings(ext, { shield: true, cloudCheck: true });
  const HOST = "daily-reading-example.com";
  net.setVerdict(HOST, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage(
    HOST,
    `<!doctype html>
<html><head><title>${HOST}</title><meta charset="utf-8"></head>
<body style="margin:0;font:16px/1.6 system-ui,sans-serif;background:#FAFAF9;color:#1C1917">
  <div style="max-width:640px;margin:56px auto;padding:0 24px">
    <p style="color:#78716C;font-size:13px;letter-spacing:.08em;text-transform:uppercase">Inbox</p>
    <h1 style="font-size:26px;margin:.2em 0 .6em">Your parcel could not be delivered</h1>
    <p>We tried to deliver your parcel today and could not reach you. Confirm
    your address and the redelivery fee to release the shipment.</p>
    <p style="margin:28px 0">
      <a id="lure" href="https://${LOOKALIKE}/redelivery/confirm?ref=8812"
         style="background:#0F766E;color:#fff;padding:11px 18px;border-radius:8px;text-decoration:none;font-weight:600">
        Confirm my address</a>
    </p>
  </div>
</body></html>`,
  );
  const { page, tabId } = await visit(ext, `https://${HOST}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await page.setViewportSize({ width: 1100, height: 620 });
  net.clearLog();
  await page.click("#lure");
  await expect
    .poll(async () => page.locator("div[style*='2147483647']").count(), { timeout: 10_000 })
    .toBeGreaterThan(0);
  // Held: the tab never moved and the target was never contacted.
  expect(page.url()).toBe(`https://${HOST}/`);
  expect(net.requestsTo(LOOKALIKE).filter((r) => r.scheme === "https")).toHaveLength(0);
  await page.screenshot({ path: join(SHOTS, "preempt-interstitial.png") });
  await page.keyboard.press("Escape");
  await page.close();
  await setSettings(ext, { shield: false });
});

test("cookie-consent auto-decline on a real-shaped banner", async () => {
  // The second half of the "handled quietly today" card, earned the same
  // way as the first: a real banner, really declined by the content module,
  // no seeded record. The page is served by the hermetic mock and the click
  // is the module's own - nothing here is staged for the camera.
  await setKey(ext, null);
  await setSettings(ext, { shield: true, cookieDecline: true, cloudCheck: true });
  const HOST = "recipes-weekly-example.com";
  net.setVerdict(HOST, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage(
    HOST,
    `<!doctype html>
<html><head><title>${HOST}</title><meta charset="utf-8"></head>
<body style="margin:0;font:16px/1.6 system-ui,sans-serif;background:#FAFAF9;color:#1C1917">
  <div style="max-width:640px;margin:56px auto;padding:0 24px">
    <h1 style="font-size:26px;margin:.2em 0 .6em">Sunday bread, four ways</h1>
    <p>A slow ferment, a hot oven, and not much else.</p>
  </div>
  <div id="cookie-bar" role="dialog" aria-label="Cookie notice"
       style="position:fixed;bottom:0;left:0;right:0;background:#292524;color:#F5F5F4;padding:16px 24px;display:flex;gap:12px;align-items:center">
    <span style="flex:1">We use cookies and similar technologies for analytics and advertising.</span>
    <button id="c-manage">Manage preferences</button>
    <button id="c-accept">Accept all</button>
    <button id="c-reject">Reject all</button>
  </div>
  <script>
    document.getElementById("c-reject").addEventListener("click", () => {
      document.getElementById("cookie-bar").remove();
    });
  </script>
</body></html>`,
  );
  const { page, tabId } = await visit(ext, `https://${HOST}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  // CONTROL: the fixture really is the banner page. Without this, a page that
  // fell through to the default mock HTML has no #cookie-bar either, and
  // "the banner is gone" would be true of a banner that never existed.
  await expect(page.locator("h1")).toContainText("Sunday bread");
  // The module clicked the site's own reject control, so the banner is gone.
  await expect(page.locator("#cookie-bar")).toHaveCount(0, { timeout: 15_000 });
  await page.close();
  await setSettings(ext, { shield: false });
});

test("popup: the calm 'handled quietly today' line, with the counts that interrupt earned", async () => {
  // Counts come from the two captures above - the held click (preemptBlock)
  // and the declined banner (cookieDecline). Real wins from real protection,
  // not a seeded record.
  await setKey(ext, null);
  const { page, tabId } = await visit(ext, "https://intranet-tools-vendor.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  await popup.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await popup.setViewportSize({ width: 380, height: 650 });
  // Pinned to the exact number, not merely "not 0". A negated matcher is
  // satisfied by a missing element, so not.toHaveText("0") would survive the
  // hero being deleted outright, and this caption quotes that number.
  await expect(popup.locator("#today-hero")).toHaveText("2");
  // Both categories are in the shot, so the caption the docs page carries
  // ("a risky click held and a cookie prompt declined") is what is on screen.
  await expect(popup.locator("#today-breakdown")).toContainText("risky click stopped");
  await expect(popup.locator("#today-breakdown")).toContainText("cookie prompt declined");
  await popup.screenshot({ path: join(SHOTS, "popup-today.png"), fullPage: true });
  await popup.close();
  await page.close();
});
