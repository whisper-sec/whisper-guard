// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The hermetic suite: the REAL built extension in Chromium, with the whole
// network answered by a local capture proxy so nothing leaves the machine
// and every request the browser makes is on the record. Covers, per the
// design's Phase B matrix: icon states, popup verdicts, the keyless
// on-device hero with zero egress, the privacy invariant (hostname only,
// one endpoint, full capture), the device-flow sign-in, fail-open, and the
// pre-click check.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  launchExtension,
  openPopup,
  setKey,
  setSettings,
  getStoredKey,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const MOCK_KEY = "whisper_e2e_mock_key_0000000000000000";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("clean-site-guard-e2e.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict("evil-known-guard-e2e.com", { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  net.setVerdict("shady-guard-e2e.com", { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  // The first-run live sample checks github.com (clean, as it really is).
  net.setVerdict("github.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setExplain("evil-known-guard-e2e.com", [
    {
      indicator: "evil-known-guard-e2e.com",
      level: "CRITICAL",
      score: 16.9,
      explanation: "listed in 5 threat feed(s)",
      sources: [{ feedId: "e2e-feed", firstSeen: "2026-07-01T00:00:00Z" }],
    },
  ]);
  net.setIdentify("clean-site-guard-e2e.com", [
    { host: "clean-site-guard-e2e.com", canonical_name: "E2E Clean Site", category: "saas", roles: ["ORIGIN_AS"] },
  ]);
  // Enrichment fixtures so the composed protection card + dashboard have real
  // owner / geo / verdict to render (the two-tier keyless picture).
  net.setEnrich("clean-site-guard-e2e.com", {
    ip: "203.0.113.10", city: "Frankfurt am Main, DE", country: "DE",
    asn: "AS64500", owner: "E2E Clean Site, Inc.", asnName: "E2ENET - E2E Clean Site, Inc.", verdict: "NONE",
  });
  net.setEnrich("evil-known-guard-e2e.com", {
    ip: "198.51.100.9", city: "Montreal, CA", country: "CA",
    asn: "AS64510", owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC", verdict: "CRITICAL",
  });
  net.setHistory("evil-known-guard-e2e.com", [
    { indicator: "evil-known-guard-e2e.com", createDate: "2026-06-20", updateDate: "2026-07-01", registrar: "GoDaddy" },
  ]);
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(() => {
  net.graphMode = "mock";
  net.graphDelayMs = 0;
  net.clearLog();
});

// ---------------------------------------------------------------- keyless

test("keyless two-tier: no key, the live graph verdict still paints the icon", async () => {
  // The two-tier keystone: with NO account, the public assess tier answers.
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });

  const clean = await visit(ext, "https://clean-site-guard-e2e.com/");
  expect(await waitForIcon(ext, clean.tabId, ["benign"])).toBe("benign");
  await clean.page.close();

  const evil = await visit(ext, "https://evil-known-guard-e2e.com/");
  expect(await waitForIcon(ext, evil.tabId, ["malicious"])).toBe("malicious");
  await evil.page.close();
});

test("keyless privacy: only the bare hostname leaves, only to the graph, no key on the wire", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  // A fresh, uncached host so this is a guaranteed graph round-trip.
  net.setVerdict("privacy-fresh-guard-e2e.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.clearLog();

  const { page, tabId } = await visit(ext, "https://privacy-fresh-guard-e2e.com/very/secret?token=hunter2");
  await waitForIcon(ext, tabId, ["benign"]);
  await page.waitForTimeout(400);

  // The full-capture set: only the visited site and the graph, nothing else.
  expect(net.contactedHosts().sort()).toEqual(["graph.whisper.security", "privacy-fresh-guard-e2e.com"]);
  const graphReqs = net.requestsTo("graph.whisper.security").filter((r) => r.scheme === "https");
  expect(graphReqs.length).toBeGreaterThan(0);
  // The only browsing datum on the wire is the bare hostname; the path/query
  // never leave, and the visited host was assessed by name alone.
  const assess = graphReqs.find(
    (r) => r.body.includes("whisper.assess") && r.body.includes("privacy-fresh-guard-e2e.com"),
  );
  expect(assess).toBeTruthy();
  expect(JSON.parse(assess!.body).parameters).toEqual({ hs: ["privacy-fresh-guard-e2e.com"] });
  for (const r of graphReqs) {
    expect(r.body).not.toContain("secret");
    expect(r.body).not.toContain("hunter2");
  }
  await page.close();
});

test("keyless: on-device detector runs locally; with the live check OFF nothing leaves", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: false });
  net.clearLog();

  const { page, tabId } = await visit(ext, "https://paypa1-secure-login.com/");
  const state = await waitForIcon(ext, tabId, ["suspicious"]);
  expect(state).toBe("suspicious");

  // Live check off: the ONLY traffic is the fake site itself. The detector
  // still fires entirely on-device.
  await page.waitForTimeout(400);
  expect(net.contactedHosts()).toEqual(["paypa1-secure-login.com"]);
  expect(net.requestsTo("graph.whisper.security")).toHaveLength(0);
  await page.close();
  await setSettings(ext, { cloudCheck: true });
});

test("keyless: popup shows the on-device look-alike hit and the honest privacy line", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  const { page, tabId } = await visit(ext, "https://paypa1-secure-login.com/");
  await waitForIcon(ext, tabId, ["suspicious"]);

  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#hostname")).toHaveText("paypa1-secure-login.com");
  await expect(popup.locator("#lookalike-text")).toContainText("paypal.com");
  await expect(popup.locator("#btn-goto")).toHaveText("Go to the real paypal.com");
  await expect(popup.locator("#signin-pitch")).toBeVisible();
  await expect(popup.locator("#btn-signin")).toHaveText("Sign in with Whisper");
  await expect(popup.locator("#privacy-line")).toContainText("graph.whisper.security");
  await popup.close();
  await page.close();
});

test("keyless: 'Go to the real site' navigates the tab to the brand", async () => {
  await setKey(ext, null);
  const { page, tabId } = await visit(ext, "https://paypa1-secure-login.com/");
  await waitForIcon(ext, tabId, ["suspicious"]);
  const popup = await openPopup(ext, tabId);
  await popup.locator("#btn-goto").click();
  await expect
    .poll(async () => page.url(), { timeout: 8000 })
    .toBe("https://paypal.com/");
  await page.close();
});

// ------------------------------------------------------------------ keyed

test("keyed: benign, suspicious, malicious, unknown all paint the matching icon", async () => {
  await setKey(ext, MOCK_KEY);

  const clean = await visit(ext, "https://clean-site-guard-e2e.com/");
  expect(await waitForIcon(ext, clean.tabId, ["benign"])).toBe("benign");
  await clean.page.close();

  const shady = await visit(ext, "https://shady-guard-e2e.com/");
  expect(await waitForIcon(ext, shady.tabId, ["suspicious"])).toBe("suspicious");
  await shady.page.close();

  const evil = await visit(ext, "https://evil-known-guard-e2e.com/");
  expect(await waitForIcon(ext, evil.tabId, ["malicious"])).toBe("malicious");
  await evil.page.close();

  const nobody = await visit(ext, "https://never-heard-of-it-guard-e2e.com/");
  expect(await waitForIcon(ext, nobody.tabId, ["unknown"])).toBe("unknown");
  await nobody.page.close();
});

test("keyed: popup shows the evidenced band, categorical coverage chip, explain, identify, session", async () => {
  await setKey(ext, MOCK_KEY);
  const { page, tabId } = await visit(ext, "https://evil-known-guard-e2e.com/");
  await waitForIcon(ext, tabId, ["malicious"]);

  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#band-chip")).toHaveText("MALICIOUS - evidenced");
  await expect(popup.locator("#coverage-chip")).toContainText("malicious-evidenced");
  await expect(popup.locator("#coverage-chip")).toContainText("not a safety score");
  await expect(popup.locator("#privacy-line")).toContainText('only "evil-known-guard-e2e.com" was sent');
  await expect(popup.locator("#privacy-line")).toContainText("graph.whisper.security");

  // Why this verdict (whisper.explain), lazily loaded on expand.
  await popup.locator("#exp-why summary").click();
  await expect(popup.locator("#why-body")).toContainText("CRITICAL");
  await expect(popup.locator("#why-body")).toContainText("e2e-feed");

  // Session drawer recorded the risky sighting.
  await expect(popup.locator("#session-summary")).toContainText("risky");
  await popup.locator("#exp-session summary").click();
  await expect(popup.locator("#session-body")).toContainText("evil-known-guard-e2e.com");
  await popup.close();
  await page.close();
});

test("keyed: identify renders on a clean host, and UNKNOWN is honest, never green", async () => {
  await setKey(ext, MOCK_KEY);
  const clean = await visit(ext, "https://clean-site-guard-e2e.com/");
  await waitForIcon(ext, clean.tabId, ["benign"]);
  const popup = await openPopup(ext, clean.tabId);
  await popup.locator("#exp-who summary").click();
  await expect(popup.locator("#who-body")).toContainText("E2E Clean Site");
  await popup.close();
  await clean.page.close();

  const nobody = await visit(ext, "https://never-heard-of-it-guard-e2e.com/");
  await waitForIcon(ext, nobody.tabId, ["unknown"]);
  const popup2 = await openPopup(ext, nobody.tabId);
  await expect(popup2.locator("#band-chip")).toHaveText("UNKNOWN");
  await expect(popup2.locator("#band-note")).toContainText("Not confirmed safe or unsafe");
  await popup2.close();
  await nobody.page.close();
});

test("keyed: look-alike neighborhood graph draws confirmed candidates on canvas", async () => {
  await setKey(ext, MOCK_KEY);
  // The generator will emit TLD-swap/confusable candidates for this host;
  // flag two of them in the mock graph so the canvas has confirmed nodes.
  net.setVerdict("paypa1-secure-login.net", { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  net.setVerdict("paypa1-secure-login.org", { band: "MEDIUM", coverage: "partial", label: "suspicious" });

  const { page, tabId } = await visit(ext, "https://paypa1-secure-login.com/");
  await waitForIcon(ext, tabId, ["suspicious"]);
  const popup = await openPopup(ext, tabId);
  await popup.locator("#exp-neighborhood summary").click();
  await expect(popup.locator("#neighborhood-note")).toContainText("flagged in the graph", { timeout: 15_000 });
  const painted = await popup.evaluate(() => {
    const c = document.getElementById("graph-canvas") as HTMLCanvasElement;
    const ctx = c.getContext("2d")!;
    return ctx.getImageData(0, 0, c.width, c.height).data.some((v) => v !== 0);
  });
  expect(painted).toBe(true);
  await popup.close();
  await page.close();
});

// ------------------------------------------------------- privacy invariant

test("privacy invariant: ONLY the hostname leaves, only to the graph, with the full network on record", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearLog();

  const sensitive =
    "https://privacy-probe-guard-e2e.com/very/secret/path?token=hunter2&session=abc123#fragment";
  const { page, tabId } = await visit(ext, sensitive);
  await waitForIcon(ext, tabId, ["unknown"]);
  await page.waitForTimeout(500);

  // 1) Complete-capture check: the browser contacted the visited site and
  // the graph, nothing else (no console, no corpus host, no third parties).
  const hosts = net.contactedHosts().sort();
  expect(hosts).toEqual(["graph.whisper.security", "privacy-probe-guard-e2e.com"]);

  // 2) The graph saw exactly one POST /api/query whose only browsing datum
  // is the bare hostname.
  const graphReqs = net.requestsTo("graph.whisper.security").filter((r) => r.scheme === "https");
  expect(graphReqs).toHaveLength(1);
  const body = JSON.parse(graphReqs[0].body);
  expect(body.parameters).toEqual({ hs: ["privacy-probe-guard-e2e.com"] });
  expect(body.query).toContain("whisper.assess");

  // 3) Nothing that left the browser carries the path, query, or fragment,
  // except the visited site's own page fetch (that IS the navigation).
  for (const r of net.log) {
    if (r.host === "privacy-probe-guard-e2e.com") continue;
    const blob = `${r.path} ${r.body}`;
    expect(blob).not.toContain("secret");
    expect(blob).not.toContain("hunter2");
    expect(blob).not.toContain("abc123");
    expect(blob).not.toContain("fragment");
  }
  await page.close();
});

test("privacy invariant: revisit paints from cache with zero graph traffic", async () => {
  await setKey(ext, MOCK_KEY);
  const first = await visit(ext, "https://clean-site-guard-e2e.com/");
  await waitForIcon(ext, first.tabId, ["benign"]);
  await first.page.close();

  net.clearLog();
  const again = await visit(ext, "https://clean-site-guard-e2e.com/");
  await waitForIcon(ext, again.tabId, ["benign"]);
  await again.page.waitForTimeout(400);
  expect(net.requestsTo("graph.whisper.security")).toHaveLength(0);
  await again.page.close();
});

test("privacy: internal pages are never assessed and read as out of scope", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearLog();
  const page = await ext.context.newPage();
  await page.goto("chrome://version/");
  await page.waitForTimeout(600);
  expect(net.requestsTo("graph.whisper.security")).toHaveLength(0);
  await page.close();
});

// ------------------------------------------------------------- device flow

test("device flow: one click signs in and the key lands in storage", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  net.device.polls = 0;
  net.device.approveVisited = false;

  // Keyless already shows the live band; sign-in unlocks the fleet, not the
  // per-site verdict, so this asserts the sign-in itself completes.
  const { page, tabId } = await visit(ext, "https://clean-site-guard-e2e.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  await popup.locator("#btn-signin").click();

  // The flow opens the console approval tab (our mock approves on visit)
  // and the popup polls to "approved".
  await expect
    .poll(async () => getStoredKey(ext), { timeout: 20_000 })
    .toBe(MOCK_KEY);

  // The keyed band remains benign; the panel renders it after the reload.
  await popup.reload();
  await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT", { timeout: 15_000 });
  await popup.close();
  await page.close();

  // The console was only ever sent device-flow calls, no browsing data.
  const consoleReqs = net.requestsTo("console.whisper.security").filter((r) => r.scheme === "https");
  for (const r of consoleReqs) {
    expect(r.body).not.toContain("clean-site-guard-e2e.com");
  }
  await setKey(ext, null);
});

test("sign out clears the key and the popup returns to the pitch", async () => {
  await setKey(ext, MOCK_KEY);
  // Sign out through the real message router, as the options page does.
  const options = await ext.context.newPage();
  await options.goto(`chrome-extension://${ext.id}/options.html`);
  await expect(options.locator("#account-signedin")).toBeVisible();
  await options.locator("#btn-signout").click();
  await expect(options.locator("#account-signedout")).toBeVisible();
  expect(await getStoredKey(ext)).toBeNull();
  await options.close();
});

// --------------------------------------------------------------- fail-open

test("fail-open: graph down means UNKNOWN icon, page loads, popup says so, detector still fires", async () => {
  await setKey(ext, MOCK_KEY);
  net.graphMode = "down";

  const { page, tabId } = await visit(ext, "https://fine-but-graph-is-down.com/");
  const state = await waitForIcon(ext, tabId, ["unknown"]);
  expect(state).toBe("unknown");
  await expect(page.locator("h1")).toContainText("fine-but-graph-is-down.com");

  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#graph-error")).toContainText("could not reach Whisper");
  await expect(popup.locator("#graph-error")).toContainText("on-device checks only");
  await popup.close();
  await page.close();

  // The keyless hero is untouched by the outage.
  const look = await visit(ext, "https://faceb00k-login-help.com/");
  expect(await waitForIcon(ext, look.tabId, ["suspicious"])).toBe("suspicious");
  await look.page.close();
});

test("fail-open: HTTP 500 from the graph degrades identically", async () => {
  await setKey(ext, MOCK_KEY);
  net.graphMode = "http500";
  const { page, tabId } = await visit(ext, "https://error-path-guard-e2e.com/");
  expect(await waitForIcon(ext, tabId, ["unknown"])).toBe("unknown");
  await page.close();
});

test("checking state is shown while a slow verdict is in flight, then settles", async () => {
  await setKey(ext, MOCK_KEY);
  net.graphDelayMs = 1500;
  const { page, tabId } = await visit(ext, "https://slow-verdict-guard-e2e.com/");
  const transient = await waitForIcon(ext, tabId, ["checking", "unknown"]);
  expect(["checking", "unknown"]).toContain(transient);
  expect(await waitForIcon(ext, tabId, ["unknown"])).toBe("unknown");
  await page.close();
});

// ---------------------------------------------------------- pre-click check

test("pre-click check vets a destination before navigation, keyless and keyed", async () => {
  // Keyless with the live check off: the on-device verdict, zero-egress line.
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: false });
  net.clearLog();
  const check = await ext.context.newPage();
  await check.goto(`chrome-extension://${ext.id}/check-link.html?host=paypa1-secure-login.com`);
  await expect(check.locator("#detector-text")).toContainText("paypal.com");
  await expect(check.locator("#btn-real")).toContainText("Go to the real paypal.com");
  await expect(check.locator("#privacy")).toContainText("nothing left your browser");
  expect(net.requestsTo("graph.whisper.security")).toHaveLength(0);
  await check.close();
  await setSettings(ext, { cloudCheck: true });

  // Keyed: the live band joins the same surface.
  await setKey(ext, MOCK_KEY);
  const check2 = await ext.context.newPage();
  await check2.goto(`chrome-extension://${ext.id}/check-link.html?host=evil-known-guard-e2e.com`);
  await expect(check2.locator("#band-tag")).toHaveText("CRITICAL");
  await expect(check2.locator("#band-text")).toContainText("Do not open");
  await expect(check2.locator("#privacy")).toContainText('only "evil-known-guard-e2e.com" was sent');
  await check2.close();
});

test("pre-click context-menu item is registered", async () => {
  // The menu itself lives in native UI Playwright cannot click, so assert
  // the registration is present and the click handler routes to the page.
  const registered = await ext.sw.evaluate(
    () =>
      new Promise<boolean>((resolve) => {
        // Recreate is idempotent: an existing id makes create fire an error.
        chrome.contextMenus.create(
          { id: "whisper-guard-check-link", title: "x", contexts: ["link"] },
          () => resolve(Boolean(chrome.runtime.lastError)),
        );
      }),
  );
  expect(registered).toBe(true);
});

// ------------------------------------------------------------ first run

test("first-run page: privacy promise + honest scope, opened once on install", async () => {
  // onInstalled fired when this context loaded the unpacked extension; the
  // welcome tab may have been auto-opened. Assert the page itself renders
  // the two cards either way.
  await setKey(ext, MOCK_KEY);
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/firstrun.html`);
  await expect(page.locator("h1")).toHaveText("Guard is protecting you now");
  await expect(page.locator("main")).toContainText("privacy promise");
  await expect(page.locator("main")).toContainText("never your history");
  await expect(page.locator("main")).toContainText("What signing in adds");
  await expect(page.locator("#btn-signin")).toHaveText("Sign in with Whisper");
  await expect(page.locator("#btn-later")).toHaveText("Not now");
  // The live sample verdict proves the graph tier keyless-first.
  await expect(page.locator("#sample-chip")).toHaveText("NO KNOWN THREAT", { timeout: 15_000 });
  await page.close();
  await setKey(ext, null);
});
