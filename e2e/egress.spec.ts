// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Browser-as-endpoint, hermetic Chromium proof, driven from the DASHBOARD
// half of the one control (the panel's half is e2e/protect.spec.ts). This
// is the hard e2e the design demands, not a structural pass: click the one
// control and prove
//   (a) the browser is actually routed through the Whisper egress endpoint
//       (its own registered identity), captured on the proxy;
//   (b) that identity appears in the account's op:list roster;
//   (c) keyless rdap verify-identity of the routed /128 returns
//       is_whisper_agent: true, so the dashboard's chip reads VERIFIED.
//
// The optional proxy permissions are promoted to required at install time
// (makeEgressDist), because the browser's own consent dialog for optional
// permissions cannot be scripted; every code path exercised: register /
// connect, chrome.proxy.set, onAuthRequired, the WebRTC policy, is real.
//
// Firefox parity rides the SAME HTTPS-CONNECT code path (proxy.onRequest +
// proxyAuthorizationHeader) and is covered by the web-ext load gate; the
// routed-traffic assertion here is Chromium, where Playwright can drive it.

import { test, expect } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, makeEgressDist, openDashboard, setKey, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("example-egress-e2e.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeEgressDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("browser-as-endpoint: turning it on registers, routes, and verifies the browser's own identity", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearEndpoints();

  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });

  // One click. The page requests the (pre-granted) permissions on the
  // gesture, then the background registers the device + provisions egress.
  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Protected", { timeout: 25_000 });
  await expect(dash.locator("#btn-protect")).toHaveText("Turn routing off");

  // (b) The browser now appears in the account roster as a device.
  const registered = net.endpoints.find((e) => e.label.includes("This browser"));
  expect(registered, "the browser registered itself as a device").toBeTruthy();

  // (c) The identity chip verifies the routed /128 against keyless rdap.
  await expect(dash.locator("#identity-chip")).toHaveText("VERIFIED WHISPER ENDPOINT", { timeout: 15_000 });

  // (a) A fresh page's traffic is now carried through the Whisper egress
  // endpoint (authenticated CONNECT), i.e. the browser sources from its own
  // identity, not direct. The egress endpoint recorded the CONNECT.
  net.clearEgressLog();
  const page = await ext.context.newPage();
  await page.goto("https://example-egress-e2e.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
  await page.waitForTimeout(600);
  expect(
    net.egressConnects("example-egress-e2e.com"),
    "site traffic routed via the Whisper egress endpoint",
  ).toBeGreaterThan(0);
  await page.close();

  // The same button turns it off and restores a direct route.
  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Identity reserved", { timeout: 20_000 });
  net.clearEgressLog();
  net.clearLog(); // so the control below counts THIS navigation, not the routed one above
  const page2 = await ext.context.newPage();
  await page2.goto("https://example-egress-e2e.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
  await page2.waitForTimeout(400);
  // CONTROL: goto's rejection is swallowed on the line above, so a page that
  // never loaded produces zero egress CONNECTs just as convincingly as one
  // that loaded directly. Prove the traffic HAPPENED before reading that it
  // did not go through the endpoint.
  expect(
    net.requestsTo("example-egress-e2e.com").length,
    "the page must actually have loaded, or a zero egress count proves nothing",
  ).toBeGreaterThan(0);
  expect(net.egressConnects("example-egress-e2e.com")).toBe(0);
  await page2.close();
  await dash.close();
});

test("browser-as-endpoint: the identity is register-once and reused, never duplicated", async () => {
  await setKey(ext, MOCK_KEY);
  const before = net.endpoints.filter((e) => e.label.includes("This browser")).length;
  // CONTROL: this test builds on the registration the previous one made, and
  // "no second row" is trivially true when there is no first row. Pin it, so
  // running this in isolation says so instead of passing on two zeroes.
  expect(before, "the browser must already be registered from the previous test, or reuse is untested").toBe(1);

  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#btn-protect")).toHaveText("Turn routing on", { timeout: 10_000 });
  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Protected", { timeout: 25_000 });

  // No SECOND device row was minted: the stored identity was reused.
  const after = net.endpoints.filter((e) => e.label.includes("This browser")).length;
  expect(after).toBe(before);

  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Identity reserved", { timeout: 20_000 });
  await dash.close();
});
