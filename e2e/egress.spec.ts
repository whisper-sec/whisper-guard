// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Browser-as-endpoint (WB6), hermetic Chromium proof. This is the hard
// e2e the design demands, not a structural pass: flip the toggle and prove
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
import { E2ENetwork } from "./helpers/servers";
import { launchExtension, makeEgressDist, openDashboard, setKey, type Extension } from "./helpers/extension";

const MOCK_KEY = "whisper_e2e_mock_key_0000000000000000";

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
  await expect(dash.locator("#egress-toggle")).toHaveText("Turn on", { timeout: 10_000 });

  // Flip it on. The page requests the (pre-granted) permissions on the
  // gesture, then the background registers the device + provisions egress.
  await dash.locator("#egress-toggle").click();
  await expect(dash.locator("#egress-toggle")).toHaveText("Turn off", { timeout: 20_000 });
  await expect(dash.locator("#egress-detail")).toContainText("ROUTED");

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

  // Turning it off restores a direct route (no more egress CONNECTs).
  await dash.locator("#egress-toggle").click();
  await expect(dash.locator("#egress-toggle")).toHaveText("Turn on", { timeout: 15_000 });
  net.clearEgressLog();
  const page2 = await ext.context.newPage();
  await page2.goto("https://example-egress-e2e.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
  await page2.waitForTimeout(400);
  expect(net.egressConnects("example-egress-e2e.com")).toBe(0);
  await page2.close();
  await dash.close();
});

test("browser-as-endpoint: the identity is register-once and reused, never duplicated", async () => {
  await setKey(ext, MOCK_KEY);
  const before = net.endpoints.filter((e) => e.label.includes("This browser")).length;

  const dash = await openDashboard(ext, "browser");
  await dash.locator("#egress-toggle").click();
  await expect(dash.locator("#egress-toggle")).toHaveText("Turn off", { timeout: 20_000 });

  // No SECOND device row was minted: the stored identity was reused.
  const after = net.endpoints.filter((e) => e.label.includes("This browser")).length;
  expect(after).toBe(before);

  await dash.locator("#egress-toggle").click();
  await expect(dash.locator("#egress-toggle")).toHaveText("Turn on", { timeout: 15_000 });
  await dash.close();
});
