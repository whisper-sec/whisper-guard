// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// ENROLL is not PROTECT: the two regression proofs behind the split.
//
//   1) Enrollment succeeds WITHOUT the egress permissions. A signed-in user
//      on a bone-stock install (optional proxy permissions never granted)
//      clicks Enroll and gets a real registered identity: it appears in the
//      account roster, renders with its address + reverse-DNS + RDAP link,
//      verifies keylessly, and no traffic is routed anywhere new.
//
//   2) The proxy-conflict path is not a dead end. With a second extension
//      genuinely holding the proxy setting (the real-world VPN case,
//      reproduced with an actual second extension), turning routing on
//      still enrolls the browser, then explains the conflict in plain
//      words with a way forward, instead of failing with a bare "cannot".

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  launchExtension,
  makeEgressDist,
  makeProxyHolderExt,
  openDashboard,
  setKey,
  type Extension,
} from "./helpers/extension";

const MOCK_KEY = "whisper_e2e_mock_key_0000000000000000";

test.describe("enroll without egress", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    // The PLAIN dist: optional proxy permissions exist but are NOT granted.
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("enrolling reserves + verifies the identity with no proxy permission and no routing", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();

    const dash = await openDashboard(ext, "browser");
    await expect(dash.locator("#enroll-btn")).toBeVisible({ timeout: 10_000 });
    await expect(dash.locator("#identity-chip")).toHaveText("NOT ON THE WHISPER NETWORK");

    await dash.locator("#enroll-btn").click();

    // The identity renders: chip, address, reverse-DNS name, RDAP proof link.
    await expect(dash.locator("#identity-detail")).toContainText("ENROLLED", { timeout: 20_000 });
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the browser registered itself on the control plane").toBeTruthy();
    await expect(dash.locator("#identity-detail")).toContainText(registered!.address);
    await expect(dash.locator("#identity-detail")).toContainText("Reverse-DNS");
    await expect(dash.locator("#identity-detail").locator("a")).toContainText("RDAP");

    // The header chip verifies the fresh /128 against keyless rdap.
    await expect(dash.locator("#identity-chip")).toHaveText("VERIFIED WHISPER ENDPOINT", {
      timeout: 15_000,
    });

    // Routing was NEVER touched: the toggle still offers "Turn on" and page
    // traffic does not flow through the egress endpoint.
    await expect(dash.locator("#egress-toggle")).toHaveText("Turn on");
    net.clearEgressLog();
    const page = await ext.context.newPage();
    await page.goto("https://example-enroll-only.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
    await page.waitForTimeout(400);
    expect(net.egressConnects("example-enroll-only.com")).toBe(0);
    await page.close();

    // The popup shows the same identity, front and center.
    const popup = await ext.context.newPage();
    await popup.goto(`chrome-extension://${ext.id}/popup.html`);
    await expect(popup.locator("#identity-card")).toBeVisible();
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 15_000 });
    await expect(popup.locator("#identity-detail")).toContainText(registered!.address);
    await popup.close();
    await dash.close();
  });

  test("enrolling twice never duplicates the identity", async () => {
    const before = net.endpoints.filter((e) => e.label.includes("This browser")).length;
    const dash = await openDashboard(ext, "browser");
    // Already enrolled: the CTA yields to the identity detail.
    await expect(dash.locator("#identity-detail")).toContainText("This browser's identity", {
      timeout: 10_000,
    });
    await expect(dash.locator("#enroll-btn")).toBeHidden();
    expect(net.endpoints.filter((e) => e.label.includes("This browser")).length).toBe(before);
    await dash.close();
  });
});

test.describe("proxy conflict is not a dead end", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    // A REAL second extension owns the proxy (pointed at the same capture
    // proxy so the run stays hermetic). It installs after Guard, so it wins
    // the setting: Guard sees controlled_by_other_extensions.
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

  test("turning routing on under a conflict still enrolls, says why, and points at the fix", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();

    const dash = await openDashboard(ext, "browser");
    await expect(dash.locator("#egress-toggle")).toHaveText("Turn on", { timeout: 10_000 });
    await dash.locator("#egress-toggle").click();

    // Honest conflict message + an actionable way out, not a bare failure.
    await expect(dash.locator("#egress-detail")).toContainText("Another extension", {
      timeout: 20_000,
    });
    await expect(dash.locator("#egress-detail")).toContainText("verdicts keep working");
    await expect(dash.locator("#egress-detail").locator("button")).toHaveText(
      "Open the extensions page",
    );
    await expect(dash.locator("#egress-toggle")).toHaveText("Turn on");

    // ENROLLMENT SURVIVED: the conflict blocked routing, never the identity.
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the browser enrolled despite the proxy conflict").toBeTruthy();
    await expect(dash.locator("#identity-detail")).toContainText(registered!.address);
    await expect(dash.locator("#identity-chip")).toHaveText("VERIFIED WHISPER ENDPOINT", {
      timeout: 15_000,
    });
    await dash.close();
  });
});
