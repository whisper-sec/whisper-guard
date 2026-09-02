// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The dashboard's half of the ONE control, and the proof that it IS the
// panel's control rather than a second one that happens to look alike.
//
// The dashboard used to carry its own idiom: an "Enroll this browser"
// button plus a separate routing toggle, two steps for the one thing the
// panel now does in a click. Both surfaces mount the same module
// (src/shared/protect-control.ts), so what is proved here is:
//
//   1) IDENTITY WITHOUT ROUTING. On a bone-stock install (the optional
//      proxy permissions exist but are never granted), one click still
//      reserves a real registered identity: it appears in the account
//      roster, renders with its address + reverse-DNS + RDAP proof link,
//      verifies keylessly, and nothing is routed anywhere new.
//   2) THE SAME CONTROL. Panel and dashboard show the same state, in the
//      same words, from the same status. If one surface's vocabulary ever
//      drifts from the other's, this goes red.
//   3) THE PROXY CONFLICT IS NOT A DEAD END. With a second extension
//      genuinely holding the proxy setting (the real-world VPN case,
//      reproduced with an actual second extension), the click still
//      enrolls the browser and then explains the conflict in plain words
//      with a way forward, instead of failing with a bare "cannot".

import { test, expect } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeEgressDist,
  makeProxyHolderExt,
  openDashboard,
  openPopup,
  setKey,
  visit,
  type Extension,
} from "./helpers/extension";

test.describe("identity without routing", () => {
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

  test("one click reserves + verifies the identity with no proxy permission and nothing routed", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();

    const dash = await openDashboard(ext, "browser");
    await expect(dash.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });
    await expect(dash.locator("#identity-state")).toHaveText("NOT ENROLLED");
    await expect(dash.locator("#identity-chip")).toHaveText("NOT ON THE WHISPER NETWORK");
    // There is exactly ONE control here. The two-step idiom this replaced is
    // gone, and its absence is asserted so it cannot quietly come back.
    await expect(dash.locator("#enroll-btn")).toHaveCount(0);
    await expect(dash.locator("#egress-toggle")).toHaveCount(0);

    await dash.locator("#btn-protect").click();

    // The identity renders: chip, address, reverse-DNS name, RDAP proof link.
    await expect(dash.locator("#identity-detail")).toContainText(/2a04:2a01:[0-9a-f:]+/i, {
      timeout: 20_000,
    });
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the browser registered itself on the control plane").toBeTruthy();
    await expect(dash.locator("#identity-detail")).toContainText(registered!.address);
    await expect(dash.locator("#identity-detail")).toContainText("Name");
    await expect(dash.locator("#identity-detail").locator("a")).toContainText("RDAP");

    // The header chip verifies the fresh /128 against keyless rdap.
    await expect(dash.locator("#identity-chip")).toHaveText("VERIFIED WHISPER ENDPOINT", {
      timeout: 25_000,
    });
    await expect(dash.locator("#identity-state")).toHaveText("VERIFIED");

    // Routing was never granted, so it never engaged, and the control says
    // so in words rather than leaving the reader to infer it. The generous
    // budget is the permission wait itself: a headless browser never answers
    // the prompt, so the control waits out its own deadline before it will
    // say it has no answer.
    await expect(dash.locator("#route-line")).toContainText("Not routed", { timeout: 25_000 });
    await expect(dash.locator("#route-line")).toContainText("proxy permission");
    await expect(dash.locator("#btn-protect")).toHaveText("Turn routing on");

    net.clearEgressLog();
    net.clearLog(); // so the control below counts THIS navigation only
    const page = await ext.context.newPage();
    await page.goto("https://example-enroll-only.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
    await page.waitForTimeout(400);
    // CONTROL: goto's rejection is swallowed on the line above, so a page that
    // never loaded gives the same zero as one that loaded directly. Prove the
    // traffic happened before reading that it did not take the egress route.
    expect(
      net.requestsTo("example-enroll-only.com").length,
      "the page must actually have loaded, or a zero egress count proves nothing",
    ).toBeGreaterThan(0);
    expect(net.egressConnects("example-enroll-only.com")).toBe(0);
    await page.close();
    await dash.close();
  });

  test("the panel and the dashboard show the SAME control, in the same words", async () => {
    await setKey(ext, MOCK_KEY);
    // CONTROL: the comparison is only worth anything against a real enrolled
    // identity, which the previous test made. Pin that it is there, or two
    // empty surfaces would agree perfectly and prove nothing.
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the previous test must have enrolled, or agreement is untested").toBeTruthy();

    const { page, tabId } = await visit(ext, "https://example-same-control.com/");
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    const panel = {
      state: await popup.locator("#identity-state").textContent(),
      route: await popup.locator("#route-line").textContent(),
      button: await popup.locator("#btn-protect").textContent(),
    };
    await popup.close();
    await page.close();

    const dash = await openDashboard(ext, "browser");
    await expect(dash.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    expect(await dash.locator("#identity-state").textContent()).toBe(panel.state);
    expect(await dash.locator("#route-line").textContent()).toBe(panel.route);
    expect(await dash.locator("#btn-protect").textContent()).toBe(panel.button);
    // And the identity is the SAME one: clicking on either surface never
    // mints a second.
    expect(net.endpoints.filter((e) => e.label.includes("This browser")).length).toBe(1);
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

  test("under a conflict the dashboard still enrolls, says why, and points at the fix", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();

    const dash = await openDashboard(ext, "browser");
    await expect(dash.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });
    await dash.locator("#btn-protect").click();

    // Honest conflict message + an actionable way out, not a bare failure.
    await expect(dash.locator("#route-line")).toContainText("Another extension", { timeout: 25_000 });
    await expect(dash.locator("#route-line")).toContainText("verdicts keep working");
    await expect(dash.locator("#btn-route-fix")).toHaveText("Open the extensions page");
    await expect(dash.locator("#btn-protect")).toHaveText("Try again");

    // ENROLLMENT SURVIVED: the conflict blocked routing, never the identity.
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the browser enrolled despite the proxy conflict").toBeTruthy();
    await expect(dash.locator("#identity-detail")).toContainText(registered!.address);
    await expect(dash.locator("#identity-chip")).toHaveText("VERIFIED WHISPER ENDPOINT", {
      timeout: 25_000,
    });
    await dash.close();
  });
});
