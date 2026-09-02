// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// ONE control, in the panel, for the whole thing.
//
// Enrolment (reserve this browser's routable identity) and routing (send its
// traffic out through that identity) used to be two separate steps in two
// separate surfaces: the panel could only enrol, and told the reader to go
// find routing in the dashboard. The panel now does both from one button,
// asking for the permission routing needs at the moment it is needed.
//
// The three outcomes that matter are all proved here against the real
// extension and the hermetic mock control plane / egress endpoint:
//
//   1. GRANTED      one click enrols AND routes: the device appears in the
//                   account roster, keyless RDAP verifies the /128, and page
//                   traffic really leaves through the Whisper egress
//                   endpoint. A second click turns it off and traffic goes
//                   direct again.
//   2. REFUSED      the browser refuses the routing permission: the identity
//                   is STILL reserved and verified, the panel names the
//                   permission as what is in the way, and nothing routes.
//   3. TAKEN        another extension owns the proxy setting: same again,
//                   with the conflict named and the extensions page offered.
//
// In 2 and 3 the identity surviving is the whole point: routing can fail,
// the browser's own address may not silently fail with it.

import { test, expect, type Page } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeEgressDist,
  makeProxyHolderExt,
  openPopup,
  setKey,
  settlePopup,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const SHOTS = resolve(dirname(fileURLToPath(import.meta.url)), "../shots");
const CLEAN = "intranet-tools-vendor.com";

/** Capture the panel exactly as a reader in that colour scheme sees it,
 *  with every animated value settled (see settlePopup). */
async function shot(popup: Page, file: string, scheme: "dark" | "light" = "dark"): Promise<void> {
  mkdirSync(SHOTS, { recursive: true });
  await settlePopup(popup, { colorScheme: scheme, width: 400, height: 700 });
  await popup.screenshot({ path: join(SHOTS, file), fullPage: true });
}

function seed(net: E2ENetwork): void {
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setIdentify(CLEAN, [{ host: CLEAN, canonical_name: "Intranet Tools", category: "work", roles: [] }]);
  net.setEnrich(CLEAN, {
    ip: "203.0.113.12", city: "Amsterdam, NL", country: "NL", asn: "AS64500",
    owner: "Intranet Tools B.V.", asnName: "INTRANET - Intranet Tools B.V.",
    verdict: "NONE", prefix: "203.0.113.0/24",
  });
}

// ------------------------------------------- 1 + 2: refused, then granted

test.describe("the routing permission is refused", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seed(net);
    // The PLAIN dist: the routing permissions are optional and NOT granted,
    // and a headless browser refuses the request. Exactly a reader who says
    // no to the prompt.
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("signed out, the panel offers the one thing that unlocks it", async () => {
    await setKey(ext, null);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign", "signedout", "unknown"]);
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#signin-pitch")).toBeVisible();
    await expect(popup.locator("#btn-signin")).toHaveText("Sign in with Whisper");
    // The keyed control is not offered to a reader who cannot use it.
    await expect(popup.locator("#identity-card")).toBeHidden();
    await shot(popup, "popup-signedout.png");
    await shot(popup, "popup-signedout-light.png", "light");
    await popup.close();
    await page.close();
  });

  test("the one control still reserves the identity, and names the permission as what is in the way", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId);

    // Before: one control, and it is the primary one.
    await expect(popup.locator("#identity-state")).toHaveText("NOT ENROLLED", { timeout: 10_000 });
    await expect(popup.locator("#btn-protect")).toHaveText("Protect this browser");
    await expect(popup.locator("#btn-protect")).toHaveClass(/primary/);
    await expect(popup.locator("#route-line")).toContainText("Not protected");
    await shot(popup, "popup-protect-offer.png");
    await shot(popup, "popup-protect-offer-light.png", "light");

    net.clearEgressLog();
    await popup.locator("#btn-protect").click();

    // The identity is reserved BEFORE the panel waits on the permission at
    // all, which is the whole ordering: on a real toolbar popup the prompt
    // can close this page while the dialog is still up, so anything queued
    // behind the prompt is work that may never run. The permission wait is
    // 12s here (a headless browser never answers the prompt), so an address
    // on screen well inside that can only mean the enrolment did not queue
    // behind it.
    await expect(popup.locator("#identity-detail")).toContainText(/2a04:2a01:[0-9a-f:]+/i, {
      timeout: 8_000,
    });

    // And it is real: reserved on the control plane, rendered with its
    // address, and confirmed against keyless RDAP.
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the browser reserved its identity despite the refusal").toBeTruthy();
    await expect(popup.locator("#identity-detail")).toContainText(registered!.address);
    await expect(popup.locator("#identity-detail").locator("a")).toContainText("RDAP");

    // And the panel says exactly what is in the way, with a way to retry.
    // The generous budget is the permission wait itself: a headless browser
    // never answers the prompt, so the panel waits out its own deadline
    // before it will say it has no answer (src/popup/popup.ts).
    await expect(popup.locator("#route-line")).toContainText("Not routed", { timeout: 25_000 });
    await expect(popup.locator("#route-line")).toContainText("proxy permission");
    await expect(popup.locator("#route-line")).toContainText("keep working");
    await expect(popup.locator("#btn-protect")).toHaveText("Turn routing on");
    await shot(popup, "popup-protect-refused.png");
    await popup.close();

    // Nothing was routed: the refusal cost the routing and only the routing.
    const probe = await ext.context.newPage();
    await probe.goto(`https://${CLEAN}/`, { waitUntil: "domcontentloaded" }).catch(() => undefined);
    await probe.waitForTimeout(400);
    // CONTROL: goto's rejection is swallowed above, so a page that never
    // loaded gives the same zero as one that loaded direct. Prove the
    // traffic happened before reading that it did not take the egress route.
    expect(
      net.requestsTo(CLEAN).length,
      "the page must actually have loaded, or a zero egress count proves nothing",
    ).toBeGreaterThan(0);
    expect(net.egressConnects(CLEAN)).toBe(0);
    await probe.close();
    await page.close();
  });
});

test.describe("the routing permission is granted", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seed(net);
    // The routing permissions are granted at install time, because the
    // browser's own consent dialog cannot be scripted. Every code path the
    // click then takes (request, register, connect, proxy.set,
    // onAuthRequired, the WebRTC policy) is the real one.
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeEgressDist() });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("one click enrols AND routes, and a second turns it off", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId);

    await expect(popup.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });
    await popup.locator("#btn-protect").click();

    // ONE click did both halves.
    await expect(popup.locator("#route-line")).toContainText("Protected", { timeout: 25_000 });
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 15_000 });
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the browser registered itself as a device").toBeTruthy();
    await expect(popup.locator("#identity-detail")).toContainText(registered!.address);
    await shot(popup, "popup-protected.png");
    await shot(popup, "popup-protected-light.png", "light");

    // Routed for real: a fresh page's traffic leaves through the Whisper
    // egress endpoint, on an authenticated CONNECT it recorded.
    net.clearEgressLog();
    const routed = await ext.context.newPage();
    await routed.goto(`https://${CLEAN}/`, { waitUntil: "domcontentloaded" }).catch(() => undefined);
    await routed.waitForTimeout(600);
    expect(
      net.egressConnects(CLEAN),
      "site traffic routed via the Whisper egress endpoint",
    ).toBeGreaterThan(0);
    await routed.close();

    // The same button turns it back off, and traffic goes direct again.
    await expect(popup.locator("#btn-protect")).toHaveText("Turn routing off");
    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#route-line")).toContainText("Identity reserved", { timeout: 15_000 });
    net.clearEgressLog();
    net.clearLog();
    const direct = await ext.context.newPage();
    await direct.goto(`https://${CLEAN}/`, { waitUntil: "domcontentloaded" }).catch(() => undefined);
    await direct.waitForTimeout(400);
    // CONTROL: as above, a page that never loaded would also show zero.
    expect(
      net.requestsTo(CLEAN).length,
      "the page must actually have loaded, or a zero egress count proves nothing",
    ).toBeGreaterThan(0);
    expect(net.egressConnects(CLEAN)).toBe(0);
    await direct.close();

    await popup.close();
    await page.close();
  });

  test("clicking it again reuses the identity and never mints a second", async () => {
    await setKey(ext, MOCK_KEY);
    const before = net.endpoints.filter((e) => e.label.includes("This browser")).length;
    // CONTROL: "no second device" is trivially true when there is no first.
    expect(before, "the previous test must have enrolled, or reuse is untested").toBe(1);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#btn-protect")).toHaveText("Turn routing on", { timeout: 10_000 });
    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#route-line")).toContainText("Protected", { timeout: 25_000 });
    expect(net.endpoints.filter((e) => e.label.includes("This browser")).length).toBe(before);
    await popup.close();
    await page.close();
  });
});

// ---------------------------------------------- 3: another extension owns it

test.describe("another extension owns the proxy setting", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seed(net);
    // A REAL second extension takes the proxy setting (pointed at the same
    // capture proxy so the run stays hermetic). It installs after Guard, so
    // it wins: Guard sees controlled_by_other_extensions, the VPN case.
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

  test("the identity still stands, the conflict is named, and the fix is one click away", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    // Wait for the verdict, as the other two cases do. Without it the panel is
    // opened mid-flight and the capture this test publishes showed "UNKNOWN -
    // no verdict yet" for a host the fixture seeds as clean, differently on
    // every run. The conflict being captured is about ROUTING; the site
    // verdict above it should be settled, not racing.
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId);

    await expect(popup.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });
    await popup.locator("#btn-protect").click();

    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    const registered = net.endpoints.find((e) => e.label.includes("This browser"));
    expect(registered, "the browser enrolled despite the proxy conflict").toBeTruthy();
    await expect(popup.locator("#identity-detail")).toContainText(registered!.address);

    await expect(popup.locator("#route-line")).toContainText("Another extension");
    await expect(popup.locator("#route-line")).toContainText("keep working");
    await expect(popup.locator("#btn-route-fix")).toHaveText("Open the extensions page");
    await expect(popup.locator("#btn-protect")).toHaveText("Try again");
    await shot(popup, "popup-protect-conflict.png");
    await popup.close();
    await page.close();
  });
});

// ------------------------------------------------- the ordering, statically

/**
 * The one failure in this control that no behavioural test can see.
 *
 * chrome.permissions.request only counts as user-gestured if it is reached
 * synchronously from the click. Put ONE await in front of it - make protect()
 * async, read a status first, look something up - and the browser drops the
 * request: no dialog appears, the promise never settles, and the control
 * waits out its 12s deadline and then reports, truthfully but uselessly, that
 * it has no answer. Every test in this file still passes, because the e2e
 * dists either pre-grant the permissions or refuse them outright, and a
 * headless browser never shows the dialog either way. It fails only for real
 * users, in a real Chrome, forever.
 *
 * So it is pinned where it can be seen: in the SHIPPED bundles, on both
 * surfaces, because the control is one module mounted twice and a regression
 * would reach both at once.
 */
test("the permission request is first on the gesture, in both shipped bundles", () => {
  const dist = resolve(dirname(fileURLToPath(import.meta.url)), "../dist/chromium");
  for (const file of ["popup.js", "dashboard.js"]) {
    const src = readFileSync(join(dist, file), "utf8");
    const at = src.indexOf("function protect()");
    // CONTROL: a bundle without the control at all would satisfy every
    // "does not contain an await" check below by containing nothing.
    expect(at, `${file} does not ship the one control`).toBeGreaterThan(-1);

    // Not async: an async function cannot help but be a suspension point for
    // anything that awaits it, and the temptation to await inside is the
    // whole risk.
    expect(
      src.slice(Math.max(0, at - 12), at),
      `${file}: protect() must not be async - the request has to run on the gesture`,
    ).not.toContain("async");

    const body = src.slice(at, at + 4000);
    const request = body.indexOf("chrome.permissions.request");
    expect(request, `${file}: protect() must call chrome.permissions.request`).toBeGreaterThan(-1);
    const firstAwait = body.indexOf("await");
    // Either there is no await at all in the function, or the request comes
    // first. Both are fine; an await in front of it is not.
    if (firstAwait !== -1) {
      expect(
        request,
        `${file}: an await runs before chrome.permissions.request; the browser will drop it as un-gestured`,
      ).toBeLessThan(firstAwait);
    }
  }
});
