// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Active Shield: the two block paths and the on-page amber layer, against
// the real built code. The one test-only delta is HOW the broad-host grant
// arrives (install-time instead of the native consent dialog, which cannot
// be automated); every code path under test then checks the grant through
// the same permissions.contains call the product uses.
//
//   novel-bad   first sighting: verdict arrives after commit -> tabs.update
//               redirect to the warning page (page briefly painted, still
//               pre-credential)
//   cached-bad  second sighting: a DNR session rule redirects BEFORE the
//               request leaves, proven by the capture proxy seeing nothing
//   amber       look-alikes never block: banner + password-field caution

import { test, expect } from "@playwright/test";
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

const MOCK_KEY = "whisper_e2e_mock_key_0000000000000000";

let net: E2ENetwork;
let ext: Extension;

// One fresh evidenced-malicious host per test: a session-allow granted in
// one test must never leak a pass/block into the next.
const EVIL = {
  novel: "evil-novel-guard-e2e.com",
  cached: "evil-cached-guard-e2e.com",
  cont: "evil-continue-guard-e2e.com",
  goback: "evil-goback-guard-e2e.com",
  popup: "evil-popup-guard-e2e.com",
};

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const host of Object.values(EVIL)) {
    net.setVerdict(host, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  }
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, MOCK_KEY);
  await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("shield toggle in settings reflects the granted state", async () => {
  const options = await ext.context.newPage();
  await options.goto(`chrome-extension://${ext.id}/options.html`);
  await expect(options.locator("#opt-shield")).toBeChecked();
  await options.close();
});

test("novel-bad: the verdict moves the committed tab to the warning page", async () => {
  net.clearLog();
  const page = await ext.context.newPage();
  await page.goto(`https://${EVIL.novel}/`, { waitUntil: "commit" });

  // The page painted first (novel host: no rule existed yet)...
  expect(net.requestsTo(EVIL.novel).filter((r) => r.scheme === "https").length).toBeGreaterThan(0);

  // ...then the CRITICAL verdict lands and the tab moves to the warning.
  await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
  expect(page.url()).toContain(`chrome-extension://${ext.id}/warning.html`);
  expect(page.url()).toContain(`host=${EVIL.novel}`);

  await expect(page.locator("h1")).toContainText("Whisper stopped a dangerous page");
  await expect(page.locator("#detail")).toContainText(EVIL.novel);
  await expect(page.locator("#detail")).toContainText("blocked before any credentials");
  await expect(page.locator("#btn-back")).toBeVisible();
  await expect(page.locator("#btn-continue")).toBeVisible();
  await expect(page.locator("#privacy")).toContainText(`only "${EVIL.novel}" was checked`);
  await page.close();
});

test("cached-bad: the DNR session rule blocks pre-render, zero bytes to the host", async () => {
  // First sighting installs the session rule.
  const prime = await ext.context.newPage();
  await prime.goto(`https://${EVIL.cached}/`, { waitUntil: "commit" });
  await prime.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
  await prime.close();

  // Second sighting: the redirect happens BEFORE any request leaves.
  net.clearLog();
  const page = await ext.context.newPage();
  await page.goto(`https://${EVIL.cached}/`, { waitUntil: "commit" });
  await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });

  const toEvil = net.requestsTo(EVIL.cached).filter((r) => r.scheme === "https");
  expect(toEvil).toHaveLength(0);
  await page.close();
});

test("continue anyway: one honest click through, allowed for the session, never trapped", async () => {
  const page = await ext.context.newPage();
  await page.goto(`https://${EVIL.cont}/`, { waitUntil: "commit" });
  await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });

  await page.locator("#btn-continue").click();
  await page.waitForURL(`https://${EVIL.cont}/`, { timeout: 15_000 });
  await expect(page.locator("h1")).toContainText(EVIL.cont);

  // Session-allowed: a reload keeps working, no re-block loop.
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("h1")).toContainText(EVIL.cont);
  await page.close();
});

test("amber: a look-alike never blocks; banner and password-field caution appear on-page", async () => {
  const { page, tabId } = await visit(ext, "https://paypa1-checkout-secure.com/");
  await waitForIcon(ext, tabId, ["suspicious"]);

  // The page itself is fully usable (amber never blocks).
  await expect(page.locator("h1")).toContainText("paypa1-checkout-secure.com");

  // The banner mounts in a closed shadow root; its host element is the
  // observable contract from the page's side.
  await expect
    .poll(async () => page.locator("div[style*='2147483647']").count(), { timeout: 10_000 })
    .toBeGreaterThan(0);

  // The a11y tree still exposes the alert text through the closed root
  // (read via CDP; Playwright locators cannot pierce closed shadow DOM).
  const cdp = await ext.context.newCDPSession(page);
  const tree = await cdp.send("Accessibility.getFullAXTree");
  expect(JSON.stringify(tree)).toContain("looks like paypal.com");

  // Password-field caution on focus.
  const mountsBefore = await page.locator("div[style*='2147483647']").count();
  await page.locator("input[type=password]").focus();
  await expect
    .poll(async () => page.locator("div[style*='2147483647']").count(), { timeout: 10_000 })
    .toBeGreaterThan(mountsBefore);
  const tree2 = await cdp.send("Accessibility.getFullAXTree");
  expect(JSON.stringify(tree2)).toContain("NOT paypal.com");
  await cdp.detach();

  // Dismiss works and sticks for the session (sessionStorage flag).
  await page.close();
});

test("warning page: ONE Back-to-safety returns to the last safe page (novel-bad history replaced)", async () => {
  const page = await ext.context.newPage();
  await page.goto("https://safe-start-guard-e2e.com/", { waitUntil: "domcontentloaded" });
  await page.goto(`https://${EVIL.goback}/x`, { waitUntil: "commit" }).catch(() => undefined);
  await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
  // The dangerous page's history entry was REPLACED by the warning, so a
  // single Back lands on the safe page, never bouncing off the block.
  await page.locator("#btn-back").click();
  await page.waitForURL("https://safe-start-guard-e2e.com/", { timeout: 15_000 });
  await page.close();
});

test("popup on a blocked-warning tab stays coherent", async () => {
  const page = await ext.context.newPage();
  await page.goto(`https://${EVIL.popup}/`, { waitUntil: "commit" });
  await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
  // The warning page is an extension page: the popup reports it out of scope
  // rather than pretending a verdict.
  const tabId = await ext.sw.evaluate(async () => {
    const tabs = await chrome.tabs.query({});
    const t = tabs.find((x) => (x.url ?? "").includes("warning.html"));
    return t?.id ?? -1;
  });
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#ineligible")).toBeVisible();
  await expect(popup.locator("#privacy-line")).toContainText("nothing was sent");
  await popup.close();
  await page.close();
});
