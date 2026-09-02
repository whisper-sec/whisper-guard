// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// WHERE A LINK ACTUALLY GOES.
//
// Guard shipped three references to the sign-in origin, one of them a
// button labelled "Open in console". Measured against the live hosts on
// 2026-09-01, that origin answers a signed-out visitor with HTTP 404 on
// every page, while console.whisper.online answers 307 to the sign-in and
// returns the reader afterwards. So the button did not open the console; it
// opened a dead end, and no test noticed, because no test had ever asked
// where the button goes.
//
// The split that remains is deliberate and is pinned here too: the RFC
// 8628 device-flow endpoints are unauthenticated by design and exist ONLY
// on console.whisper.security (console.whisper.online answers 401
// UNAUTHENTICATED for its whole /api surface, which a browserless device
// flow cannot satisfy). So that host stays as an auth ORIGIN we fetch
// from, and never as a destination we send a reader to.
//
// This spec asserts the distinction from the outside, by clicking the
// buttons and reading the tab that opens.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, openPopup, setKey, visit, waitForIcon, type Extension } from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(HERE, "../dist/chromium");

/** The console a reader is sent to, and the sign-in origin we only fetch from. */
const CONSOLE = "https://console.whisper.online";
const DEVICE_FLOW = "https://console.whisper.security";

const CLEAN = "intranet-tools-vendor.com";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

/** Click something that opens a tab, and answer with the tab's URL. */
async function urlOpenedBy(page: import("@playwright/test").Page, selector: string): Promise<string> {
  const opened = ext.context.waitForEvent("page", { timeout: 20_000 });
  await page.locator(selector).click();
  const tab = await opened;
  // A brand-new tab can report "about:blank" for an instant before the
  // navigation it was created with commits, so wait for the real URL rather
  // than reading whichever one happens to be current.
  await expect.poll(() => tab.url(), { timeout: 20_000 }).not.toBe("about:blank");
  const url = tab.url();
  await tab.close().catch(() => undefined);
  return url;
}

test("the panel's 'Open in console' opens the console, not the sign-in origin", async () => {
  await setKey(ext, MOCK_KEY);
  const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  const popup = await openPopup(ext, tabId);
  // CONTROL: the button is only offered to a signed-in reader, so prove it
  // is really on screen - a hidden button opens nothing and would make the
  // assertion below vacuous.
  await expect(popup.locator("#btn-console")).toBeVisible({ timeout: 15_000 });

  const url = await urlOpenedBy(popup, "#btn-console");
  expect(new URL(url).origin).toBe(CONSOLE);
  expect(url).not.toContain("console.whisper.security");
  await popup.close();
  await page.close();
});

test("settings' 'Open the console' opens the console, not the sign-in origin", async () => {
  await setKey(ext, MOCK_KEY);
  const opts = await ext.context.newPage();
  await opts.goto(`chrome-extension://${ext.id}/options.html`);
  await expect(opts.locator("#account-signedin")).toBeVisible({ timeout: 15_000 });

  const url = await urlOpenedBy(opts, "#btn-console");
  expect(new URL(url).origin).toBe(CONSOLE);
  expect(url).not.toContain("console.whisper.security");
  await opts.close();
});

test("the sign-in origin is fetched from and never navigated to", async () => {
  // The two halves of the split, read off the shipped bundles rather than
  // the sources, so a build that rewrote them would be caught too.
  const background = readFileSync(join(DIST, "background.js"), "utf8");
  const popup = readFileSync(join(DIST, "popup.js"), "utf8");
  const options = readFileSync(join(DIST, "options.js"), "utf8");
  const dashboard = readFileSync(join(DIST, "dashboard.js"), "utf8");

  // The device flow fetches the sign-in origin. It lives in the background
  // and nowhere else.
  expect(background).toContain(`${DEVICE_FLOW}`);
  expect(background).toContain("/api/device/authorize");

  // No SURFACE carries the sign-in origin at all: every surface is where a
  // reader is sent somewhere, and none of them may be sent there. This is
  // the assertion the old code would have failed.
  for (const [name, src] of [
    ["popup.js", popup],
    ["options.js", options],
    ["dashboard.js", dashboard],
  ] as const) {
    expect(src, `${name} must not carry the sign-in origin`).not.toContain("console.whisper.security");
  }

  // CONTROL: "not present" is trivially true of a string nothing uses. The
  // surfaces that offer a console link DO carry the console, so the
  // assertions above are about code that really does open a tab.
  expect(popup).toContain(CONSOLE);
  expect(options).toContain(CONSOLE);
});
