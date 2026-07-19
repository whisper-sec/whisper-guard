// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// BUG 1 regression: on a bone-stock install (no <all_urls>, and no toolbar
// gesture to arm activeTab), the page-link sweep used to dead-end on the raw
// Chrome error "Cannot access contents of the page. Extension manifest must
// request permission to access the respective host." It must now degrade
// gracefully: a clear, honest "Allow this page" affordance that requests the
// CURRENT SITE ONLY on the next click, instead of an opaque failure.
//
// Driven with the PLAIN dist and the popup opened as a page: exactly the
// no-host-access condition, so the "could not read the page's links" path is
// the real one under test.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import { launchExtension, openPopup, visit, waitForIcon, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const FIXTURE_HTML = `<!doctype html><html><head><title>fx</title></head>
<body><a href="https://linked-a.com/x">a</a><a href="https://linked-b.com/y">b</a></body></html>`;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("fixture-noperm.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage("fixture-noperm.com", FIXTURE_HTML);
  // PLAIN dist: no <all_urls>, no promoted permissions.
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("link sweep without host access degrades to an honest 'allow this page', not an opaque error", async () => {
  const { page, tabId } = await visit(ext, "https://fixture-noperm.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });

  await popup.locator("#btn-linkscan").click();

  // No opaque Chrome error; a plain-language ask, and the button becomes the
  // grant affordance for the next (gesture) click.
  await expect(popup.locator("#linkscan-summary")).toContainText("needs your OK", { timeout: 15_000 });
  await expect(popup.locator("#linkscan-summary")).not.toContainText("Cannot access contents");
  await expect(popup.locator("#btn-linkscan")).toHaveText("Allow this page & check");

  // Nothing was navigated, and the privacy model held: no page content leaked.
  expect(net.requestsTo("linked-a.com").length).toBe(0);

  await popup.close();
  await page.close();
});
