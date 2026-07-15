// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Page-link pre-verdicts, hermetic proof: one click verdicts every
// destination the current page links to, BEFORE any of them is visited,
// keyless, and the capture proxy proves the privacy invariant held: only
// bare registrable hostnames reached the graph; the links' paths, query
// strings and the page's text never left the browser.
//
// The dist grants <all_urls> at install time (makeShieldDist) because the
// popup here is driven as a plain page, outside a real toolbar-click
// gesture, so activeTab cannot arm; the injection code path under test
// (chrome.scripting.executeScript into the tab) is the real one either way.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import { launchExtension, makeShieldDist, openPopup, visit, waitForIcon, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const FIXTURE_HTML = `<!doctype html>
<html><head><title>fixture</title></head>
<body>
  <h1>Do not follow the bad link</h1>
  <a href="https://evil-linked.com/secret-path?q=1&token=abc">totally legit prize</a>
  <a href="https://sub.good-linked.com/deep/page.html">docs</a>
  <a href="https://good-linked.com/other">more docs</a>
  <a href="/about">about us</a>
  <a href="#section">jump</a>
  <a href="mailto:hello@fixture-links.com">mail</a>
  <a href="https://192.168.1.1/router">router</a>
  <a href="http://intranet/wiki">intranet</a>
</body></html>`;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("fixture-links.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict("evil-linked.com", { band: "CRITICAL", coverage: "known-clean", label: "malicious" });
  net.setVerdict("good-linked.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage("fixture-links.com", FIXTURE_HTML);
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("one click verdicts every linked destination before any visit, keyless", async () => {
  // Keyless on purpose: the sweep is a public-tier feature.
  const { page, tabId } = await visit(ext, "https://fixture-links.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });

  await popup.locator("#btn-linkscan").click();

  // The riskiest destination leads, badged; private hosts never appear.
  await expect(popup.locator("#linkscan-summary")).toContainText("1 malicious", { timeout: 15_000 });
  const first = popup.locator("#linkscan-list .link-row").first();
  await expect(first).toContainText("evil-linked.com");
  await expect(first.locator(".w-chip")).toHaveText("MALICIOUS");
  await expect(popup.locator("#linkscan-list")).not.toContainText("192.168.1.1");
  await expect(popup.locator("#linkscan-list")).not.toContainText("intranet");
  // Subdomain + apex + relative links reduce to registrable destinations.
  const summary = (await popup.locator("#linkscan-summary").textContent()) ?? "";
  expect(summary).toContain("3 destination(s)");
  await expect(popup.locator("#linkscan-note")).toContainText("never the page");

  // THE PRIVACY INVARIANT, asserted on the capture proxy's complete log:
  // the graph saw registrable hostnames and nothing else of the page.
  const graphBodies = net
    .requestsTo("graph.whisper.security")
    .map((r) => r.body)
    .join("\n");
  expect(graphBodies).toContain("evil-linked.com");
  expect(graphBodies).toContain("good-linked.com");
  expect(graphBodies).not.toContain("secret-path");
  expect(graphBodies).not.toContain("token=abc");
  expect(graphBodies).not.toContain("deep/page");
  expect(graphBodies).not.toContain("prize");
  expect(graphBodies).not.toContain("sub.good-linked.com");

  // Nothing was navigated by the scan: the fake sites got no new requests.
  expect(net.requestsTo("evil-linked.com").length).toBe(0);

  await popup.close();
  await page.close();
});

test("re-checking rides the verdict cache: no duplicate assess for the same hosts", async () => {
  const { page, tabId } = await visit(ext, "https://fixture-links.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  await popup.locator("#btn-linkscan").click();
  await expect(popup.locator("#linkscan-summary")).toContainText("destination", { timeout: 15_000 });

  const assessCalls = (): number =>
    net.requestsTo("graph.whisper.security").filter((r) => r.body.includes("whisper.assess")).length;
  const before = assessCalls();
  await popup.locator("#btn-linkscan").click();
  await expect(popup.locator("#linkscan-summary")).toContainText("destination");
  // All three destinations were cached by the first sweep.
  expect(assessCalls()).toBe(before);

  await popup.close();
  await page.close();
});
