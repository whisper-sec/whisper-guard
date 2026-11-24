// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE DOT ON THE THIS PAGE TAB. While the link result drawn on This page
// holds a malicious link (a CRITICAL or HIGH link result, as the link check
// counts them), the tab carries a red dot and a text alternative that names how
// many. The dot sends nothing, shows on a tab that is not selected, and is not
// kept once the popup closes.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openPopup,
  selectPopupTab,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const PAGE_A = "dot-page-a-guard-e2e.com";
const PAGE_B = "dot-page-b-guard-e2e.com";
const PAGE_C = "dot-page-c-guard-e2e.com";

const html = (...hosts: string[]): string =>
  `<!doctype html><html><head><title>fixture</title></head><body>${hosts
    .map((h) => `<a href="https://${h}/landing">link</a>`)
    .join("")}</body></html>`;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const page of [PAGE_A, PAGE_B, PAGE_C]) net.setVerdict(page, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict("dot-critical-guard-e2e.com", { band: "CRITICAL", coverage: "known-clean", label: "malicious" });
  net.setVerdict("dot-high-guard-e2e.com", { band: "HIGH", coverage: "known-clean", label: "malicious" });
  net.setVerdict("dot-medium-guard-e2e.com", { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setVerdict("dot-clean-guard-e2e.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict("dot-other-critical-guard-e2e.com", { band: "CRITICAL", coverage: "known-clean", label: "malicious" });
  net.setPage(
    PAGE_A,
    html("dot-critical-guard-e2e.com", "dot-high-guard-e2e.com", "dot-medium-guard-e2e.com", "dot-clean-guard-e2e.com"),
  );
  net.setPage(PAGE_B, html("dot-other-critical-guard-e2e.com"));
  net.setPage(PAGE_C, html("dot-medium-guard-e2e.com", "dot-clean-guard-e2e.com"));
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function resolvedBackground(popup: Page, token: string): Promise<string> {
  return popup.evaluate((t) => {
    const probe = document.createElement("span");
    probe.style.setProperty("background-color", `var(${t})`);
    document.body.appendChild(probe);
    const value = getComputedStyle(probe).backgroundColor;
    probe.remove();
    return value;
  }, token);
}

test("the This page tab carries a red dot with a text alternative while its link result holds a malicious link", async () => {
  const { page, tabId } = await visit(ext, `https://${PAGE_A}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId, { popupTab: "page" });
  await expect(popup.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });

  // Before the check: no dot, and the tab is named by its label alone.
  await expect(popup.locator("#tab-page-dot")).toBeHidden();
  await expect(popup.locator("#tab-page")).toHaveAccessibleName("This page");

  await popup.locator("#btn-linkscan").click();
  await expect(popup.locator("#linkscan-summary")).toContainText("destination", { timeout: 15_000 });

  // Two malicious links (CRITICAL and HIGH); the MEDIUM one is not counted.
  await expect(popup.locator("#tab-page-dot")).toBeVisible();
  await expect(popup.locator("#tab-page")).toHaveAccessibleName("This page 2 malicious links on this page");
  expect(await popup.locator("#tab-page-dot").evaluate((e) => getComputedStyle(e).backgroundColor)).toBe(
    await resolvedBackground(popup, "--w-v-high-fill"),
  );

  // Selecting This site sends nothing, and the dot stays on the tab that is not selected.
  const before = net.requestsTo(GRAPH_READ_HOST).length;
  await selectPopupTab(popup, "site");
  // One known round trip to the worker, so a request the tab change started late would be in the log.
  await popup.evaluate(() => chrome.runtime.sendMessage({ kind: "getSession" }));
  await expect(popup.locator("#tab-page-dot")).toBeVisible();
  await expect(popup.locator("#tab-page")).toHaveAccessibleName("This page 2 malicious links on this page");
  expect(net.requestsTo(GRAPH_READ_HOST).length, "selecting a tab sent a graph request").toBe(before);
  await popup.close();

  // The result is not kept: a reopened popup shows no dot until the check is run again.
  const again = await openPopup(ext, tabId, { popupTab: "page" });
  await expect(again.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });
  await expect(again.locator("#tab-page-dot")).toBeHidden();
  await expect(again.locator("#tab-page")).toHaveAccessibleName("This page");
  await again.close();
  await page.close();
});

test("one malicious link is named in the singular, and a result with none shows no dot", async () => {
  {
    const { page, tabId } = await visit(ext, `https://${PAGE_B}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId, { popupTab: "page" });
    await popup.locator("#btn-linkscan").click();
    await expect(popup.locator("#linkscan-summary")).toContainText("destination", { timeout: 15_000 });
    await expect(popup.locator("#tab-page-dot")).toBeVisible();
    await expect(popup.locator("#tab-page")).toHaveAccessibleName("This page 1 malicious link on this page");
    await popup.close();
    await page.close();
  }
  {
    const { page, tabId } = await visit(ext, `https://${PAGE_C}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId, { popupTab: "page" });
    await popup.locator("#btn-linkscan").click();
    await expect(popup.locator("#linkscan-summary")).toContainText("destination", { timeout: 15_000 });
    await expect(popup.locator("#tab-page-dot")).toBeHidden();
    await expect(popup.locator("#tab-page")).toHaveAccessibleName("This page");
    await popup.close();
    await page.close();
  }
});
