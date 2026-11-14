// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Regression (#51): a check result is applied to a tab whatever page the tab
// shows by the time the answer arrives. With site A's answer held for 2 s and
// the tab moved on to site B, A's late verdict must not paint, store, block,
// redirect or inject anything: the mark and the popup describe the page in the
// address bar.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  iconState,
  launchExtension,
  makeShieldDist,
  navigateInTab,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const DELAY_MS = 2000;
const SETTLE_MS = 500;

const title = (ext: Extension, tabId: number) =>
  ext.sw.evaluate(async (id: number) => chrome.action.getTitle({ tabId: id }), tabId);

/** Everything the worker stored for the session, plus the live DNR rules. */
async function stored(ext: Extension) {
  return ext.sw.evaluate(async () => {
    const s = await chrome.storage.session.get(["risks", "blocked"]);
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    return {
      risks: ((s["risks"] as { host: string }[] | undefined) ?? []).map((r) => r.host),
      blocked: (s["blocked"] as string[] | undefined) ?? [],
      ruleFilters: rules.map((r) => r.condition.urlFilter ?? ""),
    };
  });
}

test.describe("default dist: mark, popup state and stored state", () => {
  const A = "late-evil-guard-e2e.com";
  const B = "now-shady-guard-e2e.com";
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    net.setVerdict(A, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
    net.setVerdict(B, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
    ext = await launchExtension({ proxyPort: net.proxyPort });
    await setKey(ext, null);
    await setSettings(ext, { cloudCheck: true });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });
  test.afterEach(() => {
    net.assessDelayMs.clear();
    net.lateAnswered.clear();
  });

  test("keeps B's mark and popup state when A's late answer lands after the tab moved to B", async () => {
    net.assessDelayMs.set(A, DELAY_MS);
    const { page, tabId } = await visit(ext, `https://${A}/`);
    await waitForIcon(ext, tabId, ["checking"]);
    await navigateInTab(page, `https://${B}/`);
    await waitForIcon(ext, tabId, ["suspicious"]);
    const bTitle = await title(ext, tabId);

    // Watch the mark from now until well after A's answer was written.
    await net.waitForLateAnswer(A);
    const seen = new Set<string>();
    const until = Date.now() + SETTLE_MS + 500;
    while (Date.now() < until) {
      seen.add(await iconState(ext, tabId));
      await new Promise((r) => setTimeout(r, 50));
    }
    // AC2, no paint: neither A's malicious mark nor a "checking" repaint.
    expect([...seen]).toEqual(["suspicious"]);
    expect(await title(ext, tabId)).toBe(bTitle);

    // AC1: the popup state is B's.
    const popup = await openPopup(ext, tabId);
    const state = await popup.evaluate(
      async (id: number) =>
        (await chrome.runtime.sendMessage({ kind: "getTabState", tabId: id })) as {
          tabState: { hostname: string | null; icon: string };
        },
      tabId,
    );
    expect(state.tabState.hostname).toBe(B);
    expect(state.tabState.icon).toBe("suspicious");
    await expect(popup.locator("#hostname")).toHaveText(B);
    expect(await popup.locator("body").innerText()).not.toContain(A);
    await popup.close();

    // AC2, no stored state: no risk logged, no block recorded for A.
    const s = await stored(ext);
    expect(s.risks).not.toContain(A);
    expect(s.blocked).not.toContain(A);
    await page.close();
  });
});

test.describe("shield dist: redirect and banner", () => {
  const A_BLOCK = "late-block-guard-e2e.com";
  const A_AMBER = "late-amber-guard-e2e.com";
  const B = "now-clean-guard-e2e.com";
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    net.setVerdict(A_BLOCK, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
    net.setVerdict(A_AMBER, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
    net.setVerdict(B, { band: "NONE", coverage: "known-clean", label: "clean" });
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
    await setKey(ext, null);
    await setSettings(ext, { cloudCheck: true, shield: true, amberBanner: true, fieldGuard: true });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });
  test.afterEach(() => {
    net.assessDelayMs.clear();
    net.lateAnswered.clear();
  });

  test("A's late blocking verdict does not redirect, rule or log anything on B", async () => {
    net.assessDelayMs.set(A_BLOCK, DELAY_MS);
    const { page, tabId } = await visit(ext, `https://${A_BLOCK}/`);
    await waitForIcon(ext, tabId, ["checking"]);
    await navigateInTab(page, `https://${B}/`);
    await waitForIcon(ext, tabId, ["benign"]);

    await net.waitForLateAnswer(A_BLOCK);
    await page.waitForTimeout(SETTLE_MS + 500);

    expect(page.url()).toBe(`https://${B}/`);
    expect(page.url()).not.toContain("warning.html");
    await expect(page.locator("h1")).toContainText(B);
    expect(await iconState(ext, tabId)).toBe("benign");

    const s = await stored(ext);
    expect(s.risks).not.toContain(A_BLOCK);
    expect(s.blocked).not.toContain(A_BLOCK);
    expect(s.ruleFilters.filter((f) => f.includes(A_BLOCK))).toHaveLength(0);
    await page.close();
  });

  test("A's late conversational verdict injects no banner on B", async () => {
    net.assessDelayMs.set(A_AMBER, DELAY_MS);
    const { page, tabId } = await visit(ext, `https://${A_AMBER}/`);
    await waitForIcon(ext, tabId, ["checking"]);
    await navigateInTab(page, `https://${B}/`);
    await waitForIcon(ext, tabId, ["benign"]);

    await net.waitForLateAnswer(A_AMBER);
    await page.waitForTimeout(SETTLE_MS + 500);

    expect(await page.locator("div[style*='2147483647']").count()).toBe(0);
    const cdp = await ext.context.newCDPSession(page);
    const tree = await cdp.send("Accessibility.getFullAXTree");
    expect(JSON.stringify(tree)).not.toContain("flagged as suspicious");
    await cdp.detach();
    await page.close();
  });
});
