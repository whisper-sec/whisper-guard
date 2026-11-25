// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Regression (#51): a check result is applied to a tab whatever page the tab
// shows by the time the answer arrives. With site A's answer held for 2 s and
// the tab moved on to site B, A's late verdict must not paint, store, block,
// redirect or inject anything: the mark and the popup describe the page in the
// address bar.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  holdNextCall,
  installCallSpy,
  makeShieldProbeDist,
  releaseHeldCalls,
  removeCallSpy,
  SHIELD_PROBE_FILE,
  spyLog,
  waitForSpyEntry,
} from "./helpers/page-side";
import {
  iconState,
  launchExtension,
  makeShieldDist,
  navigateInTab,
  openPopup,
  extensionPage,
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
    // The check is in flight once its request has reached the graph; the
    // checking tile alone shows from the commit.
    await net.waitForAssessRequest(A);
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
    // The check is in flight once its request has reached the graph; the
    // checking tile alone shows from the commit.
    await net.waitForAssessRequest(A_BLOCK);
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
    // The check is in flight once its request has reached the graph; the
    // checking tile alone shows from the commit.
    await net.waitForAssessRequest(A_AMBER);
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

// ---------------------------------------------------------------------------
// The page-side halves of the guard. In every case above the background stops
// a superseded check first, so deleting a page-side comparison leaves them
// green. These cases take the background out of the way and pin the page-side
// comparisons, and the last step of a check, on their own.

/** Any injected Guard UI mounts on a max-z-index host element. */
const OVERLAY = "div[style*='2147483647']";

const configFor = (host: string) => ({
  kind: "whisper-guard-config",
  host,
  severity: "medium",
  brand: null,
  brandDomain: null,
  banner: true,
  fieldGuard: true,
});

test.describe("shield dist: page-side host checks", () => {
  const A = "other-site-guard-e2e.com";
  const B = "shown-site-guard-e2e.com";
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    net.setVerdict(B, { band: "NONE", coverage: "known-clean", label: "clean" });
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: await makeShieldProbeDist() });
    await setKey(ext, null);
    await setSettings(ext, { cloudCheck: true, shield: true, amberBanner: true, fieldGuard: true });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("a banner config for another host renders nothing and leaves the page's one-shot banner unspent", async () => {
    const { page, tabId } = await visit(ext, `https://${B}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    await ext.sw.evaluate(async (id: number) => {
      await chrome.scripting.executeScript({ target: { tabId: id }, files: ["content.js"] });
    }, tabId);

    // Messages to one frame are handled in order, and each call resolves only
    // once the page's listener has returned.
    const send = (cfg: object) =>
      ext.sw.evaluate(
        async ({ id, c }: { id: number; c: object }) => {
          await chrome.tabs.sendMessage(id, c, { frameId: 0 });
        },
        { id: tabId, c: cfg },
      );

    await send(configFor(A));
    expect(await page.locator(OVERLAY).count()).toBe(0);
    const cdp = await ext.context.newCDPSession(page);
    expect(JSON.stringify(await cdp.send("Accessibility.getFullAXTree"))).not.toContain("flagged as suspicious");
    await cdp.detach();

    // Positive anchor: the same frame, already past A's message, still shows B's
    // banner when B's own config arrives, so A's was handled and spent nothing.
    await send(configFor(B));
    await expect(page.locator(OVERLAY)).toHaveCount(1);
    await page.close();
  });

  test("the redirect for another host leaves the tab on the page it shows", async () => {
    const { page, tabId } = await visit(ext, `https://${B}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    // Record every navigation the page starts, synchronously when it is asked
    // for, so "nothing was started" does not depend on how long a commit takes.
    await page.evaluate(() => {
      const w = window as unknown as { __navs: string[] };
      w.__navs = [];
      (window as unknown as { navigation: EventTarget }).navigation.addEventListener("navigate", (e) => {
        w.__navs.push((e as unknown as { destination: { url: string } }).destination.url);
      });
    });
    const via = await extensionPage(ext);
    const redirect = (host: string) =>
      via.evaluate(
        `(async () => {
          const m = await import(chrome.runtime.getURL(${JSON.stringify(SHIELD_PROBE_FILE)}));
          await m.redirectToWarning(${tabId}, ${JSON.stringify(host)}, null);
        })()`,
      );

    // The injection has finished when this resolves; it ran in the page.
    await redirect(A);
    expect(await page.evaluate(() => (window as unknown as { __navs: string[] }).__navs)).toEqual([]);
    expect(page.url()).toBe(`https://${B}/`);

    // Positive anchor: the same call for the page's own host does navigate, so
    // the harness runs the real redirect and the first call was declined by the
    // hostname check. The warning it lands on names B, never A.
    await redirect(B);
    await page.waitForURL(/warning\.html/);
    const landed = new URL(page.url());
    expect(landed.protocol).toBe("chrome-extension:");
    expect(landed.searchParams.get("host")).toBe(B);
    await via.close();
    await page.close();
  });
});

test.describe("shield dist: a superseded check arms nothing", () => {
  const A_AT_INJECT = "stale-inject-guard-e2e.com";
  const A_AT_PREEMPT = "stale-preempt-guard-e2e.com";
  // A private name: the tab's own check for it has nothing to arm, so anything
  // armed on it was armed by the check for the site the tab left.
  const B = "now-private-guard-e2e.test";
  const FRAME_HOST = "frame-guard-e2e.com";
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    for (const h of [A_AT_INJECT, A_AT_PREEMPT]) {
      net.setVerdict(h, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
    }
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
    await setKey(ext, null);
    await setSettings(ext, {
      cloudCheck: true,
      shield: true,
      amberBanner: true,
      fieldGuard: true,
      cookieDecline: true,
    });
  });
  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });
  test.afterEach(async () => {
    await removeCallSpy(ext);
  });

  /** Whether a frame of the tab answers the on-page layer's diagnostic ping. */
  const ping = (tabId: number, frameId: number) =>
    ext.sw.evaluate(
      async ({ id, f }: { id: number; f: number }) => {
        try {
          return (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" }, { frameId: f })) as {
            armed: boolean;
            consent: boolean;
          };
        } catch {
          return null;
        }
      },
      { id: tabId, f: frameId },
    );

  /** Add a cross-origin frame to the page and wait until the worker has seen it commit. */
  async function addFrame(page: Page, tabId: number): Promise<number> {
    await page.evaluate((src: string) => {
      const f = document.createElement("iframe");
      f.src = src;
      document.body.appendChild(f);
    }, `https://${FRAME_HOST}/`);
    const sub = await waitForSpyEntry(
      ext,
      (e) => e.tabId === tabId && e.ev === "committed" && e.label.startsWith("sub "),
      "the frame's commit",
    );
    return sub.frameId as number;
  }

  /**
   * After `anchorN` (the last entry of the check under test), the worker made no
   * call into the tab that could arm anything: no injection, no config message.
   * Pings from the test itself are the only calls allowed.
   */
  async function nothingArmedAfter(tabId: number, anchorN: number): Promise<void> {
    const later = (await spyLog(ext)).filter(
      (e) => e.n > anchorN && e.tabId === tabId && e.ev === "call" && !e.label.includes("ping"),
    );
    expect(later.map((e) => e.label)).toEqual([]);
  }

  /** The three outcomes, once the check has finished its last step. */
  async function expectNothingArmed(page: Page, tabId: number, anchorN: number): Promise<void> {
    await nothingArmedAfter(tabId, anchorN);
    // No preempt and no consent script armed on the page the tab shows now.
    const top = await ping(tabId, 0);
    if (top !== null) expect(top).toEqual({ armed: false, consent: false });
    // No consent URL recorded: a frame that commits afterwards is left alone.
    // The spy's commit listener runs after the product's for the same event, so
    // seeing the commit means the product's handler had already decided.
    const frameId = await addFrame(page, tabId);
    expect(await ping(tabId, frameId)).toBeNull();
    const calls = (await spyLog(ext)).filter(
      (e) => e.tabId === tabId && e.ev === "call" && e.label.startsWith("exec content.js frame"),
    );
    expect(calls.map((e) => e.label)).toEqual([]);
    // Once more, after the round trips above: still no arming call of any kind.
    await nothingArmedAfter(tabId, anchorN);
  }

  test("a check superseded while its banner injection is in flight arms no preempt, consent URL or consent script", async () => {
    await installCallSpy(ext);
    await holdNextCall(ext, { label: "exec content.js top" });
    const { page, tabId } = await visit(ext, `https://${A_AT_INJECT}/`);

    // The check for A is past its verdict step and suspended at the injection.
    await waitForSpyEntry(ext, (e) => e.tabId === tabId && e.ev === "held", "A's banner injection");
    await navigateInTab(page, `https://${B}/`);
    await waitForSpyEntry(
      ext,
      (e) => e.tabId === tabId && e.ev === "committed" && e.label.includes(B),
      "the tab's commit of B",
    );
    await releaseHeldCalls(ext);

    // Positive anchor: the injection and A's config message both landed on B
    // (B's page declines it), and the check then went on to its last step.
    const done = await waitForSpyEntry(
      ext,
      (e) => e.tabId === tabId && e.ev === "settled" && e.label === "msg whisper-guard-config",
      "A's config message being delivered",
    );
    expect(await ping(tabId, 0)).toEqual({ armed: false, consent: false });
    await expectNothingArmed(page, tabId, done.n);
    expect(await page.locator(OVERLAY).count()).toBe(0);
    await page.close();
  });

  test("a check superseded while its preempt arming is in flight records no consent URL and injects no consent script", async () => {
    await installCallSpy(ext);
    await holdNextCall(ext, { label: "msg whisper-preempt-config" });
    const { page, tabId } = await visit(ext, `https://${A_AT_PREEMPT}/`);

    await waitForSpyEntry(ext, (e) => e.tabId === tabId && e.ev === "held", "A's preempt arming");
    await navigateInTab(page, `https://${B}/`);
    await waitForSpyEntry(
      ext,
      (e) => e.tabId === tabId && e.ev === "committed" && e.label.includes(B),
      "the tab's commit of B",
    );
    await releaseHeldCalls(ext);

    // Positive anchor: the arming message settled (B's page has no listener for
    // it), so the check proceeds to the consent step after it.
    const done = await waitForSpyEntry(
      ext,
      (e) => e.tabId === tabId && e.ev === "settled" && e.label === "msg whisper-preempt-config",
      "A's preempt message settling",
    );
    await expectNothingArmed(page, tabId, done.n);
    await page.close();
  });
});
