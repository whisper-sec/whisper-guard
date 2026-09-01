// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Pre-emptive click / form-submit interruption, against the real
// built extension with the whole network answered locally (full capture).
// The matrix: an evidenced-CRITICAL link target gets the inline closed-
// shadow-root interstitial with ZERO bytes to the target; cached-malicious
// interrupts with zero network; Proceed faithfully resumes the original
// action (same tab; target=_blank into a fresh tab WITH the page's own
// click handler honored; middle-click into a genuine BACKGROUND tab;
// keyboard Enter same-tab); an off-origin
// form submit is held with the typed values never leaving; same-registrable
// links and same-origin forms are never touched; a slow graph FAILS OPEN;
// and the privacy invariant (bare hostname only, ever) holds on the new
// wire path exactly as it does on the nav pipeline.

import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

// One evidenced-malicious target per scenario: a session-allow granted by
// one test's Proceed must never leak an allow into the next.
const EVIL = {
  link: "evil-preempt-link-e2e.com",
  proceed: "evil-preempt-proceed-e2e.com",
  blank: "evil-preempt-blank-e2e.com",
  middle: "evil-preempt-middle-e2e.com",
  enter: "evil-preempt-enter-e2e.com",
  form: "evil-preempt-form-e2e.com",
};
const CLEAN = "clean-preempt-guard-e2e.com";
const PRIVACY_TARGET = "fresh-privacy-target-e2e.com";
const TIMEOUT_TARGET = "fresh-timeout-target-e2e.com";

const START = {
  interstitial: "start1-preempt-guard-e2e.com",
  cached: "start2-preempt-guard-e2e.com",
  proceed: "start3-preempt-guard-e2e.com",
  blank: "start4-preempt-guard-e2e.com",
  form: "start5-preempt-guard-e2e.com",
  samesite: "start6-preempt-guard-e2e.com",
  timeout: "start7-preempt-guard-e2e.com",
  privacy: "start8-preempt-guard-e2e.com",
  middle: "start9-preempt-guard-e2e.com",
  enter: "start10-preempt-guard-e2e.com",
};

function startHtml(host: string): string {
  return `<!doctype html>
<html><head><title>${host}</title></head>
<body>
  <h1>${host}</h1>
  <a id="lnk-evil" href="https://${EVIL.link}/lure/path?token=hunter2evil#sec">win a prize</a>
  <a id="lnk-proceed" href="https://${EVIL.proceed}/landing">continue here</a>
  <a id="lnk-blank" target="_blank" href="https://${EVIL.blank}/landing"
     onclick="this.href='https://${EVIL.blank}/landing?via=onclick'">open elsewhere</a>
  <a id="lnk-middle" href="https://${EVIL.middle}/landing">middle me</a>
  <a id="lnk-enter" href="https://${EVIL.enter}/landing">enter me</a>
  <a id="lnk-same" href="https://sub.${host}/inner">same site</a>
  <a id="lnk-clean" href="https://${CLEAN}/ok">clean offsite</a>
  <a id="lnk-privacy" href="https://${PRIVACY_TARGET}/very/secret?token=hunter2#frag">privacy probe</a>
  <a id="lnk-timeout" href="https://${TIMEOUT_TARGET}/go">timeout probe</a>
  <form id="frm-off" action="https://${EVIL.form}/collect" method="post">
    <input type="text" name="card" value="supersecret-4111111111111111">
    <button id="btn-off" type="submit">Pay</button>
  </form>
  <form id="frm-same" action="/local-post" method="post">
    <input type="text" name="q" value="local-only-value">
    <button id="btn-same" type="submit">Go</button>
  </form>
</body></html>`;
}

/** The interstitial's observable contract from outside the closed root. */
const OVERLAY = "div[style*='2147483647']";

async function waitArmed(tabId: number): Promise<void> {
  await expect
    .poll(
      async () =>
        ext.sw.evaluate(async (id: number) => {
          try {
            const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as
              | { armed?: boolean }
              | undefined;
            return r?.armed === true;
          } catch {
            return false;
          }
        }, tabId),
      { timeout: 15_000 },
    )
    .toBe(true);
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const host of Object.values(EVIL)) {
    net.setVerdict(host, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  }
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict(PRIVACY_TARGET, { band: "NONE", coverage: "known-clean", label: "clean" });
  for (const host of Object.values(START)) {
    net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
    net.setPage(host, startHtml(host));
  }
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, null); // keyless throughout: the preempt check is keyless by design
  await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(() => {
  net.graphMode = "mock";
  net.graphDelayMs = 0;
  net.clearLog();
});

test("held link to an evidenced-CRITICAL target: inline interstitial, zero bytes to the target, Escape goes back", async () => {
  const { page, tabId } = await visit(ext, `https://${START.interstitial}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  net.clearLog();

  await page.click("#lnk-evil");

  // The interstitial mounts (closed shadow root; the host element is the
  // page-side contract), and the tab never navigated.
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);
  expect(page.url()).toBe(`https://${START.interstitial}/`);

  // The a11y tree exposes the verdict + evidence through the closed root.
  const cdp = await ext.context.newCDPSession(page);
  const tree = JSON.stringify(await cdp.send("Accessibility.getFullAXTree"));
  expect(tree).toContain("Whisper stopped a dangerous link");
  expect(tree).toContain(EVIL.link);
  expect(tree).toContain("CRITICAL");
  expect(tree).toContain("Go back");
  expect(tree).toContain("Proceed anyway");
  await cdp.detach();

  // Zero bytes to the flagged target: the click was held pre-flight.
  expect(net.requestsTo(EVIL.link).filter((r) => r.scheme === "https")).toHaveLength(0);

  // Exactly one graph round-trip, carrying the BARE hostname and nothing else.
  const graphReqs = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https");
  expect(graphReqs).toHaveLength(1);
  expect(JSON.parse(graphReqs[0].body).parameters).toEqual({ hs: [EVIL.link] });

  // Escape = Go back: overlay gone, page untouched, still not navigated.
  await page.keyboard.press("Escape");
  await expect.poll(async () => page.locator(OVERLAY).count()).toBe(0);
  expect(page.url()).toBe(`https://${START.interstitial}/`);
  await page.close();
});

test("cached-malicious target: instant interstitial with ZERO network", async () => {
  // The previous test's check cached the CRITICAL verdict for EVIL.link.
  const { page, tabId } = await visit(ext, `https://${START.cached}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  net.clearLog();

  await page.click("#lnk-evil");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);

  // No graph call, no target contact: the cache answered.
  expect(net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https")).toHaveLength(0);
  expect(net.requestsTo(EVIL.link).filter((r) => r.scheme === "https")).toHaveLength(0);
  await page.close();
});

test("Proceed resumes the original same-tab click faithfully", async () => {
  const { page, tabId } = await visit(ext, `https://${START.proceed}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);

  await page.click("#lnk-proceed");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);

  // Focus sits on "Go back"; Tab reaches "Proceed anyway", Enter activates
  // (real keys pierce the closed shadow root; locators cannot).
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");

  // The original click resumes: same tab, the exact href, and the session-
  // allow means Active Shield does NOT re-block the landing.
  await page.waitForURL(`https://${EVIL.proceed}/landing`, { timeout: 15_000 });
  await expect(page.locator("h1")).toContainText(EVIL.proceed);
  await page.close();
});

test("Proceed honors target=_blank faithfully: fresh tab AND the page's own click handler runs", async () => {
  const { page, tabId } = await visit(ext, `https://${START.blank}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);

  await page.click("#lnk-blank");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);

  const popupPromise = ext.context.waitForEvent("page", { timeout: 15_000 });
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");

  // The resume re-dispatches the anchor itself, so the link's own onclick
  // (which finalizes the real destination, the affiliate/redirect pattern)
  // runs exactly as it would have: the popup lands on the REWRITTEN href,
  // not the static one.
  const popup = await popupPromise;
  await popup.waitForURL(`https://${EVIL.blank}/landing?via=onclick`, { timeout: 15_000 });
  // The origin page stayed put: the user's new-tab intent was honored.
  expect(page.url()).toBe(`https://${START.blank}/`);
  await popup.close();
  await page.close();
});

test("middle-click (auxclick) is held; Proceed opens a genuine BACKGROUND tab, the user keeps their place", async () => {
  const { page, tabId } = await visit(ext, `https://${START.middle}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  net.clearLog();

  await page.click("#lnk-middle", { button: "middle" });
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);

  // Held pre-flight: zero bytes to the target, the tab never navigated.
  expect(net.requestsTo(EVIL.middle).filter((r) => r.scheme === "https")).toHaveLength(0);
  expect(page.url()).toBe(`https://${START.middle}/`);

  const popupPromise = ext.context.waitForEvent("page", { timeout: 15_000 });
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");

  const popup = await popupPromise;
  await popup.waitForURL(`https://${EVIL.middle}/landing`, { timeout: 15_000 });

  // Native middle-click disposition: the new tab loads in the BACKGROUND
  // and the origin tab keeps focus (window.open would have stolen it).
  expect(page.url()).toBe(`https://${START.middle}/`);
  const activeTabId = await ext.sw.evaluate(async () => {
    const [active] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return active?.id;
  });
  expect(activeTabId).toBe(tabId);
  await popup.close();
  await page.close();
});

test("keyboard Enter on a focused link is held and resumes same-tab, exactly like the click it is", async () => {
  const { page, tabId } = await visit(ext, `https://${START.enter}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  net.clearLog();

  // Real keys: focus the link, press Enter. The activation arrives as a
  // trusted click (button 0, detail 0) and is held like any other.
  await page.focus("#lnk-enter");
  await page.keyboard.press("Enter");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);
  expect(net.requestsTo(EVIL.enter).filter((r) => r.scheme === "https")).toHaveLength(0);
  expect(page.url()).toBe(`https://${START.enter}/`);

  // Proceed: keyboard activation resumes same-tab via the anchor itself.
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await page.waitForURL(`https://${EVIL.enter}/landing`, { timeout: 15_000 });
  await expect(page.locator("h1")).toContainText(EVIL.enter);
  await page.close();
});

test("off-origin form submit is held; nothing typed ever leaves; Proceed resumes the POST intact", async () => {
  const { page, tabId } = await visit(ext, `https://${START.form}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  net.clearLog();

  await page.click("#btn-off");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);

  const cdp = await ext.context.newCDPSession(page);
  const tree = JSON.stringify(await cdp.send("Accessibility.getFullAXTree"));
  expect(tree).toContain("Whisper stopped a dangerous form submission");
  expect(tree).toContain(EVIL.form);
  await cdp.detach();

  // While held: zero bytes to the collector, and the typed value appears
  // NOWHERE in the full capture (the graph saw only the bare hostname).
  expect(net.requestsTo(EVIL.form).filter((r) => r.scheme === "https")).toHaveLength(0);
  for (const r of net.log) {
    expect(r.body).not.toContain("supersecret");
  }
  const graphReqs = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https");
  expect(graphReqs).toHaveLength(1);
  expect(JSON.parse(graphReqs[0].body).parameters).toEqual({ hs: [EVIL.form] });

  // Proceed: the ORIGINAL submission resumes, payload intact, only to the
  // intended host (that POST is the submission itself, nothing else).
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await page.waitForURL(`https://${EVIL.form}/collect`, { timeout: 15_000 });
  const posts = net.requestsTo(EVIL.form).filter((r) => r.method === "POST");
  expect(posts.length).toBeGreaterThan(0);
  expect(posts[0].body).toContain("supersecret-4111111111111111");
  for (const r of net.log) {
    if (r.host === EVIL.form) continue;
    expect(r.body).not.toContain("supersecret");
  }
  await page.close();
});

test("same-registrable link and same-origin form are never interrupted", async () => {
  const { page, tabId } = await visit(ext, `https://${START.samesite}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);

  // Same-site link: flows straight through, no overlay ever.
  await page.click("#lnk-same");
  await page.waitForURL(`https://sub.${START.samesite}/inner`, { timeout: 15_000 });
  expect(await page.locator(OVERLAY).count()).toBe(0);

  // Back to the start page for the same-origin form.
  await page.goto(`https://${START.samesite}/`, { waitUntil: "domcontentloaded" });
  await waitArmed(tabId);
  await page.click("#btn-same");
  await page.waitForURL(`https://${START.samesite}/local-post`, { timeout: 15_000 });
  expect(await page.locator(OVERLAY).count()).toBe(0);
  await page.close();
});

test("fail-open: a slow graph never blocks the click; the action proceeds after the bounded timeout", async () => {
  const { page, tabId } = await visit(ext, `https://${START.timeout}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);

  // NOW the graph goes dark-slow. The held click's bounded keyless assess
  // aborts at its budget and the original navigation resumes untouched.
  net.graphMode = "slow";
  await page.click("#lnk-timeout");
  await page.waitForURL(`https://${TIMEOUT_TARGET}/go`, { timeout: 15_000 });
  expect(await page.locator(OVERLAY).count()).toBe(0);
  await page.close();
});

test("privacy invariant on the preempt path: only the bare target hostname leaves, ever", async () => {
  const { page, tabId } = await visit(ext, `https://${START.privacy}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  net.clearLog();

  // A clean off-site link with a sensitive path + query + fragment: held,
  // vetted by hostname alone, and resumed automatically.
  await page.click("#lnk-privacy");
  await page.waitForURL((u) => u.href.startsWith(`https://${PRIVACY_TARGET}/`), { timeout: 15_000 });

  // The preempt check carried the bare hostname.
  const graphReqs = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https");
  const preemptReq = graphReqs.find((r) => r.body.includes(PRIVACY_TARGET));
  expect(preemptReq).toBeTruthy();
  expect(JSON.parse(preemptReq!.body).parameters).toEqual({ hs: [PRIVACY_TARGET] });

  // Nothing that left the browser carries the path/query/fragment except
  // the visited site's own page fetch (that IS the navigation).
  for (const r of net.log) {
    if (r.host === PRIVACY_TARGET) continue;
    const blob = `${r.path} ${r.body}`;
    expect(blob).not.toContain("secret");
    expect(blob).not.toContain("hunter2");
    expect(blob).not.toContain("frag");
  }
  await page.close();
});
