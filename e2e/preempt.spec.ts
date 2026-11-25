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

import { readFileSync } from "node:fs";
import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import { ClosedShadow, SCROLL_TO_BUTTONS_FN, SNAPSHOT_FN, type CardSnapshot } from "./helpers/closed-shadow";
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
  cardForm: "evil-preempt-card-form-e2e.com",
  twiceLink: "evil-preempt-twice-link-e2e.com",
  twiceForm: "evil-preempt-twice-form-e2e.com",
  fakeEnter: "evil-preempt-fake-enter-e2e.com",
  fakeTab: "evil-preempt-fake-tab-e2e.com",
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
  cardLink: "start11-preempt-guard-e2e.com",
  cardForm: "start12-preempt-guard-e2e.com",
  keys: "start13-preempt-guard-e2e.com",
  twiceLink: "start14-preempt-guard-e2e.com",
  twiceForm: "start15-preempt-guard-e2e.com",
  narrow: "start16-preempt-guard-e2e.com",
  fakeEnter: "start17-preempt-guard-e2e.com",
  fakeTab: "start18-preempt-guard-e2e.com",
  fonts: "start19-preempt-guard-e2e.com",
  offFocus: "start20-preempt-guard-e2e.com",
};

function fontDataUri(file: string): string {
  return `data:font/woff2;base64,${readFileSync(new URL(`../assets/fonts/${file}`, import.meta.url)).toString("base64")}`;
}

/** Extra markup for the start pages that need a hostile or instrumented page. */
const EXTRA: Record<string, string> = {
  // A page that fakes a Tab keydown on the document whenever it sees a real Enter.
  [START.fakeEnter]: `<script>
    window.addEventListener("keydown", (e) => {
      if (e.isTrusted && e.key === "Enter") {
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true }));
      }
    }, true);
  </script>`,
  // A page that keeps faking Tab keydowns on the document and counts them.
  [START.fakeTab]: `<script>
    window.__fakes = 0;
    setInterval(() => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true }));
      window.__fakes++;
    }, 20);
  </script>`,
  // A page that declares its own faces under the names a card might ask for.
  [START.fonts]: `<style>
    @font-face { font-family: Lato; font-weight: 100 900; src: url(${fontDataUri("lato-latin-900-normal.woff2")}) format("woff2"); }
    @font-face { font-family: "JetBrains Mono"; font-weight: 100 900; src: url(${fontDataUri("jetbrains-mono-latin-400-normal.woff2")}) format("woff2"); }
    @font-face { font-family: Arial; src: url(${fontDataUri("lato-latin-900-normal.woff2")}) format("woff2"); }
  </style>`,
};

function startHtml(host: string, extra = ""): string {
  return `<!doctype html>
<html><head><title>${host}</title>${extra}</head>
<body>
  <h1>${host}</h1>
  <a id="lnk-evil" href="https://${EVIL.link}/lure/path?token=hunter2evil#sec">win a prize</a>
  <a id="lnk-proceed" href="https://${EVIL.proceed}/landing">continue here</a>
  <a id="lnk-blank" target="_blank" href="https://${EVIL.blank}/landing"
     onclick="this.href='https://${EVIL.blank}/landing?via=onclick'">open elsewhere</a>
  <a id="lnk-middle" href="https://${EVIL.middle}/landing">middle me</a>
  <a id="lnk-enter" href="https://${EVIL.enter}/landing">enter me</a>
  <a id="lnk-twice" target="_blank" href="https://${EVIL.twiceLink}/landing"
     onclick="window.__clicks = (window.__clicks || 0) + 1">counted link</a>
  <a id="lnk-fake" href="https://${EVIL.fakeEnter}/landing">fake enter link</a>
  <a id="lnk-faketab" href="https://${EVIL.fakeTab}/landing">fake tab link</a>
  <a id="lnk-same" href="https://sub.${host}/inner">same site</a>
  <a id="lnk-clean" href="https://${CLEAN}/ok">clean offsite</a>
  <a id="lnk-privacy" href="https://${PRIVACY_TARGET}/very/secret?token=hunter2#frag">privacy probe</a>
  <a id="lnk-timeout" href="https://${TIMEOUT_TARGET}/go">timeout probe</a>
  <form id="frm-off" action="https://${EVIL.form}/collect" method="post">
    <input type="text" name="card" value="supersecret-4111111111111111">
    <button id="btn-off" type="submit">Pay</button>
  </form>
  <form id="frm-card" action="https://${EVIL.cardForm}/collect" method="post">
    <input type="text" name="note" value="card-note">
    <button id="btn-card" type="submit">Send card</button>
  </form>
  <form id="frm-twice" target="_blank" onsubmit="window.__submits = (window.__submits || 0) + 1" action="https://${EVIL.twiceForm}/collect" method="post">
    <input type="text" name="note" value="twice-note">
    <button id="btn-twice" type="submit">Send</button>
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
    net.setPage(host, startHtml(host, EXTRA[host] ?? ""));
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
  expect(JSON.parse(graphReqs[0]!.body).parameters).toEqual({ hs: [EVIL.link] });

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
  expect(JSON.parse(graphReqs[0]!.body).parameters).toEqual({ hs: [EVIL.form] });

  // Proceed: the ORIGINAL submission resumes, payload intact, only to the
  // intended host (that POST is the submission itself, nothing else).
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await page.waitForURL(`https://${EVIL.form}/collect`, { timeout: 15_000 });
  const posts = net.requestsTo(EVIL.form).filter((r) => r.method === "POST");
  expect(posts.length).toBeGreaterThan(0);
  expect(posts[0]!.body).toContain("supersecret-4111111111111111");
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

// ------------------------------------------------ the card, board 4b

/** WCAG relative luminance of a computed "rgb(...)" / "rgba(...)" colour. */
function luminance(css: string): number {
  const m = css.match(/[\d.]+/g)!.slice(0, 3).map(Number);
  const [r, g, b] = m.map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

async function openCard(
  startHost: string,
  trigger: string,
  viewport?: { width: number; height: number },
): Promise<{ page: import("@playwright/test").Page; shadow: ClosedShadow }> {
  const { page, tabId } = await visit(ext, `https://${startHost}/`);
  if (viewport) await page.setViewportSize(viewport);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  await page.click(trigger);
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);
  const shadow = await ClosedShadow.open(ext.context, page);
  await expect
    .poll(async () => (await shadow.call<string>("function () { return this.textContent || ''; }")) ?? "", {
      timeout: 10_000,
    })
    .toContain("Whisper stopped");
  return { page, shadow };
}

async function snapshot(shadow: ClosedShadow): Promise<CardSnapshot> {
  const s = await shadow.call<CardSnapshot>(SNAPSHOT_FN);
  expect(s).not.toBeNull();
  return s!;
}

/** True while the page's own focus is on Guard's host (so focus never reached the page behind). */
async function focusOnGuardHost(page: import("@playwright/test").Page): Promise<boolean> {
  return page.evaluate(() => {
    const a = document.activeElement;
    return !!a && (a.getAttribute("style") ?? "").includes("2147483647");
  });
}

test("held link card draws board 4b: colours, header, heading, host, verdict pill, privacy line, button order and size", async () => {
  const { page, shadow } = await openCard(START.cardLink, "#lnk-evil");
  const s = await snapshot(shadow);

  expect(s.role).toBe("alertdialog");
  expect(s.modal).toBe("true");
  expect(s.labelledby).toBe("w-title");
  expect(s.describedby).toBe("w-desc");

  expect(s.card!.css.backgroundColor).toBe("rgb(13, 13, 26)");
  expect(s.card!.css.borderTopWidth).toBe("4px");
  expect(s.card!.css.borderTopColor).toBe("rgb(239, 68, 68)");
  expect(s.card!.css.borderRadius).toBe("16px");

  expect(s.mark!.tag).toBe("img");
  expect(s.mark!.src.startsWith("data:image/png;base64,")).toBe(true);
  expect(s.mark!.alt).toBe("");
  expect(s.mark!.rect.w).toBe(22);
  expect(s.wordmark!.text).toBe("Whisper");
  expect(s.wordmark!.css.fontWeight).toBe("900");
  expect(s.guardPill!.text).toBe("Guard");
  expect(s.tag!.text).toBe("click held");

  expect(s.heading!.tag).toBe("h2");
  expect(s.heading!.text).toBe("Whisper stopped a dangerous link");
  expect(s.heading!.css.color).toBe("rgb(254, 202, 202)");
  expect(s.heading!.css.fontWeight).toBe("900");

  expect(s.host!.text).toBe(EVIL.link);
  expect(s.host!.css.fontFamily.toLowerCase()).toMatch(/monospace/);
  expect(s.sentence!.text).toBe(
    `${EVIL.link} is flagged CRITICAL in the Whisper security graph. The click was stopped before anything loaded.`,
  );

  expect(s.pill!.text).toBe("CRITICAL");
  expect(s.pill!.css.backgroundColor).toBe("rgb(184, 32, 42)");
  expect(s.pill!.css.color).toBe("rgb(255, 255, 255)");

  expect(s.privacy!.text).toBe(`Privacy: only \u201c${EVIL.link}\u201d was checked. Your browsing stays yours.`);

  expect(s.back!.text).toBe("Go back");
  expect(s.proceed!.text).toBe("Proceed anyway");
  expect(s.back!.css.backgroundColor).toBe("rgb(125, 92, 224)");
  expect(s.back!.css.color).toBe("rgb(255, 255, 255)");
  expect(s.back!.rect.l).toBeGreaterThan(s.proceed!.rect.r);
  expect(s.back!.rect.h).toBeGreaterThanOrEqual(44);
  expect(s.proceed!.rect.h).toBeGreaterThanOrEqual(44);

  expect(s.runs.length).toBeGreaterThan(5);
  for (const run of s.runs) {
    expect(contrast(run.color, run.bg), `"${run.text}" ${run.color} on ${run.bg}`).toBeGreaterThanOrEqual(4.5);
  }

  await shadow.close();
  await page.close();
});

test("held form card draws the form wording: heading, form held tag, nothing typed was sent, same card look", async () => {
  const { page, shadow } = await openCard(START.cardForm, "#btn-card");
  const s = await snapshot(shadow);

  expect(s.heading!.tag).toBe("h2");
  expect(s.heading!.text).toBe("Whisper stopped a dangerous form submission");
  expect(s.tag!.text).toBe("form held");
  expect(s.sentence!.text.endsWith("Nothing you typed was sent.")).toBe(true);
  expect(s.host!.text).toBe(EVIL.cardForm);
  expect(s.card!.css.backgroundColor).toBe("rgb(13, 13, 26)");
  expect(s.card!.css.borderTopColor).toBe("rgb(239, 68, 68)");
  expect(s.back!.css.backgroundColor).toBe("rgb(125, 92, 224)");

  await shadow.close();
  await page.close();
});

test("card keyboard: Go back is focused with a ring at open, Tab and Shift+Tab wrap between the two buttons inside the card, Enter on Go back closes without navigating", async () => {
  const { page, shadow } = await openCard(START.keys, "#lnk-evil");
  const ringed = (b: CardSnapshot["back"]): boolean =>
    b!.css.outlineStyle !== "none" && parseFloat(b!.css.outlineWidth) >= 2;

  let s = await snapshot(shadow);
  expect(s.focusedId).toBe("w-back");
  expect(ringed(s.back)).toBe(true);
  expect(ringed(s.proceed)).toBe(false);

  await page.keyboard.press("Tab");
  s = await snapshot(shadow);
  expect(s.focusedId).toBe("w-proceed");
  expect(ringed(s.proceed)).toBe(true);
  expect(ringed(s.back)).toBe(false);
  expect(await focusOnGuardHost(page)).toBe(true);

  await page.keyboard.press("Tab");
  s = await snapshot(shadow);
  expect(s.focusedId).toBe("w-back");
  expect(await focusOnGuardHost(page)).toBe(true);

  await page.keyboard.press("Shift+Tab");
  s = await snapshot(shadow);
  expect(s.focusedId).toBe("w-proceed");
  await page.keyboard.press("Shift+Tab");
  s = await snapshot(shadow);
  expect(s.focusedId).toBe("w-back");
  expect(await focusOnGuardHost(page)).toBe(true);

  await page.keyboard.press("Enter");
  await expect.poll(async () => page.locator(OVERLAY).count()).toBe(0);
  expect(page.url()).toBe(`https://${START.keys}/`);

  await shadow.close();
  await page.close();
});

/** Two real mouse clicks on Proceed anyway, sent back to back before the background can answer. */
async function pressProceedTwice(shadow: ClosedShadow): Promise<void> {
  const s = await snapshot(shadow);
  await shadow.mouseClicks(s.proceed!.rect.l + s.proceed!.rect.w / 2, s.proceed!.rect.t + s.proceed!.rect.h / 2, 2);
}

test("two quick presses on Proceed anyway open one new tab and run the page's own click handler once", async () => {
  const { page, shadow } = await openCard(START.twiceLink, "#lnk-twice");
  const before = ext.context.pages().length;
  const popupPromise = ext.context.waitForEvent("page", { timeout: 15_000 });

  await pressProceedTwice(shadow);

  const popup = await popupPromise;
  await popup.waitForURL(`https://${EVIL.twiceLink}/landing`, { timeout: 15_000 });
  expect(ext.context.pages().length).toBe(before + 1);
  expect(await page.evaluate(() => (window as unknown as { __clicks?: number }).__clicks)).toBe(1);

  await shadow.close();
  await popup.close();
  await page.close();
});

test("two quick presses on Proceed anyway on a held form deliver exactly one POST to the target", async () => {
  const { page, shadow } = await openCard(START.twiceForm, "#btn-twice");
  net.clearLog();
  const before = ext.context.pages().length;
  const popupPromise = ext.context.waitForEvent("page", { timeout: 15_000 });

  await pressProceedTwice(shadow);

  // The form opens its result in a new tab, so a second submission would
  // show up as a second tab and a second POST.
  const popup = await popupPromise;
  await popup.waitForURL(`https://${EVIL.twiceForm}/collect`, { timeout: 15_000 });
  expect(ext.context.pages().length).toBe(before + 1);
  const posts = net.requestsTo(EVIL.twiceForm).filter((r) => r.method === "POST");
  expect(posts).toHaveLength(1);
  expect(await page.evaluate(() => (window as unknown as { __submits?: number }).__submits)).toBe(1);

  await shadow.close();
  await popup.close();
  await page.close();
});

test("in a window shorter than the card the overlay scrolls, the card stays inside the width and both buttons can be scrolled into view", async () => {
  const { page, shadow } = await openCard(START.narrow, "#lnk-evil", { width: 390, height: 420 });
  const m = await shadow.call<{
    back: { l: number; r: number; t: number; b: number };
    proceed: { l: number; r: number; t: number; b: number };
    card: { l: number; r: number; h: number };
    overflowY: string;
    vw: number;
    vh: number;
  }>(SCROLL_TO_BUTTONS_FN);

  expect(m!.card.h).toBeGreaterThan(m!.vh);
  expect(m!.overflowY).toBe("auto");
  expect(m!.card.r).toBeLessThanOrEqual(m!.vw - 16);
  expect(m!.card.l).toBeGreaterThanOrEqual(0);
  for (const b of [m!.back, m!.proceed]) {
    expect(b.l).toBeGreaterThanOrEqual(0);
    expect(b.r).toBeLessThanOrEqual(m!.vw);
    expect(b.t).toBeGreaterThanOrEqual(0);
    expect(b.b).toBeLessThanOrEqual(m!.vh);
  }

  await shadow.close();
  await page.close();
});

test("a page that fakes a Tab keydown on the document when a real Enter arrives cannot redirect Enter to Proceed anyway", async () => {
  const { page, shadow } = await openCard(START.fakeEnter, "#lnk-fake");
  net.clearLog();

  await page.keyboard.press("Enter");

  await expect.poll(async () => page.locator(OVERLAY).count()).toBe(0);
  expect(page.url()).toBe(`https://${START.fakeEnter}/`);
  expect(net.requestsTo(EVIL.fakeEnter).filter((r) => r.scheme === "https")).toHaveLength(0);

  await shadow.close();
  await page.close();
});

test("a page that keeps faking Tab keydowns cannot move focus off Go back", async () => {
  const { page, shadow } = await openCard(START.fakeTab, "#lnk-faketab");

  await expect
    .poll(async () => page.evaluate(() => (window as unknown as { __fakes: number }).__fakes), { timeout: 10_000 })
    .toBeGreaterThan(3);
  const s = await snapshot(shadow);
  expect(s.focusedId).toBe("w-back");

  await shadow.close();
  await page.close();
});

test("with focus off both buttons, Enter does nothing and puts focus on Go back, and Tab goes to Go back", async () => {
  const { page, shadow } = await openCard(START.offFocus, "#lnk-evil");
  const blur = "function () { if (this.activeElement) this.activeElement.blur(); return this.activeElement === null; }";

  expect(await shadow.call<boolean>(blur)).toBe(true);
  await page.keyboard.press("Enter");
  expect((await snapshot(shadow)).focusedId).toBe("w-back");
  expect(await page.locator(OVERLAY).count()).toBeGreaterThan(0);
  expect(page.url()).toBe(`https://${START.offFocus}/`);

  expect(await shadow.call<boolean>(blur)).toBe(true);
  await page.keyboard.press("Tab");
  expect((await snapshot(shadow)).focusedId).toBe("w-back");

  await shadow.close();
  await page.close();
});

test("the card is drawn in generic faces only: no page-supplied web font reaches its text", async () => {
  const { page, shadow } = await openCard(START.fonts, "#lnk-evil");

  const heading = await shadow.platformFonts("w-title");
  const host = await shadow.platformFonts("w-host");
  expect(heading).not.toBeNull();
  expect(host).not.toBeNull();
  for (const f of [...heading!, ...host!]) {
    expect(f.isCustomFont, `${f.familyName} must not be a page-supplied font`).toBe(false);
  }

  // The stacks themselves name no family a page could redefine.
  const s = await snapshot(shadow);
  for (const el of [s.heading, s.sentence, s.host, s.tag, s.back, s.proceed]) {
    expect(el!.css.fontFamily).not.toMatch(/["']|lato|jetbrains|arial|helvetica|menlo|consolas|sfmono/i);
  }

  await shadow.close();
  await page.close();
});
