// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The popup is never blank. A tab that Guard has not checked (opened before
// Guard started, or whose answer was dropped) shows one not-yet-checked card
// with a button; pressing it checks the site and draws the verdict in place,
// without reloading the page or the popup, and the toolbar follows. While a
// check runs the popup shows a ring and placeholder bars, which stand still for
// readers who ask for reduced motion. Browser pages and local files keep their
// own message.
//
// "A tab opened before an install" is simulated: the page is visited and
// settled, the worker is stopped, and the tab's saved state, the verdict mirror
// and the destination log are removed from storage. The fresh worker then holds
// nothing for the tab, as it does after an install. A real install or update is
// not exercised here.

import { test, expect, type Page, type TestInfo } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST, MOCK_API_KEY } from "./helpers/servers";
import {
  badgeText,
  extensionPage,
  iconState,
  launchExtension,
  openPopup,
  rebindWorker,
  scrollPopupTo,
  setKey,
  setSettings,
  stopWorker,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const CLEAN = { band: "NONE", coverage: "known-clean", label: "clean" } as const;

const HEADING = "Guard hasn’t checked this tab yet";
const SENTENCE =
  "This can happen when the page was open before Guard started, for example right after an install or update.";
const BUTTON = "Check this site now";
const NOTE = "No reload needed. Only the site name is sent.";
const CHECKING = "Checking this site…";

/** True when the text holds the hostname as a whole token, never as part of a longer name. */
function namesHost(text: string, host: string): boolean {
  return text.split(/[^a-z0-9.-]+/i).some((token) => token === host);
}

/** True for a whisper.assess request whose host list holds exactly this hostname. */
function assessesHost(body: string, host: string): boolean {
  try {
    const q = JSON.parse(body) as { query?: string; parameters?: { hs?: unknown } };
    const hs = q.parameters?.hs;
    return (q.query ?? "").includes("whisper.assess") && Array.isArray(hs) && hs.some((h) => h === host);
  } catch {
    return false;
  }
}

const stateKey = (tabId: number) => `tabState:${tabId}`;

async function sessionStore(): Promise<Record<string, unknown>> {
  const page = await extensionPage(ext);
  return page.evaluate(() => chrome.storage.session.get(null));
}

/** The tab is settled, its state is saved and its verdict reached the cache mirror. */
async function settled(tabId: number, host: string): Promise<void> {
  await expect.poll(async () => stateKey(tabId) in (await sessionStore()), { timeout: 8000 }).toBe(true);
  await expect
    .poll(
      async () => {
        const v = (await sessionStore())["verdicts"] as Record<string, unknown> | undefined;
        return v !== undefined && host in v;
      },
      { timeout: 8000 },
    )
    .toBe(true);
}

/** Visit a host, let Guard settle on it, then leave the fresh worker holding nothing for the tab. */
async function visitUnchecked(host: string): Promise<{ page: Page; tabId: number }> {
  net.setVerdict(host, CLEAN);
  const tab = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tab.tabId, ["benign"]);
  await settled(tab.tabId, host);
  await stopWorker(ext);
  const via = await extensionPage(ext);
  await via.evaluate(async (k) => {
    await chrome.storage.session.remove(["verdicts", k]);
    await chrome.storage.local.remove("navlog");
  }, stateKey(tab.tabId));
  return tab;
}

async function reviewPictures(popup: Page, name: string, testInfo: TestInfo): Promise<void> {
  await popup.setViewportSize({ width: 400, height: 600 });
  for (const scheme of ["dark", "light"] as const) {
    await popup.emulateMedia({ colorScheme: scheme });
    await popup.screenshot({ path: testInfo.outputPath(`${name}-${scheme}.png`) });
  }
  await popup.emulateMedia({ colorScheme: null });
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
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
});

test("a tab Guard has not checked shows the not-yet-checked card and sends nothing about the site", async ({}, testInfo) => {
  const host = "unchecked-card-guard-e2e.com";
  const { page, tabId } = await visitUnchecked(host);
  net.clearLog();

  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#not-checked-view")).toBeVisible();
  await expect(popup.locator("#not-checked-title")).toHaveText(HEADING);
  await expect(popup.locator("#not-checked-text")).toHaveText(SENTENCE);
  await expect(popup.locator("#btn-check-now")).toHaveText(BUTTON);
  await expect(popup.locator("#not-checked-note")).toHaveText(NOTE);
  await expect(popup.locator("#host-row")).toBeHidden();
  await expect(popup.locator("#chain-card")).toBeHidden();
  await expect(popup.locator("#protect-card")).toBeHidden();
  await expect(popup.locator("#privacy-line")).toBeEmpty();
  await expect(popup.locator(".pp-footer")).toBeHidden();
  await reviewPictures(popup, "not-checked", testInfo);

  // Sampled for a while: nothing that left the browser names the site.
  const until = Date.now() + 2000;
  while (Date.now() < until) {
    await popup.locator("#not-checked-view").isVisible();
    await new Promise((r) => setTimeout(r, 100));
  }
  const naming = net.log.filter((r) => namesHost(`${r.host} ${r.path} ${r.body}`, host));
  expect(naming).toHaveLength(0);

  // Positive control: the press sends exactly one assess, naming the site. The
  // answer is held past the debounce, so the popup's reads start while it is out.
  net.assessDelayMs.set(host, 1000);
  await popup.locator("#btn-check-now").click();
  await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
  const assessed = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.assess"));
  expect(assessed).toHaveLength(1);
  expect(assessed[0]!.body).toContain(host);

  await popup.close();
  await page.close();
  await rebindWorker(ext);
});

test("on a page Guard has not checked the card leads, This page is not shown and This browser waits below", async () => {
  const { page, tabId } = await visitUnchecked("unchecked-parts-guard-e2e.com");
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#not-checked-view")).toBeVisible();

  // The card says it all once: This page does not repeat its heading.
  await expect(popup.locator("#panel-page")).toBeHidden();
  await expect(popup.locator("#page-empty")).toBeHidden();
  const heading = (await popup.locator("body").innerText()).split(HEADING).length - 1;
  expect(heading, "the card's heading is repeated").toBe(1);

  // The card fills the first screen; This browser is below it, never empty.
  const where = await popup.evaluate(() => {
    const region = document.getElementById("popup-scroll")!.getBoundingClientRect();
    return {
      siteBottom: document.getElementById("panel-site")!.getBoundingClientRect().bottom,
      browserTop: document.getElementById("panel-browser")!.getBoundingClientRect().top,
      regionBottom: region.bottom,
    };
  });
  expect(where.browserTop, "This browser starts above the first screen's foot").toBeGreaterThanOrEqual(where.regionBottom);
  expect(where.browserTop).toBeGreaterThanOrEqual(where.siteBottom);
  await scrollPopupTo(popup, "browser");
  await expect(popup.locator("#btn-dashboard")).toBeVisible();
  await expect(popup.locator("#signin-pitch")).toBeVisible();

  await popup.close();
  await page.close();
  await rebindWorker(ext);
});

test("the console button is there for a signed-in reader on a page Guard has not checked, and the dossier is not", async () => {
  const { page, tabId } = await visitUnchecked("unchecked-console-guard-e2e.com");
  await rebindWorker(ext);
  await setKey(ext, MOCK_API_KEY);
  try {
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#not-checked-view")).toBeVisible();
    await expect(popup.locator("#btn-console")).toBeVisible({ timeout: 10_000 });
    await expect(popup.locator("#btn-console")).toHaveText("Open in console");
    await expect(popup.locator("#btn-dossier")).toBeHidden();
    // Nothing was sent about the site, so there is no sent-line.
    await expect(popup.locator("#privacy-line")).toBeHidden();
    await popup.close();
  } finally {
    await setKey(ext, null);
  }
  await page.close();
  await rebindWorker(ext);
});

for (const how of ["key", "click"] as const) {
  test(`after Check this site now by ${how === "key" ? "a key press" : "a mouse click"}, focus stays inside This site`, async () => {
    const { page, tabId } = await visitUnchecked(`unchecked-focus-${how}-guard-e2e.com`);
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#not-checked-view")).toBeVisible();
    await rebindWorker(ext);
    if (how === "key") {
      await popup.locator("#btn-check-now").focus();
      await popup.keyboard.press("Enter");
    } else {
      // Not focused first: a click does not focus a button in every browser.
      await popup.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await popup.locator("#btn-check-now").dispatchEvent("click");
    }
    await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
    await expect(popup.locator("#btn-check-now")).toBeHidden();
    const focus = await popup.evaluate(() => {
      const a = document.activeElement as HTMLElement | null;
      return { id: a?.id ?? "", inside: !!a?.closest("#panel-site"), tabindex: document.getElementById("panel-site")!.tabIndex };
    });
    expect(focus.inside, `focus is on #${focus.id || "body"}, outside This site`).toBe(true);
    expect(focus.id).toBe("panel-site");
    // It is a place for focus to rest, never a stop of the Tab key.
    expect(focus.tabindex).toBe(-1);
    await popup.close();
    await page.close();
    await rebindWorker(ext);
  });
}

test("Check this site now draws the verdict in place without reloading, and the toolbar follows", async () => {
  const host = "press-check-guard-e2e.com";
  const { page, tabId } = await visitUnchecked(host);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#not-checked-view")).toBeVisible();
  await rebindWorker(ext);
  await expect.poll(() => iconState(ext, tabId)).toBe("unknown");
  expect(await badgeText(ext, tabId)).toBe("");

  await page.evaluate(() => ((window as unknown as { __marker: number }).__marker = 1));
  await popup.evaluate(() => ((window as unknown as { __marker: number }).__marker = 1));
  const popupUrl = popup.url();

  await popup.locator("#btn-check-now").click();
  await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
  await expect(popup.locator("#not-checked-view")).toBeHidden();
  await expect(popup.locator("#host-row")).toBeVisible();
  await expect(popup.locator("#hostname")).toHaveText(host);
  expect(await popup.evaluate(() => (window as unknown as { __marker?: number }).__marker)).toBe(1);
  expect(await page.evaluate(() => (window as unknown as { __marker?: number }).__marker)).toBe(1);
  expect(popup.url()).toBe(popupUrl);

  await expect.poll(() => iconState(ext, tabId)).toBe("benign");
  expect(await badgeText(ext, tabId)).toBe("");
  await expect.poll(async () => stateKey(tabId) in (await sessionStore())).toBe(true);

  await popup.close();
  await page.close();
});

test("while the check runs the ring and the bars stand in, and the verdict replaces them in place", async ({}, testInfo) => {
  const host = "press-progress-guard-e2e.com";
  const { page, tabId } = await visitUnchecked(host);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#not-checked-view")).toBeVisible();
  await rebindWorker(ext);
  net.assessDelayMs.set(host, 2500);
  await popup.evaluate(() => ((window as unknown as { __marker: number }).__marker = 1));

  await popup.locator("#btn-check-now").click();
  await expect(popup.locator("#checking-view")).toBeVisible();
  await expect(popup.locator("#not-checked-view")).toBeHidden();
  await expect(popup.locator("#checking-host")).toHaveText(host);
  await expect(popup.locator("#checking-text")).toHaveText(CHECKING);
  await expect(popup.locator(".pp-ring")).toBeVisible();
  await expect(popup.locator(".pp-skel-pill")).toBeVisible();
  await expect(popup.locator(".pp-skel-bar")).toHaveCount(5);
  for (const bar of await popup.locator(".pp-skel-bar").all()) await expect(bar).toBeVisible();
  await expect(popup.locator("#host-row")).toBeHidden();
  await expect.poll(() => iconState(ext, tabId)).toBe("checking");
  expect(await badgeText(ext, tabId)).toBe("");
  await reviewPictures(popup, "checking", testInfo);

  await expect(popup.locator("#host-row")).toBeVisible({ timeout: 8000 });
  await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
  await expect(popup.locator("#checking-view")).toBeHidden();
  expect(await popup.evaluate(() => (window as unknown as { __marker?: number }).__marker)).toBe(1);

  await popup.close();
  await page.close();
});

test("a check that fails shows the could-not-check message", async () => {
  const host = "press-fails-guard-e2e.com";
  const { page, tabId } = await visitUnchecked(host);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#not-checked-view")).toBeVisible();
  await rebindWorker(ext);
  net.assessDelayMs.set(host, 60_000);

  await popup.locator("#btn-check-now").click();
  await expect(popup.locator("#checking-view")).toBeVisible();
  await expect(popup.locator("#band-chip")).toHaveText("COULD NOT CHECK", { timeout: 8000 });
  await expect(popup.locator("#band-note")).toHaveText("Not confirmed either way. On-device checks still ran.");
  await expect(popup.locator("#graph-error")).toBeVisible();
  await expect(popup.locator("#checking-view")).toBeHidden();
  await expect(popup.locator("#not-checked-view")).toBeHidden();

  await popup.close();
  await page.close();
});

/** What the ring and the placeholders are doing, read inside the page so no timer is involved. */
async function motion(popup: Page): Promise<{
  ring: string[];
  pill: string[];
  bars: string[][];
  ringName: string;
  barOpacities: string[];
  ringMoves: boolean;
}> {
  return popup.evaluate(async () => {
    const names = (el: Element): string[] =>
      el.getAnimations().map((a) => (a as CSSAnimation).animationName);
    const ring = document.querySelector(".pp-ring") as HTMLElement;
    const bars = [...document.querySelectorAll<HTMLElement>(".pp-skel-bar")];
    const first = getComputedStyle(ring).transform;
    let moves = false;
    for (let frame = 0; frame < 40; frame++) {
      await new Promise((r) => requestAnimationFrame(() => r(null)));
      if (getComputedStyle(ring).transform !== first) moves = true;
    }
    return {
      ring: names(ring),
      pill: names(document.querySelector(".pp-skel-pill")!),
      bars: bars.map(names),
      ringName: getComputedStyle(ring).animationName,
      barOpacities: bars.map((b) => getComputedStyle(b).opacity),
      ringMoves: moves,
    };
  });
}

test("the ring spins and the bars pulse, and both stand still under reduced motion", async () => {
  const host = "motion-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  net.assessDelayMs.set(host, 60_000);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);

  const moving = await openPopup(ext, tabId);
  const still = await ext.context.newPage();
  await still.emulateMedia({ reducedMotion: "reduce" });
  await still.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
  await expect(moving.locator("#checking-view")).toBeVisible();
  await expect(still.locator("#checking-view")).toBeVisible();

  const a = await motion(moving);
  expect(a.ring).toContain("pp-spin");
  expect(a.pill).toContain("pp-pulse");
  expect(a.bars).toHaveLength(5);
  for (const names of a.bars) expect(names).toContain("pp-pulse");
  expect(a.ringMoves).toBe(true);

  const b = await motion(still);
  expect(b.ring).toEqual([]);
  expect(b.pill).toEqual([]);
  for (const names of b.bars) expect(names).toEqual([]);
  expect(b.ringName).toBe("none");
  expect(b.ringMoves).toBe(false);
  for (const o of b.barOpacities) expect(o).toBe("1");

  await moving.close();
  await still.close();
  await page.close();
});

test("browser pages and local files keep their own message", async () => {
  for (const url of ["about:blank", "file:///etc/hosts"]) {
    const { page, tabId } = await visit(ext, url);
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#ineligible")).toBeVisible();
    await expect(popup.locator("#ineligible")).toContainText(
      "Nothing to check on this page (browser page, local address, or file).",
    );
    await expect(popup.locator("#not-checked-view")).toBeHidden();
    await expect(popup.locator("#checking-view")).toBeHidden();
    await expect(popup.locator("#privacy-line")).toHaveText("Privacy: nothing was sent.");
    await popup.close();
    await page.close();
  }
});

test("pressing during a check that is already running does not start a second check", async () => {
  const host = "press-during-check-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  net.assessDelayMs.set(host, 2000);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const via = await extensionPage(ext);
  const res = await via.evaluate((id) => chrome.runtime.sendMessage({ kind: "checkTab", tabId: id }), tabId);
  expect(res.ok).toBe(true);
  expect(res.tabState.icon).toBe("benign");
  const assessed = net.requestsTo(GRAPH_READ_HOST).filter((r) => assessesHost(r.body, host));
  expect(assessed).toHaveLength(1);
  await page.close();
});
