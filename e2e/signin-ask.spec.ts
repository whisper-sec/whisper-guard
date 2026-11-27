// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE SIGN-IN ASK AFTER A HELD CLICK (board 4e).
//
// When Guard holds a click and the reader goes back, the next time the popup
// opens on that page, for a signed-out reader, a card leads the popup: what
// Guard held, today's figures on this device, and the offer to sign in. It is
// shown once per install, it is never a notification, and the held click is
// remembered as a hostname in this browser's session storage only: never sent,
// never in the wins record, and never written for a private-window tab.
//
// A click is held and backed out of the way the on-page layer does it: the
// question and the answer are sent from inside the tab (the same sender), and
// one spec drives the real hold card with real keys end to end.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test, expect, type Page } from "@playwright/test";
import { DIST_CHROMIUM } from "./helpers/extension";
import { CONSOLE_HOST, E2ENetwork, GRAPH_READ_HOST, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { measureContrast } from "./helpers/contrast";
import { settledLayout, withWiderGlyphs, WIDER_EM } from "./helpers/popup-fit";
import { choose, expectScheme } from "./helpers/theme";
import {
  allowInIncognito,
  extensionPage,
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

let net: E2ENetwork;
let own: Extension;

const CLEAN = { band: "NONE", coverage: "known-clean", label: "clean" } as const;
const MALICIOUS = { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" } as const;
const NO_LABEL = { band: "HIGH", coverage: "malicious-evidenced", label: null } as const;

const PAGE = "ask-source-guard-e2e.com";
const PAGE_TWO = "ask-source-two-guard-e2e.com";
const TARGET = "ask-target-one-guard-e2e.com";
const TARGET_TWO = "ask-target-two-guard-e2e.com";
const TARGET_BARE = "ask-target-bare-guard-e2e.com";
const REAL_CARD = "ask-realcard-source-guard-e2e.com";
const REAL_TARGET = "ask-realcard-target-guard-e2e.com";
const PROCEED_TARGET = "ask-target-proceed-guard-e2e.com";
const LONG_TARGET = "ask-a-very-long-label-for-the-held-link-and-more.xxxxxxxxxxxxxxxxxx-guard-e2e.com";

const FLAG = "signinAskShown";

type Answer = { ok?: boolean; error?: string; [k: string]: unknown } | undefined;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const h of [PAGE, PAGE_TWO, REAL_CARD]) net.setVerdict(h, CLEAN);
  for (const h of [TARGET, TARGET_TWO, PROCEED_TARGET, REAL_TARGET, LONG_TARGET]) net.setVerdict(h, MALICIOUS);
  net.setVerdict(TARGET_BARE, NO_LABEL);
  net.setPage(
    REAL_CARD,
    `<!doctype html><html><head><title>${REAL_CARD}</title></head><body><h1>${REAL_CARD}</h1>
     <a id="lnk" href="https://${REAL_TARGET}/lure">win a prize</a></body></html>`,
  );
  const dist = makeShieldDist();
  const first = await launchExtension({ proxyPort: net.proxyPort, dist });
  own = await allowInIncognito(first, { proxyPort: net.proxyPort, dist });
  await setSettings(own, { shield: true, amberBanner: true, fieldGuard: true, cloudCheck: true });
});

test.afterAll(async () => {
  await own?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.resetDeviceFlow();
  await setKey(own, null);
  await own.sw.evaluate(async (flag: string) => {
    await chrome.storage.local.remove(flag);
    const all = await chrome.storage.session.get(null);
    await chrome.storage.session.remove(Object.keys(all).filter((k) => k.startsWith("heldClick:")));
  }, FLAG);
  await own.sw.evaluate(() => chrome.storage.local.remove("egress"));
  await setSettings(own, { cloudCheck: true });
});

test.afterEach(async () => {
  await send({ kind: "signInCancel" });
  await choose(own, "auto");
});

// ------------------------------------------------------------------ helpers

/** Send a message from inside a tab, in the isolated world: the sender the on-page layer has. */
async function fromTab(tabId: number, msg: Record<string, unknown>): Promise<Answer> {
  return own.sw.evaluate(
    async ([id, m]: [number, Record<string, unknown>]) => {
      const r = await chrome.scripting.executeScript({
        target: { tabId: id },
        func: (message: Record<string, unknown>) => chrome.runtime.sendMessage(message),
        args: [m],
      });
      return r[0]?.result as Answer;
    },
    [tabId, msg] as [number, Record<string, unknown>],
  );
}

async function send(msg: Record<string, unknown>): Promise<Answer> {
  const page = await extensionPage(own);
  return page.evaluate((m) => chrome.runtime.sendMessage(m), msg);
}

/** Guard holds a click to `host` on this tab (the question the on-page layer asks). */
async function hold(tabId: number, host: string): Promise<void> {
  const answer = (await fromTab(tabId, { kind: "preemptCheck", host })) as { ok?: boolean; preempt?: { action?: string } };
  expect(answer?.ok).toBe(true);
  expect(answer?.preempt?.action, `${host} is held`).toBe("interrupt");
}

/** The reader presses Go back on the hold card. */
async function goBack(tabId: number, host: string): Promise<void> {
  expect((await fromTab(tabId, { kind: "preemptBack", host }))?.ok).toBe(true);
}

/** The reader presses Proceed anyway on the hold card. */
async function proceed(tabId: number, host: string): Promise<void> {
  expect((await fromTab(tabId, { kind: "preemptAllow", host }))?.ok).toBe(true);
}

/** Every held-click key in this browser's session storage. */
function heldKeys(): Promise<string[]> {
  return own.sw.evaluate(async () => Object.keys(await chrome.storage.session.get(null)).filter((k) => k.startsWith("heldClick:")));
}

/** The held-click record kept for a tab, as the background wrote it. */
function heldRecord(tabId: number): Promise<{ wentBack?: boolean } | null> {
  return own.sw.evaluate(async (id: number) => (await chrome.storage.session.get(`heldClick:${id}`))[`heldClick:${id}`] ?? null, tabId);
}

/** Today's tally, as the popup's own read gets it. */
async function wins(): Promise<{ total: number; counts: Record<string, number> }> {
  return (await send({ kind: "getWins" }))?.["wins"] as { total: number; counts: Record<string, number> };
}

/** A tab on `PAGE` with a click held to `TARGET` and gone back from. */
async function heldAndBack(host = PAGE, target = TARGET): Promise<{ page: Page; tabId: number }> {
  const v = await visit(own, `https://${host}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, target);
  await goBack(v.tabId, target);
  return v;
}

/** The popup's first open after a hold: the card is there before anything else is asserted. */
async function openAsk(tabId: number): Promise<Page> {
  const popup = await openPopup(own, tabId);
  await expect(popup.locator("#signin-ask")).toBeVisible();
  return popup;
}

// ------------------------------------------------------- when the card shows

test("signed out: the first popup open after a held click and a Go back leads the scroll with the card, naming the held host and its band", async () => {
  const { page, tabId } = await heldAndBack();
  const popup = await openAsk(tabId);

  await expect(popup.locator("#ask-head")).toHaveText("Guard held 1 click on this page");
  await expect(popup.locator("#ask-line")).toHaveText(
    `A link to ${TARGET} (CRITICAL, malicious). You went back. Nothing loaded.`,
  );
  await expect(popup.locator("#ask-line .pp-ask-host")).toHaveText(TARGET);
  expect(
    await popup.locator("#ask-line .pp-ask-host").evaluate((e) => getComputedStyle(e).fontFamily),
    "the host is set in the mono face",
  ).toContain("JetBrains Mono");

  // First under the header, above the site's verdict, which follows below it.
  expect(await popup.evaluate(() => document.getElementById("popup-scroll")!.firstElementChild!.id)).toBe("signin-ask");
  await expect(popup.locator("#hostname")).toHaveText(PAGE);
  expect(
    await popup.evaluate(
      () => document.getElementById("signin-ask")!.getBoundingClientRect().bottom <= document.getElementById("host-row")!.getBoundingClientRect().top,
    ),
    "the verdict is below the card",
  ).toBe(true);

  await expect(popup.locator("#ask-offer-head")).toHaveText("Get the same protection on every device you use");
  await expect(popup.locator("#btn-ask-signin")).toHaveText("Sign in with Whisper");
  await expect(popup.locator("#btn-ask-later")).toHaveText("Not now");
  // The shared footer shows as always.
  await expect(popup.locator("#privacy-line")).toBeVisible();
  await popup.close();
  await page.close();
});

test("signed out: the card names the band alone when the held host has no label", async () => {
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, TARGET_BARE);
  await goBack(v.tabId, TARGET_BARE);
  const popup = await openAsk(v.tabId);
  await expect(popup.locator("#ask-line")).toHaveText(`A link to ${TARGET_BARE} (HIGH). You went back. Nothing loaded.`);
  await popup.close();
  await v.page.close();
});

test("signed out: the three figures on the card are today's figures from the same read the popup uses", async () => {
  const { page, tabId } = await heldAndBack();
  const popup = await openAsk(tabId);
  const w = await wins();
  expect(w.counts["preemptBlock"], "the held click was counted").toBeGreaterThan(0);
  await expect(popup.locator("#signin-ask .pp-ask-row")).toHaveCount(3);
  await expect(popup.locator("#signin-ask [data-win='preemptBlock']")).toHaveText(String(w.counts["preemptBlock"]));
  await expect(popup.locator("#signin-ask [data-win='lookalikeCaught']")).toHaveText(String(w.counts["lookalikeCaught"]));
  await expect(popup.locator("#signin-ask [data-win='cookieDecline']")).toHaveText(String(w.counts["cookieDecline"]));
  await expect(popup.locator("#signin-ask .pp-ask-row").nth(0)).toContainText("Dangerous clicks held");
  await expect(popup.locator("#signin-ask .pp-ask-row").nth(1)).toContainText("Look-alikes caught");
  await expect(popup.locator("#signin-ask .pp-ask-row").nth(2)).toContainText("Cookie prompts declined");
  await expect(popup.locator("#signin-ask .w-label")).toHaveText("TODAY, ON THIS DEVICE");
  await popup.close();
  await page.close();
});

test("signed out: two held clicks and a Go back from each read 'held 2 clicks' and name the last", async () => {
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, TARGET);
  await goBack(v.tabId, TARGET);
  await hold(v.tabId, TARGET_TWO);
  await goBack(v.tabId, TARGET_TWO);
  const popup = await openAsk(v.tabId);
  await expect(popup.locator("#ask-head")).toHaveText("Guard held 2 clicks on this page");
  await expect(popup.locator("#ask-line")).toHaveText(
    `The last was a link to ${TARGET_TWO} (CRITICAL, malicious). You went back each time. Nothing loaded.`,
  );
  await popup.close();
  await v.page.close();
});

test("signed out: when the first of two held clicks was not backed out of, the card does not say the reader went back each time", async () => {
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, TARGET);
  await hold(v.tabId, TARGET_TWO);
  await goBack(v.tabId, TARGET_TWO);
  const popup = await openAsk(v.tabId);
  await expect(popup.locator("#ask-head")).toHaveText("Guard held 2 clicks on this page");
  await expect(popup.locator("#ask-line")).toHaveText(
    `The last was a link to ${TARGET_TWO} (CRITICAL, malicious). You went back from it. Nothing loaded.`,
  );
  await popup.close();
  await v.page.close();
});

test("signed out: the real hold card's Go back (Enter on the focused button) shows the card on the next popup open", async () => {
  const v = await visit(own, `https://${REAL_CARD}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await expect
    .poll(
      () =>
        own.sw.evaluate(async (id: number) => {
          try {
            const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as { armed?: boolean } | undefined;
            return r?.armed === true;
          } catch {
            return false;
          }
        }, v.tabId),
      { timeout: 15_000 },
    )
    .toBe(true);
  await v.page.click("#lnk");
  await expect.poll(() => v.page.locator("div[style*='2147483647']").count(), { timeout: 10_000 }).toBeGreaterThan(0);
  // Focus sits on "Go back": the key press is the reader's own.
  await v.page.keyboard.press("Enter");
  await expect.poll(() => v.page.locator("div[style*='2147483647']").count()).toBe(0);
  await expect.poll(() => heldRecord(v.tabId).then((r) => r?.wentBack), { message: "the Go back was remembered" }).toBe(true);

  const popup = await openAsk(v.tabId);
  await expect(popup.locator("#ask-line")).toHaveText(
    `A link to ${REAL_TARGET} (CRITICAL, malicious). You went back. Nothing loaded.`,
  );
  await popup.close();
  await v.page.close();
});

test("signed out: Escape on the real hold card is a Go back and shows the card on the next popup open", async () => {
  const v = await visit(own, `https://${REAL_CARD}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await expect
    .poll(
      () =>
        own.sw.evaluate(async (id: number) => {
          try {
            const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as { armed?: boolean } | undefined;
            return r?.armed === true;
          } catch {
            return false;
          }
        }, v.tabId),
      { timeout: 15_000 },
    )
    .toBe(true);
  await v.page.click("#lnk");
  await expect.poll(() => v.page.locator("div[style*='2147483647']").count(), { timeout: 10_000 }).toBeGreaterThan(0);
  await v.page.keyboard.press("Escape");
  await expect.poll(() => v.page.locator("div[style*='2147483647']").count()).toBe(0);
  await expect.poll(() => heldRecord(v.tabId).then((r) => r?.wentBack), { message: "the Go back was remembered" }).toBe(true);

  const popup = await openAsk(v.tabId);
  await expect(popup.locator("#ask-head")).toHaveText("Guard held 1 click on this page");
  await popup.close();
  await v.page.close();
});

// ------------------------------------------------------- when it does not

test("the card shows on the first open only: a second popup open on the same tab does not show it", async () => {
  const { page, tabId } = await heldAndBack();
  const first = await openAsk(tabId);
  await first.close();

  const second = await openPopup(own, tabId);
  await expect(second.locator("#hostname")).toHaveText(PAGE);
  await expect(second.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(second.locator("#signin-ask")).toBeHidden();
  await expect(second.locator("#signin-pitch")).toBeVisible();
  await second.close();
  await page.close();
});

test("the card shows once per install: a held click and a Go back on another page, after the card was shown, does not show it again", async () => {
  const one = await heldAndBack();
  const first = await openAsk(one.tabId);
  await first.close();

  const two = await heldAndBack(PAGE_TWO, TARGET_TWO);
  const second = await openPopup(own, two.tabId);
  await expect(second.locator("#hostname")).toHaveText(PAGE_TWO);
  await expect(second.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(second.locator("#signin-ask")).toBeHidden();
  await second.close();
  await one.page.close();
  await two.page.close();
});

test("Not now removes the card at once, brings the sign-in card back, starts no sign-in, and the next open does not show it", async () => {
  const { page, tabId } = await heldAndBack();
  const popup = await openAsk(tabId);
  await expect(popup.locator("#signin-pitch")).toBeHidden();
  await popup.locator("#btn-ask-later").click();
  await expect(popup.locator("#signin-ask")).toBeHidden();
  await expect(popup.locator("#signin-pitch")).toBeVisible();
  expect(net.device.authorizeBodies, "no sign-in was started").toHaveLength(0);
  await popup.close();

  const again = await openPopup(own, tabId);
  await expect(again.locator("#hostname")).toHaveText(PAGE);
  await expect(again.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(again.locator("#signin-ask")).toBeHidden();
  await again.close();
  await page.close();
});

test("signed in: the card is never shown, even with a fresh held click and a Go back", async () => {
  await setKey(own, MOCK_KEY);
  const { page, tabId } = await heldAndBack();
  const popup = await openPopup(own, tabId);
  await expect(popup.locator("#hostname")).toHaveText(PAGE);
  await expect(popup.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(popup.locator("#signin-ask")).toBeHidden();
  await expect(popup.locator("#signin-pitch")).toBeHidden();
  await expect
    .poll(() => own.sw.evaluate(async (f: string) => (await chrome.storage.local.get(f))[f] ?? null, FLAG), {
      message: "the signed-in open used the ask up",
    })
    .toBe(true);
  await popup.close();

  // After a sign-in it never shows: signing out later does not bring it.
  await setKey(own, null);
  const later = await openPopup(own, tabId);
  await expect(later.locator("#hostname")).toHaveText(PAGE);
  await expect(later.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(later.locator("#signin-ask")).toBeHidden();
  await later.close();
  await page.close();
});

test("a signed-out reader on a page with a held click and no Go back is not shown the card", async () => {
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, TARGET);
  const popup = await openPopup(own, v.tabId);
  await expect(popup.locator("#hostname")).toHaveText(PAGE);
  await expect(popup.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(popup.locator("#signin-ask")).toBeHidden();
  await popup.close();

  // Control: the same page and the same hold, once the reader goes back, shows it (nothing was used up).
  await goBack(v.tabId, TARGET);
  const after = await openAsk(v.tabId);
  await after.close();
  await v.page.close();
});

test("Proceed anyway instead of Go back: the card is not shown, and a later hold that was not backed out of does not show it either", async () => {
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, PROCEED_TARGET);
  await proceed(v.tabId, PROCEED_TARGET);
  expect(await heldKeys(), "Proceed removes the page's record").toEqual([]);
  const first = await openPopup(own, v.tabId);
  await expect(first.locator("#hostname")).toHaveText(PAGE);
  await expect(first.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(first.locator("#signin-ask")).toBeHidden();
  await first.close();

  // The next hold is the latest and has not been backed out of.
  await hold(v.tabId, TARGET_TWO);
  const second = await openPopup(own, v.tabId);
  await expect(second.locator("#hostname")).toHaveText(PAGE);
  await expect(second.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(second.locator("#signin-ask")).toBeHidden();
  await second.close();

  // Control: going back from that latest hold shows the card, counting the holds since Proceed.
  await goBack(v.tabId, TARGET_TWO);
  const third = await openAsk(v.tabId);
  await expect(third.locator("#ask-head")).toHaveText("Guard held 1 click on this page");
  await third.close();
  await v.page.close();
});

test("a Go back that names another host than the latest held one marks nothing, so the card is not shown", async () => {
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, TARGET);
  await goBack(v.tabId, TARGET_TWO);
  const popup = await openPopup(own, v.tabId);
  await expect(popup.locator("#hostname")).toHaveText(PAGE);
  await expect(popup.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(popup.locator("#signin-ask")).toBeHidden();
  await popup.close();

  // Control: a Go back that names the latest held host marks it, and then the card shows.
  await goBack(v.tabId, TARGET);
  const after = await openAsk(v.tabId);
  await after.close();
  await v.page.close();
});

test("the held click describes this page only: after the tab loads another page the card is not shown", async () => {
  const { page, tabId } = await heldAndBack();
  expect(await heldKeys()).toHaveLength(1);
  await navigateInTab(page, `https://${PAGE_TWO}/`);
  await waitForIcon(own, tabId, ["benign"]);
  await expect.poll(heldKeys, { message: "the record went with the page" }).toEqual([]);
  const popup = await openPopup(own, tabId);
  await expect(popup.locator("#hostname")).toHaveText(PAGE_TWO);
  await expect(popup.locator("#popup-scroll"), "the popup has asked").toHaveAttribute("data-ask", "none");
  await expect(popup.locator("#signin-ask")).toBeHidden();
  await popup.close();
  await page.close();
});

test("closing the tab removes its held-click record", async () => {
  const { page } = await heldAndBack();
  expect(await heldKeys()).toHaveLength(1);
  await page.close();
  await expect.poll(heldKeys, { message: "the record went with the tab" }).toEqual([]);
});

test("a check that finishes after its page was replaced writes no record onto the new page", async () => {
  const slowTarget = "ask-target-slow-guard-e2e.com";
  const next = "ask-source-next-guard-e2e.com";
  net.setVerdict(slowTarget, MALICIOUS);
  net.setVerdict(next, CLEAN);
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  const before = (await wins()).counts["preemptBlock"] ?? 0;
  net.graphDelayMs = 800;
  try {
    // The question is on the wire, and the tab moves on to another page before the answer.
    const asked = fromTab(v.tabId, { kind: "preemptCheck", host: slowTarget }).catch(() => undefined);
    await expect
      .poll(() => net.requestsTo(GRAPH_READ_HOST).some((r) => r.body.includes(slowTarget)), { message: "the check is on the wire" })
      .toBe(true);
    await navigateInTab(v.page, `https://${next}/`);
    await asked;
    // The later event: the held click is counted only once its check has answered.
    await expect.poll(async () => (await wins()).counts["preemptBlock"] ?? 0, { message: "the slow check answered" }).toBe(before + 1);
    // Behind the queue that writes records: nothing is still on its way.
    await send({ kind: "takeSigninAsk", tabId: v.tabId });
    expect(await heldKeys(), "the old page's hold was not written onto the new page").toEqual([]);
  } finally {
    net.graphDelayMs = 0;
  }
  await v.page.close();
});

test("a held click from a private-window tab writes no record, while a normal-window tab's does", async () => {
  const t = await own.sw.evaluate(async (u: string) => {
    const w = await chrome.windows.create({ incognito: true, url: u });
    const tab = w.tabs?.[0];
    return { tabId: tab?.id ?? -1, windowId: w.id ?? -1, incognito: tab?.incognito === true };
  }, `https://${PAGE}/`);
  expect(t.incognito).toBe(true);
  try {
    await waitForIcon(own, t.tabId, ["benign"]);
    await hold(t.tabId, TARGET);
    await goBack(t.tabId, TARGET);

    // The control, held after the private one: its record is in the same store.
    const control = await heldAndBack(PAGE_TWO, TARGET_TWO);
    await expect.poll(async () => (await heldKeys()).length, { message: "the normal-window record is written" }).toBe(1);
    expect(await heldKeys(), "only the normal tab has a record").toEqual([`heldClick:${control.tabId}`]);
    const answer = (await send({ kind: "takeSigninAsk", tabId: t.tabId })) as { ok?: boolean; ask?: unknown };
    expect(answer?.ok).toBe(true);
    expect(answer?.ask, "the private tab has nothing to ask").toBeNull();
    expect(
      (await own.sw.evaluate(async (flag: string) => (await chrome.storage.local.get(flag))[flag] ?? null, FLAG)),
      "asking for the private tab did not use up the ask",
    ).toBeNull();
    await control.page.close();
  } finally {
    await own.sw.evaluate(async (id: number) => chrome.windows.remove(id), t.windowId).catch(() => undefined);
  }
});

test("a look-alike visited in a private window leaves today's look-alike count unchanged, while one in a normal window adds one", async () => {
  const privateHost = "paypa1-private-count-e2e.com";
  const normalHost = "paypa1-normal-count-e2e.com";
  const count = async (): Promise<number> => (await wins()).counts["lookalikeCaught"] ?? 0;
  const base = await count();
  const t = await own.sw.evaluate(async (u: string) => {
    const w = await chrome.windows.create({ incognito: true, url: u });
    const tab = w.tabs?.[0];
    return { tabId: tab?.id ?? -1, windowId: w.id ?? -1, incognito: tab?.incognito === true };
  }, `https://${privateHost}/`);
  expect(t.incognito).toBe(true);
  try {
    await waitForIcon(own, t.tabId, ["suspicious"]);
    // The control, visited after the private one: once it is counted, the private one's chance has passed.
    const control = await visit(own, `https://${normalHost}/`);
    await waitForIcon(own, control.tabId, ["suspicious"]);
    await expect.poll(count, { message: "the normal-window look-alike is counted" }).toBe(base + 1);
    expect(await count(), "the private-window look-alike added nothing").toBe(base + 1);
    await control.page.close();
  } finally {
    await own.sw.evaluate(async (id: number) => chrome.windows.remove(id), t.windowId).catch(() => undefined);
  }
});

// ----------------------------------------------------- the privacy contract

test("the held host stays on this device: not in the wins record, and the ask sends nothing to any host", async () => {
  net.clearLog();
  const { page, tabId } = await heldAndBack();
  const popup = await openAsk(tabId);
  const raw = await own.sw.evaluate(async () => JSON.stringify((await chrome.storage.local.get("wins"))["wins"] ?? {}));
  expect(raw).not.toContain(TARGET);
  expect(raw).not.toContain("e2e.com");
  expect(net.requestsTo(TARGET), "no request goes to the held host").toHaveLength(0);
  expect(
    net.requestsTo(CONSOLE_HOST),
    "opening the card starts no sign-in and sends nothing to the console",
  ).toHaveLength(0);
  await popup.close();
  await page.close();
});

test("no notification is possible: neither built manifest declares the notifications permission", async () => {
  for (const file of [resolve(DIST_CHROMIUM, "manifest.json"), resolve(DIST_CHROMIUM, "../firefox/manifest.json")]) {
    const m = JSON.parse(readFileSync(file, "utf8")) as { permissions?: string[]; optional_permissions?: string[] };
    expect(m.permissions ?? [], `${file} permissions`).not.toContain("notifications");
    expect(m.optional_permissions ?? [], `${file} optional permissions`).not.toContain("notifications");
  }
  expect(await own.sw.evaluate(() => typeof (chrome as { notifications?: unknown }).notifications)).toBe("undefined");
});

// ----------------------------------------------------- Sign in with Whisper

test("while the card shows the sign-in card near the end stays hidden, and Sign in with Whisper starts the device flow and shows that card's waiting state in view", async () => {
  net.device.holdApproval = true;
  const { page, tabId } = await heldAndBack();
  const popup = await openAsk(tabId);
  await expect(popup.locator("#signin-pitch")).toBeHidden();

  await popup.locator("#btn-ask-signin").click();
  await expect.poll(() => net.device.authorizeBodies.length, { message: "the authorize call arrived" }).toBe(1);
  expect(JSON.parse(net.device.authorizeBodies[0]!)).toEqual({ client: "whisper-guard" });
  await expect(popup.locator("#signin-ask")).toBeHidden();
  await expect(popup.locator("#signin-pitch")).toBeVisible();
  await expect(popup.locator("#signin-wait")).toBeVisible();
  await expect(popup.locator("#signin-code")).toBeVisible();
  await settledLayout(popup);
  await expect
    .poll(() =>
      popup.evaluate(() => {
        const region = document.getElementById("popup-scroll")!.getBoundingClientRect();
        const card = document.getElementById("signin-pitch")!.getBoundingClientRect();
        return card.top >= region.top - 1 && card.top < region.bottom - 40;
      }),
    )
    .toBe(true);

  // Reopening shows the sign-in's own waiting state, not the ask again.
  const again = await openPopup(own, tabId);
  await expect(again.locator("#signin-code")).toBeVisible();
  await expect(again.locator("#popup-scroll")).toHaveAttribute("data-ask", "none");
  await expect(again.locator("#signin-ask")).toBeHidden();
  await again.close();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------- contrast and the fit

test("the card's text clears the contrast floor in both schemes, and its lines fit as drawn and wider", async () => {
  const v = await visit(own, `https://${PAGE}/`);
  await waitForIcon(own, v.tabId, ["benign"]);
  await hold(v.tabId, TARGET);
  await goBack(v.tabId, TARGET);
  await hold(v.tabId, LONG_TARGET);
  await goBack(v.tabId, LONG_TARGET);
  const popup = await openAsk(v.tabId);
  await settledLayout(popup);
  const samples = await measureContrast(popup);
  for (const part of ["#ask-head", "#ask-line", "#ask-offer-head", "#btn-ask-signin", "#btn-ask-later", "pp-ask-n"]) {
    expect(samples.some((s) => s.what.includes(part)), `${part} is measured`).toBe(true);
  }
  for (const choice of ["dark", "light"] as const) {
    await choose(own, choice);
    await popup.emulateMedia({ colorScheme: choice, reducedMotion: "reduce" });
    await expectScheme(popup, choice, `the card in ${choice}`);
    const measured = await measureContrast(popup);
    const bad = measured.filter((s) => s.ratio < s.floor).map((s) => `${s.ratio.toFixed(2)}:1 (needs ${s.floor}) ${s.what}`);
    expect(bad, `${choice}: text under the AA floor`).toEqual([]);
  }

  // "Not now" is quiet but is a full control: its height matches the popup's other wide buttons, and its focus ring shows.
  for (const choice of ["dark", "light"] as const) {
    await choose(own, choice);
    await popup.emulateMedia({ colorScheme: choice, reducedMotion: "reduce" });
    await expectScheme(popup, choice, `the card in ${choice}`);
    await popup.locator("#btn-ask-signin").focus();
    await popup.keyboard.press("Tab");
    await expect(popup.locator("#btn-ask-later")).toBeFocused();
    const ring = await popup.evaluate(() => {
      const b = document.getElementById("btn-ask-later")!;
      const cs = getComputedStyle(b);
      const card = getComputedStyle(b.closest(".pp-ask-offer")!);
      const rgb = (c: string): number[] => {
        const m = c.match(/-?[\d.]+/g)!.map(Number);
        const k = c.startsWith("color(") ? 255 : 1;
        return [m[0]! * k, m[1]! * k, m[2]! * k];
      };
      const lum = (c: number[]): number => {
        const f = (v: number): number => ((v / 255) <= 0.04045 ? v / 255 / 12.92 : ((v / 255 + 0.055) / 1.055) ** 2.4);
        return 0.2126 * f(c[0]!) + 0.7152 * f(c[1]!) + 0.0722 * f(c[2]!);
      };
      const ratio = (a: number[], b: number[]): number => {
        const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
        return (hi! + 0.05) / (lo! + 0.05);
      };
      // The card's ground is a gradient of two stops: the ring must clear both.
      const stops = [...card.backgroundImage.matchAll(/rgb\([^)]*\)/g)].map((x) => rgb(x[0]));
      const ink = rgb(cs.outlineColor);
      return {
        style: cs.outlineStyle,
        width: parseFloat(cs.outlineWidth),
        height: b.getBoundingClientRect().height,
        minRatio: Math.min(...[rgb(card.backgroundColor), ...stops].map((g) => ratio(ink, g))),
      };
    });
    expect(ring.style, `${choice}: "Not now" shows a focus ring`).toBe("solid");
    expect(ring.width, `${choice}: the ring is drawn`).toBeGreaterThanOrEqual(2);
    expect(ring.minRatio, `${choice}: the ring clears 3:1 on the offer card`).toBeGreaterThanOrEqual(3);
    expect(ring.height, `${choice}: "Not now" is at least as tall as the popup's other wide buttons`).toBeGreaterThanOrEqual(32);
  }

  const fits = (): Promise<{ rowLines: number[]; buttons: number[]; spill: boolean; lineSpill: boolean; headLines: number }> =>
    popup.evaluate(() => {
      const card = document.getElementById("signin-ask")!;
      const lines = (e: Element): number => e.getBoundingClientRect().height / parseFloat(getComputedStyle(e).lineHeight);
      const head = document.getElementById("ask-head")!;
      const line = document.getElementById("ask-line")!;
      return {
        rowLines: [...card.querySelectorAll(".pp-ask-row")].map((r) => lines(r)),
        buttons: [...card.querySelectorAll("button")].map((b) => {
          // The lines the label's own text takes, not the button's minimum height.
          const range = document.createRange();
          range.selectNodeContents(b);
          return range.getBoundingClientRect().height / parseFloat(getComputedStyle(b).lineHeight);
        }),
        spill: card.scrollWidth > card.clientWidth,
        lineSpill: line.scrollWidth > line.clientWidth,
        headLines: lines(head),
      };
    });
  for (const [how, read] of [
    ["as drawn", fits],
    [`${WIDER_EM}em wider`, () => withWiderGlyphs(popup, WIDER_EM, fits)],
  ] as const) {
    const m = await read();
    for (const n of m.rowLines) expect(n, `${how}: each figure row takes one line`).toBeCloseTo(1, 1);
    expect(m.headLines, `${how}: the head takes at most two lines`).toBeLessThanOrEqual(2.1);
    expect(m.spill, `${how}: the card does not spill sideways`).toBe(false);
    expect(m.lineSpill, `${how}: the long host wraps inside the line`).toBe(false);
    for (const n of m.buttons) expect(n, `${how}: each button takes one line of text`).toBeCloseTo(1, 0);
  }
  await popup.close();
  await v.page.close();
});
