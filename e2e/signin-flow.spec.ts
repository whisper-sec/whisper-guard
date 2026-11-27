// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// SIGN-IN, FROM THE POPUP (board 5a).
//
// The popup shows the code the console shows, counts down to that code's real
// expiry, brings the console tab back on request, and after the approval leads
// into the one protect control. These specs run the real extension against the
// stand-in console and prove, from the outside:
//
//   - what the authorize call sends (the client name and nothing else),
//   - the code in the popup is the code in the address of the tab Guard opened,
//   - the countdown ends at the expiry the console named, and a new code starts
//     a new flow,
//   - a refusal stops the waiting at once and sends no further token request,
//   - the tab Guard opened is closed on approved or denied, and only while it
//     still shows the sign-in origin,
//   - reopening the popup brings back the same waiting state,
//   - the waiting and approved states clear the contrast floor and fit.

import { test, expect, type Page } from "@playwright/test";
import { CONSOLE_HOST, E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { measureContrast } from "./helpers/contrast";
import { settledLayout, withWiderGlyphs, WIDER_EM } from "./helpers/popup-fit";
import { choose, expectScheme } from "./helpers/theme";
import {
  getStoredKey,
  launchExtension,
  openDashboard,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const CLEAN = "clean-site-guard-e2e.com";
const CODES = ["E2E-QRST-1234", "E2E-UVWX-5678"];
const SIGN_IN_ORIGIN = `https://${CONSOLE_HOST}`;
const REFUSED = "The sign-in was refused in the console.";
const EXPIRED = "This code expired before it was approved.";

let net: E2ENetwork;
let ext: Extension;
let browserTab: number;
let browserPage: Page;

// ------------------------------------------------------------- the worker

interface DeviceAnswer {
  phase: string;
  userCode: string | null;
  expiresAt: number | null;
  message: string | null;
}

/** Send one message to the worker the way an extension page does. */
async function workerSend<T>(msg: object): Promise<T> {
  const page = await ext.context.newPage();
  try {
    await page.goto(`chrome-extension://${ext.id}/theme.css`);
    return (await page.evaluate((m) => chrome.runtime.sendMessage(m), msg)) as T;
  } finally {
    await page.close();
  }
}

async function signInStatus(): Promise<DeviceAnswer> {
  return (await workerSend<{ ok: true; device: DeviceAnswer }>({ kind: "signInStatus" })).device;
}

interface ConsoleTab {
  id: number;
  url: string;
  active: boolean;
}

/** The tabs open on the sign-in origin, read by the worker. */
function consoleTabs(): Promise<ConsoleTab[]> {
  return ext.sw.evaluate(async (origin: string) => {
    const tabs = await chrome.tabs.query({ url: `${origin}/*` });
    return tabs.map((t) => ({ id: t.id as number, url: t.url ?? "", active: t.active }));
  }, SIGN_IN_ORIGIN);
}

function tabExists(id: number): Promise<boolean> {
  return ext.sw.evaluate((i: number) => chrome.tabs.get(i).then(() => true, () => false), id);
}

/** The one console tab Guard opened, once it exists. */
async function theConsoleTab(): Promise<ConsoleTab> {
  await expect.poll(async () => (await consoleTabs()).length, { message: "Guard opened one console tab" }).toBe(1);
  return (await consoleTabs())[0]!;
}

async function sessionFlow(): Promise<unknown> {
  return ext.sw.evaluate(async () => (await chrome.storage.session.get("deviceFlow"))["deviceFlow"] ?? null);
}

/** Open the popup on This browser and press the sign-in button. */
async function startFromPopup(): Promise<Page> {
  const popup = await openPopup(ext, browserTab, { section: "browser" });
  await popup.locator("#btn-signin").click();
  return popup;
}

/** The minutes and seconds the countdown shows, as seconds. */
async function secondsShown(popup: Page): Promise<number> {
  const text = (await popup.locator("#signin-countdown").textContent()) ?? "";
  const m = /^Waiting for approval · (\d+):(\d\d) left$/.exec(text);
  expect(m, `the countdown reads "Waiting for approval · m:ss left", saw "${text}"`).not.toBeNull();
  return Number(m![1]) * 60 + Number(m![2]);
}

// ------------------------------------------------------------------ setup

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  ext = await launchExtension({ proxyPort: net.proxyPort });
  const visited = await visit(ext, `https://${CLEAN}/`);
  browserPage = visited.page;
  browserTab = visited.tabId;
  await waitForIcon(ext, browserTab, ["benign", "signedout", "unknown"]);
});

test.afterAll(async () => {
  await browserPage?.close();
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.resetDeviceFlow();
  net.clearLog();
  net.clearEndpoints();
  await setKey(ext, null);
  // This browser starts every test with no address reserved: one test presses Protect.
  await ext.sw.evaluate(() => chrome.storage.local.remove("egress"));
  await setSettings(ext, { cloudCheck: true });
  await workerSend({ kind: "signInCancel" });
});

test.afterEach(async () => {
  await workerSend({ kind: "signInCancel" });
  for (const t of await consoleTabs()) await ext.sw.evaluate((i: number) => chrome.tabs.remove(i).catch(() => undefined), t.id);
  await choose(ext, "auto");
});

// ------------------------------------------------- what leaves the browser

test("the authorize call sends a body that names the client and nothing else", async ({}, info) => {
  net.device.holdApproval = true;
  const popup = await startFromPopup();
  await expect.poll(() => net.device.authorizeBodies.length, { message: "the authorize call arrived" }).toBe(1);
  const raw = net.device.authorizeBodies[0]!;
  expect(JSON.parse(raw)).toEqual({ client: "whisper-guard" });
  expect(Object.keys(JSON.parse(raw) as object), "no browser name and no system in the body").toEqual(["client"]);
  info.annotations.push({ type: "authorize body", description: raw });
  await popup.close();
});

// ------------------------------------------------------- the waiting state

test("waiting: the popup shows the code from the address of the tab Guard opened, with its words and the countdown", async () => {
  net.device.userCodes = CODES;
  net.device.holdApproval = true;
  const popup = await startFromPopup();
  await expect(popup.locator("#signin-code")).toBeVisible();

  const tab = await theConsoleTab();
  const inAddress = new URL(tab.url).searchParams.get("user_code");
  expect(inAddress, "the tab Guard opened names the code").toBe(CODES[0]);
  await expect(popup.locator("#signin-code")).toHaveText(inAddress!);

  await expect(popup.locator("#signin-wait h3")).toHaveText("Approve this browser in the console");
  await expect(popup.locator("#signin-wait")).toContainText(
    "A console tab has opened. Check that it shows this code, then press Approve.",
  );
  await expect(popup.locator("#signin-wait")).toContainText("You never see or paste a key.");
  await expect(popup.locator("#btn-signin-tab")).toHaveText("Open the console tab again");
  // The pitch, the meter and the first button give way to it.
  await expect(popup.locator("#btn-signin")).toBeHidden();
  await expect(popup.locator("#tier-meter")).toBeHidden();

  // The stand-in's expires_in is 600 s: the clock reads that, less the time the screens took.
  const shown = await secondsShown(popup);
  expect(shown).toBeLessThanOrEqual(600);
  expect(shown).toBeGreaterThan(570);

  // The seconds are not announced: the countdown is not in a live region, and
  // the card has the one polite region, which says the state.
  expect(await popup.locator("#signin-countdown").evaluate((e) => e.closest("[aria-live]") === null)).toBe(true);
  await expect(popup.locator("#signin-pitch [aria-live]")).toHaveCount(1);
  await expect(popup.locator("#signin-announce")).toContainText(`Your code is ${CODES[0]}`);
  await popup.close();
});

test("waiting: the countdown counts down, one second at a time", async () => {
  net.device.holdApproval = true;
  const popup = await startFromPopup();
  await expect(popup.locator("#signin-code")).toBeVisible();
  const first = await secondsShown(popup);
  await expect.poll(() => secondsShown(popup), { timeout: 5_000 }).toBeLessThan(first);
  await popup.close();
});

// ------------------------------------------------------ the expiry and after

test("the countdown ends at the expiry the console named, the popup says the code expired, and Get a new code starts a new flow with a new code", async () => {
  net.device.userCodes = CODES;
  net.device.holdApproval = true;
  net.device.expiresIn = 8;
  const popup = await startFromPopup();
  await expect(popup.locator("#signin-code")).toHaveText(CODES[0]!);
  const tab = await theConsoleTab();
  const { expiresAt } = await signInStatus();
  expect(expiresAt, "the answer carries the moment the code runs out").not.toBeNull();
  expect(expiresAt! - Date.now(), "that moment is within the 8 s the console named").toBeLessThanOrEqual(8_000);

  // While it counts it never reads below 0:00.
  expect(await secondsShown(popup)).toBeLessThanOrEqual(8);

  await expect(popup.locator("#signin-end-text")).toHaveText(EXPIRED, { timeout: 15_000 });
  expect(await popup.evaluate(() => Date.now()), "it said so no earlier than the expiry").toBeGreaterThanOrEqual(expiresAt!);
  await expect(popup.locator("#btn-signin-again")).toHaveText("Get a new code");
  await expect(popup.locator("#signin-wait")).toBeHidden();

  // The worker agrees, and the tab Guard opened is left alone on an expiry.
  const worker = await signInStatus();
  expect(worker.phase).toBe("expired");
  expect(worker.message).toBe(EXPIRED);
  expect(await tabExists(tab.id), "an expired code leaves the console tab open").toBe(true);

  net.device.expiresIn = 600;
  await popup.locator("#btn-signin-again").click();
  await expect(popup.locator("#signin-code")).toHaveText(CODES[1]!);
  expect(net.device.authorizeBodies, "a second authorize call").toHaveLength(2);
  const fresh = await secondsShown(popup);
  expect(fresh, "a fresh countdown").toBeGreaterThan(570);
  await popup.close();
});

// ----------------------------------------------------------------- denied

test("a refused sign-in stops the waiting, says so, closes the console tab and sends no further token request", async () => {
  net.device.denyNext = true;
  const popup = await startFromPopup();
  const tab = await theConsoleTab();

  await expect(popup.locator("#signin-end-text")).toHaveText(REFUSED, { timeout: 15_000 });
  await expect(popup.locator("#btn-signin-again")).toHaveText("Start again");
  await expect(popup.locator("#signin-wait")).toBeHidden();
  await expect.poll(() => tabExists(tab.id), { message: "the console tab Guard opened is closed" }).toBe(false);
  expect(await sessionFlow(), "the pending flow is cleared").toBeNull();
  const worker = await signInStatus();
  expect(worker.phase).toBe("denied");
  expect(worker.message).toBe(REFUSED);

  // A later observable event: start again, and wait for that flow's own first
  // poll. A poll of the refused flow would have come before it (one interval
  // is 1 s), so none in the record means none was sent.
  net.device.holdApproval = true;
  await popup.locator("#btn-signin-again").click();
  await expect(popup.locator("#signin-code")).toBeVisible();
  await expect.poll(() => net.device.tokenAnswers.some((a) => a.deviceCode === "e2e-device-code-2")).toBe(true);
  const refusedFlow = net.device.tokenAnswers.filter((a) => a.deviceCode === "e2e-device-code-1").map((a) => a.status);
  expect(refusedFlow, "the refused flow was polled once, and that answer was the refusal").toEqual(["denied"]);
  await popup.close();
});

// ---------------------------------------------------------------- approved

test("approved: the console tab Guard opened is closed, and the next-step card leads into the protect control", async () => {
  const popup = await startFromPopup();
  const tab = await theConsoleTab();

  await expect(popup.locator("#signin-done h3")).toBeVisible({ timeout: 20_000 });
  await expect(popup.locator("#signin-done h3")).toHaveText("Signed in.");
  await expect(popup.locator("#signin-done")).toContainText(
    "Your fleet now shows on the dashboard. One more step makes this browser a verifiable endpoint.",
  );
  expect(await tabExists(tab.id), "the console tab Guard opened is closed").toBe(false);
  expect(await getStoredKey(ext)).toBe(MOCK_KEY);

  // The next-step card: title, tag, line, the control's own button, the way to the dashboard.
  const card = popup.locator("#identity-card");
  await expect(card).toBeVisible();
  await expect(card.locator(".pp-next-title")).toBeVisible();
  await expect(card.locator(".pp-next-title")).toHaveText("Protect this browser");
  await expect(card.locator(".pp-next-tag")).toBeVisible();
  await expect(card.locator(".pp-next-tag")).toHaveText("NEXT STEP");
  await expect(card.locator("#nextstep-line")).toBeVisible();
  await expect(card.locator("#nextstep-line")).toHaveText(
    "Reserve its own Whisper IPv6 address and route its traffic through it. Off any time.",
  );
  await expect(popup.getByRole("button", { name: "Protect this browser" }), "exactly one such button").toHaveCount(1);
  await expect(card.locator("#btn-protect")).toBeVisible();
  await expect(popup.locator("#btn-nextstep-dashboard")).toBeVisible();
  await expect(popup.locator("#btn-nextstep-dashboard")).toHaveText("Open dashboard →");
  // The control mounted here is the real one, and so is its head: hidden in favour of the card's own.
  await expect(card.locator("#identity-state")).toBeHidden();

  // Pressing it is the control's own press: it reserves the address.
  await card.locator("#btn-protect").click();
  await expect(popup.locator("#identity-detail")).toContainText(/2a04:2a01:[0-9a-f:]+/i, { timeout: 15_000 });
  // With an address the card is the plain one again.
  await expect(card.locator(".pp-next-tag")).toBeHidden();
  await expect(popup.locator("#signin-done")).toBeHidden();
  await popup.close();
});

test("approved: a console tab the reader took to another site is not closed", async () => {
  net.device.holdApproval = true;
  const popup = await startFromPopup();
  const tab = await theConsoleTab();
  const consolePage = ext.context.pages().find((p) => p.url().startsWith(SIGN_IN_ORIGIN));
  expect(consolePage, "the page of the tab Guard opened").toBeTruthy();
  await consolePage!.goto(`https://${CLEAN}/`);

  net.device.holdApproval = false;
  net.device.approveVisited = true;
  await expect(popup.locator("#signin-done h3")).toBeVisible({ timeout: 20_000 });
  await expect(popup.locator("#signin-done h3")).toHaveText("Signed in.");
  // The answer reads approved only after the worker has dealt with the tab.
  expect(await tabExists(tab.id), "the tab the reader took elsewhere is left open").toBe(true);
  await consolePage!.close();
  await popup.close();
});

// ----------------------------------------------- the console tab, again

test("Open the console tab again makes the open console tab active, and opens a new one on the same address once it is closed", async () => {
  net.device.holdApproval = true;
  net.device.userCodes = CODES;
  const popup = await startFromPopup();
  const tab = await theConsoleTab();
  // Take the focus off it: another tab in front.
  await browserPage.bringToFront();
  await expect.poll(async () => (await consoleTabs())[0]?.active).toBe(false);

  await popup.locator("#btn-signin-tab").click();
  await expect.poll(async () => (await consoleTabs()).find((t) => t.id === tab.id)?.active).toBe(true);
  expect((await consoleTabs()).length, "the open tab was used, none was added").toBe(1);

  await ext.sw.evaluate((i: number) => chrome.tabs.remove(i), tab.id);
  await expect.poll(() => tabExists(tab.id)).toBe(false);
  await popup.locator("#btn-signin-tab").click();
  const again = await theConsoleTab();
  expect(again.id, "a new tab").not.toBe(tab.id);
  expect(again.url, "the address the console named").toBe(tab.url);
  expect(net.device.authorizeBodies, "no second sign-in was started").toHaveLength(1);
  await popup.close();
});

test("Open the console tab again, pressed while the console tab is still loading, opens no second tab", async () => {
  net.device.holdApproval = true;
  const page = net.holdNextActivate();
  const popup = await startFromPopup();
  // The tab exists and its page has been asked for but not delivered: it is still loading.
  await page.held;
  // The page's request can arrive before the worker has noted which tab it opened; wait for the note.
  await expect
    .poll(() =>
      ext.sw.evaluate(async () => {
        const flow = (await chrome.storage.session.get("deviceFlow"))["deviceFlow"] as { tabId?: unknown } | undefined;
        return typeof flow?.tabId === "number";
      }),
    )
    .toBe(true);
  const openTabs = (): Promise<number> =>
    ext.sw.evaluate(async (origin: string) => {
      const tabs = await chrome.tabs.query({});
      return tabs.filter((t) => (t.pendingUrl || t.url || "").startsWith(origin)).length;
    }, SIGN_IN_ORIGIN);
  expect(await openTabs(), "one console tab, loading").toBe(1);

  const answer = await workerSend<{ ok: true; device: DeviceAnswer }>({ kind: "signInShowTab" });
  expect(answer.device.phase).toBe("waiting");
  expect(await openTabs(), "no second tab was opened").toBe(1);
  page.release();
  await popup.close();
});

// ---------------------------------------------- close and reopen the popup

test("closing and reopening the popup part-way brings back the same code, with the countdown still running", async () => {
  net.device.holdApproval = true;
  net.device.expiresIn = 120;
  net.device.userCodes = CODES;
  const first = await startFromPopup();
  await expect(first.locator("#signin-code")).toHaveText(CODES[0]!);
  const before = await secondsShown(first);
  const flow = await signInStatus();
  await first.close();

  // Opened without choosing a part: the sign-in card is what the popup scrolls to.
  const second = await openPopup(ext, browserTab);
  await expect(second.locator("#signin-code")).toHaveText(CODES[0]!);
  const after = await secondsShown(second);
  expect(after, "the countdown carried on").toBeLessThanOrEqual(before);
  expect(after, "from the same expiry, not a fresh 2:00 that had restarted").toBeGreaterThan(before - 30);
  expect((await signInStatus()).expiresAt, "the same expiry").toBe(flow.expiresAt);
  await expect.poll(() => secondsShown(second), { timeout: 5_000 }).toBeLessThan(after);
  expect(net.device.authorizeBodies, "reopening starts no new sign-in").toHaveLength(1);

  // It polls again too: the approval, when it comes, is seen by the reopened popup.
  net.device.holdApproval = false;
  net.device.approveVisited = true;
  await expect(second.locator("#signin-done h3")).toBeVisible({ timeout: 20_000 });
  await expect(second.locator("#signin-done h3")).toHaveText("Signed in.");
  await second.close();
});

test("a popup opened while a sign-in waits has the sign-in card in view", async () => {
  net.device.holdApproval = true;
  const first = await startFromPopup();
  await expect(first.locator("#signin-code")).toBeVisible();
  await first.close();

  const second = await openPopup(ext, browserTab);
  await expect(second.locator("#signin-code")).toBeVisible();
  await settledLayout(second);
  await expect
    .poll(() =>
      second.evaluate(() => {
        const region = document.getElementById("popup-scroll")!.getBoundingClientRect();
        const card = document.getElementById("signin-pitch")!.getBoundingClientRect();
        return card.top >= region.top - 1 && card.top < region.bottom - 40;
      }),
    )
    .toBe(true);
  await second.close();
});

// ----------------------------------------------- the other pages that start it

test("first run: a refused sign-in says so and stops", async () => {
  net.device.denyNext = true;
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/firstrun.html`);
  await expect(page.locator("#steps > li")).toHaveCount(3);
  await page.locator("#btn-signin").click();
  await expect(page.locator("#device-status")).toHaveText(REFUSED, { timeout: 15_000 });
  expect((await signInStatus()).phase).toBe("denied");
  expect(await sessionFlow()).toBeNull();
  await page.close();
});

test("dashboard: a refused sign-in says so and stops", async () => {
  net.device.denyNext = true;
  const page = await openDashboard(ext, "fleet");
  await page.locator("#fleet-signin").click();
  await expect(page.locator("#fleet-device-status")).toHaveText(REFUSED, { timeout: 15_000 });
  expect((await signInStatus()).phase).toBe("denied");
  expect(await sessionFlow()).toBeNull();
  await page.close();
});

test("settings: a refused sign-in says so and stops", async () => {
  net.device.denyNext = true;
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/options.html`);
  await expect(page.locator("#account-signedout")).toBeVisible();
  await page.locator("#btn-signin").click();
  await expect(page.locator("#device-status")).toHaveText(REFUSED, { timeout: 15_000 });
  expect((await signInStatus()).phase).toBe("denied");
  await page.close();
});

// ------------------------------------------- answers that arrive too late

const LATE: { name: string; answer: Record<string, string> }[] = [
  { name: "approved", answer: { status: "approved", api_key: MOCK_KEY } },
  { name: "denied", answer: { status: "denied", error: "access_denied" } },
];
for (const late of LATE) {
  test(`a late ${late.name} answer for a flow that was replaced changes nothing: the new code keeps waiting, no key is stored and its tab stays open`, async () => {
    net.device.userCodes = CODES;
    net.device.holdApproval = true;
    const hold = net.holdNextToken();
    const popup = await startFromPopup();
    await expect(popup.locator("#signin-code")).toHaveText(CODES[0]!);
    // The first flow's poll is on the wire and unanswered.
    await hold.held;

    // A second sign-in replaces it, and the popup follows to the new code.
    await workerSend({ kind: "signInStart" });
    await expect(popup.locator("#signin-code")).toHaveText(CODES[1]!);
    const answered = (code: string): number => net.device.tokenAnswers.filter((a) => a.deviceCode === code).length;

    // The old answer arrives now. Then the new flow is polled once more: that
    // later poll is the observable event after which nothing may have changed.
    hold.release(late.answer);
    await expect.poll(() => answered("e2e-device-code-1")).toBe(1);
    await expect.poll(() => answered("e2e-device-code-2")).toBeGreaterThan(0);

    expect(await getStoredKey(ext), "the old flow's answer stored no key").toBeNull();
    const worker = await signInStatus();
    expect(worker.phase).toBe("waiting");
    expect(worker.userCode).toBe(CODES[1]);
    await expect(popup.locator("#signin-code")).toHaveText(CODES[1]!);
    await expect(popup.locator("#signin-wait")).toBeVisible();
    const tabs = await consoleTabs();
    expect(
      tabs.some((t) => new URL(t.url).searchParams.get("user_code") === CODES[1]),
      "the new flow's tab is still open",
    ).toBe(true);
    await popup.close();
  });
}

test("a verification address that is not https is never opened: the popup says the reply was incomplete and offers Try again", async () => {
  for (const address of ["http://console.whisper.security/activate", "javascript:void(0)"]) {
    net.resetDeviceFlow();
    net.device.verificationUri = address;
    const popup = await startFromPopup();
    await expect(popup.locator("#signin-end-text")).toHaveText("incomplete device-authorize reply from the console");
    await expect(popup.locator("#btn-signin-again")).toHaveText("Try again");
    // The reply came before any tab would have been opened.
    expect(await consoleTabs(), `${address}: no tab was opened`).toHaveLength(0);
    expect(await sessionFlow(), `${address}: nothing is left pending`).toBeNull();
    await popup.close();
  }
});

test("a sign-in cancelled from another page returns the waiting popup to the pitch", async () => {
  net.device.holdApproval = true;
  const popup = await startFromPopup();
  await expect(popup.locator("#signin-code")).toBeVisible();
  await workerSend({ kind: "signInCancel" });
  await expect(popup.locator("#btn-signin")).toBeVisible({ timeout: 10_000 });
  await expect(popup.locator("#signin-wait")).toBeHidden();
  await expect(popup.locator("#signin-pitch")).toHaveAttribute("data-state", "idle");
  await popup.close();
});

test("approved with an address already reserved: the popup opens at This site, not scrolled to This browser", async () => {
  const first = await startFromPopup();
  await expect(first.locator("#signin-done h3")).toBeVisible({ timeout: 20_000 });
  await first.locator("#btn-protect").click();
  await expect(first.locator("#identity-detail")).toContainText(/2a04:2a01:[0-9a-f:]+/i, { timeout: 15_000 });
  await first.close();

  const second = await openPopup(ext, browserTab);
  // The control has read its status and shows the address; the scroll had its chance by then.
  await expect(second.locator("#identity-detail")).toContainText(/2a04:2a01:[0-9a-f:]+/i, { timeout: 15_000 });
  await expect(second.locator("#signin-done")).toBeHidden();
  await settledLayout(second);
  expect(await second.evaluate(() => document.getElementById("popup-scroll")!.scrollTop), "the popup is at the top").toBe(0);
  await second.close();
});

// ---------------------------------------------------- contrast and the fit

/** Every glyph of the card's waiting or approved state clears AA in both schemes, drawn and measured. */
async function expectReadable(popup: Page, what: string): Promise<void> {
  for (const choice of ["dark", "light"] as const) {
    await choose(ext, choice);
    await popup.emulateMedia({ colorScheme: choice, reducedMotion: "reduce" });
    await expectScheme(popup, choice, `${what} ${choice}`);
    const samples = await measureContrast(popup);
    expect(samples.length, `${what} ${choice}: nothing was measured`).toBeGreaterThan(5);
    const bad = samples.filter((s) => s.ratio < s.floor).map((s) => `${s.ratio.toFixed(2)}:1 (needs ${s.floor}) ${s.what}`);
    expect(bad, `${what} ${choice}: text under the AA floor`).toEqual([]);
  }
}

test("waiting: every glyph clears the contrast floor in both schemes, and the code and the countdown fit the popup as drawn and wider", async () => {
  net.device.holdApproval = true;
  net.device.userCodes = CODES;
  const popup = await startFromPopup();
  await expect(popup.locator("#signin-code")).toBeVisible();
  await settledLayout(popup);
  // The sample has to be in the sweep: a sweep that skipped the card would pass.
  const samples = await measureContrast(popup);
  expect(samples.some((s) => s.what.includes("#signin-code")), "the code is measured").toBe(true);
  expect(samples.some((s) => s.what.includes("#signin-countdown")), "the countdown is measured").toBe(true);
  await expectReadable(popup, "waiting");

  const fits = (): Promise<{ lines: number; clipped: boolean; countLines: number; overflowX: boolean }> =>
    popup.evaluate(() => {
      const code = document.getElementById("signin-code")!;
      const cs = getComputedStyle(code);
      const inner = code.getBoundingClientRect().height - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom) - 2;
      const count = document.getElementById("signin-countdown")!;
      const card = document.getElementById("signin-pitch")!;
      return {
        lines: inner / parseFloat(cs.lineHeight),
        clipped: code.scrollWidth > code.clientWidth,
        countLines: count.getBoundingClientRect().height / parseFloat(getComputedStyle(count).lineHeight),
        overflowX: card.scrollWidth > card.clientWidth,
      };
    });
  for (const [how, read] of [
    ["as drawn", fits],
    [`${WIDER_EM}em wider`, () => withWiderGlyphs(popup, WIDER_EM, fits)],
  ] as const) {
    const m = await read();
    expect(m.lines, `${how}: the code takes one line`).toBeCloseTo(1, 1);
    expect(m.clipped, `${how}: the code is not clipped`).toBe(false);
    expect(m.countLines, `${how}: the countdown takes one line`).toBeCloseTo(1, 1);
    expect(m.overflowX, `${how}: the card does not spill sideways`).toBe(false);
  }
  await popup.close();
});

test("approved: every glyph of the confirmation and the next-step card clears the contrast floor in both schemes, and the card fits as drawn and wider", async () => {
  const popup = await startFromPopup();
  await expect(popup.locator("#signin-done h3")).toBeVisible({ timeout: 20_000 });
  await expect(popup.locator("#signin-done h3")).toHaveText("Signed in.");
  await expect(popup.locator("#btn-protect")).toBeVisible();
  await settledLayout(popup);
  const samples = await measureContrast(popup);
  expect(samples.some((s) => s.what.includes("NEXT STEP")), "the tag is measured").toBe(true);
  expect(samples.some((s) => s.what.includes("#btn-protect")), "the control's button is measured").toBe(true);
  await expectReadable(popup, "approved");

  const fits = (): Promise<{ tag: boolean; titleLines: number; spill: boolean }> =>
    popup.evaluate(() => {
      const card = document.getElementById("identity-card")!;
      const title = card.querySelector<HTMLElement>(".pp-next-title")!;
      const tag = card.querySelector<HTMLElement>(".pp-next-tag")!;
      return {
        tag: tag.getBoundingClientRect().right <= card.getBoundingClientRect().right,
        titleLines: title.getBoundingClientRect().height / parseFloat(getComputedStyle(title).lineHeight),
        spill: card.scrollWidth > card.clientWidth,
      };
    });
  for (const [how, read] of [
    ["as drawn", fits],
    [`${WIDER_EM}em wider`, () => withWiderGlyphs(popup, WIDER_EM, fits)],
  ] as const) {
    const m = await read();
    expect(m.tag, `${how}: the tag stays inside the card`).toBe(true);
    expect(m.titleLines, `${how}: the title takes one line`).toBeCloseTo(1, 1);
    expect(m.spill, `${how}: the card does not spill sideways`).toBe(false);
  }
  await popup.close();
});
