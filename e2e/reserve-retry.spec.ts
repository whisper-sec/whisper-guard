// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Reserving the browser's address is retried, and each step is shown.
//
// The service creates a device the moment it is registered, but its answer
// does not carry the device's id, and the account's list can take a few
// seconds to show it. So the background registers ONCE per reservation, reads
// the account again at once, and then up to two more times (waits of about two
// and then four seconds), adopting this browser's device when it is listed. It
// never registers a second time in the same reservation, and it shows which
// try it is on. Everything here runs through the real built extension against
// the stand-in control plane, which can answer as the service does, show the
// device on the list only after some reads, fail, refuse or hold its answer.
//
// The product's own waits are real time, so each full run costs seconds:
// the number of runs that go to the last try is kept small on purpose.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  openDashboard,
  openPopup,
  setKey,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const CLEAN = "intranet-tools-vendor.com";
const FALLBACK = "We couldn’t reserve an address yet. Your verdicts still work.";
const ROUTING_HINT = "Identity reserved. Waiting for the browser's permission before routing.";

let net: E2ENetwork;
let ext: Extension;

const browserDevices = (): number => net.endpoints.filter((e) => e.label.includes("This browser")).length;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setIdentify(CLEAN, [{ host: CLEAN, canonical_name: "Intranet Tools", category: "work", roles: [] }]);
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  net?.releaseHolds();
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.releaseHolds();
  net.clearEndpoints();
  await setKey(ext, MOCK_KEY);
  // A fresh browser each time: no identity stored from the previous test.
  await ext.sw.evaluate(() => chrome.storage.local.remove("egress"));
});

async function popupOnASite(): Promise<{ popup: Page; page: Page; tabId: number }> {
  const { page, tabId } = await visit(ext, "https://example-reserve-retry.com/");
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });
  return { popup, page, tabId };
}

/**
 * The flow ended with the browser enrolled and no error text anywhere. The
 * steps are gone first, so this cannot pass part-way through; `routeSays` is
 * what the route line says once the routing attempt has settled (a headless
 * browser never answers the permission prompt, so routing stays off).
 */
async function expectEnrolledAndQuiet(page: Page, routeSays = "Not routed"): Promise<void> {
  await expect(page.locator("#protect-progress")).toBeHidden({ timeout: 30_000 });
  await expect(page.locator("#identity-state")).toHaveText(/ENROLLED|VERIFIED/);
  await expect(page.locator("#identity-detail")).toContainText(/2a04:2a01:[0-9a-f:]+/i);
  await expect(page.locator("#identity-note")).toBeHidden();
  await expect(page.locator("#route-line")).toContainText(routeSays);
  const text = (await page.locator("#route-line").textContent()) ?? "";
  expect(text).not.toMatch(/no identity|couldn’t reserve|error/i);
}

/** Record every text the steps list ever shows on this page. */
async function watchSteps(page: Page): Promise<() => Promise<string[]>> {
  await page.evaluate(() => {
    const w = window as unknown as { __stepTexts: string[] };
    w.__stepTexts = [];
    const list = document.querySelector("#protect-steps");
    if (!list) return;
    new MutationObserver(() => w.__stepTexts.push(list.textContent ?? "")).observe(list, {
      childList: true,
      subtree: true,
      characterData: true,
    });
  });
  return () => page.evaluate(() => (window as unknown as { __stepTexts: string[] }).__stepTexts);
}

test("the usual first enrolment succeeds on try 1: one registration, the device is listed at once", async () => {
  net.scriptRegister({ outcome: "real", hiddenReads: 0 });
  const { popup, page } = await popupOnASite();
  const texts = await watchSteps(popup);
  await popup.locator("#btn-protect").click();
  await expectEnrolledAndQuiet(popup);

  const seen = (await texts()).join("\n");
  expect(seen, "the steps did show").toContain("try 1 of 3");
  expect(seen, "and never said try 2").not.toContain("try 2");
  expect(net.registerCalls).toBe(1);
  expect(browserDevices()).toBe(1);
  await popup.close();
  await page.close();
});

test("success on try 2 in the popup: the steps name the try, one registration, one device", async () => {
  net.scriptRegister({ outcome: "real", hiddenReads: 1 });
  const { popup, page } = await popupOnASite();
  await popup.locator("#btn-protect").click();

  await expect(popup.locator("#protect-steps")).toBeVisible();
  await expect(popup.locator("#protect-steps li")).toHaveCount(3);
  await expect(popup.locator("#protect-steps li[aria-current='step']")).toContainText(
    "Reserving your Whisper address (try 2 of 3)",
  );
  await expect(popup.locator("#protect-steps li").first()).toContainText("Signed in");
  await expect(popup.locator("#protect-steps li").nth(2)).toContainText("Turning routing on");
  await expect(popup.locator("#protect-progress")).toHaveAttribute("aria-live", "polite");
  await expect(popup.locator("#protect-progress")).toContainText("Protecting this browser…");
  await expect(popup.locator("#protect-progress")).toContainText("A new address can take a few seconds to appear.");
  await expect(popup.locator("#protect-progress")).not.toContainText(ROUTING_HINT);
  // Never ship the board's annotations as copy.
  await expect(popup.locator("#protect-progress")).not.toContainText("retries on its own");

  // Once the address is reserved the line under the steps follows the running step.
  await expect(popup.locator("#protect-progress")).toContainText(ROUTING_HINT);
  await expect(popup.locator("#protect-progress")).not.toContainText("A new address can take a few seconds");
  await expect(popup.locator("#protect-steps li[aria-current='step']")).toContainText("Turning routing on");
  await expectEnrolledAndQuiet(popup);
  expect(net.registerCalls, "the same registration is never sent again").toBe(1);
  expect(browserDevices()).toBe(1);
  await popup.close();
  await page.close();
});

test("success on try 3 on the dashboard: the device is listed on the third read, one registration", async () => {
  net.scriptRegister({ outcome: "real", hiddenReads: 2 });
  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });
  await dash.locator("#btn-protect").click();

  await expect(dash.locator("#protect-steps li[aria-current='step']")).toContainText("(try 3 of 3)", {
    timeout: 15_000,
  });
  await expectEnrolledAndQuiet(dash);
  expect(net.registerCalls).toBe(1);
  expect(browserDevices()).toBe(1);
  await dash.close();
});

test("after three tries with the device never listed: the fallback, one registration, verdicts work, Try again adopts it", async () => {
  net.scriptRegister({ outcome: "real", hiddenReads: Infinity });
  const { popup, page } = await popupOnASite();
  await popup.locator("#btn-protect").click();

  await expect(popup.locator("#route-line")).toContainText("Not protected.", { timeout: 30_000 });
  await expect(popup.locator("#route-line")).toContainText(FALLBACK);
  await expect(popup.locator("#route-line .w-dot")).toHaveClass(/blocked/);
  await expect(popup.locator("#btn-protect")).toHaveText("Try again");
  await expect(popup.locator("#protect-steps")).toBeHidden();
  expect(net.registerCalls, "one registration for the whole reservation").toBe(1);
  expect(browserDevices()).toBe(1);
  // The raw error is never the thing shown.
  await expect(popup.locator("body")).not.toContainText("no identity");
  await expect(popup.locator("#identity-note")).toBeHidden();

  // Verdicts keep working: a site is read and its verdict lands.
  const other = await visit(ext, `https://${CLEAN}/`);
  await waitForIcon(ext, other.tabId, ["benign"]);
  await other.page.close();

  // The list has caught up. Try again finds the device: no new registration.
  net.hideEndpointsForReads(0);
  await popup.locator("#btn-protect").click();
  await expectEnrolledAndQuiet(popup);
  expect(net.registerCalls).toBe(1);
  expect(browserDevices()).toBe(1);
  await popup.close();
  await page.close();
});

test("Try again when the service says the device is already registered: re-read, adopt, one device", async () => {
  net.scriptRegister({ outcome: "real", hiddenReads: Infinity });
  const { popup, page } = await popupOnASite();
  await popup.locator("#btn-protect").click();
  await expect(popup.locator("#route-line")).toContainText(FALLBACK, { timeout: 30_000 });
  expect(net.registerCalls).toBe(1);

  // The new registration is answered "already registered", and the list shows
  // the device on the read after that.
  net.scriptRegister("already");
  net.hideEndpointsForReads(1);
  await popup.locator("#btn-protect").click();
  await expectEnrolledAndQuiet(popup);
  expect(net.registerCalls, "one registration in each reservation").toBe(2);
  expect(browserDevices()).toBe(1);
  await expect(popup.locator("body")).not.toContainText("already registered");
  await popup.close();
  await page.close();
});

test("a registration request that fails in transport is not sent again: the account is read again", async () => {
  net.scriptRegister("transport");
  const { popup, page } = await popupOnASite();
  await popup.locator("#btn-protect").click();
  await expect.poll(() => net.registerCalls, { timeout: 15_000 }).toBe(1);
  // The request may have landed before it failed: the device shows up on the list.
  net.addEndpoint({
    agent: "agent-landed",
    address: "2a04:2a01:e2e:ffff::1",
    label: "This browser (Whisper Guard)",
    device: true,
    state: "active",
  });
  await expectEnrolledAndQuiet(popup);
  expect(net.registerCalls).toBe(1);
  expect(browserDevices()).toBe(1);
  await popup.close();
  await page.close();
});

test("a refusal (the device limit) shows at once with one call and is not retried", async () => {
  net.scriptRegister("refuse");
  const { popup, page } = await popupOnASite();
  await popup.locator("#btn-protect").click();

  await expect(popup.locator("#identity-note")).toContainText("over its device limit", { timeout: 15_000 });
  await expect(popup.locator("#protect-steps")).toBeHidden();
  await expect(popup.locator("#btn-protect")).toHaveText("Protect this browser");
  await expect(popup.locator("#route-line")).not.toContainText(FALLBACK);
  expect(net.registerCalls).toBe(1);
  expect(browserDevices()).toBe(0);
  await popup.close();
  await page.close();
});

test("closing the popup part-way does not cancel the reservation", async () => {
  const held = net.holdNextRegister();
  const { popup, page, tabId } = await popupOnASite();
  await popup.locator("#btn-protect").click();
  await held.held;
  await popup.close();

  held.release();
  await expect.poll(browserDevices, { timeout: 15_000 }).toBe(1);

  const again = await openPopup(ext, tabId);
  await expectEnrolledAndQuiet(again, "Identity reserved.");
  expect(net.registerCalls).toBe(1);
  await again.close();
  await page.close();
});

test("a popup opened while the answer is still held shows the steps and the current try", async () => {
  const held = net.holdNextRegister();
  const { popup, page, tabId } = await popupOnASite();
  await popup.locator("#btn-protect").click();
  await held.held;

  const second = await openPopup(ext, tabId);
  await expect(second.locator("#protect-steps li[aria-current='step']")).toContainText(
    "Reserving your Whisper address (try 1 of 3)",
    { timeout: 10_000 },
  );
  // Only one registration is in flight, however many surfaces are open.
  expect(net.registerCalls).toBe(1);

  held.release();
  await expectEnrolledAndQuiet(second, "Identity reserved.");
  expect(net.registerCalls).toBe(1);
  expect(browserDevices()).toBe(1);
  await second.close();
  await popup.close();
  await page.close();
});

test("a browser that already holds its address turning routing on never shows a reservation try", async () => {
  const { popup, page } = await popupOnASite();
  await popup.locator("#btn-protect").click();
  await expectEnrolledAndQuiet(popup);
  await expect(popup.locator("#btn-protect")).toHaveText("Turn routing on");

  const texts = await watchSteps(popup);
  await popup.locator("#btn-protect").click();
  await expect(popup.locator("#protect-progress")).toBeVisible();
  await expectEnrolledAndQuiet(popup);
  const seen = (await texts()).join("\n");
  expect(seen).toContain("Turning routing on");
  expect(seen).not.toContain("try 1 of 3");
  expect(net.registerCalls).toBe(1);
  await popup.close();
  await page.close();
});

test("when the background cannot be reached the control does not stay stuck, and stops polling", async () => {
  const { popup, page } = await popupOnASite();
  const baseline = await popup.evaluate(() => {
    const w = window as unknown as { __intervals: Set<unknown>; __created: number };
    w.__intervals = new Set();
    w.__created = 0;
    const set = window.setInterval.bind(window);
    const clear = window.clearInterval.bind(window);
    window.setInterval = ((...a: Parameters<typeof setInterval>) => {
      const h = set(...a);
      w.__intervals.add(h);
      w.__created++;
      return h;
    }) as typeof setInterval;
    window.clearInterval = ((h?: number) => {
      w.__intervals.delete(h);
      clear(h);
    }) as typeof clearInterval;
    // The worker is gone: every message to it is rejected.
    chrome.runtime.sendMessage = (() => Promise.reject(new Error("the worker is gone"))) as typeof chrome.runtime.sendMessage;
    return w.__intervals.size;
  });

  // In the same turn as the click, so the steps are caught before the failure ends them.
  const right = await popup.evaluate(() => {
    (document.querySelector("#btn-protect") as HTMLElement).click();
    return {
      stepsShown: !(document.querySelector("#protect-progress") as HTMLElement).hidden,
      created: (window as unknown as { __created: number }).__created,
    };
  });
  expect(right.stepsShown, "the steps were up right after the click").toBe(true);
  expect(right.created, "the click started a poll timer").toBeGreaterThanOrEqual(1);

  await expect(popup.locator("#protect-progress")).toBeHidden();
  await expect(popup.locator("#btn-protect")).toBeVisible();
  await expect(popup.locator("#btn-protect")).toBeEnabled();
  await expect
    .poll(() => popup.evaluate(() => (window as unknown as { __intervals: Set<unknown> }).__intervals.size))
    .toBe(baseline);
  await popup.close();
  await page.close();
});

// Last on purpose: it ends in the "all tries used" state, which the worker
// remembers until the next reservation starts.
test("the outcome on the route line is written while it is visible and a live region, and the first fill is silent", async () => {
  net.scriptRegister({ outcome: "real", hiddenReads: Infinity });
  const site = await visit(ext, "https://example-reserve-retry.com/");
  // Record, from before anything mounts, each write to the route line with the
  // state it was in AT THAT MOMENT (a change made in a hidden region is not announced).
  const popup = await ext.context.newPage();
  await popup.addInitScript(() => {
    const w = window as unknown as { __routeChanges: Array<{ text: string; hidden: boolean; live: string | null }> };
    w.__routeChanges = [];
    const original = Element.prototype.replaceChildren;
    Element.prototype.replaceChildren = function (this: Element, ...nodes: Array<Node | string>): void {
      const before = { hidden: (this as HTMLElement).hidden, live: this.getAttribute("aria-live") };
      original.apply(this, nodes);
      if (this.id === "route-line") w.__routeChanges.push({ text: this.textContent ?? "", ...before });
    };
  });
  await popup.goto(`chrome-extension://${ext.id}/popup.html?tab=${site.tabId}`);
  await expect(popup.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });
  await popup.locator("#btn-protect").click();
  await expect(popup.locator("#route-line")).toContainText(FALLBACK, { timeout: 30_000 });

  const changes = await popup.evaluate(
    () => (window as unknown as { __routeChanges: Array<{ text: string; hidden: boolean; live: string | null }> }).__routeChanges,
  );
  expect(changes.length, "the line was filled, then rewritten with the outcome").toBeGreaterThanOrEqual(2);
  expect(changes[0]!.live, "the first fill happens before the line is a live region").toBeNull();
  const outcome = changes.find((c) => c.text.includes(FALLBACK));
  expect(outcome, "the outcome was written").toBeTruthy();
  expect(outcome!.hidden, "visible when the outcome was written").toBe(false);
  expect(outcome!.live, "and a live region").toBe("polite");
  await popup.close();
  await site.page.close();
});
