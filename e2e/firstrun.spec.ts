// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The first-run page: a three-step setup. Each step's state is READ (the
// toolbar pin from the browser, Active Shield from the stored setting AND
// the all-sites grant, the account from the stored key), never assumed, and
// the counter in the header follows them in both directions.
//
// The page's own code runs unmodified. Where a test needs the browser to
// answer in a way a headless run cannot produce (a pinned icon, a refused
// permission request), a wrapper is installed before the page's scripts run
// (addInitScript) and records every call it sees; everything it does not
// override goes to the real API. The grant itself is held from install by
// makeShieldDist, or taken away through the browser's own site-access
// control, as e2e/shield-dependent.spec.ts does.

import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, GRAPH_READ_HOST, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, makeShieldDist, setKey, setSettings, getStoredKey, type Extension } from "./helpers/extension";
import { compact } from "../src/shared/spark";

const HERE = dirname(fileURLToPath(import.meta.url));

interface Wrap {
  /** What action.getUserSettings answers: pinned, not pinned, throws, or is not there. */
  pin: "true" | "false" | "throw" | "missing";
  /** What permissions.request does: forward, resolve false, reject, or wait for the test. */
  request: "real" | "false" | "throw" | "hold";
  /** What a getSettings message does: forward, answer not-ok, or reject. */
  settings: "real" | "fail" | "reject";
  /** Message kinds whose send rejects, as when the worker stops mid-request. */
  reject: string[];
}

interface Probe extends Wrap {
  calls: string[];
  pinReads: number;
  hold: boolean;
  held: number;
  release: () => void;
  resolveRequest: (granted: boolean) => void;
}

const WRAP = (init: Wrap) => {
  const t = {
    ...init,
    calls: [] as string[],
    pinReads: 0,
    hold: false,
    held: 0,
    release: () => undefined as void,
    resolveRequest: (_granted: boolean) => undefined as void,
  };
  (window as unknown as { __t: typeof t }).__t = t;

  const action = chrome.action as unknown as { getUserSettings?: unknown };
  if (t.pin === "missing") {
    action.getUserSettings = undefined;
  } else {
    action.getUserSettings = async () => {
      t.pinReads++;
      if (t.pin === "throw") throw new Error("the browser would not say");
      return { isOnToolbar: t.pin === "true" };
    };
  }

  const realRequest = chrome.permissions.request.bind(chrome.permissions) as (q: unknown) => Promise<boolean>;
  (chrome.permissions as { request: unknown }).request = (q: unknown) => {
    t.calls.push("permissions.request");
    if (t.request === "false") return Promise.resolve(false);
    if (t.request === "throw") return Promise.reject(new Error("the request was refused"));
    if (t.request === "hold") return new Promise<boolean>((res) => void (t.resolveRequest = res));
    return realRequest(q);
  };

  // A read of the grant that starts early and finishes late.
  const realContains = chrome.permissions.contains.bind(chrome.permissions);
  (chrome.permissions as { contains: unknown }).contains = async (q: chrome.permissions.Permissions) => {
    if (!t.hold) return realContains(q);
    t.hold = false;
    const value = await realContains(q);
    await new Promise<void>((res) => {
      t.release = res as () => void;
      t.held++;
    });
    return value;
  };

  const realSend = chrome.runtime.sendMessage.bind(chrome.runtime) as (...a: unknown[]) => unknown;
  (chrome.runtime as { sendMessage: unknown }).sendMessage = (m: { kind?: string }, ...rest: unknown[]) => {
    t.calls.push(`msg:${m?.kind}`);
    if (m?.kind && t.reject.includes(m.kind)) return Promise.reject(new Error("the worker stopped mid-request"));
    if (m?.kind === "getSettings" && t.settings === "reject") return Promise.reject(new Error("the worker stopped mid-request"));
    if (m?.kind === "getSettings" && t.settings === "fail") return Promise.resolve({ ok: false });
    return realSend(m, ...rest);
  };
};

const DEFAULTS: Wrap = { pin: "false", request: "real", settings: "real", reject: [] };

async function openFirst(ext: Extension, init: Partial<Wrap> = {}, size?: { width: number; height: number }): Promise<Page> {
  const page = await ext.context.newPage();
  if (size) await page.setViewportSize(size);
  await page.addInitScript(WRAP, { ...DEFAULTS, ...init });
  await page.goto(`chrome-extension://${ext.id}/firstrun.html`);
  // The page has drawn its steps AND the first settings read has landed and been
  // drawn, so a negative assertion below is about that read, not the first paint.
  await expect(page.locator("#steps > li")).toHaveCount(3);
  await expect(page.locator("#steps")).toHaveAttribute("data-read", "settings");
  return page;
}

const setProbe = (page: Page, patch: Partial<Wrap>) =>
  page.evaluate((p) => Object.assign((window as unknown as { __t: Wrap }).__t, p), patch);
const calls = (page: Page) => page.evaluate(() => (window as unknown as { __t: Probe }).__t.calls.slice());
const clearCalls = (page: Page) => page.evaluate(() => void ((window as unknown as { __t: Probe }).__t.calls.length = 0));

const count = (page: Page) => page.locator("#setup-count");
const pin = (page: Page) => page.locator("#step-pin");
const shield = (page: Page) => page.locator("#step-shield");
const account = (page: Page) => page.locator("#step-account");

async function storedSettings(page: Page): Promise<Record<string, unknown>> {
  return page.evaluate(async () => {
    const got = await chrome.storage.local.get("settings");
    return (got["settings"] ?? {}) as Record<string, unknown>;
  });
}

/** Withhold or restore the extension's all-sites access through the browser's own control. */
async function setSiteAccess(ext: Extension, access: "ON_CLICK" | "ON_ALL_SITES"): Promise<void> {
  const m = await ext.context.newPage();
  await m.goto(`chrome://extensions/?id=${ext.id}`);
  const select = m.locator("extensions-runtime-host-permissions select");
  await expect(
    select.locator(`option[value="${access}"]`),
    "the browser's site-access control no longer offers the option this test drives",
  ).toHaveCount(1);
  await select.selectOption(access);
  await m.close();
}

const SETTINGS_UNREAD =
  "The extension’s own settings could not be read just now, so this step is not claiming Active Shield is on.";

const SIGNED_OUT_NOT_GRANTED = "no all-sites grant, signed out";

let net: E2ENetwork;
test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("github.com", { band: "NONE", coverage: "known-clean", label: "clean" });
});
test.afterAll(async () => {
  await net?.stop();
});

// ------------------------------------------------------------------ steps

test.describe(SIGNED_OUT_NOT_GRANTED, () => {
  let ext: Extension;
  test.beforeAll(async () => {
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });
  test.afterAll(async () => {
    await ext?.close();
  });
  test.afterEach(async () => {
    await setSettings(ext, { shield: false });
    await setKey(ext, null);
  });

  test("a fresh install shows the three steps in order with their titles, step 1 current and the counter at 0 of 3", async () => {
    const page = await openFirst(ext);
    await expect(page.locator("h1")).toHaveText("Guard is protecting you now");
    await expect(page.locator("#steps > li")).toHaveCount(3);
    await expect(page.locator("#steps > li").nth(0)).toHaveAttribute("id", "step-pin");
    await expect(page.locator("#steps > li").nth(1)).toHaveAttribute("id", "step-shield");
    await expect(page.locator("#steps > li").nth(2)).toHaveAttribute("id", "step-account");
    await expect(pin(page).locator("h2")).toHaveText("Pin Guard to your toolbar");
    await expect(shield(page).locator("h2")).toHaveText("Turn on Active Shield");
    await expect(account(page).locator("h2")).toHaveText("Create your free account");
    await expect(pin(page)).toHaveAttribute("data-state", "current");
    await expect(pin(page)).toHaveAttribute("aria-current", "step");
    await expect(shield(page)).toHaveAttribute("data-state", "todo");
    await expect(account(page)).toHaveAttribute("data-state", "todo");
    await expect(page.locator("#steps [aria-current]")).toHaveCount(1);
    await expect(count(page)).toHaveText("0 of 3");
    await expect(count(page)).toHaveAttribute("aria-live", "polite");
    await page.close();
  });

  test("each step's state is also written as text, not only drawn", async () => {
    const page = await openFirst(ext, { pin: "true" });
    await expect(pin(page).locator(".step-state")).toHaveText("Done");
    await expect(shield(page).locator(".step-state")).toHaveText("Next");
    await expect(account(page).locator(".step-state")).toHaveText("Not started");
    await account(page).locator("#btn-later").click();
    await expect(account(page).locator(".step-state")).toHaveText("Skipped");
    await page.close();
  });

  // ------------------------------------------------------------- step 1

  test("step 1: its sentence says the mark shows the verdict and, if it is not on the toolbar yet, to pin it from the puzzle-piece button", async () => {
    const page = await openFirst(ext, { pin: "false" });
    await expect(pin(page).locator(".step-text")).toHaveText(
      "The mark shows each site’s verdict at a glance. If it is not on your toolbar yet, open the puzzle-piece button and pin it.",
    );
    await page.close();
  });

  test("step 1: with the browser answering that the icon is on the toolbar, it is done, reads 'Pinned. Done.' and the counter reads 1 of 3", async () => {
    const page = await openFirst(ext, { pin: "true" });
    await expect(pin(page)).toHaveAttribute("data-state", "done");
    await expect(page.locator("#pin-result")).toHaveText("Pinned. Done.");
    await expect(count(page)).toHaveText("1 of 3");
    await expect(shield(page)).toHaveAttribute("data-state", "current");
    await expect(shield(page)).toHaveAttribute("aria-current", "step");
    await page.close();
  });

  test("step 1: not on the toolbar means not done, with no result line and no claim of a pin", async () => {
    const page = await openFirst(ext, { pin: "false" });
    await expect(page.locator("#pin-result")).toBeHidden();
    await expect(pin(page)).not.toHaveAttribute("data-state", "done");
    await expect(page.locator("#btn-pinned")).toBeHidden();
    // CONTROL: the read happened, so the silence above is an answer.
    await expect.poll(() => page.evaluate(() => (window as unknown as { __t: Probe }).__t.pinReads)).toBeGreaterThan(0);
    await page.close();
  });

  test("step 1: a pin made while the page is open is picked up on the window's focus without a reload", async () => {
    const page = await openFirst(ext, { pin: "false" });
    await expect(pin(page)).toHaveAttribute("data-state", "current");
    await setProbe(page, { pin: "true" });
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await expect(pin(page)).toHaveAttribute("data-state", "done");
    await expect(count(page)).toHaveText("1 of 3");
    await page.close();
  });

  test("step 1: a pin made while the page is open is picked up when the tab becomes visible again", async () => {
    const page = await openFirst(ext, { pin: "false" });
    await setProbe(page, { pin: "true" });
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await expect(pin(page)).toHaveAttribute("data-state", "done");
    await page.close();
  });

  test("step 1: with no event at all, a slow re-read while unpinned moves the step to done, and it stops reading once pinned", async () => {
    const page = await ext.context.newPage();
    await page.clock.install();
    await page.addInitScript(WRAP, { ...DEFAULTS, pin: "false" } satisfies Wrap);
    await page.goto(`chrome-extension://${ext.id}/firstrun.html`);
    await expect(page.locator("#steps")).toHaveAttribute("data-read", "settings");
    const reads = () => page.evaluate(() => (window as unknown as { __t: Probe }).__t.pinReads);
    await expect(pin(page)).toHaveAttribute("data-state", "current");
    const before = await reads();
    await page.clock.runFor(2_100);
    await expect.poll(reads, "an unpinned page re-reads on its own").toBeGreaterThan(before);
    await setProbe(page, { pin: "true" });
    await page.clock.runFor(2_100);
    await expect(pin(page)).toHaveAttribute("data-state", "done");
    const settled = await reads();
    await page.clock.runFor(30_000);
    expect(await reads(), "no polling once it reads pinned").toBe(settled);
    await page.close();
  });

  for (const how of ["throw", "missing"] as const) {
    test(`step 1: when the browser's pin read ${how === "throw" ? "throws" : "does not exist"}, it says so and never claims a pin`, async () => {
      const page = await openFirst(ext, { pin: how });
      await expect(page.locator("#pin-result")).toHaveText("Guard could not read whether it is pinned.");
      await expect(pin(page)).not.toHaveAttribute("data-state", "done");
      await expect(count(page)).toHaveText("0 of 3");
      await expect(page.locator("#pin-result")).not.toContainText("Pinned");
      await page.locator("#btn-pinned").click();
      await expect(pin(page)).toHaveAttribute("data-state", "done");
      await expect(count(page)).toHaveText("1 of 3");
      await expect(page.locator("#pin-result")).toHaveText("You said it is pinned. Done.");
      await expect(page.locator("#pin-result")).not.toHaveText("Pinned. Done.");
      await page.close();
    });
  }

  test("step 1: when the browser cannot answer, the page stops re-reading on its timer and still re-reads on focus", async () => {
    const page = await ext.context.newPage();
    await page.clock.install();
    await page.addInitScript(WRAP, { ...DEFAULTS, pin: "throw" } satisfies Wrap);
    await page.goto(`chrome-extension://${ext.id}/firstrun.html`);
    await expect(page.locator("#steps")).toHaveAttribute("data-read", "settings");
    await expect(page.locator("#pin-result")).toHaveText("Guard could not read whether it is pinned.");
    const reads = () => page.evaluate(() => (window as unknown as { __t: Probe }).__t.pinReads);
    const settled = await reads();
    await page.clock.runFor(30_000);
    expect(await reads(), "no timer reads while the answer is impossible").toBe(settled);
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await expect.poll(reads, "a focus still re-reads").toBeGreaterThan(settled);
    await page.close();
  });

  // ------------------------------------------------------------- step 2

  test("step 2: the click asks the browser for the permission before it sends any message", async () => {
    const page = await openFirst(ext, { request: "false" });
    await expect(shield(page).locator("#btn-shield")).toBeEnabled();
    await clearCalls(page);
    await page.locator("#btn-shield").click();
    await expect(page.locator("#shield-result")).toBeVisible();
    const order = await calls(page);
    expect(order[0], `the first thing on the click: ${order.join(", ")}`).toBe("permissions.request");
    await page.close();
  });

  test("step 2: a declined request stores nothing, leaves the counter and enables the button again, with the not-turned-on line", async () => {
    const page = await openFirst(ext, { request: "false" });
    await page.locator("#btn-shield").click();
    await expect(page.locator("#shield-result")).toHaveText(
      "Not turned on. Everything else still works. You can turn it on here or in Settings.",
    );
    expect((await storedSettings(page))["shield"] ?? false).toBe(false);
    await expect(count(page)).toHaveText("0 of 3");
    await expect(page.locator("#btn-shield")).toBeEnabled();
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    expect(await calls(page)).not.toContain("msg:setSettings");
    await page.close();
  });

  test("step 2: a request that throws stores nothing, leaves the counter and enables the button again, with the not-turned-on line", async () => {
    const page = await openFirst(ext, { request: "throw" });
    await page.locator("#btn-shield").click();
    await expect(page.locator("#shield-result")).toHaveText(
      "Not turned on. Everything else still works. You can turn it on here or in Settings.",
    );
    expect((await storedSettings(page))["shield"] ?? false).toBe(false);
    await expect(count(page)).toHaveText("0 of 3");
    await expect(page.locator("#btn-shield")).toBeEnabled();
    expect(await calls(page)).not.toContain("msg:setSettings");
    await page.close();
  });

  test("step 2: the button is disabled while the browser's answer is pending and enabled again after it", async () => {
    const page = await openFirst(ext, { request: "hold" });
    await page.locator("#btn-shield").click();
    await expect(page.locator("#btn-shield")).toBeDisabled();
    await page.evaluate(() => (window as unknown as { __t: Probe }).__t.resolveRequest(false));
    await expect(page.locator("#btn-shield")).toBeEnabled();
    await expect(page.locator("#shield-result")).toContainText("Not turned on.");
    await page.close();
  });

  test("step 2: the setting on without the all-sites grant is not drawn done", async () => {
    await setSettings(ext, { shield: true });
    const page = await openFirst(ext, { pin: "true" });
    expect(await page.evaluate(() => chrome.permissions.contains({ origins: ["<all_urls>"] }))).toBe(false);
    await expect(pin(page)).toHaveAttribute("data-state", "done");
    await expect(shield(page)).toHaveAttribute("data-state", "current");
    await expect(page.locator("#btn-shield")).toBeVisible();
    await expect(page.locator("#shield-result")).not.toContainText("Active Shield is on");
    await expect(count(page)).toHaveText("1 of 3");
    await page.close();
  });

  test("step 2: when the settings read answers not-ok, it is not drawn done and says it could not read them", async () => {
    const page = await openFirst(ext, { settings: "fail" });
    await expect(page.locator("#shield-result")).toHaveText(SETTINGS_UNREAD);
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await page.close();
  });

  test("step 2: when the settings read rejects, it is not drawn done and says it could not read them", async () => {
    const page = await openFirst(ext, { settings: "reject" });
    await expect(page.locator("#shield-result")).toHaveText(SETTINGS_UNREAD);
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await expect(count(page)).toHaveText("0 of 3");
    await page.close();
  });

  // ------------------------------------------------------------- step 3

  test("step 3: Later marks it skipped, moves the counter and leaves the sign-in button usable", async () => {
    const page = await openFirst(ext);
    await expect(count(page)).toHaveText("0 of 3");
    await page.locator("#btn-later").click();
    await expect(account(page)).toHaveAttribute("data-state", "skipped");
    await expect(count(page)).toHaveText("1 of 3");
    await expect(page.locator("#account-result")).toHaveText(
      "Skipped. You can sign in any time from the toolbar panel or Settings.",
    );
    await expect(page.locator("#btn-signin")).toBeEnabled();
    // Skipping stores nothing: no new setting, nothing read after a reload.
    await page.reload();
    await expect(account(page)).not.toHaveAttribute("data-state", "skipped");
    await page.close();
  });

  test("step 3: the sign-in button still signs in after Later, and the step and the header then read Signed in.", async () => {
    net.device.polls = 0;
    net.device.approveVisited = false;
    const page = await openFirst(ext);
    await page.locator("#btn-later").click();
    await expect(account(page)).toHaveAttribute("data-state", "skipped");
    await page.locator("#btn-signin").click();
    await expect(account(page).locator("#device-status")).toBeVisible();
    await expect.poll(() => getStoredKey(ext), { timeout: 20_000 }).toBe(MOCK_KEY);
    await expect(account(page)).toHaveAttribute("data-state", "done", { timeout: 20_000 });
    await expect(page.locator("#account-result")).toHaveText("Signed in.");
    await expect(page.locator("#cta-signed-in")).toHaveText("Signed in.");
    await expect(page.locator("#btn-create")).toBeHidden();
    await page.close();
  });

  test("the header's Create free account and Sign in start the same sign-in and report in the status line of step 3", async () => {
    for (const trigger of ["#btn-create", "#btn-signin-link"]) {
      await setKey(ext, null);
      net.device.polls = 0;
      net.device.approveVisited = false;
      const page = await openFirst(ext);
      await expect(page.locator("#device-status")).toHaveCount(1);
      await expect(account(page).locator("#device-status")).toHaveCount(1);
      await page.locator(trigger).click();
      await expect(account(page).locator("#device-status")).toBeVisible();
      await expect.poll(() => getStoredKey(ext), { timeout: 20_000 }).toBe(MOCK_KEY);
      await page.close();
    }
  });

  test("signed in: step 3 is done with Signed in. and the header block reads Signed in. in place of the two buttons", async () => {
    await setKey(ext, MOCK_KEY);
    const page = await openFirst(ext);
    await expect(account(page)).toHaveAttribute("data-state", "done");
    await expect(page.locator("#account-result")).toHaveText("Signed in.");
    await expect(page.locator("#cta-signed-in")).toHaveText("Signed in.");
    await expect(page.locator("#btn-create")).toBeHidden();
    await expect(page.locator("#btn-signin-link")).toBeHidden();
    await expect(count(page)).toHaveText("1 of 3");
    await page.close();
  });

  test("nothing on the page needs an account: the first two steps' controls work and the side cards read with no key", async () => {
    expect(await getStoredKey(ext)).toBeNull();
    const page = await openFirst(ext, { pin: "throw", request: "false" });
    await expect(page.locator("#btn-pinned")).toBeEnabled();
    await expect(page.locator("#btn-shield")).toBeEnabled();
    await expect(page.locator("#sample-chip")).toHaveText("NO KNOWN THREAT", { timeout: 15_000 });
    await expect(page.locator("#privacy")).toBeVisible();
    await page.close();
  });

  // ---------------------------------------------------------- see it work

  test("see it work: the node figure is the statistics document's node count drawn with compact, and the brand figure is the loaded corpus's count", async () => {
    const page = await openFirst(ext);
    const nodes = (net.stats["graph"] as { nodes: number }).nodes;
    await expect(page.locator("#scale-nodes")).toHaveText(compact(nodes), { timeout: 15_000 });
    await expect(page.locator("#scale-down")).toBeHidden();
    const brands = await page.evaluate(async () => {
      const res = (await chrome.runtime.sendMessage({ kind: "getSettings" })) as { corpusBrands: number };
      return res.corpusBrands;
    });
    expect(brands, "the corpus loaded and counted").toBeGreaterThan(0);
    await expect(page.locator("#brand-count")).toHaveText(brands.toLocaleString("en"));
    await expect(page.locator("#brand-down")).toBeHidden();
    await expect(page.locator("#fig-nodes .figure-cap")).toHaveText("nodes in the graph");
    await expect(page.locator("#fig-brands .figure-cap")).toHaveText("brands guarded on-device");
    await expect(page.locator("#sample-host")).toHaveText("github.com");
    await expect(page.locator("#sample-chip")).toHaveText("NO KNOWN THREAT", { timeout: 15_000 });
    // The figures this ticket drops are not on the page.
    for (const gone of ["#scale-edges", "#scale-ids", "#scale-pulse", "#sample-rail", "#active-list"]) {
      await expect(page.locator(gone)).toHaveCount(0);
    }
    await page.close();
  });

  test("see it work: when the settings read fails the page says the brand count could not be read and shows no brand number", async () => {
    const page = await openFirst(ext, { settings: "fail" });
    await expect(page.locator("#brand-down")).toHaveText("The brand count could not be read just now.");
    await expect(page.locator("#brand-count")).not.toHaveText(/\d/);
    await page.close();
  });

  test("see it work: a verdict read that rejects reads UNAVAILABLE with a reason, never stuck at CHECKING", async () => {
    const page = await openFirst(ext, { reject: ["checkHost"] });
    await expect(page.locator("#sample-chip")).toHaveText("UNAVAILABLE");
    await expect(page.locator("#sample-note")).not.toHaveText("");
    await page.close();
  });

  test("see it work: a statistics read that rejects shows the graph-size line and no node number", async () => {
    const page = await openFirst(ext, { reject: ["getScale"] });
    await expect(page.locator("#scale-down")).toBeVisible();
    await expect(page.locator("#fig-nodes")).toBeHidden();
    await page.close();
  });

  test("sign-in: a worker that stops mid-request says the sign-in did not complete, and a later click starts again", async () => {
    net.device.polls = 0;
    net.device.approveVisited = false;
    const page = await openFirst(ext, { reject: ["signInStart"] });
    await page.locator("#btn-signin").click();
    await expect(page.locator("#device-status")).toHaveText("Sign-in did not complete. Try again.");
    await setProbe(page, { reject: [] });
    await page.locator("#btn-signin").click();
    await expect.poll(() => getStoredKey(ext), { timeout: 20_000 }).toBe(MOCK_KEY);
    await expect(account(page)).toHaveAttribute("data-state", "done", { timeout: 20_000 });
    await page.close();
  });

  test("sign-in: after a sign-out elsewhere the step moves back and the old Signed in status is gone", async () => {
    net.device.polls = 0;
    net.device.approveVisited = false;
    const page = await openFirst(ext);
    await page.locator("#btn-signin").click();
    await expect(account(page)).toHaveAttribute("data-state", "done", { timeout: 20_000 });
    await expect(page.locator("#device-status")).toContainText("Signed in.");
    await setKey(ext, null);
    await expect(account(page)).not.toHaveAttribute("data-state", "done");
    await expect(page.locator("#device-status")).toBeHidden();
    await expect(page.locator("#device-status")).toHaveText("");
    await expect(page.locator("#cta-signed-in")).toBeHidden();
    await page.close();
  });

  // -------------------------------------------------------------- privacy

  test("privacy: the paragraph names the one destination the README's privacy model names, and says path", async () => {
    const readme = readFileSync(resolve(HERE, "../README.md"), "utf8");
    const section = readme.slice(readme.indexOf("## Privacy model"));
    const end = section.indexOf("\n## ", 5);
    const named = /exactly one Whisper endpoint,\s+`([^`]+)`/.exec(end > 0 ? section.slice(0, end) : section);
    expect(named, "the README's privacy model names its one browsing destination").not.toBeNull();
    const page = await openFirst(ext);
    const host = await page.locator("#privacy-host").innerText();
    expect(host).toBe(named![1]);
    const text = await page.locator("#privacy-main").innerText();
    expect(text).toMatch(/\bpath\b/);
    expect(text).toContain(`The only thing about your browsing Guard sends is a site’s name, to ${GRAPH_READ_HOST}.`);
    await expect(page.locator("#privacy-link")).toHaveAttribute("href", "https://github.com/whisper-sec/whisper-guard#privacy-model");
    await expect(page.locator("#privacy-link")).toHaveAttribute("target", "_blank");
    await expect(page.locator("#privacy-link")).toHaveAttribute("rel", /noopener/);
    await page.close();
  });

  // --------------------------------------------------------------- layout

  test("layout: at 390 px there is no sideways scroll and the steps come before the side cards", async () => {
    const page = await openFirst(ext, {}, { width: 390, height: 900 });
    const m = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      client: document.documentElement.clientWidth,
      steps: document.querySelector("#steps")!.getBoundingClientRect().top,
      side: document.querySelector("#side")!.getBoundingClientRect().top,
      cta: document.querySelector("#cta")!.getBoundingClientRect().width,
      head: document.querySelector("#head-copy")!.getBoundingClientRect().bottom,
      ctaTop: document.querySelector("#cta")!.getBoundingClientRect().top,
    }));
    expect(m.scroll).toBeLessThanOrEqual(m.client);
    expect(m.side, "the side cards sit under the steps").toBeGreaterThan(m.steps);
    expect(m.ctaTop, "the account block stacks under the heading").toBeGreaterThanOrEqual(m.head);
    await page.close();
  });

  test("layout: at 1280 px the steps and the side cards sit side by side", async () => {
    const page = await openFirst(ext, {}, { width: 1280, height: 900 });
    const m = await page.evaluate(() => {
      const s = document.querySelector("#steps")!.getBoundingClientRect();
      const o = document.querySelector("#side")!.getBoundingClientRect();
      return { stepsRight: s.right, sideLeft: o.left, stepsTop: s.top, sideTop: o.top, stepsW: s.width, sideW: o.width };
    });
    expect(m.sideLeft).toBeGreaterThanOrEqual(m.stepsRight);
    expect(Math.abs(m.sideTop - m.stepsTop)).toBeLessThan(8);
    expect(m.stepsW, "the steps take the wider column").toBeGreaterThan(m.sideW);
    await page.close();
  });
});

// ------------------------------------------------- the all-sites grant held

test.describe("all-sites grant held from install", () => {
  let ext: Extension;
  test.beforeAll(async () => {
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  });
  test.afterAll(async () => {
    await ext?.close();
  });
  test.afterEach(async () => {
    await setSettings(ext, { shield: false });
  });

  test("step 2: holding the grant with the setting off is not drawn done", async () => {
    await setSettings(ext, { shield: false });
    const page = await openFirst(ext, { pin: "true" });
    expect(await page.evaluate(() => chrome.permissions.contains({ origins: ["<all_urls>"] }))).toBe(true);
    await expect(shield(page)).toHaveAttribute("data-state", "current");
    await expect(page.locator("#btn-shield")).toBeVisible();
    await expect(count(page)).toHaveText("1 of 3");
    await page.close();
  });

  test("step 2: with the setting on and the grant held it is done, reads 'Active Shield is on.' and has no button", async () => {
    await setSettings(ext, { shield: true });
    const page = await openFirst(ext, { pin: "true" });
    await expect(shield(page)).toHaveAttribute("data-state", "done");
    await expect(page.locator("#shield-result")).toHaveText("Active Shield is on.");
    await expect(page.locator("#btn-shield")).toBeHidden();
    await expect(count(page)).toHaveText("2 of 3");
    await page.close();
  });

  test("step 2: an open page moves to done when the setting is switched on elsewhere, and back when it is switched off", async () => {
    await setSettings(ext, { shield: false });
    const page = await openFirst(ext);
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await setSettings(ext, { shield: true });
    await expect(shield(page)).toHaveAttribute("data-state", "done");
    await expect(count(page)).toHaveText("1 of 3");
    await setSettings(ext, { shield: false });
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await expect(count(page)).toHaveText("0 of 3");
    await page.close();
  });

  test("step 2: a granted request stores the setting on, then the step is done and the counter moves", async () => {
    await setSettings(ext, { shield: false });
    const page = await openFirst(ext);
    await expect(count(page)).toHaveText("0 of 3");
    await clearCalls(page);
    await page.locator("#btn-shield").click();
    await expect(shield(page)).toHaveAttribute("data-state", "done");
    await expect(page.locator("#shield-result")).toHaveText("Active Shield is on.");
    await expect(count(page)).toHaveText("1 of 3");
    expect((await storedSettings(page))["shield"]).toBe(true);
    const order = await calls(page);
    expect(order[0]).toBe("permissions.request");
    expect(order.indexOf("msg:setSettings")).toBeGreaterThan(0);
    await page.close();
  });

  test("step 2: a request that resolves false while the grant is held still stores nothing", async () => {
    await setSettings(ext, { shield: false });
    const page = await openFirst(ext, { request: "false" });
    await page.locator("#btn-shield").click();
    await expect(page.locator("#shield-result")).toContainText("Not turned on.");
    expect((await storedSettings(page))["shield"] ?? false).toBe(false);
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await page.close();
  });
});

test.describe("all-sites grant withdrawn while the page is open", () => {
  let ext: Extension;
  test.beforeAll(async () => {
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  });
  test.afterAll(async () => {
    await ext?.close();
  });
  test.beforeEach(async () => {
    await setSiteAccess(ext, "ON_ALL_SITES");
    await setSettings(ext, { shield: true, nearMiss: false });
  });
  test.afterEach(async () => {
    await setSiteAccess(ext, "ON_ALL_SITES");
  });

  test("step 2 moves back from done and the counter goes down, without a reload", async () => {
    const page = await openFirst(ext, { pin: "true" });
    await expect(shield(page)).toHaveAttribute("data-state", "done");
    await expect(count(page)).toHaveText("2 of 3");
    await setSiteAccess(ext, "ON_CLICK");
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await expect(shield(page)).toHaveAttribute("data-state", "current");
    await expect(page.locator("#btn-shield")).toBeVisible();
    await expect(count(page)).toHaveText("1 of 3");
    await page.close();
  });

  test("step 2: a slow earlier read cannot put it back to done after the grant is gone", async () => {
    const page = await openFirst(ext, { pin: "true" });
    await expect(shield(page)).toHaveAttribute("data-state", "done");
    await page.evaluate(() => void ((window as unknown as { __t: Probe }).__t.hold = true));
    // Read 1: started while granted, answered "granted", then held.
    await setSettings(ext, { nearMiss: true });
    await expect.poll(() => page.evaluate(() => (window as unknown as { __t: Probe }).__t.held)).toBe(1);
    // Read 2: the grant is withdrawn and the page draws the newer state.
    await setSiteAccess(ext, "ON_CLICK");
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    expect(await page.evaluate(() => chrome.permissions.contains({ origins: ["<all_urls>"] }))).toBe(false);
    await page.evaluate(() => (window as unknown as { __t: Probe }).__t.release());
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await expect(count(page)).toHaveText("1 of 3");
    await page.close();
  });

  test("step 2: when the settings read rejects after the grant is withdrawn, it is not done and says the settings could not be read", async () => {
    const page = await openFirst(ext, { pin: "true" });
    await expect(shield(page)).toHaveAttribute("data-state", "done");
    await setProbe(page, { settings: "reject" });
    await setSiteAccess(ext, "ON_CLICK");
    await expect(page.locator("#shield-result")).toHaveText(SETTINGS_UNREAD);
    await expect(shield(page)).not.toHaveAttribute("data-state", "done");
    await expect(count(page)).toHaveText("1 of 3");
    await page.close();
  });
});

// ------------------------------------------------------ reads that fail

test.describe("the graph and its statistics are down", () => {
  let ext: Extension;
  let down: E2ENetwork;
  test.beforeAll(async () => {
    down = new E2ENetwork();
    await down.start();
    down.graphMode = "down";
    down.statsDown = true;
    ext = await launchExtension({ proxyPort: down.proxyPort });
  });
  test.afterAll(async () => {
    await ext?.close();
    await down?.stop();
  });

  test("see it work: a failed verdict read shows UNAVAILABLE with its reason, and a failed statistics read says so and shows no node number", async () => {
    const page = await openFirst(ext);
    await expect(page.locator("#sample-chip")).toHaveText("UNAVAILABLE", { timeout: 15_000 });
    await expect(page.locator("#sample-note")).not.toHaveText("");
    await expect(page.locator("#scale-down")).toBeVisible();
    await expect(page.locator("#scale-down")).toHaveText("The graph’s size could not be read just now.");
    await expect(page.locator("#scale-nodes")).toBeHidden();
    await expect(page.locator("#scale-nodes")).not.toHaveText(/\d/);
    // The brand count is read off the device, so the outage does not touch it.
    await expect(page.locator("#brand-count")).toHaveText(/^\d[\d,]*$/);
    await page.close();
  });
});
