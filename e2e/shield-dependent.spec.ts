// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The credential-field guard and the in-page banner cannot run until Active
// Shield is on (the setting AND the all-sites grant). Settings may not draw
// them on before then, and the stored preference must survive. The cookie
// decline runs without Active Shield, but only on a tab where Guard is opened,
// so Settings says where it can run. The first-run page's Active Shield step
// reads the same two-part gate and is covered in firstrun.spec.ts. The grant
// arrives install-time via makeShieldDist; the default dist holds no grant.
//
// Taking the grant away while a page is open is done for real: a required host
// permission cannot be removed with permissions.remove, but the browser's own
// site-access control for the extension can withhold it, which changes what
// permissions.contains answers and fires permissions.onRemoved. The tests
// drive that control on the extensions page. Only the timing tests add a
// wrapper in front of the page (see HOLD below), and it forwards to the real
// permissions API; the page's own code runs unmodified.

import { test, expect, type Page } from "@playwright/test";
import { launchExtension, makeShieldDist, setSettings, type Extension } from "./helpers/extension";

async function open(ext: Extension, file: string): Promise<Page> {
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/${file}`);
  return page;
}

/** Withhold or restore the extension's all-sites access through the browser's own control. */
async function setSiteAccess(ext: Extension, access: "ON_CLICK" | "ON_ALL_SITES"): Promise<void> {
  const m = await ext.context.newPage();
  await m.goto(`chrome://extensions/?id=${ext.id}`);
  const select = m.locator("extensions-runtime-host-permissions select");
  // The details view is drawn after the page loads, so wait for the option.
  await expect(
    select.locator(`option[value="${access}"]`),
    "the browser's site-access control no longer offers the option this test drives",
  ).toHaveCount(1);
  await select.selectOption(access);
  await m.close();
}

const granted = (page: Page) =>
  page.evaluate(() => chrome.permissions.contains({ origins: ["<all_urls>"] }));

/**
 * HOLD: wraps the page's permissions.contains and runtime.sendMessage before
 * its scripts run. With `hold` set, the NEXT contains call reads the real
 * answer at once and then waits for release() before returning it: a read
 * that started earlier and finishes last. With `failSettings` set, the
 * settings read reports failure (`rejectSettings`: the call rejects, as when
 * the worker stops mid-request). Everything else is forwarded untouched.
 */
const HOLD = () => {
  const g = { hold: false, held: 0, failSettings: false, rejectSettings: false, release: () => undefined as void };
  (window as unknown as { __gate: typeof g }).__gate = g;
  const realContains = chrome.permissions.contains.bind(chrome.permissions);
  (chrome.permissions as { contains: unknown }).contains = async (q: chrome.permissions.Permissions) => {
    if (!g.hold) return realContains(q);
    g.hold = false;
    const value = await realContains(q);
    await new Promise<void>((res) => {
      g.release = res as () => void;
      g.held++;
    });
    return value;
  };
  const realSend = chrome.runtime.sendMessage.bind(chrome.runtime) as (...a: unknown[]) => unknown;
  (chrome.runtime as { sendMessage: unknown }).sendMessage = (m: { kind?: string }, ...rest: unknown[]) => {
    if (m?.kind === "getSettings" && g.rejectSettings) return Promise.reject(new Error("the worker stopped mid-request"));
    if (m?.kind === "getSettings" && g.failSettings) return Promise.resolve({ ok: false });
    return realSend(m, ...rest);
  };
};

async function openHeld(ext: Extension, file: string): Promise<Page> {
  const page = await ext.context.newPage();
  await page.addInitScript(HOLD);
  await page.goto(`chrome-extension://${ext.id}/${file}`);
  return page;
}

const gate = (page: Page) => ({
  arm: () => page.evaluate(() => void ((window as any).__gate.hold = true)),
  held: () => page.evaluate(() => (window as any).__gate.held as number),
  release: () => page.evaluate(() => (window as any).__gate.release()),
  failSettings: () => page.evaluate(() => void ((window as any).__gate.failSettings = true)),
  rejectSettings: () => page.evaluate(() => void ((window as any).__gate.rejectSettings = true)),
});

/** Let the microtasks and the next frame of the page run: a late render has had its chance. */
const settled = (page: Page) =>
  page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));

// Read through the background's own reader, from an extension page: a fresh
// profile has no stored record yet, so the defaults are the preference.
async function stored(page: Page): Promise<Record<string, unknown>> {
  return page.evaluate(async () => {
    const res = (await chrome.runtime.sendMessage({ kind: "getSettings" })) as { settings: Record<string, unknown> };
    return res.settings;
  });
}

test.describe("no all-sites grant", () => {
  let ext: Extension;
  test.beforeAll(async () => {
    ext = await launchExtension();
  });
  test.afterAll(async () => {
    await ext?.close();
  });
  test.afterEach(async () => {
    await setSettings(ext, { shield: false });
  });

  test("settings: banner and field-guard sub-toggles are unchecked, disabled and say 'needs Active Shield' without the grant", async () => {
    const page = await open(ext, "options.html");
    for (const [id, note] of [
      ["#opt-banner", "#banner-needs"],
      ["#opt-fieldguard", "#fieldguard-needs"],
    ] as const) {
      await expect(page.locator(id)).not.toBeChecked();
      await expect(page.locator(id)).toBeDisabled();
      await expect(page.locator(note)).toBeVisible();
      await expect(page.locator(note)).toHaveText(/needs Active Shield/i);
    }
    const s = await stored(page);
    expect(s["amberBanner"]).toBe(true);
    expect(s["fieldGuard"]).toBe(true);
    await page.close();
  });

  test("cookie decline: on a fresh profile settings says it runs only on a tab where Guard is opened", async () => {
    // Nothing is stored yet: the defaults are what a new install shows.
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-cookiedecline")).toBeChecked();
    await expect(opts.locator("#opt-cookiedecline")).toBeEnabled();
    await expect(opts.locator("#opt-cookiedecline")).toHaveAttribute("aria-describedby", "cookiedecline-reach");
    await expect(opts.locator("#cookiedecline-reach")).toBeVisible();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText(/only on a tab where you open Guard/i);
    await opts.close();
  });

  test("cookie decline: switched off it reads off in settings", async () => {
    await setSettings(ext, { cookieDecline: false });
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-cookiedecline")).not.toBeChecked();
    await expect(opts.locator("#cookiedecline-reach")).toBeAttached();
    await expect(opts.locator("#cookiedecline-reach")).toBeHidden();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText("");
    await opts.close();
    await setSettings(ext, { cookieDecline: true });
  });

  test("Active Shield set on without the grant: settings reads the switch and both protections as not on", async () => {
    await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true });
    const probe = await open(ext, "options.html");
    expect(await granted(probe)).toBe(false);
    await probe.close();
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-shield")).not.toBeChecked();
    for (const id of ["#opt-banner", "#opt-fieldguard"]) {
      await expect(opts.locator(id)).not.toBeChecked();
      await expect(opts.locator(id)).toBeDisabled();
    }
    const s = await stored(opts);
    expect(s["shield"]).toBe(true);
    expect(s["amberBanner"]).toBe(true);
    expect(s["fieldGuard"]).toBe(true);
    await opts.close();
  });
});

test.describe("all-sites grant held", () => {
  let ext: Extension;
  test.beforeAll(async () => {
    ext = await launchExtension({ dist: makeShieldDist() });
  });
  test.afterAll(async () => {
    await ext?.close();
  });

  test("settings: holding the grant with Active Shield switched off still reads 'needs Active Shield'", async () => {
    await setSettings(ext, { shield: false });
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-shield")).not.toBeChecked();
    await expect(opts.locator("#opt-banner")).toBeDisabled();
    await expect(opts.locator("#opt-fieldguard")).not.toBeChecked();
    await opts.close();
  });

  test("settings: with Active Shield on and granted, field guard and banner read on", async () => {
    await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true });
    const opts = await open(ext, "options.html");
    for (const [id, note] of [
      ["#opt-banner", "#banner-needs"],
      ["#opt-fieldguard", "#fieldguard-needs"],
    ] as const) {
      await expect(opts.locator(id)).toBeChecked();
      await expect(opts.locator(id)).toBeEnabled();
      await expect(opts.locator(note)).toBeHidden();
    }
    await opts.close();
  });

  test("settings: switching Active Shield on enables the two sub-toggles without a reload", async () => {
    await setSettings(ext, { shield: false });
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-banner")).toBeDisabled();
    await opts.locator("#opt-shield").check();
    await expect(opts.locator("#opt-banner")).toBeEnabled();
    await expect(opts.locator("#opt-banner")).toBeChecked();
    await expect(opts.locator("#opt-fieldguard")).toBeEnabled();
    await expect(opts.locator("#banner-needs")).toBeHidden();
    await opts.close();
  });

  test("settings: cookie decline with the grant held and Active Shield off reads as only on a tab where Guard is opened", async () => {
    await setSettings(ext, { shield: false, cookieDecline: true });
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-cookiedecline")).toBeChecked();
    await expect(opts.locator("#opt-cookiedecline")).toBeEnabled();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText(/only on a tab where you open Guard/i);
    await opts.close();
  });

  test("settings: cookie decline with Active Shield on and granted reads as running on every page", async () => {
    await setSettings(ext, { shield: true, cookieDecline: true });
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-cookiedecline")).toBeChecked();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText("Runs on every page.");
    await opts.close();
  });

  test("settings: with the cookie decline off it reads off and shows no reach note, even when Active Shield is on and granted", async () => {
    await setSettings(ext, { shield: true, cookieDecline: false });
    const opts = await open(ext, "options.html");
    // Only the settings read can draw this: the switch is unchecked on first paint.
    await expect(opts.locator("#opt-shield")).toBeChecked();
    await expect(opts.locator("#opt-cookiedecline")).not.toBeChecked();
    await expect(opts.locator("#cookiedecline-reach")).toBeHidden();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText("");
    await opts.close();
    await setSettings(ext, { cookieDecline: true });
  });

  test("settings: the cookie decline note updates without a reload when Active Shield is switched on", async () => {
    await setSettings(ext, { shield: false, cookieDecline: true });
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#cookiedecline-reach")).toHaveText(/only on a tab where you open Guard/i);
    await opts.locator("#opt-shield").check();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText("Runs on every page.");
    await expect(opts.locator("#opt-cookiedecline")).toBeChecked();
    await opts.close();
  });

});

test.describe("all-sites grant withdrawn while a page is open", () => {
  let ext: Extension;
  test.beforeAll(async () => {
    ext = await launchExtension({ dist: makeShieldDist() });
  });
  test.afterAll(async () => {
    await ext?.close();
  });
  test.beforeEach(async () => {
    await setSiteAccess(ext, "ON_ALL_SITES");
    await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true, cookieDecline: true, nearMiss: false });
  });
  test.afterEach(async () => {
    await setSiteAccess(ext, "ON_ALL_SITES");
  });

  test("settings: both sub-toggles and the cookie decline note flip back without a reload", async () => {
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-shield")).toBeChecked();
    await expect(opts.locator("#opt-banner")).toBeChecked();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText("Runs on every page.");
    await setSiteAccess(ext, "ON_CLICK");
    await expect(opts.locator("#opt-shield")).not.toBeChecked();
    for (const [id, note] of [
      ["#opt-banner", "#banner-needs"],
      ["#opt-fieldguard", "#fieldguard-needs"],
    ] as const) {
      await expect(opts.locator(id)).not.toBeChecked();
      await expect(opts.locator(id)).toBeDisabled();
      await expect(opts.locator(note)).toHaveText(/needs Active Shield/i);
    }
    await expect(opts.locator("#cookiedecline-reach")).toHaveText(/only on a tab where you open Guard/i);
    const s = await stored(opts);
    expect(s["amberBanner"]).toBe(true);
    expect(s["fieldGuard"]).toBe(true);
    await opts.close();
  });

  test("settings: a slow earlier read cannot put the protections back on after the grant is gone", async () => {
    const opts = await openHeld(ext, "options.html");
    const g = gate(opts);
    await expect(opts.locator("#opt-banner")).toBeChecked();
    await g.arm();
    await setSettings(ext, { nearMiss: true });
    await expect.poll(g.held).toBe(1);
    await setSiteAccess(ext, "ON_CLICK");
    await expect(opts.locator("#opt-banner")).toBeDisabled();
    await g.release();
    await settled(opts);
    await expect(opts.locator("#opt-shield")).not.toBeChecked();
    await expect(opts.locator("#opt-banner")).toBeDisabled();
    await expect(opts.locator("#opt-banner")).not.toBeChecked();
    await expect(opts.locator("#banner-needs")).toBeVisible();
    await opts.close();
  });

  test("settings: when the settings cannot be read, the missing grant alone draws the protections as not on", async () => {
    const opts = await openHeld(ext, "options.html");
    await expect(opts.locator("#opt-banner")).toBeChecked();
    await gate(opts).failSettings();
    await setSiteAccess(ext, "ON_CLICK");
    await expect(opts.locator("#opt-shield")).not.toBeChecked();
    for (const id of ["#opt-banner", "#opt-fieldguard"]) {
      await expect(opts.locator(id)).not.toBeChecked();
      await expect(opts.locator(id)).toBeDisabled();
    }
    await expect(opts.locator("#banner-needs")).toBeVisible();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText(/only on a tab where you open Guard/i);
    await opts.close();
  });

  test("settings: when the settings read rejects, the missing grant alone draws the protections and the cookie note as not on", async () => {
    const opts = await openHeld(ext, "options.html");
    await expect(opts.locator("#opt-banner")).toBeChecked();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText("Runs on every page.");
    await gate(opts).rejectSettings();
    await setSiteAccess(ext, "ON_CLICK");
    await expect(opts.locator("#opt-shield")).not.toBeChecked();
    for (const id of ["#opt-banner", "#opt-fieldguard"]) {
      await expect(opts.locator(id)).not.toBeChecked();
      await expect(opts.locator(id)).toBeDisabled();
    }
    await expect(opts.locator("#banner-needs")).toBeVisible();
    await expect(opts.locator("#fieldguard-needs")).toBeVisible();
    await expect(opts.locator("#cookiedecline-reach")).toHaveText(/only on a tab where you open Guard/i);
    await opts.close();
  });

  test("settings: switching Active Shield on and off never changes the stored banner and field-guard preferences", async () => {
    await setSettings(ext, { shield: false, amberBanner: true, fieldGuard: true });
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-banner")).toBeDisabled();
    await opts.locator("#opt-shield").check();
    await expect(opts.locator("#opt-banner")).toBeEnabled();
    let s = await stored(opts);
    expect(s["shield"]).toBe(true);
    expect(s["amberBanner"]).toBe(true);
    expect(s["fieldGuard"]).toBe(true);
    await opts.locator("#opt-shield").uncheck();
    await expect(opts.locator("#opt-banner")).toBeDisabled();
    s = await stored(opts);
    expect(s["shield"]).toBe(false);
    expect(s["amberBanner"]).toBe(true);
    expect(s["fieldGuard"]).toBe(true);
    await opts.close();
  });
});
