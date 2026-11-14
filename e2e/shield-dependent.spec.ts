// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The credential-field guard and the in-page banner cannot run until Active
// Shield is on (the setting AND the all-sites grant). Neither the first-run
// page nor Settings may draw them on before then, and the stored preference
// must survive. The grant arrives install-time via makeShieldDist; the
// default dist holds no grant.

import { test, expect, type Page } from "@playwright/test";
import { launchExtension, makeShieldDist, setSettings, type Extension } from "./helpers/extension";

async function open(ext: Extension, file: string): Promise<Page> {
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/${file}`);
  return page;
}

const row = (page: Page, key: string) => page.locator(`.active-row[data-key=${key}]`);

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

  test("first run: field guard and banner read 'needs Active Shield' when no all-sites grant is held", async () => {
    const page = await open(ext, "firstrun.html");
    // CONTROL: a row that does not depend on Active Shield reads on, so the list rendered.
    await expect(page.locator(".active-row", { hasText: "Look-alike detector" })).toHaveAttribute("data-state", "on");
    for (const key of ["fieldGuard", "amberBanner"]) {
      await expect(row(page, key)).toHaveAttribute("data-state", "needs-shield");
      await expect(row(page, key)).toContainText(/needs Active Shield/i);
      await expect(row(page, key).locator("svg title")).toHaveText("needs Active Shield");
    }
    await page.close();
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
});

test.describe("all-sites grant held", () => {
  let ext: Extension;
  test.beforeAll(async () => {
    ext = await launchExtension({ dist: makeShieldDist() });
  });
  test.afterAll(async () => {
    await ext?.close();
  });

  test("first run and settings: holding the grant with Active Shield switched off still reads 'needs Active Shield'", async () => {
    await setSettings(ext, { shield: false });
    const first = await open(ext, "firstrun.html");
    for (const key of ["fieldGuard", "amberBanner"]) {
      await expect(row(first, key)).toHaveAttribute("data-state", "needs-shield");
    }
    await first.close();
    const opts = await open(ext, "options.html");
    await expect(opts.locator("#opt-shield")).not.toBeChecked();
    await expect(opts.locator("#opt-banner")).toBeDisabled();
    await expect(opts.locator("#opt-fieldguard")).not.toBeChecked();
    await opts.close();
  });

  test("first run and settings: with Active Shield on and granted, field guard and banner read on", async () => {
    await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true });
    const first = await open(ext, "firstrun.html");
    for (const key of ["fieldGuard", "amberBanner"]) {
      await expect(row(first, key)).toHaveAttribute("data-state", "on");
    }
    await first.close();
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

  test("first run: an open page flips to on when Active Shield is switched on", async () => {
    await setSettings(ext, { shield: false });
    const first = await open(ext, "firstrun.html");
    await expect(row(first, "fieldGuard")).toHaveAttribute("data-state", "needs-shield");
    await setSettings(ext, { shield: true });
    await expect(row(first, "fieldGuard")).toHaveAttribute("data-state", "on");
    await expect(row(first, "amberBanner")).toHaveAttribute("data-state", "on");
    await first.close();
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
});
