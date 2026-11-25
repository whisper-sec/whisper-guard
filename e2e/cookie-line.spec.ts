// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE COOKIE LINE ON THIS PAGE. When Guard declined a cookie prompt on the
// page a tab is showing, This page says so in one line. The worker keeps one
// record per tab for it: the tab's id and the value true, no host and no URL.
// The record is dropped when the tab commits a new page, and the popup shows the
// line only while the record is exactly true.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import { launchExtension, makeShieldDist, openPopup, setSettings, visit, waitForIcon, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

// Hostnames carry no consent-ish word: the wire sweep in the consent spec
// searches for such words, and a fixture name that has one would fail it.
const SITE = {
  banner: "site-a-fx-guard-e2e.com",
  none: "site-b-fx-guard-e2e.com",
  plain: "site-c-fx-guard-e2e.com",
  late: "site-d-fx-guard-e2e.com",
};

const LINE = "Cookie prompt on this page declined for you.";

/** Every button records its click in-page; the module must pick exactly one. */
const RECORDER = `<script>
  window.__clicks = [];
  addEventListener("click", (ev) => {
    const b = ev.target && ev.target.closest ? ev.target.closest("button,[role='button'],input") : null;
    if (b) window.__clicks.push(b.id || b.className || b.tagName);
  }, true);
</script>`;

const GENERIC_BANNER = `
<div class="cookie-notice-banner" id="cn" style="position:fixed;bottom:0;left:0;right:0;background:#ddd;padding:16px">
  This site uses cookies for analytics and ads.
  <button id="btn-settings">Manage preferences</button>
  <button id="btn-accept">Accept all</button>
  <button id="btn-reject">Reject all</button>
</div>`;

const bannerHtml = `<!doctype html><html><head><title>a</title></head><body><h1>site a</h1>${RECORDER}${GENERIC_BANNER}
<script>
  document.getElementById("btn-reject").addEventListener("click", () => {
    document.getElementById("cn").style.display = "none";
  });
</script></body></html>`;

const plainHtml = (title: string): string =>
  `<!doctype html><html><head><title>${title}</title></head><body><h1>${title}</h1>${RECORDER}</body></html>`;

const PREFIX = "cookieDeclined:";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const host of Object.values(SITE)) net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage(SITE.banner, bannerHtml);
  net.setPage(SITE.none, plainHtml("b"));
  net.setPage(SITE.plain, plainHtml("c"));
  net.setPage(SITE.late, plainHtml("d"));
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setSettings(ext, { shield: true, amberBanner: false, fieldGuard: false, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function clicks(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __clicks?: string[] }).__clicks ?? []);
}

async function waitConsentArmed(tabId: number): Promise<void> {
  await expect
    .poll(
      async () =>
        ext.sw.evaluate(async (id: number) => {
          try {
            const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as { consent?: boolean } | undefined;
            return r?.consent === true;
          } catch {
            return false;
          }
        }, tabId),
      { timeout: 15_000 },
    )
    .toBe(true);
}

/** The worker's records of a declined prompt, by key. */
async function records(): Promise<Record<string, unknown>> {
  return ext.sw.evaluate(async (prefix: string) => {
    const all = await chrome.storage.session.get(null);
    return Object.fromEntries(Object.entries(all).filter(([k]) => k.startsWith(prefix)));
  }, PREFIX);
}

async function declineOnBannerPage(): Promise<{ page: Page; tabId: number }> {
  const { page, tabId } = await visit(ext, `https://${SITE.banner}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);
  await expect.poll(() => clicks(page), { timeout: 10_000 }).toEqual(["btn-reject"]);
  return { page, tabId };
}

// ------------------------------------------------------------------------ C1

test("the cookie line shows once Guard declined a prompt on the page, and its record names only the tab", async () => {
  const { page, tabId } = await declineOnBannerPage();
  await expect.poll(records, { timeout: 10_000 }).toEqual({ [`${PREFIX}${tabId}`]: true });

  const popup = await openPopup(ext, tabId, { section: "page" });
  await expect(popup.locator("#cookie-line")).toBeVisible();
  await expect(popup.locator("#cookie-line")).toHaveText(LINE);
  const below = await popup.evaluate(() => {
    const card = document.getElementById("iocscan-card")!.getBoundingClientRect();
    const line = document.getElementById("cookie-line")!.getBoundingClientRect();
    return line.top >= card.bottom;
  });
  expect(below, "the cookie line sits below the indicator card").toBe(true);
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ C1b

test("a reload of the same address, where the prompt is declined again, is recorded again", async () => {
  const { page, tabId } = await declineOnBannerPage();
  await expect.poll(records, { timeout: 10_000 }).toEqual({ [`${PREFIX}${tabId}`]: true });

  // The reload commits a new page, which drops the record; the banner comes back and is declined
  // again. The day's tally counts that page once, but the tab is on a page where a prompt was declined.
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect.poll(() => clicks(page), { timeout: 15_000 }).toEqual(["btn-reject"]);
  await expect.poll(records, { timeout: 10_000 }).toEqual({ [`${PREFIX}${tabId}`]: true });

  const popup = await openPopup(ext, tabId, { section: "page" });
  await expect(popup.locator("#cookie-line")).toBeVisible();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ C2

test("no cookie line on a page where nothing was declined", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.none}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);
  expect(Object.keys(await records())).not.toContain(`${PREFIX}${tabId}`);

  const popup = await openPopup(ext, tabId, { section: "page" });
  await expect(popup.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });
  await expect(popup.locator("#cookie-line")).toHaveCount(1);
  await expect(popup.locator("#cookie-line")).toBeHidden();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ C3

test("a new page in the same tab drops the cookie line", async () => {
  const { page, tabId } = await declineOnBannerPage();
  // Control: the record is there before the tab moves on.
  await expect.poll(records, { timeout: 10_000 }).toEqual({ [`${PREFIX}${tabId}`]: true });

  await page.goto(`https://${SITE.plain}/`, { waitUntil: "domcontentloaded" });
  await expect.poll(async () => Object.keys(await records()), { timeout: 10_000 }).toEqual([]);

  const popup = await openPopup(ext, tabId, { section: "page" });
  await expect(popup.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });
  await expect(popup.locator("#cookie-line")).toHaveCount(1);
  await expect(popup.locator("#cookie-line")).toBeHidden();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ C4

test("a prompt declined while the popup is open brings the line in without reopening", async () => {
  await setSettings(ext, { shield: false });
  try {
    const { page, tabId } = await visit(ext, `https://${SITE.late}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    expect(Object.keys(await records())).not.toContain(`${PREFIX}${tabId}`);

    // Without Active Shield, opening the popup is what arms the page.
    const popup = await openPopup(ext, tabId, { section: "page" });
    await waitConsentArmed(tabId);
    await expect(popup.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });
    await expect(popup.locator("#cookie-line")).toHaveCount(1);
    await expect(popup.locator("#cookie-line")).toBeHidden();

    await page.evaluate((html: string) => {
      const mount = document.createElement("div");
      mount.innerHTML = html;
      document.body.appendChild(mount);
    }, GENERIC_BANNER);
    await expect.poll(() => clicks(page), { timeout: 10_000 }).toEqual(["btn-reject"]);
    await expect(popup.locator("#cookie-line")).toBeVisible({ timeout: 10_000 });
    await expect(popup.locator("#cookie-line")).toHaveText(LINE);
    await popup.close();
    await page.close();
  } finally {
    await setSettings(ext, { shield: true });
  }
});

// ------------------------------------------------------------------------ C7

test("with the live check off the cookie line is not shown, though the record is kept", async () => {
  const { page, tabId } = await declineOnBannerPage();
  await expect.poll(records, { timeout: 10_000 }).toEqual({ [`${PREFIX}${tabId}`]: true });
  await setSettings(ext, { cloudCheck: false });
  try {
    const popup = await openPopup(ext, tabId, { section: "page" });
    await expect(popup.locator("#page-empty")).toBeVisible({ timeout: 10_000 });
    await expect(popup.locator("#cookie-line")).toHaveCount(1);
    await expect(popup.locator("#cookie-line")).toBeHidden();
    // With no link check to describe, the footer says only what was sent: nothing.
    await expect(popup.locator("#privacy-line")).toContainText("nothing was sent");
    await popup.close();
  } finally {
    await setSettings(ext, { cloudCheck: true });
  }
  await page.close();
});
