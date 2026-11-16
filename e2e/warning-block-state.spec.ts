// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The warning page states a block, and acts on one, only for a host Guard
// stopped. Opened for any other host (as a tab, as a new window, by
// navigation) it says no block is in effect, keeps Continue disabled and reads
// no evidence; and `allowHost` from it for such a host gets an error answer
// and changes nothing. For a host Guard did stop the page is unchanged on both
// paths, and it takes its brand from the background, not from its address.
//
// Each "reads nothing" assertion is paired with a positive control: the page
// for a host Guard really stopped does read its evidence.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  DIST_CHROMIUM,
  launchExtension,
  makeShieldDist,
  markHostBlocked,
  openPopup,
  setKey,
  setSettings,
  visit,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const MALICIOUS = { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" } as const;
const CLEAN = { band: "NONE", coverage: "known-clean", label: "clean" } as const;

type Answer = { ok?: boolean; error?: string; [k: string]: unknown } | undefined;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, MOCK_KEY);
  await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

const warningUrl = (query: string) => `chrome-extension://${ext.id}/warning.html?${query}`;

async function sessionAllowList(): Promise<string[]> {
  return ext.sw.evaluate(async () => {
    const v = (await chrome.storage.session.get("allowed"))["allowed"];
    return Array.isArray(v) ? (v as string[]) : [];
  });
}

async function sessionBlockList(): Promise<string[]> {
  return ext.sw.evaluate(async () => {
    const v = (await chrome.storage.session.get("blocked"))["blocked"];
    return Array.isArray(v) ? (v as string[]) : [];
  });
}

async function permanentAllowList(): Promise<string[]> {
  return ext.sw.evaluate(async () => {
    const s = (await chrome.storage.local.get("settings"))["settings"] as { allowlist?: string[] } | undefined;
    return s?.allowlist ?? [];
  });
}

function readsNaming(host: string): number {
  return net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes(host)).length;
}

/** Let Guard really stop a host: the tab reaches the warning page. */
async function stopHost(host: string): Promise<Page> {
  net.setVerdict(host, MALICIOUS);
  const page = await ext.context.newPage();
  await page.goto(`https://${host}/`, { waitUntil: "commit" });
  await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
  await expect(page.locator("main")).toHaveAttribute("data-state", "stopped");
  return page;
}

async function expectNoBlockState(page: Page, host: string): Promise<void> {
  await expect(page.locator("main")).toHaveAttribute("data-state", "no-block");
  await expect(page.locator("h1")).toHaveText("No block is in effect for this address.");
  await expect(page.locator("#detail")).toHaveText(
    `Whisper Guard is not blocking ${host}, so there is nothing here to continue past. This says nothing about whether the address is safe.`,
  );
  await expect(page.locator("#btn-continue")).toBeDisabled();
  await expect(page.locator("#evidence")).toBeHidden();
  await expect(page.locator("#btn-real")).toBeHidden();
  await expect(page.locator("#btn-back")).toHaveText("← Go back");
}

test("should say no block is in effect for a host Guard did not stop, however the page was reached", async () => {
  const direct = "wbs-direct-guard-e2e.com";
  const opened = "wbs-opened-guard-e2e.com";
  const moved = "wbs-moved-guard-e2e.com";
  const control = "wbs-control-guard-e2e.com";
  const source = "wbs-source-guard-e2e.com";
  for (const h of [direct, opened, moved]) net.setVerdict(h, MALICIOUS);
  net.setVerdict(source, CLEAN);
  const sessionBefore = await sessionAllowList();
  const permanentBefore = await permanentAllowList();
  const open: Page[] = [];
  try {
    // 1) directly, as a tab
    const tab = await ext.context.newPage();
    open.push(tab);
    await tab.goto(warningUrl(`host=${direct}`));
    await expectNoBlockState(tab, direct);

    // 2) as a new window
    const { page: web } = await visit(ext, `https://${source}/`);
    open.push(web);
    const popupPromise = web.waitForEvent("popup");
    await web.evaluate((u) => {
      window.open(u, "_blank", "width=420,height=600");
    }, warningUrl(`host=${opened}`));
    const popup = await popupPromise;
    open.push(popup);
    await expectNoBlockState(popup, opened);

    // 3) by navigation
    const { page: mover } = await visit(ext, `https://${source}/`);
    open.push(mover);
    await mover.evaluate((u) => {
      window.location.href = u;
    }, warningUrl(`host=${moved}`));
    await mover.waitForURL((u) => u.href.includes("warning.html"));
    await expectNoBlockState(mover, moved);

    // Positive control: the page for a host Guard really stopped reads its
    // evidence. Its evidence box shows only once both reads have answered, and
    // those reads were sent after every page above had loaded.
    const stopped = await stopHost(control);
    open.push(stopped);
    await expect(stopped.locator("#evidence")).toBeVisible();
    expect(readsNaming(control), "the stopped page's evidence reads").toBeGreaterThan(0);

    for (const h of [direct, opened, moved]) expect(readsNaming(h), `reads naming ${h}`).toBe(0);
    expect(await sessionAllowList()).toEqual(sessionBefore);
    expect(await permanentAllowList()).toEqual(permanentBefore);
  } finally {
    for (const p of open) await p.close().catch(() => undefined);
  }
});

test("should refuse allowHost from the warning page for a host Guard did not stop", async () => {
  const host = "wbs-refuse-guard-e2e.com";
  const stoppedHost = "wbs-refuse-stopped-guard-e2e.com";
  net.setVerdict(host, MALICIOUS);
  const tab = await ext.context.newPage();
  let stopped: Page | undefined;
  try {
    await tab.goto(warningUrl(`host=${host}`));
    const sessionBefore = await sessionAllowList();
    const permanentBefore = await permanentAllowList();

    for (const session of [true, false]) {
      const answer = (await tab.evaluate(
        ([h, s]) => chrome.runtime.sendMessage({ kind: "allowHost", host: h, session: s }),
        [host, session] as [string, boolean],
      )) as Answer;
      expect(answer?.ok, `allowHost session=${String(session)}`).toBe(false);
      expect(typeof answer?.error).toBe("string");
    }
    expect(await sessionAllowList()).toEqual(sessionBefore);
    expect(await sessionAllowList()).not.toContain(host);
    expect(await permanentAllowList()).toEqual(permanentBefore);
    expect(await permanentAllowList()).not.toContain(host);

    // Positive control: for a host Guard stopped, the same request from its warning page is taken.
    stopped = await stopHost(stoppedHost);
    const taken = (await stopped.evaluate(
      (h) => chrome.runtime.sendMessage({ kind: "allowHost", host: h, session: true }),
      stoppedHost,
    )) as Answer;
    expect(taken?.ok).toBe(true);
    expect(await sessionAllowList()).toContain(stoppedHost);
  } finally {
    await stopped?.close();
    await tab.close();
  }
});

test("should show a stopped host as stopped and ignore the brand in the page's own address", async () => {
  const host = "wbs-brand-guard-e2e.com";
  const first = await stopHost(host);
  await first.close();
  const tab = await ext.context.newPage();
  try {
    await tab.goto(warningUrl(`host=${host}&brand=Spoofbrand&brandDomain=spoof-brand.example`));
    await expect(tab.locator("main")).toHaveAttribute("data-state", "stopped");
    await expect(tab.locator("h1")).toContainText("Whisper stopped a dangerous page");
    await expect(tab.locator("#detail")).toContainText(host);
    await expect(tab.locator("#detail")).not.toContainText("Spoofbrand");
    await expect(tab.locator("#btn-real")).toBeHidden();
    await expect(tab.locator("#btn-continue")).toBeEnabled();
    await expect(tab.locator("#btn-back")).toHaveText("← Back to safety");
  } finally {
    await tab.close();
  }
});

test("should name the brand the background found for a stopped look-alike host", async () => {
  const host = "paypa1-checkout-secure.com";
  net.setVerdict(host, MALICIOUS);
  const first = await stopHost(host);
  try {
    await expect(first.locator("#detail")).toContainText("impersonating PayPal");
    await expect(first.locator("#btn-real")).toHaveText("Go to the real paypal.com");
  } finally {
    await first.close();
  }
});

test("should allow a stopped host for the session when Continue is pressed", async () => {
  const host = "wbs-continue-guard-e2e.com";
  const page = await stopHost(host);
  try {
    await page.locator("#btn-continue").click();
    await page.waitForURL(`https://${host}/`, { timeout: 15_000 });
    expect(await sessionAllowList()).toContain(host);
  } finally {
    await page.close();
  }
});

test("should say it cannot confirm a block when the extension does not answer", async () => {
  const host = "wbs-unconfirmed-guard-e2e.com";
  const page = await ext.context.newPage();
  try {
    await page.addInitScript(`
      window.chrome = { runtime: { id: "shim", getURL: (p) => p,
        sendMessage: () => Promise.reject(new Error("no answer")) } };
    `);
    await page.goto(`file://${DIST_CHROMIUM}/warning.html?host=${host}`);
    await expect(page.locator("main")).toHaveAttribute("data-state", "unconfirmed");
    await expect(page.locator("h1")).toHaveText("Whisper Guard could not confirm a block for this address.");
    await expect(page.locator("#btn-continue")).toBeDisabled();
    await expect(page.locator("#evidence")).toBeHidden();
    await expect(page.locator("#privacy")).toHaveText("Privacy: nothing was sent from this page.");
  } finally {
    await page.close();
  }
});

test("should say no block is in effect when the page carries no host", async () => {
  const page = await ext.context.newPage();
  try {
    await page.goto(warningUrl(""));
    await expect(page.locator("main")).toHaveAttribute("data-state", "no-host");
    await expect(page.locator("h1")).toHaveText("No block is in effect.");
    await expect(page.locator("#btn-continue")).toBeDisabled();
  } finally {
    await page.close();
  }
});

test("should show the stopped state and take Continue on a later visit that the block rule redirects", async () => {
  const host = "wbs-rule-guard-e2e.com";
  const first = await stopHost(host);
  await first.close();

  // The second visit is redirected before any request leaves for the host.
  net.clearLog();
  const page = await ext.context.newPage();
  try {
    await page.goto(`https://${host}/`, { waitUntil: "commit" });
    await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
    expect(net.requestsTo(host).filter((r) => r.scheme === "https")).toHaveLength(0);
    await expect(page.locator("main")).toHaveAttribute("data-state", "stopped");
    await expect(page.locator("#btn-continue")).toBeEnabled();

    await page.locator("#btn-continue").click();
    await page.waitForURL(`https://${host}/`, { timeout: 15_000 });
    expect(await sessionAllowList()).toContain(host);
  } finally {
    await page.close();
  }
});

test("should still continue to the host after the panel cleared its block while the page was open", async () => {
  const host = "wbs-cleared-guard-e2e.com";
  const benign = "wbs-cleared-benign-guard-e2e.com";
  net.setVerdict(benign, CLEAN);
  const page = await stopHost(host);
  const { page: other, tabId } = await visit(ext, `https://${benign}/`);
  const popup = await openPopup(ext, tabId);
  try {
    await popup.locator(".blocked-item", { hasText: host }).locator(".blocked-clear").click();
    await expect(popup.locator("#blocked-body")).not.toContainText(host, { timeout: 10_000 });
    expect(await sessionBlockList()).not.toContain(host);

    await page.locator("#btn-continue").click();
    await page.waitForURL(`https://${host}/`, { timeout: 15_000 });
  } finally {
    await popup.close();
    await other.close();
    await page.close();
  }
});

test("should treat an address value that is not shaped like a hostname as no host", async () => {
  const page = await ext.context.newPage();
  try {
    await page.goto(warningUrl(`host=${encodeURIComponent("wbs-shape-guard-e2e.com. A sentence, not a host")}`));
    await expect(page.locator("main")).toHaveAttribute("data-state", "no-host");
    await expect(page.locator("#detail")).not.toContainText("sentence");
    await expect(page.locator("#btn-continue")).toBeDisabled();
  } finally {
    await page.close();
  }
});

test("should keep every change when many blocks are cleared at the same moment", async () => {
  const hosts = Array.from({ length: 16 }, (_, i) => `wbs-many-${i}-guard-e2e.com`);
  for (const h of hosts) await markHostBlocked(ext, h);
  const panel = await ext.context.newPage();
  try {
    await panel.goto(`chrome-extension://${ext.id}/popup.html`);
    const answers = (await panel.evaluate(
      (hs) => Promise.all(hs.map((h) => chrome.runtime.sendMessage({ kind: "allowHost", host: h, session: true }))),
      hosts,
    )) as Answer[];
    expect(answers.every((a) => a?.ok === true)).toBe(true);

    const allowed = await sessionAllowList();
    const blocked = await sessionBlockList();
    expect(hosts.filter((h) => !allowed.includes(h)), "cleared hosts missing from the session allow list").toEqual([]);
    expect(hosts.filter((h) => blocked.includes(h)), "cleared hosts still in the block list").toEqual([]);
  } finally {
    await panel.close();
  }
});
