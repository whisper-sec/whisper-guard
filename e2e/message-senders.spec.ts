// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The background's message router handles a kind only from the senders that
// send it. The on-page layer sends four kinds (consentDeclined, preemptOpen,
// preemptCheck, preemptAllow); any other kind from a web page's tab gets an
// error answer and changes nothing, while Guard's own pages send every kind as
// before. The `dashboard` port is accepted from the dashboard page only. The
// warning page acts only as the top-level page of its tab: inside a frame its
// Continue control is disabled, it sends no message, and the router declines
// `allowHost` from a framed page.
//
// "From the on-page layer" is a script run in the tab's isolated world through
// chrome.scripting, which is the same sender the on-page layer has. "From a
// Guard page" is the extension's own page. The site-access build lets a tab be
// scripted.
//
// Each "changes nothing" assertion is paired with a positive control: the same
// kind, sent from a Guard page, does change that thing.

import { test, expect, type Frame, type Page } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  extensionPage,
  launchExtension,
  makeShieldDist,
  markHostBlocked,
  openDashboard,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const CLEAN = { band: "NONE", coverage: "known-clean", label: "clean" } as const;
const MALICIOUS = { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" } as const;

type Answer = { ok?: boolean; error?: string; [k: string]: unknown } | undefined;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

/** Send a message from inside a web tab, in the isolated world. */
async function fromTab(tabId: number, msg: Record<string, unknown>): Promise<Answer> {
  return ext.sw.evaluate(
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

/** Send a message from one of Guard's own pages. */
async function fromGuardPage(msg: Record<string, unknown>): Promise<Answer> {
  const page = await extensionPage(ext);
  return page.evaluate((m) => chrome.runtime.sendMessage(m), msg);
}

async function sessionAllowList(): Promise<string[]> {
  return ext.sw.evaluate(async () => {
    const v = (await chrome.storage.session.get("allowed"))["allowed"];
    return Array.isArray(v) ? (v as string[]) : [];
  });
}

async function permanentAllowList(): Promise<string[]> {
  return ext.sw.evaluate(async () => {
    const s = (await chrome.storage.local.get("settings"))["settings"] as { allowlist?: string[] } | undefined;
    return s?.allowlist ?? [];
  });
}

async function storedSettings(): Promise<string> {
  return ext.sw.evaluate(async () => JSON.stringify((await chrome.storage.local.get("settings"))["settings"] ?? {}));
}

function readsNaming(host: string): number {
  return net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes(host)).length;
}

test("should answer an error and change nothing for a kind the on-page layer does not send", async () => {
  const source = "senders-source-guard-e2e.com";
  const permHost = "senders-perm-guard-e2e.com";
  const sessHost = "senders-session-guard-e2e.com";
  net.setVerdict(source, CLEAN);
  const { page, tabId } = await visit(ext, `https://${source}/`);
  try {
    await waitForIcon(ext, tabId, ["benign"]);
    const before = await storedSettings();
    const sessionBefore = await sessionAllowList();

    const refused: Record<string, unknown>[] = [
      { kind: "setSettings", patch: { amberBanner: false, allowlist: [permHost] } },
      { kind: "allowHost", host: permHost, session: false },
      { kind: "allowHost", host: sessHost, session: true },
      { kind: "getTabState", tabId },
      { kind: "getBrowserReport" },
    ];
    for (const msg of refused) {
      const answer = await fromTab(tabId, msg);
      expect(answer?.ok, `${String(msg["kind"])} from a web tab`).toBe(false);
      expect(typeof answer?.error).toBe("string");
    }

    expect(await storedSettings()).toBe(before);
    expect(await permanentAllowList()).not.toContain(permHost);
    expect(await sessionAllowList()).toEqual(sessionBefore);

    // The four kinds of the on-page layer still answer from the same tab.
    const check = await fromTab(tabId, { kind: "preemptCheck", host: "senders-target-guard-e2e.com" });
    expect(check?.ok).toBe(true);
    const declined = await fromTab(tabId, { kind: "consentDeclined" });
    expect(declined?.ok).toBe(true);

    // Positive control: the same refused kinds work from a Guard page.
    expect((await fromGuardPage({ kind: "allowHost", host: permHost, session: false }))?.ok).toBe(true);
    expect((await fromGuardPage({ kind: "getTabState", tabId }))?.ok).toBe(true);
    expect((await fromGuardPage({ kind: "getBrowserReport" }))?.ok).toBe(true);
    await expect.poll(permanentAllowList).toContain(permHost);
    expect(await sessionAllowList()).toContain(permHost);
    const patched = await fromGuardPage({ kind: "setSettings", patch: { amberBanner: false } });
    expect(patched?.ok).toBe(true);
    await expect
      .poll(async () => (JSON.parse(await storedSettings()) as { amberBanner?: boolean }).amberBanner)
      .toBe(false);
  } finally {
    // The control's host stays on the session allow list; no other test here names it.
    await setSettings(ext, { amberBanner: true, allowlist: [] });
    await page.close();
  }
});

/** Connect a `dashboard` port from a web tab's isolated world; the outcome is kept there. */
async function connectFromTab(tabId: number): Promise<void> {
  await ext.sw.evaluate(async (id: number) => {
    await chrome.scripting.executeScript({
      target: { tabId: id },
      func: () => {
        const w = globalThis as unknown as { __portOutcome?: string };
        w.__portOutcome = "pending";
        const port = chrome.runtime.connect({ name: "dashboard" });
        port.onDisconnect.addListener(() => {
          if (w.__portOutcome === "pending") w.__portOutcome = "disconnected";
        });
        port.onMessage.addListener(() => {
          if (w.__portOutcome === "pending") w.__portOutcome = "message";
        });
      },
    });
  }, tabId);
}

async function portOutcome(tabId: number): Promise<string> {
  return ext.sw.evaluate(async (id: number) => {
    const r = await chrome.scripting.executeScript({
      target: { tabId: id },
      func: () => (globalThis as unknown as { __portOutcome?: string }).__portOutcome ?? "none",
    });
    return String(r[0]?.result);
  }, tabId);
}

const fleetAlarm = () =>
  ext.sw.evaluate((name) => chrome.alarms.get(name), "whisper-guard-fleet-poll").then((a) => a ?? null);

test("should disconnect a dashboard port that a web page's tab opens", async () => {
  const source = "port-source-guard-e2e.com";
  const mover = "port-mover-guard-e2e.com";
  net.setVerdict(source, CLEAN);
  net.setVerdict(mover, CLEAN);
  const { page, tabId } = await visit(ext, `https://${source}/`);
  let other: Awaited<ReturnType<typeof visit>> | undefined;
  try {
    await waitForIcon(ext, tabId, ["benign"]);
    await connectFromTab(tabId);
    // An accepted port is nudged for every committed navigation: navigate another tab.
    other = await visit(ext, `https://${mover}/`);
    await waitForIcon(ext, other.tabId, ["benign"]);
    await expect.poll(() => portOutcome(tabId), { timeout: 10_000 }).not.toBe("pending");
    expect(await portOutcome(tabId)).toBe("disconnected");
    expect(await fleetAlarm()).toBeNull();
  } finally {
    await other?.page.close();
    await page.close();
  }
});

test("should still give the dashboard page its port", async () => {
  const dash = await openDashboard(ext, "browser");
  try {
    await expect.poll(async () => (await fleetAlarm())?.periodInMinutes).toBe(0.5);
  } finally {
    await dash.close();
  }
  await expect.poll(fleetAlarm).toBeNull();
});

const FRAME_HOST = "frame-target-guard-e2e.com";

async function framedWarning(framer: string, target: string): Promise<{ page: Page; frame: Frame }> {
  net.setPage(
    framer,
    `<!doctype html><html><body><iframe src="chrome-extension://${ext.id}/warning.html?host=${target}"></iframe></body></html>`,
  );
  net.setVerdict(framer, CLEAN);
  const { page } = await visit(ext, `https://${framer}/`);
  let frame: Frame | undefined;
  await expect
    .poll(
      () => {
        frame = page.frames().find((f) => f.url().includes("warning.html"));
        return frame !== undefined;
      },
      { message: "the framed warning page loaded" },
    )
    .toBe(true);
  return { page, frame: frame as Frame };
}

test("should leave the warning page inert when it is shown inside a frame", async () => {
  const control = "frame-control-guard-e2e.com";
  net.setVerdict(control, MALICIOUS);
  net.setVerdict(FRAME_HOST, MALICIOUS);
  const { page, frame } = await framedWarning("frame-outer-guard-e2e.com", FRAME_HOST);
  await markHostBlocked(ext, control);
  const top = await ext.context.newPage();
  try {
    await expect(frame.locator("#btn-continue")).toBeDisabled();
    await expect(frame.locator("#btn-back")).toBeVisible();

    // Positive control, opened after the framed page: the warning page as a
    // tab's own page has Continue enabled and reads its evidence. Once those
    // reads have arrived, the framed page's would have too.
    await top.goto(`chrome-extension://${ext.id}/warning.html?host=${control}`);
    await expect(top.locator("#btn-continue")).toBeEnabled();
    await expect.poll(() => readsNaming(control), { message: "the top-level page's evidence reads" }).toBeGreaterThan(0);
    expect(readsNaming(FRAME_HOST)).toBe(0);
    expect(await sessionAllowList()).not.toContain(FRAME_HOST);

    // The router declines allowHost from the framed page itself, also for a
    // host Guard is blocking.
    await markHostBlocked(ext, FRAME_HOST);
    const answer = (await frame.evaluate(
      (h) => chrome.runtime.sendMessage({ kind: "allowHost", host: h, session: false }),
      FRAME_HOST,
    )) as Answer;
    expect(answer?.ok).toBe(false);
    expect(typeof answer?.error).toBe("string");
    expect(await sessionAllowList()).not.toContain(FRAME_HOST);
    expect(await permanentAllowList()).not.toContain(FRAME_HOST);
  } finally {
    await top.close();
    await page.close();
  }
});

test("should still allow the host from the warning page shown as a tab's own page", async () => {
  const host = "frame-top-allow-guard-e2e.com";
  net.setVerdict(host, MALICIOUS);
  await markHostBlocked(ext, host);
  const top = await ext.context.newPage();
  try {
    await top.goto(`chrome-extension://${ext.id}/warning.html?host=${host}`);
    await top.locator("#btn-continue").click();
    await expect.poll(sessionAllowList).toContain(host);
  } finally {
    await top.close();
  }
});
