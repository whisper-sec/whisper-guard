// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Nothing a check learns is written for a private-window tab: not the
// destination log, not the verdict cache (memory or its session copy), not the
// session risk list. The tab still gets its toolbar mark and its verdict, and a
// normal-window tab writes all three as before. A held click that the check
// clears is reopened in the window kind and window it came from.
//
// Guard sees a private tab only once it is allowed in private windows, so this
// file runs its own browser on a profile where that is switched on, with the
// site-access build so the private tab can be scripted and scanned.
//
// The stores are flushed on timers, so every "not written" assertion is made
// after a positive control: a normal-window host is checked AFTER the private
// one, and the assertion runs only once that control is in the same stores.

import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  allowInIncognito,
  extensionPage,
  launchExtension,
  makeShieldDist,
  openPopup,
  rebindWorker,
  setKey,
  setSettings,
  stopWorker,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let own: Extension;

const FLAGGED = { band: "MEDIUM", coverage: "partial", label: "suspicious" } as const;
const MALICIOUS = { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" } as const;
const CLEAN = { band: "NONE", coverage: "known-clean", label: "clean" } as const;

interface Stores {
  navlog: string[];
  verdicts: string[];
  risks: string[];
}

async function stores(): Promise<Stores> {
  return own.sw.evaluate(async () => {
    const local = (await chrome.storage.local.get("navlog"))["navlog"] as Record<string, unknown> | undefined;
    const session = await chrome.storage.session.get(["verdicts", "risks"]);
    const verdicts = session["verdicts"] as Record<string, unknown> | undefined;
    const risks = session["risks"] as { host: string }[] | undefined;
    return {
      navlog: Object.keys(local ?? {}),
      verdicts: Object.keys(verdicts ?? {}),
      risks: (risks ?? []).map((r) => r.host),
    };
  });
}

/** Open a private window on `url`; resolves with its tab once the tab exists. */
async function openPrivate(url: string): Promise<{ tabId: number; windowId: number }> {
  const t = await own.sw.evaluate(async (u: string) => {
    const w = await chrome.windows.create({ incognito: true, url: u });
    const tab = w.tabs?.[0];
    return { tabId: tab?.id ?? -1, windowId: w.id ?? -1, incognito: tab?.incognito === true };
  }, url);
  expect(t.incognito).toBe(true);
  return { tabId: t.tabId, windowId: t.windowId };
}

async function closePrivate(windowId: number): Promise<void> {
  await own.sw.evaluate(async (id: number) => chrome.windows.remove(id), windowId).catch(() => undefined);
}

/** Verdict requests that named this host. */
function asked(host: string): number {
  return net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.assess") && r.body.includes(host))
    .length;
}

/** The click hold's question, asked from inside a tab so that tab is the sender. */
async function hold(tabId: number, host: string): Promise<{ action?: string }> {
  const out = await own.sw.evaluate(
    async ([id, h]: [number, string]) => {
      const r = await chrome.scripting.executeScript({
        target: { tabId: id },
        func: (target: string) => chrome.runtime.sendMessage({ kind: "preemptCheck", host: target }),
        args: [h],
      });
      return r[0]?.result as { ok?: boolean; preempt?: { action?: string } } | undefined;
    },
    [tabId, host] as [number, string],
  );
  expect(out?.ok).toBe(true);
  return out?.preempt ?? {};
}

async function send(msg: Record<string, unknown>): Promise<{ ok?: boolean }> {
  const page = await extensionPage(own);
  return page.evaluate((m) => chrome.runtime.sendMessage(m), msg);
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  const dist = makeShieldDist();
  const first = await launchExtension({ proxyPort: net.proxyPort, dist });
  own = await allowInIncognito(first, { proxyPort: net.proxyPort, dist });
  await setKey(own, null);
  await setSettings(own, { cloudCheck: true });
});

test.afterAll(async () => {
  await own?.close();
  await net?.stop();
});

test("should write no destination, verdict or risk entry for a private-window page check", async () => {
  const priv = "private-check-guard-e2e.com";
  const norm = "normal-check-guard-e2e.com";
  net.setVerdict(priv, FLAGGED);
  net.setVerdict(norm, FLAGGED);

  const p = await openPrivate(`https://${priv}/`);
  try {
    // The private tab still gets its toolbar mark and its verdict.
    await waitForIcon(own, p.tabId, ["suspicious"]);
    const state = await send({ kind: "getTabState", tabId: p.tabId });
    expect((state as { tabState?: { hostname?: string; verdict?: { band?: string } } }).tabState?.verdict?.band).toBe(
      "MEDIUM",
    );

    // Positive control, checked after the private page: a normal-window tab
    // writes all three stores.
    const normal = await visit(own, `https://${norm}/`);
    await waitForIcon(own, normal.tabId, ["suspicious"]);
    await expect
      .poll(
        async () => {
          const s = await stores();
          return s.navlog.includes(norm) && s.verdicts.includes(norm) && s.risks.includes(norm);
        },
        { message: "the normal-window host in all three stores", timeout: 10_000 },
      )
      .toBe(true);

    const s = await stores();
    expect(s.navlog).not.toContain(priv);
    expect(s.verdicts).not.toContain(priv);
    expect(s.risks).not.toContain(priv);

    // The in-memory cache did not keep it either: the same host in a normal
    // window is asked about afresh.
    expect(asked(priv)).toBe(1);
    const again = await visit(own, `https://${priv}/`);
    await waitForIcon(own, again.tabId, ["suspicious"]);
    expect(asked(priv)).toBe(2);
    await expect
      .poll(
        async () => {
          const after = await stores();
          return after.navlog.includes(priv) && after.verdicts.includes(priv) && after.risks.includes(priv);
        },
        { message: "the host in all three stores once a normal window checked it", timeout: 10_000 },
      )
      .toBe(true);
    await normal.page.close();
    await again.page.close();
  } finally {
    await closePrivate(p.windowId);
  }
});

test("pressing Check this site now on a private-window tab writes no saved state, destination or risk entry", async () => {
  const priv = "private-press-guard-e2e.com";
  const norm = "normal-press-guard-e2e.com";
  net.setVerdict(priv, FLAGGED);
  net.setVerdict(norm, FLAGGED);

  const p = await openPrivate(`https://${priv}/`);
  try {
    await waitForIcon(own, p.tabId, ["suspicious"]);
    // The worker restarts holding nothing for the private tab.
    await stopWorker(own);
    const via = await extensionPage(own);
    await via.evaluate(async () => {
      await chrome.storage.session.remove("verdicts");
      await chrome.storage.local.remove("navlog");
    });
    const asksBefore = asked(priv);

    const popup = await openPopup(own, p.tabId);
    await expect(popup.locator("#not-checked-view")).toBeVisible();
    await popup.locator("#btn-check-now").click();
    await expect(popup.locator("#band-chip")).toHaveText("SUSPICIOUS");
    // The check asked the graph (nothing was kept for the private tab, so the
    // popup's protection read may ask again).
    expect(asked(priv)).toBeGreaterThan(asksBefore);
    await popup.close();
    await rebindWorker(own);

    // Positive control, checked after the private page: a normal-window tab
    // writes all three stores and its own saved state.
    const normal = await visit(own, `https://${norm}/`);
    await waitForIcon(own, normal.tabId, ["suspicious"]);
    await expect
      .poll(
        async () => {
          const s = await stores();
          return [s.navlog, s.verdicts, s.risks].every((list) => list.some((h) => h === norm));
        },
        { message: "the normal-window host in all three stores", timeout: 10_000 },
      )
      .toBe(true);

    const s = await stores();
    expect(s.navlog).not.toContain(priv);
    expect(s.risks).not.toContain(priv);
    const keys = await own.sw.evaluate(async () => Object.keys(await chrome.storage.session.get(null)));
    expect(keys).toContain(`tabState:${normal.tabId}`);
    expect(keys).not.toContain(`tabState:${p.tabId}`);
    await normal.page.close();
  } finally {
    await closePrivate(p.windowId);
  }
});

test("a check request for a private-window tab writes no verdict, destination, risk or saved state", async () => {
  const priv = "private-request-guard-e2e.com";
  const norm = "normal-request-guard-e2e.com";
  net.setVerdict(priv, FLAGGED);
  net.setVerdict(norm, FLAGGED);

  const p = await openPrivate(`https://${priv}/`);
  try {
    await waitForIcon(own, p.tabId, ["suspicious"]);
    // No popup is open: the request comes from an extension page alone.
    const asksBefore = asked(priv);
    const answer = (await send({ kind: "checkTab", tabId: p.tabId })) as {
      ok?: boolean;
      tabState?: { verdict?: { band?: string } };
    };
    expect(answer.ok).toBe(true);
    expect(answer.tabState?.verdict?.band).toBe("MEDIUM");
    expect(asked(priv)).toBe(asksBefore + 1);
    // Nothing was kept in memory: a second request asks the graph afresh.
    await send({ kind: "checkTab", tabId: p.tabId });
    expect(asked(priv)).toBe(asksBefore + 2);

    // Positive control, checked after the private page: a normal-window tab
    // writes all three stores and its own saved state.
    const normal = await visit(own, `https://${norm}/`);
    await waitForIcon(own, normal.tabId, ["suspicious"]);
    await expect
      .poll(
        async () => {
          const s = await stores();
          return [s.navlog, s.verdicts, s.risks].every((list) => list.some((h) => h === norm));
        },
        { message: "the normal-window host in all three stores", timeout: 10_000 },
      )
      .toBe(true);

    const s = await stores();
    expect(s.navlog).not.toContain(priv);
    expect(s.verdicts).not.toContain(priv);
    expect(s.risks).not.toContain(priv);
    const keys = await own.sw.evaluate(async () => Object.keys(await chrome.storage.session.get(null)));
    expect(keys).toContain(`tabState:${normal.tabId}`);
    expect(keys).not.toContain(`tabState:${p.tabId}`);
    await normal.page.close();
  } finally {
    await closePrivate(p.windowId);
  }
});

test("should not cache a click hold that came from a private-window tab", async () => {
  const source = "private-hold-source-guard-e2e.com";
  const target = "hold-target-private-guard-e2e.com";
  const control = "hold-target-normal-guard-e2e.com";
  net.setVerdict(source, CLEAN);
  net.setVerdict(target, MALICIOUS);
  net.setVerdict(control, MALICIOUS);

  const p = await openPrivate(`https://${source}/`);
  try {
    await waitForIcon(own, p.tabId, ["benign"]);
    // The hold still decides for the private tab.
    expect((await hold(p.tabId, target)).action).toBe("interrupt");
    expect(asked(target)).toBe(1);

    // A hold from a normal-window tab is cached, and is the positive control.
    const normal = await visit(own, `https://${source}/`);
    await waitForIcon(own, normal.tabId, ["benign"]);
    expect((await hold(normal.tabId, control)).action).toBe("interrupt");
    await expect
      .poll(async () => (await stores()).verdicts, {
        message: "the normal-window hold in the verdict copy",
        timeout: 10_000,
      })
      .toContain(control);
    expect((await stores()).verdicts).not.toContain(target);

    // Nothing was kept in memory: the same target from a normal window is asked again.
    expect((await hold(normal.tabId, target)).action).toBe("interrupt");
    expect(asked(target)).toBe(2);
    await normal.page.close();
  } finally {
    await closePrivate(p.windowId);
  }
});

test("should not cache the link scan or the indicator scan of a private-window tab", async () => {
  const privSource = "private-scan-source-guard-e2e.com";
  const normSource = "normal-scan-source-guard-e2e.com";
  const privLink = "private-link-only-guard-e2e.com";
  const privText = "private-text-only-guard-e2e.com";
  const normLink = "normal-link-only-guard-e2e.com";
  const normText = "normal-text-only-guard-e2e.com";
  const page = (link: string, text: string) =>
    `<!doctype html><html><head><title>notes</title></head><body>` +
    `<p>Seen beaconing to ${text} overnight.</p><a href="https://${link}/x">a link</a></body></html>`;
  net.setPage(privSource, page(privLink, privText));
  net.setPage(normSource, page(normLink, normText));
  const againSource = "again-scan-source-guard-e2e.com";
  net.setPage(againSource, page(privLink, privText));
  for (const h of [privSource, normSource, againSource]) net.setVerdict(h, CLEAN);
  for (const h of [privLink, privText, normLink, normText]) net.setVerdict(h, FLAGGED);

  const p = await openPrivate(`https://${privSource}/`);
  try {
    await waitForIcon(own, p.tabId, ["benign"]);
    const links = (await send({ kind: "scanLinks", tabId: p.tabId })) as { ok?: boolean; scan?: { hosts: { host: string }[] } };
    const iocs = (await send({ kind: "scanIocs", tabId: p.tabId })) as { ok?: boolean; scan?: { rows: { host: string }[] } };
    // The scans still answer for the private tab.
    expect(links.ok).toBe(true);
    expect(links.scan?.hosts.map((r) => r.host)).toContain(privLink);
    expect(iocs.ok).toBe(true);
    expect(iocs.scan?.rows.map((r) => r.host)).toContain(privText);

    // The same scans of a normal-window tab are cached: the positive control.
    const normal = await visit(own, `https://${normSource}/`);
    await waitForIcon(own, normal.tabId, ["benign"]);
    expect(((await send({ kind: "scanLinks", tabId: normal.tabId })) as { ok?: boolean }).ok).toBe(true);
    expect(((await send({ kind: "scanIocs", tabId: normal.tabId })) as { ok?: boolean }).ok).toBe(true);
    await expect
      .poll(
        async () => {
          const seen = (await stores()).verdicts;
          return seen.includes(normLink) && seen.includes(normText);
        },
        { message: "the normal-window scans in the verdict copy", timeout: 10_000 },
      )
      .toBe(true);

    const v = (await stores()).verdicts;
    expect(v).not.toContain(privLink);
    expect(v).not.toContain(privText);

    // Nor is either held in memory: a normal-window page naming the same hosts
    // has them asked about afresh.
    expect(asked(privLink)).toBe(1);
    expect(asked(privText)).toBe(1);
    const again = await visit(own, `https://${againSource}/`);
    await waitForIcon(own, again.tabId, ["benign"]);
    await send({ kind: "scanLinks", tabId: again.tabId });
    await send({ kind: "scanIocs", tabId: again.tabId });
    expect(asked(privLink)).toBe(2);
    expect(asked(privText)).toBe(2);
    await normal.page.close();
    await again.page.close();
  } finally {
    await closePrivate(p.windowId);
  }
});

interface Opened {
  tabId: number;
  windowId: number;
  index: number;
  incognito: boolean;
  url: string;
}

interface Snapshot {
  tabs: Opened[];
  windows: { id: number; incognito: boolean }[];
}

/** Every tab and window now open, for comparing before and after a reopen. */
async function snapshot(): Promise<Snapshot> {
  return own.sw.evaluate(async () => {
    const tabs = await chrome.tabs.query({});
    const windows = await chrome.windows.getAll();
    return {
      tabs: tabs.map((t) => ({
        tabId: t.id ?? -1,
        windowId: t.windowId,
        index: t.index,
        incognito: t.incognito,
        url: t.url ?? t.pendingUrl ?? "",
      })),
      windows: windows.map((w) => ({ id: w.id ?? -1, incognito: w.incognito })),
    };
  });
}

/** The held click's resume, sent from inside a tab so that tab is the sender. */
async function resume(tabId: number, url: string, disposition: string): Promise<void> {
  const out = await own.sw.evaluate(
    async ([id, u, d]: [number, string, string]) => {
      const r = await chrome.scripting.executeScript({
        target: { tabId: id },
        func: (dest: string, disp: string) =>
          chrome.runtime.sendMessage({ kind: "preemptOpen", url: dest, disposition: disp }),
        args: [u, d],
      });
      return r[0]?.result as { ok?: boolean } | undefined;
    },
    [tabId, url, disposition] as [number, string, string],
  );
  expect(out?.ok).toBe(true);
}

/** The tab the reopen created: the one whose address names `host`. */
async function reopened(host: string): Promise<Opened> {
  let found: Opened | undefined;
  await expect
    .poll(
      async () => {
        const s = await snapshot();
        found = s.tabs.find((t) => t.url.includes(host));
        return found !== undefined;
      },
      { message: `a tab opened for ${host}`, timeout: 10_000 },
    )
    .toBe(true);
  return found as Opened;
}

async function focusNormalWindow(url: string): Promise<number> {
  return own.sw.evaluate(async (u: string) => {
    const w = await chrome.windows.create({ incognito: false, focused: true, url: u });
    return w.id ?? -1;
  }, url);
}

async function closeWindow(windowId: number): Promise<void> {
  await own.sw.evaluate(async (id: number) => chrome.windows.remove(id), windowId).catch(() => undefined);
}

test("should reopen a held Shift click from a private-window tab in a private window", async () => {
  const source = "reopen-shift-source-guard-e2e.com";
  const dest = "reopen-shift-dest-guard-e2e.com";
  net.setVerdict(source, CLEAN);
  net.setVerdict(dest, CLEAN);

  const p = await openPrivate(`https://${source}/`);
  let created: Opened | undefined;
  try {
    await waitForIcon(own, p.tabId, ["benign"]);
    await resume(p.tabId, `https://${dest}/`, "window");
    created = await reopened(dest);
    expect(created.incognito).toBe(true);
    // A new window, not a tab in the one the click came from.
    expect(created.windowId).not.toBe(p.windowId);
    const s = await snapshot();
    expect(s.windows.find((w) => w.id === created?.windowId)?.incognito).toBe(true);
  } finally {
    if (created !== undefined) await closeWindow(created.windowId);
    await closePrivate(p.windowId);
  }
});

for (const disposition of ["background-tab", "foreground-tab"]) {
  test(`should reopen a held ${disposition} click in the clicking private tab's window, whichever window has focus`, async () => {
    const tag = disposition === "background-tab" ? "bg" : "fg";
    const source = `reopen-${tag}-source-guard-e2e.com`;
    const dest = `reopen-${tag}-dest-guard-e2e.com`;
    net.setVerdict(source, CLEAN);
    net.setVerdict(dest, CLEAN);

    const p = await openPrivate(`https://${source}/`);
    let focused = -1;
    try {
      await waitForIcon(own, p.tabId, ["benign"]);
      focused = await focusNormalWindow("about:blank");
      await resume(p.tabId, `https://${dest}/`, disposition);
      const created = await reopened(dest);
      expect(created.windowId).toBe(p.windowId);
      expect(created.incognito).toBe(true);
      const opener = (await snapshot()).tabs.find((t) => t.tabId === p.tabId);
      expect(created.index).toBe((opener?.index ?? -2) + 1);
    } finally {
      await closeWindow(focused);
      await closePrivate(p.windowId);
    }
  });
}

test("should reopen a held click from a normal-window tab as before", async () => {
  const source = "reopen-normal-source-guard-e2e.com";
  const winDest = "reopen-normal-window-guard-e2e.com";
  const tabDest = "reopen-normal-tab-guard-e2e.com";
  for (const h of [source, winDest, tabDest]) net.setVerdict(h, CLEAN);

  const normal = await visit(own, `https://${source}/`);
  let tab: Opened | undefined;
  let created: Opened | undefined;
  try {
    await waitForIcon(own, normal.tabId, ["benign"]);
    const before = await snapshot();
    const opener = before.tabs.find((t) => t.tabId === normal.tabId);

    await resume(normal.tabId, `https://${tabDest}/`, "background-tab");
    tab = await reopened(tabDest);
    expect(tab.incognito).toBe(false);
    expect(tab.windowId).toBe(opener?.windowId);
    expect(tab.index).toBe((opener?.index ?? -2) + 1);

    await resume(normal.tabId, `https://${winDest}/`, "window");
    created = await reopened(winDest);
    expect(created.incognito).toBe(false);
    expect(created.windowId).not.toBe(opener?.windowId);
  } finally {
    if (created !== undefined) await closeWindow(created.windowId);
    if (tab !== undefined) {
      await own.sw.evaluate(async (id: number) => chrome.tabs.remove(id), tab.tabId).catch(() => undefined);
    }
    await normal.page.close();
  }
});
