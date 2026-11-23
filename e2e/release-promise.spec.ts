// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Regression (#54): the browser stops an MV3 service worker after about 30 s
// idle, and Guard kept every tab's verdict only in that worker's memory. A
// popup opened afterwards said "Nothing to check on this page" and "Privacy:
// nothing was sent." about a site Guard had checked, and switching tabs
// repainted the mark neutral. A verdict the product already earned must
// survive the worker, and where it cannot, the popup says exactly what is
// true: still checking, could not check, or no answer was kept.
//
// The worker is stopped for real (CDP ServiceWorker.stopAllWorkers) and each
// test proves the replacement is a fresh worker, so a stop that silently
// failed cannot pass.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  allowInIncognito,
  badgeText,
  extensionPage,
  iconState,
  launchExtension,
  openPopup,
  rebindWorker,
  setKey,
  setSettings,
  stopWorker,
  visit,
  waitForIcon,
  workerIsFresh,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const CLEAN = { band: "NONE", coverage: "known-clean", label: "clean" } as const;

/** Storage read from the extension's own page, so it works while the worker is stopped. */
async function sessionStore(): Promise<Record<string, unknown>> {
  const page = await extensionPage(ext);
  return page.evaluate(() => chrome.storage.session.get(null));
}

async function waitFor(what: string, ok: () => Promise<boolean>, timeoutMs = 8000): Promise<void> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (await ok()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

const stateKey = (tabId: number) => `tabState:${tabId}`;

/** The tab is settled, its state is saved and its verdict reached the cache mirror. */
async function settled(tabId: number, host: string): Promise<void> {
  await waitFor(`saved state of tab ${tabId}`, async () => stateKey(tabId) in (await sessionStore()));
  await waitFor(`cache mirror of ${host}`, async () => {
    const v = (await sessionStore())["verdicts"] as Record<string, unknown> | undefined;
    return v !== undefined && host in v;
  });
}

async function chipText(popup: Page): Promise<string> {
  return ((await popup.locator("#band-chip").textContent().catch(() => "")) ?? "").trim();
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("github.com", CLEAN);
  ext = await launchExtension({ proxyPort: net.proxyPort });
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.afterEach(() => {
  net.assessDelayMs.clear();
});

test("should show the site's verdict in the popup after the worker stops", async () => {
  const host = "kept-verdict-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await settled(tabId, host);

  await stopWorker(ext);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
  await expect(popup.locator("#ineligible")).toBeHidden();
  await expect(popup.locator("#privacy-line")).not.toContainText("nothing was sent");

  await rebindWorker(ext);
  expect(await workerIsFresh(ext)).toBe(true);
  await popup.close();
  await page.close();
});

test("should keep the mark across a tab switch after the worker stops", async () => {
  net.setVerdict("switch-a-guard-e2e.com", CLEAN);
  net.setVerdict("switch-b-guard-e2e.com", CLEAN);
  const a = await visit(ext, "https://switch-a-guard-e2e.com/");
  await waitForIcon(ext, a.tabId, ["benign"]);
  const b = await visit(ext, "https://switch-b-guard-e2e.com/");
  await waitForIcon(ext, b.tabId, ["benign"]);
  await settled(a.tabId, "switch-a-guard-e2e.com");
  await settled(b.tabId, "switch-b-guard-e2e.com");

  await stopWorker(ext);
  // The browser keeps a tab's badge while the worker is stopped; read from the
  // helper page, since the worker handle is unusable until it is rebound.
  const via = await extensionPage(ext);
  const badgeOf = (id: number) => via.evaluate((t) => chrome.action.getBadgeText({ tabId: t }), id);
  expect(await badgeOf(a.tabId)).toBe("\u2713");
  await b.page.bringToFront();
  await a.page.bringToFront();
  await rebindWorker(ext);
  expect(await workerIsFresh(ext)).toBe(true);

  // The mark of A is sampled until well past the switch: never neutral.
  const seen = new Set<string>();
  const until = Date.now() + 1500;
  while (Date.now() < until) {
    seen.add(await iconState(ext, a.tabId));
    await new Promise((r) => setTimeout(r, 50));
  }
  expect([...seen]).toEqual(["benign"]);
  expect(await badgeText(ext, a.tabId)).toBe("\u2713");
  await a.page.close();
  await b.page.close();
});

test("should answer from the exact-name cache with no request", async () => {
  const host = "exact-cache-guard-e2e.com";
  const apex = "apex-only-guard-e2e.com";
  const sub = `www.${apex}`;
  net.setVerdict(host, CLEAN);
  net.setVerdict(apex, CLEAN);
  const a = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, a.tabId, ["benign"]);
  await settled(a.tabId, host);
  // Parent-domain control: only the apex has ever been answered.
  const p = await visit(ext, `https://${apex}/`);
  await waitForIcon(ext, p.tabId, ["benign"]);
  await settled(p.tabId, apex);
  const s = await visit(ext, `https://${sub}/`);
  await waitForIcon(ext, s.tabId, ["benign"]);
  await waitFor("saved state of the subdomain tab", async () => stateKey(s.tabId) in (await sessionStore()));

  await stopWorker(ext);
  const page = await extensionPage(ext);
  await page.evaluate(([k1, k2]) => chrome.storage.session.remove([k1!, k2!]), [stateKey(a.tabId), stateKey(s.tabId)]);
  net.clearLog();

  // The strict count: reading the state sends nothing to the graph.
  const res = await page.evaluate(
    (id) => chrome.runtime.sendMessage({ kind: "getTabState", tabId: id }),
    a.tabId,
  );
  expect(res.tabState.icon).toBe("benign");
  expect(res.tabState.verdict.band).toBe("NONE");
  expect(net.requestsTo(GRAPH_READ_HOST)).toHaveLength(0);

  const popup = await openPopup(ext, a.tabId);
  await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
  const assessed = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.assess"));
  expect(assessed).toHaveLength(0);
  await popup.close();

  // A subdomain is not answered with its parent's verdict.
  net.clearLog();
  const subPopup = await openPopup(ext, s.tabId);
  await expect(subPopup.locator("#band-note")).toHaveText(
    "No answer kept for this page. Reload it to check again.",
  );
  expect(await chipText(subPopup)).not.toBe("NO KNOWN THREAT");
  expect(net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.assess"))).toHaveLength(0);
  await subPopup.close();
  for (const t of [a, p, s]) await t.page.close();
});

test("should say no answer was kept when the state and the cache are both gone", async () => {
  const host = "nothing-kept-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await settled(tabId, host);

  await stopWorker(ext);
  const via = await extensionPage(ext);
  await via.evaluate((k) => chrome.storage.session.remove(["verdicts", k]), stateKey(tabId));

  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#band-note")).toHaveText(
    "No answer kept for this page. Reload it to check again.",
  );
  const until = Date.now() + 5000;
  while (Date.now() < until) {
    const body = await popup.locator("body").innerText();
    expect(body).not.toMatch(/could not check/i);
    expect(body).not.toMatch(/nothing was sent/i);
    await new Promise((r) => setTimeout(r, 200));
  }
  await popup.close();
  await page.close();
  await rebindWorker(ext);
});

test("should say no answer was kept when the worker stops in the middle of a check", async () => {
  const host = "stopped-mid-check-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  // The answer is held back, so the check is still in flight when the worker stops.
  net.assessDelayMs.set(host, 60_000);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  expect(stateKey(tabId) in (await sessionStore())).toBe(false);

  await stopWorker(ext);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#band-note")).toHaveText(
    "No answer kept for this page. Reload it to check again.",
  );
  await expect(popup.locator("#band-chip")).toBeHidden();
  // The lost check is not reported as a failed one, and nothing was kept as a
  // verdict. Sampled for a while, as above: a late "could not check" from the
  // abandoned check is exactly what must not appear.
  const until = Date.now() + 5000;
  while (Date.now() < until) {
    const body = await popup.locator("body").innerText();
    expect(body).not.toMatch(/could not check/i);
    expect(body).not.toMatch(/nothing was sent/i);
    await new Promise((r) => setTimeout(r, 200));
  }

  await rebindWorker(ext);
  expect(await workerIsFresh(ext)).toBe(true);
  await popup.close();
  await page.close();
});

test("should discard a saved state whose hostname is not the page's", async () => {
  const matching = "saved-match-guard-e2e.com";
  const mismatch = "saved-mismatch-guard-e2e.com";
  net.setVerdict(matching, CLEAN);
  net.setVerdict(mismatch, CLEAN);
  const a = await visit(ext, `https://${matching}/`);
  await waitForIcon(ext, a.tabId, ["benign"]);
  await settled(a.tabId, matching);
  const b = await visit(ext, `https://${mismatch}/`);
  await waitForIcon(ext, b.tabId, ["benign"]);
  await settled(b.tabId, mismatch);

  await stopWorker(ext);
  const via = await extensionPage(ext);
  // Both saved states now claim a high-risk answer; only A's is for its own page.
  // The verdict mirror is emptied so nothing else can answer for B.
  await via.evaluate(
    async ([ka, kb, hostA]) => {
      const planted = (hostname: string) => ({
        hostname,
        registrable: hostname,
        eligible: true,
        signedIn: false,
        icon: "suspicious",
        verdict: { host: hostname, band: "HIGH", coverage: "known-bad", label: "planted" },
        detector: null,
        graphError: null,
        shieldOn: false,
      });
      await chrome.storage.session.remove("verdicts");
      await chrome.storage.session.set({
        [ka!]: planted(hostA!),
        [kb!]: planted("some-other-site-guard-e2e.com"),
      });
    },
    [stateKey(a.tabId), stateKey(b.tabId), matching],
  );

  // Positive control: the planted state is read when its hostname is the page's.
  const popupA = await openPopup(ext, a.tabId);
  await expect(popupA.locator("#band-chip")).toHaveText("HIGH RISK");
  await popupA.close();

  // A state saved for another hostname is not shown for this page.
  const popupB = await openPopup(ext, b.tabId);
  await expect(popupB.locator("#band-note")).toHaveText(
    "No answer kept for this page. Reload it to check again.",
  );
  await expect(popupB.locator("#band-chip")).toBeHidden();
  expect(await popupB.locator("body").innerText()).not.toMatch(/HIGH RISK|planted/);
  await popupB.close();

  await rebindWorker(ext);
  expect(await workerIsFresh(ext)).toBe(true);
  for (const t of [a, b]) await t.page.close();
});

test("should move from Checking to Could not check within 4.5 s", async () => {
  const host = "never-answers-guard-e2e.com";
  net.assessDelayMs.set(host, 60_000);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#band-chip")).toHaveText("CHECKING");
  const t0 = Date.now();
  await expect(popup.locator("#band-chip")).toHaveText("COULD NOT CHECK", { timeout: 4500 });
  expect(Date.now() - t0).toBeLessThanOrEqual(4500);
  await popup.close();
  await page.close();
});

test("should show live check off at once and at 5 s", async () => {
  await setSettings(ext, { cloudCheck: false });
  try {
    const { page, tabId } = await visit(ext, "https://live-off-guard-e2e.com/");
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#band-chip")).toHaveText("LIVE CHECK OFF", { timeout: 500 });
    const seen: string[] = [];
    const until = Date.now() + 5000;
    while (Date.now() < until) {
      seen.push(await chipText(popup));
      await new Promise((r) => setTimeout(r, 100));
    }
    expect(seen).not.toContain("CHECKING");
    expect(seen.at(-1)).toBe("LIVE CHECK OFF");
    await popup.close();
    await page.close();
  } finally {
    await setSettings(ext, { cloudCheck: true });
  }
});

test("should never write state for a private-window tab", async () => {
  // Guard sees a private tab only once it is allowed in private windows, so
  // this test runs its own browser on a profile where that is switched on.
  const first = await launchExtension({ proxyPort: net.proxyPort });
  const own = await allowInIncognito(first, { proxyPort: net.proxyPort });
  try {
    await setKey(own, null);
    await setSettings(own, { cloudCheck: true });
    const host = "private-window-guard-e2e.com";
    net.setVerdict(host, CLEAN);
    net.setVerdict("normal-window-guard-e2e.com", CLEAN);
    const normal = await visit(own, "https://normal-window-guard-e2e.com/");
    await waitForIcon(own, normal.tabId, ["benign"]);

    const privateTab = await own.sw.evaluate(async (url: string) => {
      const w = await chrome.windows.create({ incognito: true, url });
      const t = w.tabs?.[0];
      return { id: t?.id ?? -1, incognito: t?.incognito === true };
    }, `https://${host}/`);
    expect(privateTab.incognito).toBe(true);

    // Positive control: Guard did evaluate the private tab (it painted its mark).
    await waitForIcon(own, privateTab.id, ["benign"]);
    const keys = await own.sw.evaluate(async () => Object.keys(await chrome.storage.session.get(null)));
    expect(keys).toContain(stateKey(normal.tabId));
    expect(keys).not.toContain(stateKey(privateTab.id));
  } finally {
    await own.close();
  }
});

test("should re-check a tab opened before a worker stop when the person signs in", async () => {
  const host = "signin-after-stop-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  const { page, tabId } = await visit(
    ext,
    `https://${host}/private-path-segment?token=query-secret#frag-secret`,
  );
  await waitForIcon(ext, tabId, ["benign"]);
  await settled(tabId, host);
  const savedState = async (): Promise<{ signedIn?: boolean } | undefined> =>
    (await sessionStore())[stateKey(tabId)] as { signedIn?: boolean } | undefined;
  expect((await savedState())?.signedIn).toBe(false);

  // Nothing of the address sits in session storage, with a positive control
  // that the hostname (which is allowed there) is.
  const noAddress = async (): Promise<void> => {
    const dump = JSON.stringify(await sessionStore());
    expect(dump).toContain(host);
    for (const secret of [`https://${host}`, "private-path-segment", "query-secret", "frag-secret"]) {
      expect(dump).not.toContain(secret);
    }
  };
  await noAddress();

  await stopWorker(ext);
  net.clearLog();
  // Hold the answer so the cleared window is observable.
  net.assessDelayMs.set(host, 2000);
  const via = await extensionPage(ext);
  await via.evaluate(() => chrome.runtime.sendMessage({ kind: "saveKey", key: "e2e-sign-in-after-stop" }));
  await rebindWorker(ext);
  expect(await workerIsFresh(ext)).toBe(true);

  try {
    // The earlier tier's saved answer is gone...
    await waitFor("the saved state to be cleared", async () => !(stateKey(tabId) in (await sessionStore())));
    // ...the tab the fresh worker never saw commit is re-checked...
    await waitFor("a re-check of the open tab", async () =>
      net.requestsTo(GRAPH_READ_HOST).some((r) => r.body.includes("whisper.assess") && r.body.includes(host)),
    );
    // ...and its new state is the signed-in answer.
    await waitFor("the signed-in state", async () => (await savedState())?.signedIn === true, 10_000);
    await noAddress();
  } finally {
    // Back to the keyless tier for the tests after this one.
    await via.evaluate(() => chrome.runtime.sendMessage({ kind: "signOut" }));
    net.assessDelayMs.clear();
    await waitFor("the keyless state", async () => (await savedState())?.signedIn === false, 10_000);
    await page.close();
  }
});
