// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The popup keeps its loader until the whole answer is in. While a site is
// being checked the popup never draws a verdict, and never draws "No verdict
// yet": a check that runs past the popup's wait ends as "could not check" at
// the limit, and the popup redraws when the check settles later. The verdict,
// "Why this verdict", the age line and the facts appear in one draw. The
// toolbar shows the checking tile from the moment an eligible page commits
// until its check settles, and the toolbar and the popup agree at the end.
//
// What the reader sees is recorded inside the popup, one entry whenever what
// is visible changes, sampled every animation frame, so no test waits on a
// guessed pause. The stand-in network holds an answer's body (headers at
// once) or the explain and facts reads, with its own hooks.

import { test, expect, type Page } from "@playwright/test";
import { CHECK_LIMIT_MS } from "../src/shared/config";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  extensionPage,
  iconState,
  launchExtension,
  markHostBlocked,
  rebindWorker,
  setKey,
  setSettings,
  stopWorker,
  visit,
  navigateInTab,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const DAY = 86_400_000;
const CLEAN = { band: "NONE", coverage: "known-clean", label: "clean" } as const;
const NO_VERDICT = "No verdict yet for this site.";
const COULD_NOT = "COULD NOT CHECK";
const CLEAN_CHIP = "NO KNOWN THREAT";

/** Three weighted threat sources whose weights add up to the score. */
const WEIGHTED = [
  {
    score: 47.5,
    sources: [
      { feedId: "e2e-newreg-feed", weight: 10 },
      { feedId: "e2e-typo-feed", weight: 20 },
      { feedId: "e2e-young-feed", weight: 17.5 },
    ],
  },
];

let nextAddress = 10;

/** A host the graph knows, with a verdict, an explain row, a walk and an age. */
function seed(host: string, band = "MEDIUM", o: { owner?: string; ageDays?: number } = {}): void {
  net.setVerdict(host, { band, coverage: "partial", label: "suspicious" });
  net.setEnrich(host, {
    ip: `198.51.100.${nextAddress++}`,
    city: "London, GB",
    country: "GB",
    asn: "AS64541",
    owner: o.owner ?? "MediaCo plc",
    asnName: "MEDIACO - MediaCo plc",
    prefix: "198.51.100.0/24",
    threatNeighbors: 0,
    prevalence: 812,
    verdict: band,
  });
  net.setIdentify(host, [
    { host, canonical_name: "MediaCo", category: "media", roles: ["ORIGIN_AS"], confidence: 0.85, host_class: "single_tenant", evidence: [] },
  ]);
  net.setExplain(host, WEIGHTED);
  const created = new Date(Date.now() - (o.ageDays ?? 5) * DAY).toISOString();
  net.setHistory(host, [{ createDate: created, updateDate: created }]);
}

// ----------------------------------------------------------- the recorder

interface Frame {
  at: number;
  ring: boolean;
  verdict: boolean;
  why: boolean;
  facts: boolean;
  age: boolean;
  lookalike: boolean;
  blocked: boolean;
}

interface Seen {
  texts: string[];
  frames: Frame[];
  chips: { chip: string; at: number }[];
  notes: string[];
}

/** Runs in the popup before its own scripts: one entry per change of what is
 *  visible, read every animation frame. */
const RECORDER = `(() => {
  const vis = (sel) => { const e = document.querySelector(sel); return !!e && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== "hidden"; };
  const text = (sel) => (document.querySelector(sel) && document.querySelector(sel).textContent || "").trim();
  const w = window;
  w.__frames = []; w.__chips = []; w.__notes = []; w.__texts = [];
  let prev = "";
  let prevText = "";
  const tick = () => {
    const f = { ring: vis(".pp-ring"), verdict: vis("#host-row"), why: vis("#protect-card"), facts: vis("#chain-card"), age: vis("#band-age"), lookalike: vis("#lookalike"), blocked: vis("#blocked-card") };
    const at = performance.timeOrigin + performance.now();
    const key = JSON.stringify(f);
    if (key !== prev) { prev = key; w.__frames.push({ at, ...f }); }
    const body = document.body ? document.body.innerText : "";
    if (body !== prevText) { prevText = body; w.__texts.push(body); }
    if (f.verdict) {
      const chip = text("#band-chip"), note = text("#band-note");
      if (!w.__chips.length || w.__chips[w.__chips.length - 1].chip !== chip) w.__chips.push({ chip, at });
      if (!w.__notes.includes(note)) w.__notes.push(note);
    }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
})();`;

/** Open the popup for a tab with the recorder in place, and optionally a clock
 *  that runs ahead (only the popup's own reading of the time). */
async function openWatched(tabId: number, opts: { skewMs?: number; reducedMotion?: boolean } = {}): Promise<Page> {
  const page = await ext.context.newPage();
  if (opts.reducedMotion) await page.emulateMedia({ reducedMotion: "reduce" });
  if (opts.skewMs) {
    await page.addInitScript(`(() => { const real = Date.now.bind(Date); Date.now = () => real() + ${opts.skewMs}; })();`);
  }
  await page.addInitScript(RECORDER);
  await page.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
  return page;
}

async function seen(popup: Page): Promise<Seen> {
  return popup.evaluate(() => {
    const w = window as unknown as {
      __frames: Frame[];
      __chips: { chip: string; at: number }[];
      __notes: string[];
      __texts: string[];
    };
    return { frames: w.__frames, chips: w.__chips, notes: w.__notes, texts: w.__texts };
  });
}

/** While the ring showed, no verdict and none of its evidence was drawn. */
function expectNothingBesideTheRing(frames: Frame[]): void {
  const mixed = frames.filter((f) => f.ring && (f.verdict || f.why || f.facts || f.age));
  expect(mixed, "a verdict or its evidence was drawn while the ring showed").toEqual([]);
}

/** The verdict, "Why this verdict", the facts and the age line first showed in one frame. */
function expectOneDraw(frames: Frame[]): void {
  const first = (pick: (f: Frame) => boolean): number => frames.findIndex(pick);
  const verdict = first((f) => f.verdict);
  expect(verdict, "the verdict was never drawn").toBeGreaterThanOrEqual(0);
  expect(first((f) => f.why), "Why this verdict was not drawn in the verdict's frame").toBe(verdict);
  expect(first((f) => f.facts), "the facts were not drawn in the verdict's frame").toBe(verdict);
  expect(first((f) => f.age), "the age line was not drawn in the verdict's frame").toBe(verdict);
}

const assessRequest = (host: string) =>
  net
    .requestsTo(GRAPH_READ_HOST)
    .find((r) => r.body.includes("whisper.assess") && r.body.includes(host));

// ------------------------------------------------- unchecked-tab scaffolding

const stateKey = (tabId: number) => `tabState:${tabId}`;

async function sessionStore(): Promise<Record<string, unknown>> {
  const page = await extensionPage(ext);
  return page.evaluate(() => chrome.storage.session.get(null));
}

/** Visit a host, let Guard settle on it, then leave the fresh worker holding nothing for the tab. */
async function visitUnchecked(host: string): Promise<{ page: Page; tabId: number }> {
  net.setVerdict(host, CLEAN);
  const tab = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tab.tabId, ["benign"]);
  await expect.poll(async () => stateKey(tab.tabId) in (await sessionStore()), { timeout: 8000 }).toBe(true);
  await expect
    .poll(async () => host in (((await sessionStore())["verdicts"] as Record<string, unknown> | undefined) ?? {}), { timeout: 8000 })
    .toBe(true);
  await stopWorker(ext);
  const via = await extensionPage(ext);
  await via.evaluate(async (k) => {
    await chrome.storage.session.remove(["verdicts", k]);
    await chrome.storage.local.remove("navlog");
  }, stateKey(tab.tabId));
  return tab;
}

// ------------------------------------------------------------ the worker log

/** Record every title the worker paints on a tab, in order. The title is the last step of a paint. */
async function recordTitles(): Promise<void> {
  await ext.sw.evaluate(() => {
    const g = globalThis as unknown as { __titles?: { tabId: number; title: string; at: number }[]; __setTitle?: unknown };
    g.__titles = [];
    const action = chrome.action as unknown as { setTitle: (d: { tabId?: number; title: string }) => Promise<void> };
    if (!g.__setTitle) g.__setTitle = action.setTitle.bind(chrome.action);
    const orig = g.__setTitle as (d: { tabId?: number; title: string }) => Promise<void>;
    action.setTitle = (d) => {
      g.__titles!.push({ tabId: d.tabId ?? -1, title: d.title, at: Date.now() });
      return orig(d);
    };
  });
}

async function titleLog(tabId: number): Promise<{ title: string; at: number }[]> {
  return ext.sw.evaluate(
    (id: number) =>
      ((globalThis as unknown as { __titles: { tabId: number; title: string; at: number }[] }).__titles ?? [])
        .filter((t) => t.tabId === id)
        .map((t) => ({ title: t.title, at: t.at })),
    tabId,
  );
}

async function titlesOf(tabId: number): Promise<string[]> {
  return ext.sw.evaluate(
    (id: number) =>
      ((globalThis as unknown as { __titles: { tabId: number; title: string }[] }).__titles ?? [])
        .filter((t) => t.tabId === id)
        .map((t) => t.title),
    tabId,
  );
}

/**
 * Hold the worker's read of the stored key, which is the first thing a check
 * waits on, until the returned function is called. A tile painted while it is
 * held was painted by the early paint, not by the check.
 */
async function holdKeyRead(): Promise<() => Promise<void>> {
  await ext.sw.evaluate(() => {
    const g = globalThis as unknown as { __release?: () => void; __getKey?: unknown };
    const local = chrome.storage.local as unknown as { get: (...a: unknown[]) => Promise<unknown> };
    const orig = local.get.bind(chrome.storage.local);
    g.__getKey = orig;
    const gate = new Promise<void>((r) => (g.__release = r));
    local.get = (...a: unknown[]) => (a[0] === "apiKey" ? gate.then(() => orig(...a)) : orig(...a));
  });
  let released = false;
  return async () => {
    if (released) return;
    released = true;
    await ext.sw.evaluate(() => {
      const g = globalThis as unknown as { __release?: () => void; __getKey?: (...a: unknown[]) => Promise<unknown> };
      (chrome.storage.local as unknown as { get: unknown }).get = g.__getKey!;
      g.__release?.();
    });
  };
}

const CHECKING_TITLE = "Whisper Guard: checking this site";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
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
  net.assessBodyDelayMs.clear();
  net.queryDelayMs.clear();
  net.lateAnswered.clear();
});

// ----------------------------------------------------------- the time limit

test("a graph answer whose body is held past the time limit ends the check at the limit and the toolbar leaves the checking tile", async () => {
  const host = "body-held-toolbar-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  net.assessBodyDelayMs.set(host, 30_000);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  // The headers came at once; only the body is held. The check still ends.
  await waitForIcon(ext, tabId, ["unknown"], CHECK_LIMIT_MS + 1000);
  await page.close();
});

test("a check held past the popup's old wait never shows No verdict yet and ends as could not check, with the toolbar in agreement", async () => {
  const host = "body-held-popup-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  net.assessBodyDelayMs.set(host, 30_000);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#checking-view")).toBeVisible();
  await expect(popup.locator("#checking-view")).toBeHidden({ timeout: CHECK_LIMIT_MS + 3000 });

  const s = await seen(popup);
  expect(s.notes, "the popup said no verdict for a check that was not over").not.toContain(NO_VERDICT);
  await expect(popup.locator("#band-chip")).toHaveText(COULD_NOT);
  await expect(popup.locator("#band-note")).toHaveText("Not confirmed either way. On-device checks still ran.");
  expectNothingBesideTheRing(s.frames);
  const ended = s.chips.find((c) => c.chip === COULD_NOT);
  const sent = assessRequest(host);
  expect(sent, "no assess request reached the graph").toBeTruthy();
  expect(ended!.at - sent!.at, "could not check came after the limit").toBeLessThan(CHECK_LIMIT_MS);
  expect(await iconState(ext, tabId)).toBe("unknown");
  await popup.close();
  await page.close();
});

test("a check that settles after the popup drew could not check redraws the site part from the settled state", async () => {
  const host = "settles-late-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  // In time for the worker (its limit is the graph's), late for a popup whose
  // clock runs ahead by all but a second of the limit.
  net.assessDelayMs.set(host, 3000);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const popup = await openWatched(tabId, { skewMs: CHECK_LIMIT_MS - 1000 });
  await expect(popup.locator("#band-chip")).toHaveText(CLEAN_CHIP, { timeout: 10_000 });
  const s = await seen(popup);
  expect(s.chips.map((c) => c.chip)).toEqual([COULD_NOT, CLEAN_CHIP]);
  expect(s.notes).not.toContain(NO_VERDICT);
  // Nothing of the first answer is left behind.
  await expect(popup.locator("#graph-error")).toBeHidden();
  await expect(popup.locator("#band-note")).not.toHaveText("Not confirmed either way. On-device checks still ran.");
  expect(await iconState(ext, tabId)).toBe("benign");
  await popup.close();
  await page.close();
});

test("a slow verdict that lands in time is drawn when it lands, with the ring until then", async () => {
  const host = "slow-in-time-guard-e2e.com";
  seed(host);
  net.assessDelayMs.set(host, 2500);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#chain-mount .ch-rung").first()).toBeVisible({ timeout: 10_000 });
  const s = await seen(popup);
  expectNothingBesideTheRing(s.frames);
  const ringFrom = s.frames.find((f) => f.ring)!;
  const drawn = s.frames.find((f) => f.verdict)!;
  expect(drawn.at - ringFrom.at, "the verdict was drawn before the check was in").toBeGreaterThan(1500);
  expectOneDraw(s.frames);
  await expect(popup.locator("#band-chip")).toHaveText("SUSPICIOUS · MEDIUM");
  expect(await iconState(ext, tabId)).toBe("suspicious");
  await popup.close();
  await page.close();
});

// ---------------------------------------------------------- one draw

test("the verdict, Why this verdict, the age line and the facts appear in one frame while the explain and facts reads are slow", async () => {
  const host = "one-draw-guard-e2e.com";
  seed(host);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  net.queryDelayMs.set("whisper.explain", 800);
  net.queryDelayMs.set("whisper.enrich", 1500);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#chain-mount .ch-rung").first()).toBeVisible({ timeout: 10_000 });
  const s = await seen(popup);
  expect(s.frames.some((f) => f.ring), "the ring never showed").toBe(true);
  expectNothingBesideTheRing(s.frames);
  expectOneDraw(s.frames);
  await popup.close();
  await page.close();
});

test("a fact read that fails keeps its could-not-be-read words and the verdict is still drawn with Why this verdict", async () => {
  const host = "one-draw-failed-facts-guard-e2e.com";
  seed(host);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  net.failQueries.add("whisper.enrich");
  net.failQueries.add("whisper.history");
  net.queryDelayMs.set("whisper.explain", 600);
  try {
    const popup = await openWatched(tabId);
    await expect(popup.locator("#band-chip")).toHaveText("SUSPICIOUS · MEDIUM", { timeout: 10_000 });
    const s = await seen(popup);
    expectNothingBesideTheRing(s.frames);
    const verdict = s.frames.findIndex((f) => f.verdict);
    expect(s.frames.findIndex((f) => f.why)).toBe(verdict);
    expect(s.frames.findIndex((f) => f.facts)).toBe(verdict);
    await expect(popup.locator("#chain-note")).toContainText("could not be read just now");
    await popup.close();
  } finally {
    net.failQueries.clear();
  }
  await page.close();
});

// ------------------------------------------- the on-device parts draw at once

test("a look-alike card and the session's blocked list show beside the loader while the check runs", async () => {
  const host = "www.dr0pbox.com";
  const blocked = "blocked-beside-loader-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  net.assessDelayMs.set(host, 2500);
  await markHostBlocked(ext, blocked);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const popup = await openWatched(tabId);
  try {
    await expect(popup.locator("#checking-view")).toBeVisible();
    await expect(popup.locator("#lookalike")).toBeVisible();
    await expect(popup.locator("#btn-goto")).toBeVisible();
    await expect(popup.locator("#blocked-card")).toBeVisible();
    await expect(popup.locator("#blocked-body")).toContainText(blocked);
    await expect(popup.locator("#host-row")).toBeVisible({ timeout: 10_000 });
    const s = await seen(popup);
    // The on-device parts read nothing from the check: both were drawn
    // before the verdict, beside the ring.
    const at = (pick: (f: Frame) => boolean): number => s.frames.findIndex(pick);
    expect(at((f) => f.ring && f.lookalike), "the look-alike card waited for the check").toBeGreaterThanOrEqual(0);
    expect(at((f) => f.ring && f.blocked), "the blocked list waited for the check").toBeGreaterThanOrEqual(0);
    expect(at((f) => f.verdict)).toBeGreaterThan(at((f) => f.ring && f.lookalike && f.blocked));
  } finally {
    await ext.sw.evaluate(() => chrome.storage.session.remove("blocked"));
  }
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------- the toolbar

test("the toolbar shows the checking tile from the commit of an eligible page, before the check has begun", async () => {
  const host = "commit-paint-guard-e2e.com";
  net.setVerdict(host, CLEAN);
  net.assessDelayMs.set(host, 1200);
  // Hold the check's first read, so the check itself has not begun when the page commits.
  const release = await holdKeyRead();
  try {
    const { page, tabId } = await visit(ext, `https://${host}/`);
    await waitForIcon(ext, tabId, ["checking"], 3000);
    await release();
    await waitForIcon(ext, tabId, ["benign"]);
    await page.close();
  } finally {
    await release();
  }
});

test("a superseded navigation never ends on the checking tile and a page answered from the cache never shows it", async () => {
  const a = "superseded-a-guard-e2e.com";
  const b = "superseded-b-guard-e2e.com";
  net.setVerdict(a, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setVerdict(b, CLEAN);
  await recordTitles();
  net.assessDelayMs.set(a, 2000);
  const { page, tabId } = await visit(ext, `https://${a}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  await net.waitForAssessRequest(a);
  await navigateInTab(page, `https://${b}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await net.waitForLateAnswer(a);
  // The late answer has been sent; wait until the worker could have acted on it.
  await expect.poll(async () => (await titlesOf(tabId)).at(-1)).not.toBe(CHECKING_TITLE);
  const titles = await titlesOf(tabId);
  const firstSettled = titles.findIndex((t) => t !== CHECKING_TITLE);
  expect(firstSettled, "no verdict tile was painted").toBeGreaterThan(-1);
  expect(titles.slice(firstSettled), "the checking tile came back after a verdict").not.toContain(CHECKING_TITLE);
  expect(await iconState(ext, tabId)).toBe("benign");
  expect(titles.at(-1)).toBe("Whisper Guard: no known threat on this site");

  // The second visit to b is answered from the cache: it may paint its own tile first.
  const again = await visit(ext, `https://${b}/`);
  await waitForIcon(ext, again.tabId, ["benign"]);
  const second = await titlesOf(again.tabId);
  expect(second.length, "no tile was painted for the cached page").toBeGreaterThan(0);
  expect(second, "the checking tile showed for a page answered from the cache").not.toContain(CHECKING_TITLE);
  await again.page.close();
  await page.close();
});

// --------------------------------------------------- Check this site now

test("Check this site now on a check held past the limit never shows No verdict yet, ends as could not check, and the toolbar agrees", async () => {
  const host = "press-held-guard-e2e.com";
  const { page, tabId } = await visitUnchecked(host);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#not-checked-view")).toBeVisible();
  await rebindWorker(ext);
  net.assessBodyDelayMs.set(host, 30_000);
  await popup.locator("#btn-check-now").click();
  await expect(popup.locator("#checking-view")).toBeVisible();
  await expect.poll(() => iconState(ext, tabId)).toBe("checking");
  await expect(popup.locator("#checking-view")).toBeHidden({ timeout: CHECK_LIMIT_MS + 3000 });
  const s = await seen(popup);
  expect(s.notes, "the popup said no verdict for a check that was not over").not.toContain(NO_VERDICT);
  await expect(popup.locator("#band-chip")).toHaveText(COULD_NOT);
  expectNothingBesideTheRing(s.frames);
  await expect.poll(() => iconState(ext, tabId)).toBe("unknown");
  await popup.close();
  await page.close();
});

test("Check this site now draws the verdict, Why this verdict, the age line and the facts in one frame, with the checking tile until then", async () => {
  const host = "press-one-draw-guard-e2e.com";
  const { page, tabId } = await visitUnchecked(host);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#not-checked-view")).toBeVisible();
  await rebindWorker(ext);
  seed(host);
  net.assessDelayMs.set(host, 1500);
  net.queryDelayMs.set("whisper.explain", 800);
  net.queryDelayMs.set("whisper.enrich", 1200);
  await recordTitles();
  const release = await holdKeyRead();
  try {
    await popup.locator("#btn-check-now").click();
    await expect(popup.locator("#checking-view")).toBeVisible();
    // The check is held at its first read: only the early paint can have painted this.
    await expect.poll(() => iconState(ext, tabId)).toBe("checking");
  } finally {
    await release();
  }
  await expect(popup.locator("#chain-mount .ch-rung").first()).toBeVisible({ timeout: 12_000 });
  const s = await seen(popup);
  expect(s.frames.some((f) => f.ring)).toBe(true);
  expectNothingBesideTheRing(s.frames);
  expectOneDraw(s.frames);
  await expect.poll(() => iconState(ext, tabId)).toBe("suspicious");
  // The checking tile was the tile from before the ring showed until the answer was sent.
  const log = await titleLog(tabId);
  const firstOther = log.findIndex((t) => t.title !== CHECKING_TITLE);
  expect(firstOther, "no verdict tile was painted").toBeGreaterThan(0);
  expect(log[0]!.title).toBe(CHECKING_TITLE);
  expect(log[firstOther]!.at, "the verdict tile came before the answer").toBeGreaterThanOrEqual(net.lateAnswered.get(host)! - 5);
  await popup.close();
  await page.close();
});

// ------------------------------------------------ one name, one assess

test("opening the popup during a held check sends exactly one assess for the name", async () => {
  const host = "one-assess-popup-guard-e2e.com";
  seed(host);
  net.assessDelayMs.set(host, 2500);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await net.waitForAssessRequest(host);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#band-chip")).toHaveText("SUSPICIOUS · MEDIUM", { timeout: 10_000 });
  const sent = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.assess") && r.body.includes(host));
  expect(sent).toHaveLength(1);
  await popup.close();
  await page.close();
});

test("the explain and the facts are asked of the graph before the verdict's answer is sent", async () => {
  const host = "side-by-side-guard-e2e.com";
  seed(host);
  net.assessDelayMs.set(host, 2500);
  net.queryDelayMs.set("whisper.explain", 2500);
  net.queryDelayMs.set("whisper.enrich", 2500);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await net.waitForAssessRequest(host);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#chain-mount .ch-rung").first()).toBeVisible({ timeout: 15_000 });
  const s = await seen(popup);
  const drawn = s.frames.find((f) => f.verdict)!;
  expect(drawn).toBeTruthy();
  // Both reads reached the graph before the assess answer was sent: they ran beside it.
  const answeredAt = net.lateAnswered.get(host)!;
  const asked = (needle: string) =>
    net.requestsTo(GRAPH_READ_HOST).find((r) => r.body.includes(needle) && r.body.includes(host));
  expect(asked("whisper.explain")!.at, "the explain waited for the verdict").toBeLessThan(answeredAt);
  expect(asked("whisper.enrich")!.at, "the facts waited for the verdict").toBeLessThan(answeredAt);
  expectOneDraw(s.frames);
  await popup.close();
  await page.close();
});

test("a tab that moves to a second name while the popup waits on the first ends with the second name's verdict and facts and none of the first's", async () => {
  const a = "moves-from-guard-e2e.com";
  const b = "moves-to-guard-e2e.com";
  seed(a, "MEDIUM", { owner: "Intranet Tools B.V.", ageDays: 11 });
  seed(b, "HIGH", { owner: "WorkMail Cloud GmbH", ageDays: 200 });
  net.assessDelayMs.set(a, 3000);
  const { page, tabId } = await visit(ext, `https://${a}/`);
  await net.waitForAssessRequest(a);
  const popup = await openWatched(tabId);
  await expect(popup.locator("#checking-host")).toHaveText(a);
  await navigateInTab(page, `https://${b}/`);
  await expect(popup.locator("#hostname")).toHaveText(b, { timeout: 15_000 });
  await expect(popup.locator("#band-chip")).toHaveText("HIGH RISK");
  await expect(popup.locator("#chain-mount")).toContainText("WorkMail Cloud");
  await expect(popup.locator("#band-age")).toContainText("7 months");
  const s = await seen(popup);
  for (const text of s.texts) {
    expect(text, "the first name's evidence was drawn").not.toContain("Intranet Tools");
    expect(text).not.toMatch(/\b11 days\b/);
  }
  expectNothingBesideTheRing(s.frames);
  await popup.close();
  await page.close();
});

test("a drawer read for the first name does not land under the second name", async () => {
  const a = "drawer-from-guard-e2e.com";
  const b = "drawer-to-guard-e2e.com";
  net.setVerdict(a, CLEAN);
  net.setExplain(a, [{ marker: "OldNameAnswerMarker" }]);
  seed(b, "MEDIUM", { owner: "WorkMail Cloud GmbH", ageDays: 200 });
  // Held for the popup, whose clock runs ahead, so it draws could not check and keeps listening.
  net.assessDelayMs.set(a, 3500);
  const { page, tabId } = await visit(ext, `https://${a}/`);
  await net.waitForAssessRequest(a);
  const popup = await openWatched(tabId, { skewMs: CHECK_LIMIT_MS - 2500 });
  await expect(popup.locator("#band-chip")).toHaveText(COULD_NOT, { timeout: 10_000 });
  await popup.locator("#expanders > summary").click();
  net.queryDelayMs.set("whisper.explain", 2000);
  const before = net.answered.length;
  // The popup asked the graph about the first name when it opened; only a
  // request after the press is the drawer's own.
  const explainsForA = (): number =>
    net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.explain") && r.body.includes(a)).length;
  const askedBefore = explainsForA();
  await popup.locator("#exp-why > summary").click();
  await expect(popup.locator("#why-body")).toHaveText("Asking the graph...");
  // The drawer's read is now held at the graph; the second name's reads are not.
  await expect.poll(explainsForA).toBeGreaterThan(askedBefore);
  net.queryDelayMs.clear();
  await navigateInTab(page, `https://${b}/`);
  await expect(popup.locator("#hostname")).toHaveText(b, { timeout: 15_000 });
  // The first name's answer has been sent, and the popup has since heard from the worker.
  await expect
    .poll(() => net.answered.slice(before).some((r) => r.query.includes("whisper.explain") && r.host === a))
    .toBe(true);
  await popup.evaluate(() => chrome.runtime.sendMessage({ kind: "getSession" }));
  await expect(popup.locator("#why-body")).not.toContainText("OldNameAnswerMarker");
  await popup.close();
  await page.close();
});

// ------------------------------------------------------- reduced motion

test("the ring and the placeholders have no running animation under reduced motion while the evidence is awaited", async () => {
  const host = "still-evidence-guard-e2e.com";
  seed(host);
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  net.queryDelayMs.set("whisper.explain", 2500);
  const popup = await openWatched(tabId, { reducedMotion: true });
  await expect(popup.locator(".pp-ring")).toBeVisible();
  const motion = await popup.evaluate(() => {
    const names = (el: Element): string[] => el.getAnimations().map((a) => (a as CSSAnimation).animationName);
    const placeholders = [...document.querySelectorAll(".pp-skel-pill, .pp-skel-bar")];
    return {
      ring: names(document.querySelector(".pp-ring")!),
      ringName: getComputedStyle(document.querySelector(".pp-ring")!).animationName,
      placeholders: placeholders.map(names),
      count: placeholders.length,
    };
  });
  expect(motion.ring).toEqual([]);
  expect(motion.ringName).toBe("none");
  expect(motion.count).toBe(6);
  for (const names of motion.placeholders) expect(names).toEqual([]);
  await popup.close();
  await page.close();
});
