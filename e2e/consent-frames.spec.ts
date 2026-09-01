// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: the cookie-consent auto-decline inside SUB-FRAMES, against the
// real built extension with the whole network answered locally.
//
// Why this exists. scanned the top frame's light DOM only, because
// document.querySelectorAll crosses no frame boundary. Measured against the
// real internet with the real built extension, that is not a corner case: of
// six large publishers, one was declined and every single miss was an iframe
// wall (Sourcepoint-shaped). The feature worked and reached almost none of
// the sites people actually read.
//
// What must be true after widening it, and what each test here pins:
//
//   1. a cross-origin CMP wall in an iframe is declined
//   2. a same-origin framed wall is declined
//   3. a page with TWO framed walls declines both and counts ONE win, because
//      the tally counts what Guard handled for you and a person who saw one
//      prompt disappear did not have two handled
//   4. the safety contract does not soften per frame: a decline-verb decoy
//      with no cookie word and no accept sibling is untouched inside a frame
//      exactly as it is in the top document
//   5. widening where the module RUNS did not widen what it may INTERCEPT:
//      the pre-emptive click guard is armed in the top frame and in no other
//
// Test 5 is the one that would be easy to leave out and is the reason to be
// careful here. Both layers ride the same content.js, so injecting it into
// every frame for the consent pass hands the click guard a new home for free
// unless something stops it.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

// Hostnames deliberately carry no consent-ish word, so a wire sweep can look
// for banner vocabulary without tripping over the fixtures' own names.
const TOP_X = "site-h-1022-guard-e2e.com"; // frames a wall on another origin
const CMP_X = "vendor-1022-guard-e2e.com"; // the other origin
const TOP_S = "site-i-1022-guard-e2e.com"; // frames a wall on its own origin
const TOP_2 = "site-j-1022-guard-e2e.com"; // frames TWO walls
const TOP_D = "site-k-1022-guard-e2e.com"; // frames a decoy that must be left alone
const TOP_L = "site-l-1022-guard-e2e.com"; // injects its wall frame AFTER load
const FRAME_PATH = "/w-frame";
/**
 * How long site l waits before injecting its wall frame.
 *
 * This has to be comfortably LONGER than the arming latency, or the test does
 * not test anything: arming is asynchronous (a settings read, a grant check
 * and a graph verdict all happen first), so a frame injected inside that
 * window is caught by the ordinary allFrames pass and the late path is never
 * exercised. At 1200ms the mutation proof came back green with the fix
 * removed, which is exactly the trap. Four seconds is past it, and matches the
 * order of magnitude a real consent platform takes.
 */
const LATE_FRAME_MS = 4000;

/** Any injected Guard UI mounts on a max-z-index host element. */
const OVERLAY = "div[style*='2147483647']";

/** Every button records its click in its OWN document. */
const RECORDER = `<script>
  window.__clicks = [];
  addEventListener("click", (ev) => {
    const b = ev.target && ev.target.closest ? ev.target.closest("button,[role='button'],input") : null;
    if (b) window.__clicks.push(b.id || b.className || b.tagName);
  }, true);
</script>`;

/** A OneTrust-shaped wall, as a whole document, for framing. */
function wallDoc(title: string): string {
  return `<!doctype html>
<html><head><title>${title}</title></head><body>
${RECORDER}
<div id="onetrust-consent-sdk">
  <div id="onetrust-banner-sdk" role="alertdialog" aria-label="Cookie banner"
       style="position:fixed;bottom:0;left:0;right:0;background:#eee;padding:16px">
    <p id="onetrust-policy-text">We use cookies to enhance your experience.</p>
    <div id="onetrust-button-group">
      <button id="onetrust-pc-btn-handler">Cookies Settings</button>
      <button id="onetrust-accept-btn-handler">Accept All Cookies</button>
      <button id="onetrust-reject-all-handler">Reject All</button>
    </div>
  </div>
</div>
<script>
  for (const b of document.querySelectorAll("#onetrust-button-group button")) {
    b.addEventListener("click", () => {
      document.getElementById("onetrust-banner-sdk").style.display = "none";
    });
  }
</script>
</body></html>`;
}

/**
 * A decline verb with NO cookie word and NO accept sibling: a session-expiry
 * modal. The top-frame suite already proves this is left alone; here it is
 * proving the same contract holds one frame down.
 */
function decoyDoc(): string {
  return `<!doctype html>
<html><head><title>decoy</title></head><body>
${RECORDER}
<div role="dialog" aria-label="Session" style="position:fixed;top:20px;left:20px;padding:16px;background:#fff">
  <p>Your session is about to expire. See our privacy policy for details.</p>
  <button id="decoy-decline">Decline and log out</button>
</div>
</body></html>`;
}

/**
 * A page with NO frame at load, which injects its wall frame a second later.
 * This is not an exotic fixture: it is what a consent platform does, and the
 * real-internet probe caught it. On theguardian.com and spiegel.de the
 * Sourcepoint frame reported the pass UNARMED after a 12 second settle, while
 * every frame that existed at nav time was armed, because executeScript is a
 * one-shot that cannot see a frame that does not exist yet.
 */
function lateFrameDoc(): string {
  return `<!doctype html>
<html><head><title>site l</title></head><body>
${RECORDER}
<h1>site l</h1>
<p>The wall arrives after load, the way a consent platform delivers one.</p>
<script>
  setTimeout(() => {
    const f = document.createElement("iframe");
    f.id = "f0";
    f.src = "https://${CMP_X}/";
    f.style.cssText = "width:600px;height:200px";
    document.body.appendChild(f);
  }, ${LATE_FRAME_MS});
</script>
</body></html>`;
}

function framingDoc(title: string, srcs: string[]): string {
  const frames = srcs
    .map((s, i) => `<iframe id="f${i}" src="${s}" style="width:600px;height:200px"></iframe>`)
    .join("\n");
  return `<!doctype html>
<html><head><title>${title}</title></head><body>
${RECORDER}
<h1>${title}</h1>
<p>No consent wall in this document at all. The wall is one frame down.</p>
${frames}
</body></html>`;
}

/** Clicks recorded inside one frame of the page, by frame index. */
async function frameClicks(page: import("@playwright/test").Page, i: number): Promise<string[]> {
  const f = page.frames()[i];
  if (!f) return [];
  try {
    return (await f.evaluate(() => (window as unknown as { __clicks?: string[] }).__clicks ?? [])) ?? [];
  } catch {
    return [];
  }
}

async function winCount(): Promise<number> {
  const rec = await ext.sw.evaluate(async () => {
    const s = await chrome.storage.local.get("wins");
    return (s["wins"] ?? null) as { counts?: Record<string, number> } | null;
  });
  return rec?.counts?.["cookieDecline"] ?? 0;
}

async function resetWins(): Promise<void> {
  await ext.sw.evaluate(async () => {
    await chrome.storage.local.remove("wins");
  });
}

/** Which frames of a tab have the consent pass armed, and which the click guard. */
async function frameArming(tabId: number): Promise<{ consent: number[]; preempt: number[] }> {
  return ext.sw.evaluate(async (id: number) => {
    const frames = (await chrome.webNavigation.getAllFrames({ tabId: id })) ?? [];
    const consent: number[] = [];
    const preempt: number[] = [];
    for (const f of frames) {
      let r: { armed?: boolean; consent?: boolean } | undefined;
      try {
        r = (await chrome.tabs.sendMessage(
          id,
          { kind: "whisper-preempt-ping" },
          { frameId: f.frameId },
        )) as { armed?: boolean; consent?: boolean } | undefined;
      } catch {
        continue; // no content script in that frame
      }
      if (r?.consent === true) consent.push(f.frameId);
      if (r?.armed === true) preempt.push(f.frameId);
    }
    return { consent, preempt };
  }, tabId);
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const host of [TOP_X, CMP_X, TOP_S, TOP_2, TOP_D, TOP_L]) {
    net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
  }
  net.setPage(CMP_X, wallDoc("vendor wall"));
  net.setPage(TOP_X, framingDoc("site h", [`https://${CMP_X}/`]));
  // Same-origin: the wall lives at its own PATH so the frame does not load
  // the framing document again and recurse.
  net.setPagePath(TOP_S, FRAME_PATH, wallDoc("own wall"));
  net.setPage(TOP_S, framingDoc("site i", [`https://${TOP_S}${FRAME_PATH}`]));
  net.setPagePath(TOP_2, FRAME_PATH, wallDoc("wall one"));
  net.setPage(TOP_2, framingDoc("site j", [`https://${TOP_2}${FRAME_PATH}`, `https://${CMP_X}/`]));
  net.setPagePath(TOP_D, FRAME_PATH, decoyDoc());
  net.setPage(TOP_D, framingDoc("site k", [`https://${TOP_D}${FRAME_PATH}`]));
  net.setPage(TOP_L, lateFrameDoc());

  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, null); // keyless throughout: auto-decline is a keyless feature
  await setSettings(ext, { shield: true, amberBanner: false, fieldGuard: false, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  await resetWins();
});

test("a CROSS-ORIGIN CMP wall in an iframe is declined, and counts one win", async () => {
  const { page, tabId } = await visit(ext, `https://${TOP_X}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  // The reject handle inside the FRAME is the one clicked, and only it. The
  // accept and the settings button sit right beside it in the same document.
  await expect.poll(() => frameClicks(page, 1), { timeout: 15_000 }).toEqual([
    "onetrust-reject-all-handler",
  ]);
  await expect(page.frames()[1].locator("#onetrust-banner-sdk")).toBeHidden();
  await expect.poll(winCount, { timeout: 5000 }).toBe(1);

  // The top document has no banner and must have been left entirely alone.
  expect(await frameClicks(page, 0)).toEqual([]);
  // Silent, like every other win: no injected Whisper UI anywhere.
  expect(await page.locator(OVERLAY).count()).toBe(0);
  await page.close();
});

test("a SAME-ORIGIN framed wall is declined too", async () => {
  const { page, tabId } = await visit(ext, `https://${TOP_S}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  await expect.poll(() => frameClicks(page, 1), { timeout: 15_000 }).toEqual([
    "onetrust-reject-all-handler",
  ]);
  await expect(page.frames()[1].locator("#onetrust-banner-sdk")).toBeHidden();
  await expect.poll(winCount, { timeout: 5000 }).toBe(1);
  await page.close();
});

test("TWO framed walls are both declined, and the page counts ONE win", async () => {
  const { page, tabId } = await visit(ext, `https://${TOP_2}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  // Both walls really are dismissed. This is the part a naive per-page guard
  // would break by declining once and stopping: two frames, two prompts, and
  // a person who only had one of them handled is worse off than before.
  await expect.poll(() => frameClicks(page, 1), { timeout: 15_000 }).toEqual([
    "onetrust-reject-all-handler",
  ]);
  await expect.poll(() => frameClicks(page, 2), { timeout: 15_000 }).toEqual([
    "onetrust-reject-all-handler",
  ]);

  // And the tally still reads one, because one page's prompts were handled.
  // Settle first: the assertion is that it never climbs, not that it has not
  // climbed yet.
  await page.waitForTimeout(1500);
  expect(await winCount()).toBe(1);
  await page.close();
});

test("the safety contract does not soften one frame down", async () => {
  const { page, tabId } = await visit(ext, `https://${TOP_D}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  // CONTROL: the pass really did arm in that frame, so the absence of a click
  // below is a decision and not a module that never ran. Without this the
  // test passes just as well when the whole feature is switched off.
  await expect
    .poll(async () => (await frameArming(tabId)).consent.length, { timeout: 15_000 })
    .toBeGreaterThan(1);

  // A lone "Decline and log out" in a privacy-mentioning modal has no cookie
  // word and no accept sibling. It is destructive and it is not consent.
  await page.waitForTimeout(1500);
  expect(await frameClicks(page, 1)).toEqual([]);
  expect(await frameClicks(page, 0)).toEqual([]);
  expect(await winCount()).toBe(0);
  await page.close();
});

test("the click guard is armed in the top frame and in NO other", async () => {
  const { page, tabId } = await visit(ext, `https://${TOP_X}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  // Wait for the consent pass to reach the sub-frame, so this is measured at
  // the moment the widening is fully in effect rather than before it.
  await expect
    .poll(async () => (await frameArming(tabId)).consent.length, { timeout: 15_000 })
    .toBeGreaterThan(1);

  const before = await frameArming(tabId);
  // The consent pass reached more than one frame: that is the feature.
  expect(before.consent.length).toBeGreaterThan(1);
  expect(before.consent).toContain(0);
  // The click guard reached exactly one, the top document: that is the bound.
  expect(before.preempt).toEqual([0]);

  // Now the case the ordering alone does not cover, and the reason the bound
  // lives in the content module rather than only in the caller. The nav
  // pipeline is debounced and re-arms, so a preempt config CAN be sent after
  // the consent pass has already put content.js in every frame. Broadcast one
  // exactly as an unpinned caller would, and the sub-frames must still refuse:
  // a click guard must never acquire a new home as a side effect of a change
  // about cookie banners.
  await ext.sw.evaluate(async (id: number) => {
    await chrome.tabs.sendMessage(id, {
      kind: "whisper-preempt-config",
      host: "site-h-1022-guard-e2e.com",
    });
  }, tabId);
  await page.waitForTimeout(800);

  const after = await frameArming(tabId);
  expect(after.preempt, "the click guard must stay in the top document").toEqual([0]);
  // CONTROL: the broadcast really did reach the sub-frames. Their consent
  // arming is the proof that a listener was there to hear it, so the refusal
  // above is a decision and not an undelivered message.
  expect(after.consent.length).toBeGreaterThan(1);
  await page.close();
});

/*
 * An OUTCOME test, and deliberately not sold as a guard.
 *
 * The mechanism it exercises in production is armConsentFrame, which arms a
 * frame that commits after the page did. Remove that function and this test
 * still passes, because in this harness something reaches the frame anyway and
 * I could not identify what inside a reasonable budget. A test that passes
 * either way is not a regression guard, and saying so is cheaper than letting
 * the next person trust it.
 *
 * The guard for that mechanism is the LIVE probe, e2e/consent-live.spec.ts,
 * which does discriminate and was mutation-proven against the real web:
 * 13/13 sub-frames armed with the fix, 7/13 without it, and the six it loses
 * are exactly the CMP frames (sourcepoint.theguardian.com, sp-spiegel-de,
 * consent-cdn.zeit.de, cmp.heise.de).
 *
 * What this one is still worth: it is the only place that asserts the whole
 * user-visible outcome for a late wall, from the frame appearing to the click
 * landing to the win counting once.
 */
test("a wall in a frame injected AFTER load is declined too", async () => {
  const { page, tabId } = await visit(ext, `https://${TOP_L}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  // CONTROL: at nav time this page has no sub-frame at all, so whatever
  // reaches the wall cannot be the one-shot injection that ran back then.
  expect(page.frames().length).toBe(1);

  // The frame arrives, and the pass has to arrive with it. executeScript is a
  // one-shot; a consent platform injects its wall after load; on the real web
  // that combination meant the frame that mattered was the one frame never
  // reached.
  await expect.poll(() => page.frames().length, { timeout: 10_000 }).toBe(2);
  await expect
    .poll(async () => (await frameArming(tabId)).consent.length, { timeout: 15_000 })
    .toBe(2);
  await expect.poll(() => frameClicks(page, 1), { timeout: 15_000 }).toEqual([
    "onetrust-reject-all-handler",
  ]);
  await expect.poll(winCount, { timeout: 5000 }).toBe(1);

  // The bound holds for a late frame as much as an early one.
  expect((await frameArming(tabId)).preempt).toEqual([0]);
  await page.close();
});
