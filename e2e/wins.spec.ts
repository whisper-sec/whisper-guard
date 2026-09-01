// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: the daily protection-wins tally, against the real built
// extension with the whole network answered locally. The matrix: a REAL
// pre-emptive block increments the counter; the stored record is category
// + count ONLY (no host, ever, asserted against the raw storage bytes);
// the popup's calm "today" card shows the hero number + breakdown; silent
// and ambient outcomes raise NO toast (no overlay, no injected UI, no
// notifications surface at all); a confirmed identity verification counts;
// the tally survives a REAL service-worker restart (runtime.reload) while
// resetting only by calendar date; and, keyed and enrolled, the popup's
// display-time re-verification on every open counts the identity win ONCE
// per day, never once per render.

import { test, expect } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openPopup,
  restartExtension,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;
let shieldDist: string;

const EVIL = "evil-wins-target-e2e.com";
const AMBER = "amber-wins-page-e2e.com";
const CLEAN = "clean-wins-target-e2e.com";
const START = {
  block: "start1-wins-guard-e2e.com",
  silent: "start2-wins-guard-e2e.com",
};
const IDENTITY_ADDR = "2a04:2a01:e2e:7777::1";
function startHtml(host: string): string {
  return `<!doctype html>
<html><head><title>${host}</title></head>
<body>
  <h1>${host}</h1>
  <a id="lnk-evil" href="https://${EVIL}/lure">win a prize</a>
  <a id="lnk-clean" href="https://${CLEAN}/ok">clean offsite</a>
</body></html>`;
}

/** Any injected Guard UI mounts on a max-z-index host element. */
const OVERLAY = "div[style*='2147483647']";

async function waitArmed(tabId: number): Promise<void> {
  await expect
    .poll(
      async () =>
        ext.sw.evaluate(async (id: number) => {
          try {
            const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as
              | { armed?: boolean }
              | undefined;
            return r?.armed === true;
          } catch {
            return false;
          }
        }, tabId),
      { timeout: 15_000 },
    )
    .toBe(true);
}

interface StoredWins {
  date?: string;
  counts?: Record<string, number>;
}

async function storedWins(): Promise<{ raw: string; rec: StoredWins }> {
  const rec = await ext.sw.evaluate(async () => {
    const s = await chrome.storage.local.get("wins");
    return (s["wins"] ?? null) as StoredWins | null;
  });
  return { raw: JSON.stringify(rec ?? {}), rec: rec ?? {} };
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(EVIL, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict(AMBER, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  for (const host of Object.values(START)) {
    net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
    net.setPage(host, startHtml(host));
  }
  net.addEndpoint({ agent: "agent-wins-e2e", address: IDENTITY_ADDR, label: "wins-e2e" });
  shieldDist = makeShieldDist();
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: shieldDist });
  await setKey(ext, null); // keyless throughout: wins are a keyless feature
  // amberBanner/fieldGuard OFF so the AMBER page exercises the pure
  // ambient rung (icon only), with zero injected UI to tell apart.
  await setSettings(ext, { shield: true, amberBanner: false, fieldGuard: false, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("a real pre-emptive block increments the wins counter; the record is category + count ONLY", async () => {
  const { page, tabId } = await visit(ext, `https://${START.block}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  net.clearLog();

  await page.click("#lnk-evil");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);
  expect(net.requestsTo(EVIL).filter((r) => r.scheme === "https")).toHaveLength(0);

  await expect
    .poll(async () => (await storedWins()).rec.counts?.["preemptBlock"] ?? 0, { timeout: 5000 })
    .toBe(1);

  // Privacy: the stored record carries a date and counts, nothing else:
  // no URL, no domain, no hostname, asserted on the raw bytes.
  const { raw, rec } = await storedWins();
  expect(raw).not.toContain("e2e.com");
  expect(raw).not.toContain(EVIL);
  expect(Object.keys(rec).sort()).toEqual(["counts", "date"]);
  expect(rec.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  await page.keyboard.press("Escape"); // Go back; the block still counted
  await page.close();
});

test("the popup's calm today card: one hero number + the per-category breakdown", async () => {
  const { page, tabId } = await visit(ext, `https://${START.silent}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#today-hero")).toHaveText("1");
  // Exactly one win today, so the breakdown reads in the singular: the one
  // place the count is shown must not mis-count its own arithmetic.
  await expect(popup.locator("#today-breakdown")).toHaveText(
    "1 risky click stopped before anything loaded",
  );
  await expect(popup.locator("#today-note")).toContainText("category only, never which sites");
  await popup.close();
  await page.close();
});

test("silent and ambient outcomes raise NO toast: no injected UI, no badge residue, no notifications surface at all", async () => {
  // Ambient: a MEDIUM page changes the toolbar signal and nothing else
  // (banner settings off => the conversational rung degrades to ambient).
  const amber = await visit(ext, `https://${AMBER}/`);
  await waitForIcon(ext, amber.tabId, ["suspicious"]);
  expect(await amber.page.locator(OVERLAY).count()).toBe(0);
  // The one-time sighting pulse decays; no persistent badge remains.
  await expect
    .poll(
      async () =>
        ext.sw.evaluate(async (id: number) => chrome.action.getBadgeText({ tabId: id }), amber.tabId),
      { timeout: 5000 },
    )
    .toBe("");
  await amber.page.close();

  // Silent: a clean off-site click is vetted and waved through untouched.
  const { page, tabId } = await visit(ext, `https://${START.silent}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitArmed(tabId);
  await page.click("#lnk-clean");
  await page.waitForURL(`https://${CLEAN}/ok`, { timeout: 15_000 });
  expect(await page.locator(OVERLAY).count()).toBe(0);
  expect(
    await ext.sw.evaluate(async (id: number) => chrome.action.getBadgeText({ tabId: id }), tabId),
  ).toBe("");

  // Silent outcomes count nothing and announce nothing; and the extension
  // holds NO notifications capability, so a toast is impossible, not just
  // avoided.
  const { rec } = await storedWins();
  expect(rec.counts?.["preemptBlock"] ?? 0).toBe(1);
  expect(
    await ext.sw.evaluate(() => typeof (chrome as { notifications?: unknown }).notifications),
  ).toBe("undefined");
  await page.close();
});

test("a confirmed identity verification counts as a quiet win", async () => {
  const { page, tabId } = await visit(ext, `https://${START.silent}/`);
  const popup = await openPopup(ext, tabId);
  await popup.evaluate(
    async (ip: string) => chrome.runtime.sendMessage({ kind: "verifyIdentity", ip }),
    IDENTITY_ADDR,
  );
  await expect
    .poll(async () => (await storedWins()).rec.counts?.["identityVerified"] ?? 0, { timeout: 5000 })
    .toBe(1);
  const { raw } = await storedWins();
  expect(raw).not.toContain(IDENTITY_ADDR); // never the address, only the count
  await popup.close();
  await page.close();
});

test("wins persist across a REAL service-worker restart and stay date-keyed", async () => {
  const before = (await storedWins()).rec;
  expect((before.counts?.["preemptBlock"] ?? 0) + (before.counts?.["identityVerified"] ?? 0)).toBe(2);

  // Full relaunch on the same profile: the old worker's memory is gone,
  // a fresh worker boots, storage.local is all that survives.
  ext = await restartExtension(ext, { proxyPort: net.proxyPort, dist: shieldDist });

  const after = (await storedWins()).rec;
  expect(after).toEqual(before);

  // The popup renders the persisted tally through the real getWins path.
  const { page, tabId } = await visit(ext, `https://${START.silent}/`);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#today-hero")).toHaveText("2");
  // Two wins, one per category, so BOTH breakdown lines read in the singular.
  await expect(popup.locator("#today-breakdown")).toContainText("1 endpoint identity verified");
  await expect(popup.locator("#today-breakdown")).toContainText(
    "1 risky click stopped before anything loaded",
  );
  await popup.close();
  await page.close();
});

test("keyed: the popup's display-time re-verification never inflates the tally", async () => {
  // Sign in and enroll, so loadIdentityCard's signed-in branch re-verifies
  // the enrolled address on EVERY popup open, the display path that must
  // count the day's win once, not once per render.
  await setKey(ext, MOCK_KEY);
  const { page, tabId } = await visit(ext, `https://${START.silent}/`);

  // Enroll from an extension page (the popup), like the real CTA does.
  // enrollBrowser verifies directly (not via the message handler), so the
  // enrollment itself records nothing.
  const first = await openPopup(ext, tabId);
  const address = await first.evaluate(async () => {
    const r = (await chrome.runtime.sendMessage({ kind: "enroll" })) as {
      ok: boolean;
      enrollment?: { address: string };
    };
    return r.ok ? (r.enrollment?.address ?? null) : null;
  });
  await first.close();
  expect(address, "the browser enrolled a real identity on the mock control plane").toBeTruthy();

  // Today's identity win already stands (counted once, above).
  expect((await storedWins()).rec.counts?.["identityVerified"] ?? 0).toBe(1);

  // Open the popup repeatedly; each open completes a REAL confirmed
  // verification round-trip (the chip lands on VERIFIED only after the
  // verifyIdentity response, whose win recording is awaited first).
  for (let i = 0; i < 3; i++) {
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 15_000 });
    await popup.close();
  }

  // Still exactly one: the day's win, not a per-render tick. And the
  // stored record never carries the address: category + count only.
  const { raw, rec } = await storedWins();
  expect(rec.counts?.["identityVerified"] ?? 0).toBe(1);
  expect(raw).not.toContain(address as string);
  await page.close();
});
