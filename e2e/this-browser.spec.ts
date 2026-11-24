// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE THIS BROWSER TAB. The identity card, the last 24 hours and the
// footer's Active Shield readout.
//
// The tab shows one card for the browser's identity (one chip, the facts, one
// sentence, one button; signed out, the sign-in card in the same style), a
// "Last 24 hours" card with three figures, a time strip, a caption and a link
// to the dashboard, and a footer with the Active Shield state. Each claim is
// measured on the built extension:
//
//   - each of the four states shows its chip, sentence and single button;
//   - the address and the name can be selected and copied;
//   - the destination and flagged figures equal the dashboard's tiles, even
//     for destinations past the 200 the popup enriches;
//   - the tab fits 600 px signed out and in the steady signed-in states, and
//     the routed state is measured in both schemes with one and three
//     categories (its sentence keeps its full wording, so its fit is recorded);
//   - the state names are the same on the popup and on the dashboard;
//   - the footer reads Active Shield live, and the console link shows only
//     signed in.
//
// Fictional hosts only; hostnames are matched exactly, never by substring.

import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, GRAPH_READ_HOST, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeEgressDist,
  makeProxyHolderExt,
  openDashboard,
  openPopup,
  rebindWorker,
  selectPopupTab,
  setKey,
  setSettings,
  stopWorker,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";
import { expectBrowserTabFits, expectRoutedCardLayout } from "./helpers/popup-fit";
import { CONSOLE_URL } from "../src/shared/config";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(HERE, "../dist/chromium");

const CLEAN = "browser-tab-clean-guard-e2e.com";
const SECOND = "browser-tab-second-guard-e2e.com";
const FLAGGED = "browser-tab-flagged-guard-e2e.com";
const ANCHOR = "browser-tab-anchor-guard-e2e.com";

const HELD_SENTENCE = "Another extension controls the proxy setting. Your identity and verdicts still work.";
const ROUTE_BASE =
  "Every window in this profile leaves from this address, except tailnet and private-network destinations, which connect directly.";
const SECOND_LINE =
  "Private windows are not routed unless Whisper Guard is allowed in them. WebRTC is hardened to proxied-only.";

/** A fictional address that no stand-in RDAP record anchors. */
const SEEDED = {
  agent: "agent-browser-tab-guard-e2e",
  address: "2001:db8:aa:bb:cc:dd:ee:ff",
  label: "This browser (Whisper Guard)",
  fqdn: null as string | null,
};

function seedWorld(net: E2ENetwork): void {
  for (const host of [CLEAN, SECOND]) {
    net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
    net.setIdentify(host, [{ host, canonical_name: "MediaCo", category: "work", roles: [] }]);
  }
}

/** The buttons a reader can press in the identity control. */
function visibleButtons(popup: Page): ReturnType<Page["locator"]> {
  return popup.locator("#identity-control button:visible");
}

async function exactlyOneButton(popup: Page, text: string): Promise<void> {
  await expect(visibleButtons(popup)).toHaveCount(1);
  await expect(visibleButtons(popup)).toHaveText(text);
}

async function plantWins(ext: Extension, counts: Record<string, number>): Promise<void> {
  await ext.sw.evaluate(async (c: Record<string, number>) => {
    const d = new Date();
    const p = (n: number): string => String(n).padStart(2, "0");
    const date = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
    await chrome.storage.local.set({ wins: { date, counts: c } });
  }, counts);
}

/** Enrol and route from the popup if this browser has not done so yet; leaves it verified and routed. */
async function ensureRouted(popup: Page): Promise<void> {
  const protect = popup.locator("#btn-protect");
  // The control is settled once it carries a state other than busy.
  await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", /^(none|enrolled|routed|error|failed)$/, { timeout: 15_000 });
  await expect(protect).toHaveText(/Protect this browser|Turn routing off|Turn routing on/, { timeout: 15_000 });
  if ((await protect.textContent()) !== "Turn routing off") await protect.click();
  await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
  await expect(popup.locator("#route-line")).toContainText("Protected.", { timeout: 25_000 });
}

async function clearIdentity(ext: Extension): Promise<void> {
  await ext.sw.evaluate(() => chrome.storage.local.remove("egress"));
}

// ------------------------------------------- P: the plain build, routing refused

test.describe("This browser, on the plain build (the routing permission is refused)", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seedWorld(net);
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test.beforeEach(async () => {
    net.clearEndpoints();
    await setKey(ext, MOCK_KEY);
    await clearIdentity(ext);
  });

  test("NOT ENROLLED: the chip, the sentence and one button", async () => {
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await expect(popup.locator("#identity-state")).toHaveText("NOT ENROLLED", { timeout: 10_000 });
    await expect(popup.locator("#route-line")).toHaveText("No Whisper identity yet.");
    await expect(popup.locator("#identity-detail")).toBeHidden();
    await exactlyOneButton(popup, "Protect this browser");
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "none");
    await popup.close();
    await page.close();
  });

  test("ENROLLED: routing off and not verified shows the address and one button", async () => {
    await ext.sw.evaluate(
      (identity) => chrome.storage.local.set({ egress: { on: false, identity, config: null, error: null } }),
      SEEDED,
    );
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await expect(popup.locator("#identity-state")).toHaveText("ENROLLED", { timeout: 15_000 });
    // The stand-in record does not anchor this address, so the answer is no
    // and the rows that need a yes (the name and the proof) are not drawn.
    const rows = popup.locator("#identity-detail .w-kv");
    await expect(rows).toHaveCount(1);
    await expect(rows.locator(".k")).toHaveText("Address");
    expect(((await rows.locator(".v").textContent()) ?? "").trim()).toBe(SEEDED.address);
    await expect(popup.locator("#route-line")).toBeHidden();
    await exactlyOneButton(popup, "Turn routing on");
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "enrolled");
    await popup.close();
    await page.close();
  });

  test("the outcome of Turn routing on is written while the route line is visible and a live region", async () => {
    // An identity is held and routing is off, so the control first paints the state with no sentence.
    await ext.sw.evaluate(
      (identity) => chrome.storage.local.set({ egress: { on: false, identity, config: null, error: null } }),
      SEEDED,
    );
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    // Record each write to the route line with the state it was in AT THAT MOMENT
    // (a change made in a hidden or not-yet-live region is not announced).
    const popup = await ext.context.newPage();
    await popup.addInitScript(() => {
      const w = window as unknown as { __routeChanges: Array<{ text: string; hidden: boolean; live: string | null }> };
      w.__routeChanges = [];
      const original = Element.prototype.replaceChildren;
      Element.prototype.replaceChildren = function (this: Element, ...nodes: Array<Node | string>): void {
        const before = { hidden: (this as HTMLElement).hidden, live: this.getAttribute("aria-live") };
        original.apply(this, nodes);
        if (this.id === "route-line") w.__routeChanges.push({ text: this.textContent ?? "", ...before });
      };
    });
    await popup.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
    await selectPopupTab(popup, "browser");
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "enrolled", { timeout: 15_000 });
    await expect(popup.locator("#route-line")).toBeHidden();
    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#route-line")).toContainText("Not routed.", { timeout: 30_000 });
    const changes = await popup.evaluate(
      () => (window as unknown as { __routeChanges: Array<{ text: string; hidden: boolean; live: string | null }> }).__routeChanges,
    );
    expect(changes[0]!.live, "the first write to the line is made before it is live: the first paint is silent").toBeNull();
    const outcome = changes.find((c) => c.text.includes("Not routed."));
    expect(outcome, "the outcome was written").toBeTruthy();
    expect(outcome!.hidden, "visible when the outcome was written").toBe(false);
    expect(outcome!.live, "and already a live region").toBe("polite");
    await popup.close();
    await page.close();
  });

  test("routing refused: the chip follows the public record, the sentence names the permission", async () => {
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await exactlyOneButton(popup, "Protect this browser");
    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    await expect(popup.locator("#route-line")).toContainText("Not routed.", { timeout: 25_000 });
    await expect(popup.locator("#route-line")).toContainText("proxy permission");
    await exactlyOneButton(popup, "Turn routing on");
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "error");
    await popup.close();
    await page.close();
  });

  // ---------------------------------------------------------------- T3

  test("the destination and flagged figures equal the dashboard's This browser view", async () => {
    test.setTimeout(150_000);
    await setKey(ext, null);
    net.setVerdict(FLAGGED, { band: "HIGH", coverage: "known-clean", label: "malicious" });

    // One visit to the flagged host, so it sits in the verdict cache and in the
    // log with one sighting. A second tab stays open to pin the popup to.
    const flagged = await visit(ext, `https://${FLAGGED}/`);
    await waitForIcon(ext, flagged.tabId, ["malicious"]);
    await flagged.page.close();
    const anchor = await visit(ext, `https://${ANCHOR}/`);
    await waitForIcon(ext, anchor.tabId, ["unknown", "benign", "signedout"]);
    // The log is written a moment after a sighting: wait until both are in it.
    await expect
      .poll(() =>
        ext.sw.evaluate(async (hosts: string[]) => {
          const log = ((await chrome.storage.local.get("navlog"))["navlog"] ?? {}) as Record<string, unknown>;
          return hosts.every((h) => Object.keys(log).includes(h));
        }, [FLAGGED, ANCHOR]),
      )
      .toBe(true);

    // 205 more destinations, each seen more often than the flagged one, so it
    // lies past the 200 the popup enriches.
    const total = await ext.sw.evaluate(async () => {
      const stored = ((await chrome.storage.local.get("navlog"))["navlog"] ?? {}) as Record<
        string,
        { q: number; lastAt: number }
      >;
      const now = Date.now();
      for (let i = 0; i < 205; i++) stored[`dest-${i}-guard-e2e.com`] = { q: 300 - i, lastAt: now - 60_000 - i * 1000 };
      await chrome.storage.local.set({ navlog: stored });
      return Object.keys(stored).length;
    });
    expect(total, "the log holds the seeded destinations and the flagged one").toBeGreaterThanOrEqual(206);

    // The worker reads the log once per start: stop it so the seeded one is read.
    await stopWorker(ext);
    await rebindWorker(ext);
    net.clearLog();

    const popup = await openPopup(ext, anchor.tabId, { popupTab: "browser" });
    await expect(popup.locator("#activity-destinations")).toHaveText(String(total), { timeout: 20_000 });
    await expect(popup.locator("#activity-flagged")).toHaveText("1");
    await expect(popup.locator("#today-row .pp-fig-l")).toHaveText("handled quietly today");
    // The strip draws the 200 busiest and says so.
    await expect(popup.locator("#browser-strip svg > title")).toHaveText(
      `The last sighting of each of the 200 destinations drawn here, out of ${total}, in the last 24 hours`,
    );

    // Still at most 200 hostnames sent for enrichment, and the flagged one is not among them.
    const sent = new Set<string>();
    for (const r of net.requestsTo(GRAPH_READ_HOST)) {
      if (r.scheme !== "https" || !r.body.includes("whisper.enrich")) continue;
      const hs = (JSON.parse(r.body) as { parameters?: { hs?: string[] } }).parameters?.hs ?? [];
      for (const h of hs) sent.add(h);
    }
    expect(sent.size, "something was enriched").toBeGreaterThan(0);
    expect(sent.size).toBeLessThanOrEqual(200);
    expect(sent.has(FLAGGED)).toBe(false);

    const dash = await openDashboard(ext, "browser");
    const tile = (label: string): ReturnType<Page["locator"]> =>
      dash.locator("#b-tiles .w-tile").filter({ has: dash.locator(".w-label", { hasText: new RegExp(`^${label}$`) }) });
    await expect(tile("Destinations").locator(".w-stat")).toHaveText(String(total), { timeout: 30_000 });
    await expect(tile("Flagged").locator(".w-stat")).toHaveText("1");
    await dash.close();
    await popup.close();
    await anchor.page.close();
  });

  // ---------------------------------------------------------------- T5

  test("the state names are the same in the popup and on the dashboard", async () => {
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);

    const compare = async (name: string): Promise<void> => {
      const popup = await openPopup(ext, tabId, { popupTab: "browser" });
      await expect(popup.locator("#identity-state")).toHaveText(name, { timeout: 25_000 });
      const dash = await openDashboard(ext, "browser");
      await expect(dash.locator("#identity-state")).toHaveText(name, { timeout: 25_000 });
      await expect(dash.locator("#identity-chip")).toHaveText(name, { timeout: 25_000 });
      await dash.close();
      await popup.close();
    };

    await compare("NOT ENROLLED");

    await ext.sw.evaluate(
      (identity) => chrome.storage.local.set({ egress: { on: false, identity, config: null, error: null } }),
      SEEDED,
    );
    await compare("ENROLLED");

    await clearIdentity(ext);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    await popup.close();
    await compare("VERIFIED");
    await page.close();
  });

  test("signed out, This browser shows no state chip at all", async () => {
    await setKey(ext, null);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await expect(popup.locator("#signin-pitch")).toBeVisible();
    await expect(popup.locator("#signin-pitch .w-chip")).toHaveCount(0);
    await expect(popup.locator("#identity-state")).toBeHidden();
    await popup.close();
    await page.close();
  });

  test("the old state names are in no built file", () => {
    const names = ["NOT ON THE WHISPER NETWORK", "VERIFIED WHISPER ENDPOINT", "IDENTITY NOT VERIFIED", "NOT ON THE NETWORK"];
    const read = (f: string): string => readFileSync(join(DIST, f), "utf8");
    for (const f of ["popup.js", "popup.html", "dashboard.js", "dashboard.html"]) {
      const src = read(f);
      for (const n of names) expect(src, `${f} still carries "${n}"`).not.toContain(n);
    }
    // CONTROL: the new name is in the files that draw it, so an empty read would not pass.
    expect(read("popup.js")).toContain("NOT ENROLLED");
    expect(read("dashboard.html")).toContain("NOT ENROLLED");
  });

  // ---------------------------------------------------------------- T6

  test("the footer reads Active Shield, and the console link shows only signed in", async () => {
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign", "unknown", "signedout"]);
    try {
      // Signed out: the readout, no link.
      await setKey(ext, null);
      await setSettings(ext, { shield: false });
      let popup = await openPopup(ext, tabId, { popupTab: "browser" });
      await expect(popup.locator("#shield-readout")).toHaveText("Active Shield off");
      await expect(popup.locator("#browser-console")).toBeHidden();
      await popup.close();

      // The setting alone is not enough: this build holds no all-sites grant.
      await setSettings(ext, { shield: true });
      popup = await openPopup(ext, tabId, { popupTab: "browser" });
      await expect(popup.locator("#shield-readout")).toHaveText("Active Shield off");
      await popup.close();

      // Signed in: the link, and it opens the console.
      await setKey(ext, MOCK_KEY);
      popup = await openPopup(ext, tabId, { popupTab: "browser" });
      const link = popup.locator("#browser-console");
      await expect(link).toBeVisible({ timeout: 15_000 });
      await expect(link).toHaveText("Open console ↗");
      const opened = ext.context.waitForEvent("page", { timeout: 20_000 });
      await link.click();
      const tab = await opened;
      await expect.poll(() => tab.url(), { timeout: 20_000 }).not.toBe("about:blank");
      expect(new URL(tab.url()).origin).toBe(new URL(CONSOLE_URL).origin);
      await tab.close().catch(() => undefined);
      await popup.close();
    } finally {
      await setSettings(ext, { shield: false });
    }
    await page.close();
  });

  // ---------------------------------------------------------------- T4

  test("signed out, the tab fits 600 px without scrolling, in the dark and the light scheme", async () => {
    await setKey(ext, null);
    await plantWins(ext, { preemptBlock: 1, identityVerified: 0, cookieDecline: 0 });
    for (const host of [CLEAN, SECOND]) {
      const v = await visit(ext, `https://${host}/`);
      await waitForIcon(ext, v.tabId, ["benign", "unknown", "signedout"]);
      await v.page.close();
    }
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await popup.setViewportSize({ width: 400, height: 600 });
    for (const scheme of ["dark", "light"] as const) {
      await popup.emulateMedia({ colorScheme: scheme });
      // The measurement is not vacuous: everything the tab holds is on screen.
      for (const id of ["signin-pitch", "tier-meter", "activity-destinations", "activity-flagged", "today-row", "today-caption", "btn-dashboard", "shield-readout"]) {
        await expect(popup.locator(`#${id}`), `#${id}`).toBeVisible({ timeout: 15_000 });
      }
      await expect(popup.locator("#browser-strip svg")).toBeVisible();
      await expectBrowserTabFits(popup, `signed-out-${scheme}`);
    }
    await popup.close();
    await page.close();
    await plantWins(ext, { preemptBlock: 0, identityVerified: 0, cookieDecline: 0 });
  });

  test("signed in after the permission is refused, the tab fits 600 px without scrolling, in both schemes", async () => {
    test.setTimeout(150_000);
    await plantWins(ext, { preemptBlock: 1, identityVerified: 0, cookieDecline: 0 });
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await popup.setViewportSize({ width: 400, height: 600 });
    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    await expect(popup.locator("#route-line")).toContainText("Not routed.", { timeout: 25_000 });
    for (const scheme of ["dark", "light"] as const) {
      await popup.emulateMedia({ colorScheme: scheme });
      for (const id of ["identity-card", "identity-detail", "route-line", "activity-destinations", "today-row", "today-caption", "btn-dashboard", "shield-readout"]) {
        await expect(popup.locator(`#${id}`), `#${id}`).toBeVisible();
      }
      await expect(popup.locator("#browser-strip svg")).toBeVisible();
      await expectBrowserTabFits(popup, `refused-${scheme}`);
    }
    await popup.close();
    await page.close();
    await plantWins(ext, { preemptBlock: 0, identityVerified: 0, cookieDecline: 0 });
  });
});

// ------------------------------------------- G: the routing permission is granted

test.describe("This browser, routed (the routing permission is granted)", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seedWorld(net);
    ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeEgressDist() });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("VERIFIED and routed: the full routing sentence, its limits on a second line, one button", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    await clearIdentity(ext);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await exactlyOneButton(popup, "Protect this browser");
    await popup.locator("#btn-protect").click();

    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "routed", { timeout: 25_000 });
    const line = popup.locator("#route-line");
    await expect(line.locator(".w-dot")).toHaveClass(/\bon\b/);
    // Today's whole line, word for word, with the limits on a second, smaller line.
    await expect(line).toHaveText(`Protected. ${ROUTE_BASE} ${SECOND_LINE}`);
    const more = line.locator(".pc-route-more");
    await expect(more).toHaveText(SECOND_LINE);
    expect(((await more.textContent()) ?? "").trim()).toBe(SECOND_LINE);

    // The line is the module's own text for this status, whitespace and all.
    const status = await popup.evaluate(async () => {
      const res = (await chrome.runtime.sendMessage({ kind: "egressStatus" })) as { egress: Record<string, unknown> };
      return res.egress;
    });
    const g = globalThis as Record<string, unknown>;
    g["chrome"] = { runtime: {} };
    try {
      const { routeLineText } = await import("../src/shared/protect-control");
      const expected = `Protected. ${routeLineText(status as Parameters<typeof routeLineText>[0])}`;
      expect(((await line.textContent()) ?? "").replace(/\s+/g, " ").trim()).toBe(expected.replace(/\s+/g, " ").trim());
      expect(await line.textContent()).toBe(expected);
    } finally {
      delete g["chrome"];
    }

    const rows = popup.locator("#identity-detail .w-kv .k");
    await expect(rows).toHaveText(["Address", "Name", "Proof"]);
    await expect(popup.locator("#identity-detail a")).toHaveText("RDAP record, anyone can check ↗");
    await exactlyOneButton(popup, "Turn routing off");
    await popup.close();
    await page.close();
  });

  test("turning routing off is announced without a visible word, and focus stays on a visible button", async () => {
    await setKey(ext, MOCK_KEY);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    // Record what is written into the announcement region and the state it is in at that moment.
    const popup = await ext.context.newPage();
    await popup.addInitScript(() => {
      const w = window as unknown as { __said: Array<{ text: string; hidden: boolean; live: string | null }> };
      w.__said = [];
      new MutationObserver(() => {
        const e = document.getElementById("route-announce");
        if (e && (e.textContent ?? "") !== "") {
          w.__said.push({ text: e.textContent ?? "", hidden: e.closest("[hidden]") !== null, live: e.getAttribute("aria-live") });
        }
      }).observe(document, { childList: true, subtree: true, characterData: true });
    });
    await popup.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
    await selectPopupTab(popup, "browser");
    await ensureRouted(popup);
    const said = (): Promise<Array<{ text: string; hidden: boolean; live: string | null }>> =>
      popup.evaluate(() => (window as unknown as { __said: Array<{ text: string; hidden: boolean; live: string | null }> }).__said);
    expect(await said(), "nothing is announced while the card is first drawn or routing is turned on").toEqual([]);

    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "enrolled", { timeout: 15_000 });
    await expect(popup.locator("#route-line")).toBeHidden();
    // The press disabled the button for a moment; focus is back on a visible one.
    await expect(popup.locator("#btn-protect")).toBeFocused();
    await expect.poll(async () => (await said()).length).toBeGreaterThan(0);
    const first = (await said())[0]!;
    expect(first.text).toBe("Routing is off.");
    expect(first.hidden, "written into a region that is not hidden").toBe(false);
    expect(first.live, "and a live region").toBe("polite");
    // The words are for assistive technology only: they take no room on the card.
    expect(await popup.locator("#route-announce").evaluate((e) => e.getBoundingClientRect().width)).toBeLessThanOrEqual(1);
    await popup.close();
    await page.close();
  });

  test("focus moved elsewhere while the identity is re-verified stays where the reader put it", async () => {
    await setKey(ext, MOCK_KEY);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    // The stand-in record's answer can be held from the page, so the wait after
    // the control is redrawn is long enough to act in.
    const popup = await ext.context.newPage();
    await popup.addInitScript(() => {
      const w = window as unknown as {
        __holdVerify: Promise<void> | null;
        __verifyDone: boolean;
      };
      w.__holdVerify = null;
      w.__verifyDone = false;
      const original = chrome.runtime.sendMessage.bind(chrome.runtime);
      (chrome.runtime as unknown as { sendMessage: unknown }).sendMessage = async (msg: { kind?: string }) => {
        const held = msg?.kind === "verifyIdentity" ? w.__holdVerify : null;
        if (held) {
          const res = await original(msg as never);
          await held;
          w.__verifyDone = true;
          return res;
        }
        return original(msg as never);
      };
    });
    await popup.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
    await selectPopupTab(popup, "browser");
    await ensureRouted(popup);
    await popup.evaluate(() => {
      const w = window as unknown as { __holdVerify: Promise<void> | null; __release: () => void };
      w.__holdVerify = new Promise<void>((r) => {
        w.__release = r;
      });
    });
    await popup.locator("#btn-protect").click();
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "enrolled", { timeout: 15_000 });
    // The control is drawn and the verification is still pending: put focus on another control.
    await popup.locator("#btn-dashboard").focus();
    await expect(popup.locator("#btn-dashboard")).toBeFocused();
    await popup.evaluate(() => (window as unknown as { __release: () => void }).__release());
    await expect.poll(() => popup.evaluate(() => (window as unknown as { __verifyDone: boolean }).__verifyDone)).toBe(true);
    await popup.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    await expect(popup.locator("#btn-dashboard")).toBeFocused();
    await popup.close();
    await page.close();
  });

  test("on the dashboard the same control says nothing when it is first drawn, and says routing is off when it is", async () => {
    await setKey(ext, MOCK_KEY);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await ensureRouted(popup);
    await popup.close();
    await page.close();

    const dash = await openDashboard(ext, "browser");
    await expect(dash.locator("#identity-control")).toHaveAttribute("data-state", "routed", { timeout: 25_000 });
    await expect(dash.locator("#route-announce")).toHaveText("");
    await expect(dash.locator("#route-announce")).toHaveAttribute("aria-live", "polite");
    await dash.locator("#btn-protect").click();
    await expect(dash.locator("#route-announce")).toHaveText("Routing is off.", { timeout: 15_000 });
    await expect(dash.locator("#btn-protect")).toBeFocused();
    await dash.close();
  });

  test("the dashboard draws the whole name, and only the popup keeps it to one line", async () => {
    await setKey(ext, MOCK_KEY);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await ensureRouted(popup);
    await popup.close();
    await page.close();
    const stored = await ext.sw.evaluate(async () => {
      const e = (await chrome.storage.local.get("egress"))["egress"] as { identity: { fqdn: string | null } };
      return e.identity.fqdn;
    });
    expect(stored?.length ?? 0, "the stand-in's name is as long as a real one").toBeGreaterThanOrEqual(73);

    const dash = await openDashboard(ext, "browser");
    // Narrow enough that the whole name has to wrap.
    await dash.setViewportSize({ width: 600, height: 900 });
    await expect(dash.locator("#identity-control")).toHaveAttribute("data-state", "routed", { timeout: 25_000 });
    const name = dash.locator("#identity-detail .pc-name");
    await expect(name).toBeVisible({ timeout: 25_000 });
    const drawn = await name.evaluate((n) => {
      const cell = n.closest(".v")!;
      const box = cell.getBoundingClientRect();
      // Nothing between the name and the card clips it.
      const clipped: string[] = [];
      for (let a: Element | null = cell; a && a.id !== "identity-control"; a = a.parentElement) {
        const cs = getComputedStyle(a);
        const clips = cs.overflowX !== "visible" || cs.overflowY !== "visible";
        if (clips && (a.scrollWidth > a.clientWidth || a.scrollHeight > a.clientHeight)) clipped.push(a.className || a.tagName.toLowerCase());
      }
      const outside = [...n.getClientRects()].filter(
        (r) => r.width > 0 && (r.left < box.left - 0.5 || r.right > box.right + 0.5 || r.top < box.top - 0.5 || r.bottom > box.bottom + 0.5),
      ).length;
      // Each label is drawn whole on one line, and the name takes more than one:
      // so it wraps, and only at the breaks after the dots.
      const texts: Text[] = [];
      const walk = document.createTreeWalker(n, NodeFilter.SHOW_TEXT);
      for (let t = walk.nextNode(); t; t = walk.nextNode()) texts.push(t as Text);
      const tops = new Set<number>();
      let split = 0;
      for (const t of texts) {
        const r = document.createRange();
        r.selectNodeContents(t);
        const rects = [...r.getClientRects()].filter((x) => x.width > 0);
        if (rects.length !== 1) split++;
        for (const x of rects) tops.add(Math.round(x.top));
      }
      return {
        text: n.textContent,
        title: (n as HTMLElement).title,
        clipped,
        outside,
        split,
        lines: tops.size,
        held: [n, ...n.querySelectorAll("*")]
          .filter((e) => {
            const cs = getComputedStyle(e);
            return cs.overflowX !== "visible" || cs.textOverflow === "ellipsis" || cs.whiteSpace === "nowrap";
          })
          .map((e) => e.className || e.tagName.toLowerCase()),
        breaks: [...n.querySelectorAll("wbr")].filter((w) => getComputedStyle(w).display !== "none").length,
        dots: (n.textContent ?? "").split(".").length - 1,
      };
    });
    expect(drawn.text, "the dashboard draws the stored name").toBe(stored);
    expect(drawn.title, "its title is the stored name").toBe(stored);
    expect(drawn.held, "no part of the dashboard's name is clipped or kept to one line").toEqual([]);
    expect(drawn.clipped, "nothing around the name clips it").toEqual([]);
    expect(drawn.outside, "every line of the name is inside its cell").toBe(0);
    expect(drawn.breaks, "the dashboard keeps a break after each dot").toBe(drawn.dots);
    expect(drawn.lines, "at 600 px the name wraps").toBeGreaterThan(1);
    expect(drawn.split, "it wraps only after a dot: no label is split").toBe(0);
    await dash.close();
  });

  test("the address and the name can be selected and copied", async () => {
    await setKey(ext, MOCK_KEY);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await ensureRouted(popup);
    const stored = await ext.sw.evaluate(async () => {
      const e = (await chrome.storage.local.get("egress"))["egress"] as { identity: { address: string; fqdn: string | null } };
      return e.identity;
    });
    expect(stored.fqdn, "the identity is enrolled and named").toBeTruthy();
    await expect(popup.locator("#identity-detail .w-kv .k")).toHaveText(["Address", "Name", "Proof"]);

    for (const [label, want] of [["Address", stored.address], ["Name", stored.fqdn!]] as const) {
      const got = await popup.evaluate((l) => {
        const row = [...document.querySelectorAll("#identity-detail .w-kv")].find((r) => r.querySelector(".k")?.textContent === l);
        const value = row?.querySelector(".v") as HTMLElement | null;
        if (!value) return null;
        const noneAnywhere: string[] = [];
        for (let n: Element | null = value; n; n = n.parentElement) {
          if (getComputedStyle(n).userSelect === "none") noneAnywhere.push(n.tagName.toLowerCase() + (n.id ? `#${n.id}` : ""));
        }
        const range = document.createRange();
        range.selectNodeContents(value);
        const sel = getSelection()!;
        sel.removeAllRanges();
        sel.addRange(range);
        const text = sel.toString();
        sel.removeAllRanges();
        return { text, noneAnywhere };
      }, label);
      expect(got, `${label} row`).not.toBeNull();
      expect(got!.noneAnywhere, `${label}: user-select is none here`).toEqual([]);
      expect(got!.text, `${label}: the selection is the stored value`).toBe(want);
    }
    // A real copy in Chromium: select the name, press the copy key and read what
    // the browser put on the clipboard. (Firefox's copy is not exercised here.)
    await popup.evaluate(() => {
      const row = [...document.querySelectorAll("#identity-detail .w-kv")].find((r) => r.querySelector(".k")?.textContent === "Name")!;
      const range = document.createRange();
      range.selectNodeContents(row.querySelector(".v")!);
      const sel = getSelection()!;
      sel.removeAllRanges();
      sel.addRange(range);
    });
    await ext.context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await popup.bringToFront();
    await popup.keyboard.press("ControlOrMeta+c");
    // Read what the browser put on the clipboard.
    const copied = await popup.evaluate(() => navigator.clipboard.readText());
    expect(copied, "the copied name is the exact name").toBe(stored.fqdn);
    expect(copied, "no zero-width space").not.toMatch(/[\u200b\u200c\u200d\ufeff]/);
    expect(copied, "no line break").not.toMatch(/[\r\n]/);
    // The name's markup keeps a <wbr> after each dot: an element, not a
    // character, so a copy stays exact. The popup hides them and keeps the Name
    // to one line; the dashboard test checks that they still break there.
    const breaks = await popup.evaluate((fqdn) => {
      const row = [...document.querySelectorAll("#identity-detail .w-kv")].find((r) => r.querySelector(".k")?.textContent === "Name");
      return { wbrs: row?.querySelectorAll("wbr").length ?? -1, dots: fqdn.split(".").length - 1 };
    }, stored.fqdn!);
    expect(breaks.wbrs).toBe(breaks.dots);
    await popup.close();
    await page.close();
  });

  test("the footer reads Active Shield live: off, then on with the grant", async () => {
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign", "unknown", "signedout"]);
    try {
      await setSettings(ext, { shield: false });
      let popup = await openPopup(ext, tabId, { popupTab: "browser" });
      await expect(popup.locator("#shield-readout")).toHaveText("Active Shield off");
      await popup.close();

      await setSettings(ext, { shield: true });
      popup = await openPopup(ext, tabId, { popupTab: "browser" });
      await expect(popup.locator("#shield-readout")).toHaveText("Active Shield on");
      await popup.close();
    } finally {
      await setSettings(ext, { shield: false });
    }
    await page.close();
  });

  test("routed, the full routing sentence is measured at 400 x 600 in both schemes, with one category and with three", async () => {
    test.setTimeout(150_000);
    await setKey(ext, MOCK_KEY);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    {
      const first = await openPopup(ext, tabId, { popupTab: "browser" });
      await ensureRouted(first);
      await first.close();
    }
    for (const [name, counts] of [
      ["one-category", { preemptBlock: 1, identityVerified: 0, cookieDecline: 0 }],
      ["three-categories", { preemptBlock: 2, identityVerified: 1, cookieDecline: 3 }],
    ] as const) {
      await plantWins(ext, counts);
      const popup = await openPopup(ext, tabId, { popupTab: "browser" });
      await popup.setViewportSize({ width: 400, height: 600 });
      await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "routed", { timeout: 25_000 });
      // The card is complete before it is measured: verified, with all three rows.
      await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
      await expect(popup.locator("#identity-detail .w-kv .k")).toHaveText(["Address", "Name", "Proof"]);
      for (const scheme of ["dark", "light"] as const) {
        await popup.emulateMedia({ colorScheme: scheme });
        for (const id of ["identity-detail", "route-line", "activity-destinations", "today-row", "today-caption", "btn-dashboard", "shield-readout"]) {
          await expect(popup.locator(`#${id}`), `#${id}`).toBeVisible();
        }
        await expect(popup.locator("#browser-strip svg")).toBeVisible();
        await expectRoutedCardLayout(popup, `routed-${name}-${scheme}`);
        await expectBrowserTabFits(popup, `routed-${name}-${scheme}`);
      }
      await popup.close();
    }
    await plantWins(ext, { preemptBlock: 0, identityVerified: 0, cookieDecline: 0 });
    await page.close();
  });
});

// ------------------------------------------- H: another extension holds the proxy

test.describe("This browser, a log of one destination", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seedWorld(net);
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("the strip is titled in the singular", async () => {
    await setKey(ext, null);
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign", "unknown", "signedout"]);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await expect(popup.locator("#activity-destinations")).toHaveText("1");
    await expect(popup.locator("#browser-strip svg > title")).toHaveText(
      "The last sighting of the one destination in the last 24 hours",
    );
    await popup.close();
    await page.close();
  });
});

test.describe("This browser, a day with a flagged destination and nothing handled", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seedWorld(net);
    net.setVerdict(FLAGGED, { band: "HIGH", coverage: "known-clean", label: "malicious" });
    ext = await launchExtension({ proxyPort: net.proxyPort });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("the day line never says nothing needed attention beside a flagged destination", async () => {
    await setKey(ext, null);
    await plantWins(ext, { preemptBlock: 0, identityVerified: 0, cookieDecline: 0 });
    const SENTENCE = "Nothing needed your attention today; checks ran on every site.";
    const clean = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, clean.tabId, ["benign", "unknown", "signedout"]);

    // Control: with nothing flagged and nothing handled, the sentence is shown.
    let popup = await openPopup(ext, clean.tabId, { popupTab: "browser" });
    await expect(popup.locator("#activity-flagged")).toHaveText("0");
    await expect(popup.locator("#today-hero")).toHaveText("0");
    await expect(popup.locator("#today-caption")).toHaveText(SENTENCE, { useInnerText: true });
    await popup.close();

    // One flagged destination: the figure says 1 and the sentence is gone.
    const flagged = await visit(ext, `https://${FLAGGED}/`);
    await waitForIcon(ext, flagged.tabId, ["malicious"]);
    popup = await openPopup(ext, clean.tabId, { popupTab: "browser" });
    await expect(popup.locator("#activity-destinations")).toHaveText("2");
    await expect(popup.locator("#activity-flagged")).toHaveText("1");
    await expect(popup.locator("#today-row")).toBeVisible();
    await expect(popup.locator("#today-hero")).toHaveText("0");
    await expect(popup.locator("#activity-card")).not.toContainText("Nothing needed your attention", { useInnerText: true });
    // The strip says what it draws: both destinations have a time.
    await expect(popup.locator("#browser-strip svg > title")).toHaveText(
      "The last sighting of each of the 2 destinations in the last 24 hours",
    );
    await popup.close();
    await flagged.page.close();
    await clean.page.close();
  });
});

test.describe("This browser, held by another extension", () => {
  let net: E2ENetwork;
  let ext: Extension;

  test.beforeAll(async () => {
    net = new E2ENetwork();
    await net.start();
    seedWorld(net);
    ext = await launchExtension({
      proxyPort: net.proxyPort,
      dist: makeEgressDist(),
      extraExtensions: [makeProxyHolderExt(net.proxyPort)],
    });
  });

  test.afterAll(async () => {
    await ext?.close();
    await net?.stop();
  });

  test("held: the chip follows the record, the sentence names the other extension, the one button is the way out", async () => {
    await setKey(ext, MOCK_KEY);
    net.clearEndpoints();
    await plantWins(ext, { preemptBlock: 1, identityVerified: 0, cookieDecline: 0 });
    const { page, tabId } = await visit(ext, `https://${CLEAN}/`);
    await waitForIcon(ext, tabId, ["benign"]);
    const popup = await openPopup(ext, tabId, { popupTab: "browser" });
    await popup.setViewportSize({ width: 400, height: 600 });
    await exactlyOneButton(popup, "Protect this browser");
    await popup.locator("#btn-protect").click();

    await expect(popup.locator("#identity-state")).toHaveText("VERIFIED", { timeout: 25_000 });
    await expect(popup.locator("#route-line")).toHaveText(HELD_SENTENCE, { timeout: 25_000 });
    await exactlyOneButton(popup, "Open the extensions page");
    await expect(popup.locator("#btn-route-fix")).toBeVisible();
    await expect(popup.locator("#btn-protect")).toBeHidden();
    await expect(popup.locator("#identity-control")).toHaveAttribute("data-state", "held");
    // Focus follows to the visible button when the steps end, never to the hidden one.
    await expect(popup.locator("#btn-route-fix")).toBeFocused();

    // The held state fits too, in both schemes.
    for (const scheme of ["dark", "light"] as const) {
      await popup.emulateMedia({ colorScheme: scheme });
      for (const id of ["identity-detail", "activity-destinations", "today-row", "today-caption", "btn-dashboard", "shield-readout"]) {
        await expect(popup.locator(`#${id}`), `#${id}`).toBeVisible();
      }
      await expect(popup.locator("#browser-strip svg")).toBeVisible();
      await expectBrowserTabFits(popup, `held-${scheme}`);
    }
    await popup.close();
    await page.close();
    await plantWins(ext, { preemptBlock: 0, identityVerified: 0, cookieDecline: 0 });
  });
});
