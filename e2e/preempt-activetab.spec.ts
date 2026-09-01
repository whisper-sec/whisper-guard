// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// the pre-emptive rung WITHOUT the broad Active-Shield grant. The
// extension under test holds NO <all_urls> anywhere (the optional route
// is deleted from the manifest), only a scoped grant for the start page,
// the faithful stand-in for an activeTab invocation, whose real grant
// gesture (a toolbar click) cannot be automated. The matrix: the guard
// arms on the invoked tab (both the navigation attempt and the explicit
// popup-open message path); an evidenced-CRITICAL link click is held with
// the inline interstitial and ZERO bytes to the target; the scoped DNR
// second line then stops even a direct navigation to that host, with no
// host permission for it, proving the block-flavor rule needs none; the
// quiet win is counted keyless; and the privacy invariant (bare hostname
// only, ever) holds on this path exactly as on every other.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  launchExtension,
  makeScopedDist,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;
let dist: string;

const START = "start-noshield-guard-e2e.com";
const EVIL = "evil-noshield-target-e2e.com";

const OVERLAY = "div[style*='2147483647']";

async function armed(tabId: number): Promise<boolean> {
  return ext.sw.evaluate(async (id: number) => {
    try {
      const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as
        | { armed?: boolean }
        | undefined;
      return r?.armed === true;
    } catch {
      return false;
    }
  }, tabId);
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(EVIL, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  net.setVerdict(START, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage(
    START,
    `<!doctype html>
<html><head><title>${START}</title></head>
<body>
  <h1>${START}</h1>
  <a id="lnk-evil" href="https://${EVIL}/lure/path?token=hunter2#sec">win a prize</a>
</body></html>`,
  );
  dist = makeScopedDist([START]);
  ext = await launchExtension({ proxyPort: net.proxyPort, dist });
  await setKey(ext, null); // keyless: pre-click protection needs no account
  // DEFAULTS on purpose: Active Shield stays OFF (never opted in).
  await setSettings(ext, { cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("the extension under test provably holds NO broad grant", async () => {
  const manifest = JSON.parse(readFileSync(join(dist, "manifest.json"), "utf8")) as {
    permissions: string[];
    host_permissions: string[];
    optional_permissions?: string[];
    optional_host_permissions?: string[];
  };
  // No grant route to <all_urls> exists: not held, not even requestable.
  // (web_accessible_resources.matches is a resource-exposure matcher for
  // the warning page, not a permission; it grants the extension nothing.)
  expect(manifest.permissions).not.toContain("<all_urls>");
  expect(manifest.host_permissions).not.toContain("<all_urls>");
  expect(manifest.optional_permissions ?? []).not.toContain("<all_urls>");
  expect(manifest.optional_host_permissions).toBeUndefined();
  expect(manifest.host_permissions).toContain(`https://${START}/*`);
  expect(manifest.host_permissions).not.toContain(`https://${EVIL}/*`);
  // And the product settings never opted into Active Shield.
  const shieldOn = await ext.sw.evaluate(async () => {
    const s = (await chrome.storage.local.get("settings"))["settings"] as
      | { shield?: boolean }
      | undefined;
    return s?.shield === true;
  });
  expect(shieldOn).toBe(false);
});

test("pre-click protection on the invoked tab: held link, inline interstitial, ZERO bytes to the target", async () => {
  const { page, tabId } = await visit(ext, `https://${START}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  // The guard arms on the tab the user can invoke Guard on (the scoped
  // grant standing in for activeTab), and the popup-open message path
  // arms it explicitly too.
  const popup = await openPopup(ext, tabId);
  await expect.poll(async () => armed(tabId), { timeout: 15_000 }).toBe(true);
  await popup.close();
  net.clearLog();

  await page.click("#lnk-evil");
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);

  // Held pre-flight: zero bytes to the flagged target, the tab never moved.
  expect(net.requestsTo(EVIL).filter((r) => r.scheme === "https")).toHaveLength(0);
  expect(page.url()).toBe(`https://${START}/`);

  // The privacy invariant on this path: ONE assess for the held target,
  // carrying the BARE hostname, never the path, query, or fragment. (The
  // popup's own report enrichment may land in the window too; it is also
  // hostname-only, and the full-capture sweep below covers it.)
  const assess = net
    .requestsTo(GRAPH_READ_HOST)
    .filter((r) => r.scheme === "https" && r.body.includes("whisper.assess") && r.body.includes(EVIL));
  expect(assess).toHaveLength(1);
  expect(JSON.parse(assess[0].body).parameters).toEqual({ hs: [EVIL] });
  for (const r of net.log) {
    expect(`${r.path} ${r.body}`).not.toContain("hunter2");
  }

  // The interrupt's side effects are in place before the answer renders:
  // the scoped session BLOCK rule exists (main_frame, this host only).
  const rules = await ext.sw.evaluate(async () =>
    (await chrome.declarativeNetRequest.getSessionRules()).map((r) => ({
      action: r.action.type as string,
      filter: r.condition.urlFilter ?? "",
    })),
  );
  expect(rules).toEqual([{ action: "block", filter: `||${EVIL}^` }]);

  // Go back: overlay gone, page untouched.
  await page.keyboard.press("Escape");
  await expect.poll(async () => page.locator(OVERLAY).count()).toBe(0);
  expect(page.url()).toBe(`https://${START}/`);
  await page.close();
});

test("the scoped DNR second line blocks a direct navigation to the evidenced host, no host permission needed", async () => {
  // The interrupt above installed a session BLOCK rule for EVIL (and only
  // EVIL). The extension holds NO host permission for it: block-flavor
  // DNR rules need none, which is exactly why this line works without the
  // broad grant.
  const { page } = await visit(ext, `https://${START}/`);
  net.clearLog();
  await expect(page.goto(`https://${EVIL}/landing`)).rejects.toThrow(/ERR_BLOCKED_BY_CLIENT/);
  expect(net.requestsTo(EVIL).filter((r) => r.scheme === "https")).toHaveLength(0);
  await page.close();
});

test("the quiet win was counted, keyless, as a category only", async () => {
  const readWins = (): Promise<string> =>
    ext.sw.evaluate(async () => {
      const s = await chrome.storage.local.get("wins");
      return JSON.stringify(s["wins"] ?? {});
    });
  await expect
    .poll(async () => (JSON.parse(await readWins()) as { counts?: Record<string, number> }).counts?.["preemptBlock"] ?? 0, {
      timeout: 5000,
    })
    .toBe(1);
  expect(await readWins()).not.toContain("e2e.com"); // no host, ever

  const { page, tabId } = await visit(ext, `https://${START}/`);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#today-hero")).toHaveText("1");
  await popup.close();
  await page.close();
});

test("the no-grant session block is discoverable and clearable from the popup", async () => {
  // The no-grant tier's block is a plain DNR BLOCK: the browser shows a bare
  // ERR_BLOCKED_BY_CLIENT with no Whisper page to explain it. The session
  // block ledger is therefore the ONLY way back to the hostname, so
  // this tier must reach it exactly like the granted tier does. Without the
  // ledger entry the user is stuck: a host they can neither see nor unblock.
  const { page, tabId } = await visit(ext, `https://${START}/`);
  const popup = await openPopup(ext, tabId);

  await expect(popup.locator("#blocked-card")).toBeVisible();
  await expect(popup.locator("#blocked-body")).toContainText(EVIL);

  // Clear = the interstitial's Proceed: session-allow + lift the DNR rule.
  await popup.locator(".blocked-item", { hasText: EVIL }).locator(".blocked-clear").click();
  await expect(popup.locator("#blocked-body")).not.toContainText(EVIL, { timeout: 10_000 });

  const rules = await ext.sw.evaluate(async () =>
    (await chrome.declarativeNetRequest.getSessionRules()).map((r) => r.condition.urlFilter ?? ""),
  );
  expect(rules).not.toContain(`||${EVIL}^`);

  // And the host really is reachable again.
  net.clearLog();
  const resp = await page.goto(`https://${EVIL}/landing`);
  expect(resp?.status()).toBe(200);

  await popup.close();
  await page.close();
});
