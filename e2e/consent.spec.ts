// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: cookie-consent auto-decline, against the real built extension
// with the whole network answered locally. The matrix: a OneTrust-like
// banner is declined via the CMP's own reject handle; a generic banner is
// declined via the strict text rule and its accept/settings buttons are
// NEVER touched; a late-injected banner is caught by the bounded
// MutationObserver; a page with NO banner (including a decoy "Decline"
// button outside any consent context) sees zero clicks; a consent decoy
// offering ONLY an accept button sees zero clicks (never a false accept);
// non-cookie dialogs with destructive decline verbs (session expiry,
// deliveries) are never touched even when they mention privacy, and a
// lone decline with no accept sibling never qualifies; a page-scale
// wrapper merely NAMED cookie-consent never becomes a button hunt;
// each successful decline counts one cookieDecline win (category + count
// only, silent, no injected UI); and the full-capture sweep proves the
// feature put NOTHING on the wire: no host beyond the sites + the graph,
// no request carrying a word of banner/DOM content, hostname-only intact.
//
// Site hostnames deliberately avoid consent-ish words so the wire sweep
// can assert the absence of "cookie"/"consent"/"reject"/... in EVERY
// captured request without tripping over its own test fixtures.

import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const SITE = {
  onetrust: "site-a-574-guard-e2e.com",
  generic: "site-b-574-guard-e2e.com",
  late: "site-c-574-guard-e2e.com",
  none: "site-d-574-guard-e2e.com",
  decoy: "site-e-574-guard-e2e.com",
  modals: "site-f-574-guard-e2e.com",
  wrapper: "site-g-574-guard-e2e.com",
};

/** Any injected Guard UI mounts on a max-z-index host element. */
const OVERLAY = "div[style*='2147483647']";

/** Every button records its click in-page; the module must pick exactly one. */
const RECORDER = `<script>
  window.__clicks = [];
  addEventListener("click", (ev) => {
    const b = ev.target && ev.target.closest ? ev.target.closest("button,[role='button'],input") : null;
    if (b) window.__clicks.push(b.id || b.className || b.tagName);
  }, true);
</script>`;

function oneTrustHtml(): string {
  return `<!doctype html>
<html><head><title>a</title></head><body>
<h1>site a</h1>${RECORDER}
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

const GENERIC_BANNER = `
<div class="cookie-notice-banner" id="cn" style="position:fixed;bottom:0;left:0;right:0;background:#ddd;padding:16px">
  This site uses cookies for analytics and ads.
  <button id="btn-settings">Manage preferences</button>
  <button id="btn-accept">Accept all</button>
  <button id="btn-reject">Reject all</button>
</div>`;

function genericHtml(): string {
  return `<!doctype html>
<html><head><title>b</title></head><body><h1>site b</h1>${RECORDER}${GENERIC_BANNER}
<script>
  document.getElementById("btn-reject").addEventListener("click", () => {
    document.getElementById("cn").style.display = "none";
  });
</script>
</body></html>`;
}

function lateHtml(): string {
  // No banner in the initial DOM; the test injects one AFTER the module is
  // armed, so the MutationObserver path (not the initial scan) must catch it.
  return `<!doctype html>
<html><head><title>c</title></head><body><h1>site c</h1>${RECORDER}</body></html>`;
}

function noBannerHtml(): string {
  // No consent UI at all, plus a decoy: a bare "Decline" button in a plain
  // promo box with NO consent context, which must never be touched.
  return `<!doctype html>
<html><head><title>d</title></head><body><h1>site d</h1>${RECORDER}
<div class="promo-box">Special offer, 20% off today!
  <button id="d-subscribe">Subscribe</button>
  <button id="d-decline">Decline</button>
</div>
<form action="/go" method="post"><button id="d-submit" type="submit">Submit</button></form>
</body></html>`;
}

function decoyHtml(): string {
  // A REAL consent container that only offers acceptance: the conservative
  // contract is to click nothing and leave the page untouched.
  return `<!doctype html>
<html><head><title>e</title></head><body><h1>site e</h1>${RECORDER}
<div class="cookie-consent-wall" role="dialog" style="position:fixed;bottom:0;left:0;right:0;background:#ccc;padding:16px">
  We value your privacy. This site uses cookies.
  <button id="e-accept">Accept all cookies</button>
  <a href="/privacy">Privacy policy</a>
</div>
</body></html>`;
}

function modalsHtml(): string {
  // Two real-world dialogs that must NEVER be touched, each defeating one
  // gate of the generic pass. First: a session-expiry modal offering a
  // destructive "Decline and log out": it mentions privacy and tracking,
  // but no cookie word, so it has no consent context. Second: a dialog that
  // DOES say cookies but offers only a lone decline with no accept-style
  // sibling: a genuine banner always presents accept next to reject, so a
  // lone decline verb is not enough.
  return `<!doctype html>
<html><head><title>f</title></head><body><h1>site f</h1>${RECORDER}
<div role="dialog" aria-modal="true" style="position:fixed;top:20%;left:25%;width:50%;background:#fff;padding:16px;border:1px solid #999">
  Your session is about to expire. See our privacy policy and tracking notice.
  <button id="f-stay">Stay signed in</button>
  <button id="f-logout">Decline and log out</button>
</div>
<div class="cookie-note" role="dialog" style="position:fixed;bottom:0;left:0;right:0;background:#eee;padding:16px">
  This site uses cookies. Details in our policy.
  <button id="f-later">Remind me later</button>
  <button id="f-refuse">Refuse delivery</button>
</div>
</body></html>`;
}

function wrapperHtml(): string {
  // A whole-app wrapper whose class merely CONTAINS a consent token. The
  // page mentions cookies and holds both an Accept and a Decline in an
  // unrelated call widget, so only the banner-scale bound stands between
  // the generic pass and a page-wide button hunt: the wrapper is page-sized
  // (hundreds of elements, taller than the viewport) and must be skipped.
  const filler = Array.from({ length: 400 }, (_, i) => `<p>article paragraph ${i}</p>`).join("");
  return `<!doctype html>
<html><head><title>g</title></head><body>${RECORDER}
<div id="app" class="cookie-consent-active theme-light">
  <h1>site g</h1>
  <p>We use cookies to improve the experience.</p>
  <div class="call-widget">Incoming call from support…
    <button id="g-take">Accept</button>
    <button id="g-drop">Decline</button>
  </div>
  ${filler}
</div>
</body></html>`;
}

async function clicks(page: import("@playwright/test").Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __clicks?: string[] }).__clicks ?? []);
}

async function waitConsentArmed(tabId: number): Promise<void> {
  await expect
    .poll(
      async () =>
        ext.sw.evaluate(async (id: number) => {
          try {
            const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as
              | { consent?: boolean }
              | undefined;
            return r?.consent === true;
          } catch {
            return false;
          }
        }, tabId),
      { timeout: 15_000 },
    )
    .toBe(true);
}

async function winCount(): Promise<number> {
  const rec = await ext.sw.evaluate(async () => {
    const s = await chrome.storage.local.get("wins");
    return (s["wins"] ?? null) as { counts?: Record<string, number> } | null;
  });
  return rec?.counts?.["cookieDecline"] ?? 0;
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const host of Object.values(SITE)) {
    net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
  }
  net.setPage(SITE.onetrust, oneTrustHtml());
  net.setPage(SITE.generic, genericHtml());
  net.setPage(SITE.late, lateHtml());
  net.setPage(SITE.none, noBannerHtml());
  net.setPage(SITE.decoy, decoyHtml());
  net.setPage(SITE.modals, modalsHtml());
  net.setPage(SITE.wrapper, wrapperHtml());
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, null); // keyless throughout: auto-decline is a keyless feature
  await setSettings(ext, { shield: true, amberBanner: false, fieldGuard: false, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("OneTrust-like banner: declined via the CMP's own reject handle; accept untouched; one silent win", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.onetrust}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);

  await expect.poll(() => clicks(page), { timeout: 10_000 }).toEqual(["onetrust-reject-all-handler"]);
  await expect(page.locator("#onetrust-banner-sdk")).toBeHidden();
  await expect.poll(winCount, { timeout: 5000 }).toBe(1);

  // One click per document, ever: nothing more happens, and the win is
  // SILENT: no injected Whisper UI, no badge, nothing to dismiss.
  await page.waitForTimeout(700);
  expect(await clicks(page)).toEqual(["onetrust-reject-all-handler"]);
  expect(await winCount()).toBe(1);
  expect(await page.locator(OVERLAY).count()).toBe(0);
  expect(
    await ext.sw.evaluate(async (id: number) => chrome.action.getBadgeText({ tabId: id }), tabId),
  ).toBe("");
  await page.close();
});

test("generic banner: the strict text rule clicks 'Reject all' and ONLY that; the popup breakdown shows the tally", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.generic}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);

  await expect.poll(() => clicks(page), { timeout: 10_000 }).toEqual(["btn-reject"]);
  await expect(page.locator("#cn")).toBeHidden();
  await expect.poll(winCount, { timeout: 5000 }).toBe(2);

  // The tally surfaces in exactly one place: the popup's today card, on the
  // user's own click, under the existing "cookie prompts declined" label,
  // in the plural here, because two prompts were declined.
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#today-breakdown")).toContainText("2 cookie prompts declined");
  await popup.close();
  await page.close();
});

test("late-injected banner: the bounded MutationObserver catches it after load", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.late}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);

  // Armed, initial scan found nothing. Now the page mounts its banner,
  // the way most CMPs do, asynchronously after load.
  await page.waitForTimeout(400);
  expect(await clicks(page)).toEqual([]);
  await page.evaluate((bannerHtml: string) => {
    const mount = document.createElement("div");
    mount.innerHTML = bannerHtml;
    document.body.appendChild(mount);
  }, GENERIC_BANNER);

  await expect.poll(() => clicks(page), { timeout: 10_000 }).toEqual(["btn-reject"]);
  await expect.poll(winCount, { timeout: 5000 }).toBe(3);
  await page.close();
});

test("no banner: nothing is clicked, not even a bare 'Decline' button outside any consent context", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.none}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);

  // CONTROL: the decoy this test is named for is really on the page. clicks()
  // reads window.__clicks and falls back to [], so a fixture that failed to
  // serve would report "nothing was clicked" and pass while proving nothing.
  await expect(page.locator("#d-decline")).toBeVisible();

  // Give the module every chance to misbehave, then assert it did nothing:
  // no clicks (the promo "Decline" lacks any consent-context signal), no
  // submitted form, no win, page untouched.
  await page.waitForTimeout(1500);
  expect(await clicks(page)).toEqual([]);
  expect(page.url()).toBe(`https://${SITE.none}/`);
  expect(await winCount()).toBe(3);
  await page.close();
});

test("accept-only decoy: a real consent container with ONLY an accept button is left alone (never a false accept)", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.decoy}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);

  await page.waitForTimeout(1500);
  expect(await clicks(page)).toEqual([]);
  await expect(page.locator("#e-accept")).toBeVisible(); // banner untouched
  expect(await winCount()).toBe(3);
  await page.close();
});

test("non-cookie dialogs with destructive decline verbs are never touched: no context, or no accept sibling", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.modals}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);

  // The session-expiry modal fails the cookie-context gate (privacy words
  // are not consent context); the lone-decline cookie note fails the
  // accept-sibling gate. Neither "Decline and log out" nor "Refuse
  // delivery" may ever be clicked.
  await page.waitForTimeout(1500);
  expect(await clicks(page)).toEqual([]);
  await expect(page.locator("#f-logout")).toBeVisible();
  await expect(page.locator("#f-refuse")).toBeVisible();
  expect(await winCount()).toBe(3);
  await page.close();
});

test("a page-scale wrapper named 'cookie-consent' never turns the pass into a page-wide button hunt", async () => {
  const { page, tabId } = await visit(ext, `https://${SITE.wrapper}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await waitConsentArmed(tabId);

  // The wrapper matches the consent-named selector, its text mentions
  // cookies, and it even contains an Accept next to a Decline (an
  // unrelated call widget): only the banner-scale bound protects the
  // widget, and it must.
  await page.waitForTimeout(1500);
  expect(await clicks(page)).toEqual([]);
  await expect(page.locator("#g-drop")).toBeVisible();
  expect(await winCount()).toBe(3);
  await page.close();
});

test("the feature puts NOTHING on the wire: hostname-only capture invariant stays green", async () => {
  // The proxy log is a COMPLETE record of everything that left the browser
  // across every scenario above. Two assertions close the loop:
  //
  // 1) The contacted set is only the seven sites + Whisper's own endpoints
  //    (the nav pipeline's hostname-only assess; corpus checks). The
  //    consent module added no destination.
  const allowed = [
    ...Object.values(SITE),
    GRAPH_READ_HOST,
    "get.whisper.online",
  ];
  for (const host of net.contactedHosts()) {
    expect(allowed, `unexpected destination on the wire: ${host}`).toContain(host);
  }

  // 2) No captured request (method, path, or body) carries a word of the
  //    banner DOM, a click, or anything consent-shaped. The graph saw bare
  //    hostnames; the sites saw plain page fetches; that is all.
  for (const r of net.log) {
    expect(`${r.path} ${r.body}`).not.toMatch(
      /cookie|consent|onetrust|cybot|didomi|qc-cmp|banner|reject|decline|refuse|accept|__clicks/i,
    );
  }
  const assessed = net
    .requestsTo(GRAPH_READ_HOST)
    .filter((r) => r.scheme === "https" && r.body.includes("whisper.assess"));
  expect(assessed.length).toBeGreaterThan(0);
  for (const r of assessed) {
    const params = (JSON.parse(r.body) as { parameters?: { hs?: string[] } }).parameters;
    for (const h of params?.hs ?? []) expect(h).toMatch(/^[a-z0-9.-]+$/);
  }
});
