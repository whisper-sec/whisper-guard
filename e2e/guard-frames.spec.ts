// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: the banner and field-guard settings message goes to the TOP frame only,
// against the real built extension with the whole network answered locally.
//
// The content script is injected into every frame for the cookie-consent pass,
// so a settings message sent to a tab without naming a frame reaches any
// same-host sub-frame that already has the script. Within one check the message
// goes out before the sub-frames get the script, so the sub-frame case needs a
// SECOND check of the same page. Signing in is the product path that causes
// one: it clears the cached verdicts and re-checks every open tab without a
// navigation, so the frames keep the script they already have.
//
// The first check runs with the banner off, so nothing is drawn by it. The
// second check turns it on, and the banner appearing in the top frame is the
// proof that the second check's message was delivered. Only then is the
// sub-frame inspected.

import { test, expect, type Frame, type Page } from "@playwright/test";
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

const HOST = "site-m-frames-guard-e2e.com";
const FRAME_PATH = "/inner";

/** Any injected Guard UI mounts on a max-z-index host element. */
const OVERLAY = "div[style*='2147483647']";

const PASSWORD = `<label>Password <input type="password" id="pw" name="pw"></label>`;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(HOST, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setPagePath(
    HOST,
    FRAME_PATH,
    `<!doctype html><html><head><title>inner</title></head><body>
<p>A sub-frame on the same host.</p>${PASSWORD}</body></html>`,
  );
  net.setPage(
    HOST,
    `<!doctype html><html><head><title>site m</title></head><body>
<h1>site m</h1>${PASSWORD}
<iframe id="inner" src="https://${HOST}${FRAME_PATH}" style="width:500px;height:160px"></iframe>
</body></html>`,
  );
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, null);
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

/** Is the content script live in this frame? Answered by the frame's own listener. */
async function frameLive(tabId: number, frameId: number): Promise<boolean> {
  return ext.sw.evaluate(
    async ([id, fid]: [number, number]) => {
      try {
        const r = (await chrome.tabs.sendMessage(
          id,
          { kind: "whisper-preempt-ping" },
          { frameId: fid },
        )) as { consent?: boolean } | undefined;
        return r?.consent === true;
      } catch {
        return false;
      }
    },
    [tabId, frameId] as [number, number],
  );
}

async function subFrameId(tabId: number): Promise<number | undefined> {
  return ext.sw.evaluate(async (id: number) => {
    const frames = (await chrome.webNavigation.getAllFrames({ tabId: id })) ?? [];
    return frames.find((f) => f.frameId !== 0)?.frameId;
  }, tabId);
}

function overlays(frame: Frame): Promise<number> {
  return frame.locator(OVERLAY).count();
}

/** Sign in the way the settings page does, which re-checks every open tab. */
async function signIn(): Promise<void> {
  const options: Page = await ext.context.newPage();
  await options.goto(`chrome-extension://${ext.id}/options.html`);
  await options.evaluate(() => chrome.runtime.sendMessage({ kind: "saveKey", key: "e2e-test-key" }));
  await options.close();
}

test("a second check of a page with a same-host sub-frame shows one banner, in the top frame", async () => {
  // First check: banner off, field guard on, so it draws nothing. Cookie
  // auto-decline is on because its pass is what puts the script in sub-frames.
  await setSettings(ext, {
    cloudCheck: true,
    shield: true,
    amberBanner: false,
    fieldGuard: true,
    cookieDecline: true,
  });
  const { page, tabId } = await visit(ext, `https://${HOST}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);

  // The sub-frame has the content script live, so a message addressed to it
  // would be heard: what follows is a decision and not a missing listener.
  await expect.poll(() => subFrameId(tabId), { timeout: 15_000 }).toBeDefined();
  const sub = (await subFrameId(tabId)) as number;
  await expect.poll(() => frameLive(tabId, sub), { timeout: 15_000 }).toBe(true);
  expect(await frameLive(tabId, 0)).toBe(true);

  const top = page.mainFrame();
  const inner = page.frames().find((f) => f !== top) as Frame;
  expect(inner, "the sub-frame must be attached").toBeDefined();
  expect(await overlays(top)).toBe(0);
  expect(await overlays(inner)).toBe(0);

  // Second check of the same page: banner on, then sign in.
  await setSettings(ext, { amberBanner: true });
  await signIn();

  // Positive anchor: the second check's settings message was delivered.
  await expect.poll(() => overlays(top), { timeout: 15_000 }).toBe(1);
  // The frame's own listener answers after anything addressed to it earlier,
  // so by the time it replies a stray copy of the message would have landed.
  expect(await frameLive(tabId, sub)).toBe(true);

  expect(await overlays(inner), "no banner inside the sub-frame").toBe(0);
  expect(await overlays(top), "exactly one banner on the page").toBe(1);

  // The field guard answers once, in the top document only.
  await top.locator("#pw").focus();
  await expect.poll(() => overlays(top), { timeout: 5000 }).toBe(2);
  await inner.locator("#pw").focus();
  expect(await frameLive(tabId, sub)).toBe(true);
  expect(await overlays(inner), "no caution inside the sub-frame").toBe(0);
  expect(await overlays(top)).toBe(2);
  await page.close();
});
