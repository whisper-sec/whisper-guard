// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: the tone of the field caution card (board 4c) for the two cases that
// credential-fields.spec.ts does not reach: a look-alike of a known brand
// (amber edge) and a site the reader chose to continue to after a stop
// (neutral edge). The wordings are asserted unchanged. The card is read from
// inside Guard's closed shadow root.

import { test, expect } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { CAUTION_FN, ClosedShadow, type CautionSnapshot } from "./helpers/closed-shadow";
import { launchExtension, makeShieldDist, setKey, setSettings, visit, waitForIcon, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const OVERLAY = "div[style*='2147483647']";
const LOOKALIKE = "paypa1-tone-caution-e2e.com";
const LOOKALIKE_SEED = "paypa1-seed-caution-e2e.com";
const CONTINUED = "evil-tone-caution-e2e.com";
const FORM = `<!doctype html><html><head><title>form</title></head><body><h1>form</h1>
<form><input id="f" type="password" name="pw"></form></body></html>`;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setPage(LOOKALIKE, FORM);
  net.setPage(CONTINUED, FORM);
  net.setPage(
    LOOKALIKE_SEED,
    `<!doctype html><html><head><title>form</title></head><body><h1>form</h1>
<form><input id="f" type="text" name="seed-phrase" placeholder="Enter your 12 word recovery phrase"></form></body></html>`,
  );
  net.setVerdict(CONTINUED, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, MOCK_KEY);
  // The amber bar is off so the only overlay that can mount is the caution.
  await setSettings(ext, { shield: true, amberBanner: false, fieldGuard: true, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function cautionAfterFocus(page: import("@playwright/test").Page): Promise<{ shadow: ClosedShadow; snap: CautionSnapshot }> {
  // The caution is armed a moment after the page settles, so focus again
  // until it answers rather than assuming the first focus was in time.
  await expect
    .poll(
      async () => {
        await page.locator("#f").evaluate((e) => {
          (e as HTMLInputElement).blur();
          (e as HTMLInputElement).focus();
        });
        return page.locator(OVERLAY).count();
      },
      { timeout: 15_000 },
    )
    .toBeGreaterThan(0);
  const shadow = await ClosedShadow.open(ext.context, page);
  let snap: CautionSnapshot | null = null;
  await expect
    .poll(async () => (snap = await shadow.call<CautionSnapshot>(CAUTION_FN)) !== null, { timeout: 10_000 })
    .toBe(true);
  return { shadow, snap: snap! };
}

test("look-alike password caution: amber edge, plain sentence, wording names the brand", async () => {
  const { page, tabId } = await visit(ext, `https://${LOOKALIKE}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow, snap } = await cautionAfterFocus(page);
  expect(snap.card.borderWidth).toBe("1px");
  expect(snap.card.borderColor).toBe("rgb(141, 93, 18)");
  expect(snap.card.backgroundColor).toBe("rgb(13, 13, 26)");
  expect(snap.sentence.strongText).toBeNull();
  expect(snap.sentence.fontSize).toBe("13.5px");
  expect(snap.sentence.text).toBe("Careful: this is NOT paypal.com. Do not enter your password.");
  await shadow.close();
  await page.close();
});

test("caution after continuing past a stop: neutral edge, plain sentence, wording unchanged", async () => {
  const page = await ext.context.newPage();
  await page.goto(`https://${CONTINUED}/`, { waitUntil: "commit" });
  await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
  await page.locator("#btn-continue").click();
  await page.waitForURL(`https://${CONTINUED}/`, { timeout: 15_000 });
  const { shadow, snap } = await cautionAfterFocus(page);
  expect(snap.card.borderWidth).toBe("1px");
  expect(snap.card.borderColor).toBe("rgb(52, 52, 63)");
  expect(snap.sentence.strongText).toBeNull();
  expect(snap.sentence.text).toBe(
    "You continued past a known-threat warning for this site. Do not enter your password here, and never one you use anywhere else.",
  );
  await shadow.close();
  await page.close();
});

test("recovery phrase on a look-alike site keeps the red tone and names the brand", async () => {
  const { page, tabId } = await visit(ext, `https://${LOOKALIKE_SEED}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow, snap } = await cautionAfterFocus(page);
  expect(snap.card.borderWidth).toBe("2px");
  expect(snap.card.borderColor).toBe("rgb(239, 68, 68)");
  expect(snap.card.backgroundColor).toBe("rgb(36, 18, 30)");
  expect(snap.sentence.text).toBe(
    "STOP. This is NOT paypal.com. A recovery phrase or private key typed here is gone, and so is everything it unlocks.",
  );
  await shadow.close();
  await page.close();
});
