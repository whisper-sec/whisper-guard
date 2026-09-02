// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: WHAT COUNTS AS A CREDENTIAL FIELD.
//
// The field guard used to fire on exactly one thing, `input[type=password]`.
// That is the field a 2009 phishing page used, and it is not the field the
// ones we actually see use:
//
//   a wallet-drain page asks for a twelve-word recovery phrase in a plain
//   type="text" box;
//   a card-skimming overlay asks for a PAN and a CVC in inputmode="numeric";
//   an MFA-relay page asks for a six-digit code in a type="tel" box.
//
// None of those is a password input. On every one of them the guard was
// silent, on the exact surfaces where silence costs the most, and the
// silence was invisible: a test that focuses a password field and sees the
// warning passes just as happily on a build that can see nothing else.
//
// So each field shape gets a case, AND the controls get one each too. The
// controls are the point: a guard that warns on everything is not a guard,
// it is a nag, and it trains the reader to dismiss the one warning that
// mattered. A search box, an email box and an ordinary name field on the
// same flagged page must stay silent.
//
// The warning mounts in a CLOSED shadow root, so it is read through the
// accessibility tree over CDP, the way shield.spec.ts reads the others.

import { test, expect } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
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

/** Any injected Guard UI mounts on a max-z-index host element. */
const OVERLAY = "div[style*='2147483647']";

/**
 * One flagged page per case: the field guard warns once per KIND, and one
 * page per case keeps each assertion about its own field rather than about
 * the order the cases happened to run in.
 */
interface FieldCase {
  name: string;
  host: string;
  /** The markup for the field under test. */
  field: string;
  /** A phrase from the warning that names what was caught. */
  expect: string;
}

const WARN_CASES: FieldCase[] = [
  {
    name: "a password input, the case that always worked",
    host: "cred-password-guard-e2e.com",
    field: `<input id="f" type="password" name="pw">`,
    expect: "password",
  },
  {
    name: "a text box that autocompletes as a password",
    host: "cred-autocomplete-guard-e2e.com",
    field: `<input id="f" type="text" autocomplete="current-password">`,
    expect: "password",
  },
  {
    name: "a one-time code in a tel box, which is how MFA relay pages ask",
    host: "cred-otp-guard-e2e.com",
    field: `<input id="f" type="tel" autocomplete="one-time-code" maxlength="6">`,
    expect: "one-time code",
  },
  {
    name: "a verification code named only in its placeholder",
    host: "cred-otp2-guard-e2e.com",
    field: `<input id="f" type="text" placeholder="Enter the 6-digit verification code">`,
    expect: "one-time code",
  },
  {
    name: "a card number in a numeric text box",
    host: "cred-card-guard-e2e.com",
    field: `<input id="f" type="text" inputmode="numeric" name="cardnumber">`,
    expect: "card details",
  },
  {
    name: "a CVC named only by its label element",
    host: "cred-cvc-guard-e2e.com",
    field: `<label for="f">CVC</label><input id="f" type="text">`,
    expect: "card details",
  },
  {
    name: "a wallet recovery phrase, the one with no chargeback",
    host: "cred-seed-guard-e2e.com",
    field: `<input id="f" type="text" name="seed-phrase" placeholder="Enter your 12 word recovery phrase">`,
    expect: "recovery phrase",
  },
  {
    name: "a private key asked for by aria-label alone",
    host: "cred-key-guard-e2e.com",
    field: `<input id="f" type="text" aria-label="Private key">`,
    expect: "recovery phrase",
  },
];

/** The controls. Each is an ordinary field on the SAME kind of flagged page. */
const QUIET_CASES: Omit<FieldCase, "expect">[] = [
  {
    name: "a site search box",
    host: "quiet-search-guard-e2e.com",
    field: `<input id="f" type="search" name="q" placeholder="Search this site">`,
  },
  {
    name: "an email address field",
    host: "quiet-email-guard-e2e.com",
    field: `<input id="f" type="email" name="email" placeholder="Your email address">`,
  },
  {
    name: "a plain name field",
    host: "quiet-name-guard-e2e.com",
    field: `<input id="f" type="text" name="full_name" placeholder="Full name">`,
  },
  {
    name: "a newsletter signup, which mentions nothing secret",
    host: "quiet-news-guard-e2e.com",
    field: `<input id="f" type="text" name="newsletter" aria-label="Newsletter signup">`,
  },
];

function pageFor(field: string): string {
  return `<!doctype html><html><head><title>form</title></head><body>
<h1>form</h1>
<form><p>Sign in to continue.</p>${field}<button type="button">Go</button></form>
</body></html>`;
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const c of [...WARN_CASES, ...QUIET_CASES]) {
    // The look-alike shape: MEDIUM is the conversational rung, which is what
    // arms the field guard without blocking the page.
    net.setVerdict(c.host, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
    net.setPage(c.host, pageFor(c.field));
  }
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, MOCK_KEY);
  // amberBanner OFF so the ONLY thing that can mount an overlay is the field
  // guard: otherwise a passing count would be measuring the banner.
  await setSettings(ext, { shield: true, amberBanner: false, fieldGuard: true, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function axText(page: import("@playwright/test").Page): Promise<string> {
  const cdp = await ext.context.newCDPSession(page);
  const tree = await cdp.send("Accessibility.getFullAXTree");
  await cdp.detach();
  return JSON.stringify(tree);
}

for (const c of WARN_CASES) {
  test(`warns at ${c.name}`, async () => {
    const { page, tabId } = await visit(ext, `https://${c.host}/`);
    await waitForIcon(ext, tabId, ["suspicious"]);
    // Nothing on screen before the field takes focus: the guard is a
    // response to what the reader is about to do, not a page decoration.
    expect(await page.locator(OVERLAY).count()).toBe(0);

    await page.locator("#f").focus();
    await expect
      .poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 })
      .toBeGreaterThan(0);

    const tree = await axText(page);
    expect(tree, "the warning does not name what it caught").toContain(c.expect);
    await page.close();
  });
}

for (const c of QUIET_CASES) {
  test(`stays quiet at ${c.name}`, async () => {
    const { page, tabId } = await visit(ext, `https://${c.host}/`);
    await waitForIcon(ext, tabId, ["suspicious"]);
    await page.locator("#f").focus();
    // Long enough that a warning would have mounted: the positive cases
    // above land well inside this.
    await page.waitForTimeout(1500);
    expect(
      await page.locator(OVERLAY).count(),
      "an ordinary field was treated as a credential; a guard that warns on everything trains the reader to ignore it",
    ).toBe(0);
    await page.close();
  });
}

test("the recovery-phrase warning is the strongest one, because that loss is final", async () => {
  const seed = WARN_CASES.find((c) => c.host === "cred-seed-guard-e2e.com");
  expect(seed, "the seed-phrase case was removed").toBeDefined();
  const { page, tabId } = await visit(ext, `https://${seed!.host}/`);
  await waitForIcon(ext, tabId, ["suspicious"]);
  await page.locator("#f").focus();
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);
  const tree = await axText(page);
  // A password can be changed and a card can be charged back. This cannot,
  // so it gets its own sentence rather than the generic one.
  expect(tree).toContain("STOP");
  expect(tree, "the seed warning reuses the ordinary copy").toContain("gone");
  await page.close();
});

test("one warning per KIND, so a card form does not become four popups", async () => {
  net.setVerdict("cred-multi-guard-e2e.com", { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setPage(
    "cred-multi-guard-e2e.com",
    pageFor(
      `<input id="a" type="text" name="cardnumber">` +
        `<input id="b" type="text" name="cvv">` +
        `<input id="c" type="text" placeholder="Expiry">`,
    ),
  );
  const { page, tabId } = await visit(ext, "https://cred-multi-guard-e2e.com/");
  await waitForIcon(ext, tabId, ["suspicious"]);
  for (const id of ["#a", "#b", "#c"]) {
    await page.locator(id).focus();
    await page.waitForTimeout(400);
  }
  // Three card-shaped fields, one card-shaped warning.
  expect(
    await page.locator(OVERLAY).count(),
    "the guard warned once per field instead of once per kind",
  ).toBe(1);
  await page.close();
});
