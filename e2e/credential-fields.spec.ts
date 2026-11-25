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
import { CAUTION_FN, CLOSE_CENTRE_FN, ClosedShadow, type CautionSnapshot } from "./helpers/closed-shadow";
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

/** Pages for the card tests (board 4c): one fixture host per test. */
const CARD_PAGES: Omit<FieldCase, "expect">[] = [
  {
    name: "look",
    host: "caution-look-guard-e2e.com",
    field: `<input id="f" type="tel" autocomplete="one-time-code" maxlength="6" style="margin-left:60px">`,
  },
  {
    name: "close",
    host: "caution-close-guard-e2e.com",
    field:
      `<input id="a" type="tel" autocomplete="one-time-code"><input id="b" type="text" name="otp-second" placeholder="Enter the code again">` +
      `<input id="c" type="text" name="cardnumber">`,
  },
  {
    name: "secret",
    host: "caution-secret-guard-e2e.com",
    field: `<input id="f" type="text" name="seed-phrase" placeholder="Enter your 12 word recovery phrase">`,
  },
  {
    name: "usable",
    host: "caution-usable-guard-e2e.com",
    field: `<input id="f" type="password" name="pw" style="margin-left:80px;width:200px">`,
  },
  {
    name: "short",
    host: "caution-short-guard-e2e.com",
    field: `<input id="f" type="text" name="seed-phrase" placeholder="Enter your 12 word recovery phrase" style="position:fixed;left:40px;top:100px;width:220px">`,
  },
  {
    name: "edge",
    host: "caution-edge-guard-e2e.com",
    field: `<input id="f" type="password" name="pw" style="position:fixed;right:10px;top:100px;width:60px">`,
  },
  {
    name: "scroll",
    host: "caution-scroll-guard-e2e.com",
    field: `<input id="f" type="password" name="pw" style="margin-top:100px;margin-left:80px"><div style="height:3000px"></div>`,
  },
  {
    name: "timeout",
    host: "caution-timeout-guard-e2e.com",
    field: `<input id="f" type="password" name="pw" style="margin-left:80px">`,
  },
  {
    name: "bottom",
    host: "caution-bottom-guard-e2e.com",
    field: `<input id="f" type="password" name="pw" style="position:fixed;left:40px;bottom:12px;width:220px">`,
  },
];

function cardPage(name: string): string {
  const c = CARD_PAGES.find((p) => p.name === name);
  if (!c) throw new Error(`no card page ${name}`);
  return `https://${c.host}/`;
}

/** WCAG relative luminance of a computed "rgb(...)" colour. */
function luminance(css: string): number {
  const [r, g, b] = css.match(/[\d.]+/g)!.slice(0, 3).map((v) => {
    const c = Number(v) / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

async function openCaution(
  page: import("@playwright/test").Page,
  focusSelector: string,
): Promise<{ shadow: ClosedShadow; snap: CautionSnapshot }> {
  await page.locator(focusSelector).focus();
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);
  const shadow = await ClosedShadow.open(ext.context, page);
  let snap: CautionSnapshot | null = null;
  await expect
    .poll(async () => (snap = await shadow.call<CautionSnapshot>(CAUTION_FN)) !== null, { timeout: 10_000 })
    .toBe(true);
  return { shadow, snap: snap! };
}

async function fieldRect(page: import("@playwright/test").Page, sel: string) {
  return page.locator(sel).evaluate((e) => {
    const b = e.getBoundingClientRect();
    return { l: b.left, r: b.right, t: b.top, b: b.bottom };
  });
}

function pageFor(field: string): string {
  return `<!doctype html><html><head><title>form</title></head><body>
<h1>form</h1>
<form><p>Sign in to continue.</p>${field}<button type="button">Go</button></form>
</body></html>`;
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const c of [...WARN_CASES, ...QUIET_CASES, ...CARD_PAGES]) {
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

// ------------------------------------------------ the card, board 4c

test("board 4c look: a flagged one-time code gets the dark card below its field, amber edge, kind in a strong, mark then sentence then Dismiss", async () => {
  const { page, tabId } = await visit(ext, cardPage("look"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow, snap } = await openCaution(page, "#f");
  const f = await fieldRect(page, "#f");

  expect(snap.role).toBe("alert");
  expect(snap.card.backgroundColor).toBe("rgb(13, 13, 26)");
  expect(snap.card.borderWidth).toBe("1px");
  expect(snap.card.borderStyle).toBe("solid");
  expect(snap.card.borderColor).toBe("rgb(141, 93, 18)");
  expect(snap.card.borderRadius).toBe("10px");
  expect(snap.childTags).toEqual(["img", "div", "button"]);
  expect(snap.markAlt).toBe("");
  expect(snap.dismiss?.label).toBe("Dismiss");
  expect(snap.dismiss?.type).toBe("button");
  expect(snap.sentence.strongText).toBe("one-time code");
  expect(snap.sentence.strongColor).toBe("rgb(251, 191, 36)");
  expect(snap.sentence.fontSize).toBe("13.5px");
  expect(snap.sentence.text).toBe("Careful: this site is flagged and it is asking for your one-time code. Think twice.");
  expect(snap.card.rect.t).toBeGreaterThan(f.b);
  expect(Math.abs(snap.card.rect.l - f.l)).toBeLessThanOrEqual(1);
  expect(snap.caret, "the caret on the top edge is missing").not.toBeNull();
  expect(snap.caret!.borders.top).toBe("1px");
  expect(snap.caret!.borders.left).toBe("1px");
  expect(snap.caret!.borders.bottom).toBe("0px");
  expect(snap.caret!.backgroundColor).toBe("rgb(13, 13, 26)");
  expect(contrast(snap.sentence.color, snap.card.backgroundColor)).toBeGreaterThanOrEqual(4.5);
  expect(contrast(snap.sentence.strongColor!, snap.card.backgroundColor)).toBeGreaterThanOrEqual(4.5);
  await shadow.close();
  await page.close();
});

test("Dismiss closes the caution and that kind never comes back, while another kind still cautions", async () => {
  const { page, tabId } = await visit(ext, cardPage("close"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow } = await openCaution(page, "#a");
  const before = await page.locator(OVERLAY).count();
  expect(before).toBe(1);

  const at = (await shadow.call<{ x: number; y: number }>(CLOSE_CENTRE_FN))!;
  await shadow.mouseClicks(at.x, at.y, 1);
  await expect.poll(async () => (await shadow.call<CautionSnapshot>(CAUTION_FN)) === null).toBe(true);

  // The same kind again, on the same field and on a second field of that kind.
  await page.locator("#a").blur();
  await page.locator("#a").focus();
  await page.locator("#b").focus();
  // A different kind is the positive signal: once its caution is showing, the
  // closed kind has had every chance to come back and did not.
  await page.locator("#c").focus();
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 }).toBeGreaterThan(0);
  await expect
    .poll(async () => (await shadow.call<CautionSnapshot>(CAUTION_FN))?.sentence.strongText ?? null)
    .toBe("card details");
  expect(await page.locator(OVERLAY).count(), "the closed kind came back").toBe(1);
  await shadow.close();
  await page.close();
});

test("recovery phrase caution: 2 px red edge, red-tinted fill, 15 px weight 900, wording unchanged", async () => {
  const { page, tabId } = await visit(ext, cardPage("secret"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow, snap } = await openCaution(page, "#f");
  expect(snap.card.borderWidth).toBe("2px");
  expect(snap.card.borderColor).toBe("rgb(239, 68, 68)");
  expect(snap.card.backgroundColor).toBe("rgb(36, 18, 30)");
  expect(snap.caret?.backgroundColor).toBe("rgb(36, 18, 30)");
  expect(snap.sentence.fontSize).toBe("15px");
  expect(snap.sentence.fontWeight).toBe("900");
  expect(snap.sentence.strongText).toBeNull();
  expect(snap.sentence.text).toBe(
    "STOP. This site is flagged and it is asking for a recovery phrase. Nobody legitimate ever asks for one. Typed here, it is gone.",
  );
  expect(contrast(snap.sentence.color, "rgb(36, 18, 30)")).toBeGreaterThanOrEqual(4.5);
  await shadow.close();
  await page.close();
});

test("the field stays usable under the caution: typing works and a point on the field hits the field", async () => {
  const { page, tabId } = await visit(ext, cardPage("usable"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow } = await openCaution(page, "#f");
  await page.keyboard.type("abc123");
  expect(await page.locator("#f").inputValue()).toBe("abc123");
  const hit = await page.evaluate(() => {
    const b = document.getElementById("f")!.getBoundingClientRect();
    const e = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
    return e?.id ?? e?.tagName ?? null;
  });
  expect(hit).toBe("f");
  await shadow.close();
  await page.close();
});

test("a field at the bottom of the window gets its caution above it, caret on the bottom edge", async () => {
  const { page, tabId } = await visit(ext, cardPage("bottom"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow, snap } = await openCaution(page, "#f");
  const f = await fieldRect(page, "#f");
  expect(snap.card.rect.b).toBeLessThanOrEqual(f.t);
  expect(snap.caret).not.toBeNull();
  expect(snap.caret!.borders.bottom).toBe("1px");
  expect(snap.caret!.borders.right).toBe("1px");
  expect(snap.caret!.borders.top).toBe("0px");
  await shadow.close();
  await page.close();
});

test("in a short window the card stays fully on screen when it fits neither below nor above the field", async () => {
  const { page, tabId } = await visit(ext, cardPage("short"));
  await page.setViewportSize({ width: 800, height: 240 });
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow, snap } = await openCaution(page, "#f");
  const vh = await page.evaluate(() => document.documentElement.clientHeight);
  expect(snap.card.rect.t).toBeGreaterThanOrEqual(0);
  expect(snap.card.rect.b).toBeLessThanOrEqual(vh);
  expect(snap.sentence.text.startsWith("STOP.")).toBe(true);
  await shadow.close();
  await page.close();
});

test("a field near the right edge: the caret still points inside the field's horizontal span", async () => {
  const { page, tabId } = await visit(ext, cardPage("edge"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow, snap } = await openCaution(page, "#f");
  const f = await fieldRect(page, "#f");
  const centre = (snap.caret!.rect.l + snap.caret!.rect.r) / 2;
  expect(centre).toBeGreaterThanOrEqual(f.l);
  expect(centre).toBeLessThanOrEqual(f.r);
  await shadow.close();
  await page.close();
});

test("the caution follows its field when the page scrolls", async () => {
  const { page, tabId } = await visit(ext, cardPage("scroll"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow } = await openCaution(page, "#f");
  await page.evaluate(() => window.scrollBy(0, 40));
  await expect
    .poll(async () => {
      const snap = (await shadow.call<CautionSnapshot>(CAUTION_FN))!;
      const f = await fieldRect(page, "#f");
      return Math.abs(snap.card.rect.t - (f.b + 10)) <= 1;
    })
    .toBe(true);
  await shadow.close();
  await page.close();
});

test("the caution and Guard's host are removed after the 8 second timeout", async () => {
  const { page, tabId } = await visit(ext, cardPage("timeout"));
  await waitForIcon(ext, tabId, ["suspicious"]);
  const { shadow } = await openCaution(page, "#f");
  expect(await page.locator(OVERLAY).count()).toBe(1);
  await expect.poll(async () => page.locator(OVERLAY).count(), { timeout: 20_000 }).toBe(0);
  await shadow.close();
  await page.close();
});
