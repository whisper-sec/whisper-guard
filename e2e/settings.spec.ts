// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE SETTINGS PAGE, five sections behind a side menu.
//
// Measured against the built extension:
//
//   - the menu holds the five sections in order, each link reaches its
//     section, and a direct link opens at the section it names;
//   - every option the page has always carried is still on it, each switch
//     writes its own key, and each shows the stored state after a reload;
//   - the version shown comes from the installed manifest and no version is
//     written into the page;
//   - the list of what leaves the browser names the same hosts the README's
//     privacy model names;
//   - the menu stacks above the content at narrow widths;
//   - the theme row reads and writes the same choice the popup does;
//   - the protect control is the shared one, mounted in This browser.

import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, makeShieldDist, setKey, setSettings, type Extension } from "./helpers/extension";
import { choose, expectScheme, MIRROR_KEY } from "./helpers/theme";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  // The all-sites grant is held, so every sub-switch of Active Shield is usable.
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function open(hash = ""): Promise<Page> {
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto(`chrome-extension://${ext.id}/options.html${hash}`);
  return page;
}

/** Wait for the page's first settings read to be drawn. */
async function drawn(page: Page): Promise<void> {
  await expect(page.locator("#corpus-info")).toHaveText(/.+/);
}

async function stored(page: Page): Promise<Record<string, unknown>> {
  return page.evaluate(async () => {
    const res = (await chrome.runtime.sendMessage({ kind: "getSettings" })) as { settings: Record<string, unknown> };
    return res.settings;
  });
}

const SECTIONS = [
  ["Protection", "protection"],
  ["Account", "account"],
  ["This browser", "browser"],
  ["Privacy", "privacy"],
  ["About", "about"],
] as const;

const menu = (page: Page) => page.locator('nav[aria-label="Settings sections"]');

/** The section's top edge is on screen, in the upper part of the window. */
async function expectNearTop(page: Page, id: string): Promise<void> {
  await expect
    .poll(() =>
      page.evaluate((i) => {
        const top = document.getElementById(i)?.getBoundingClientRect().top;
        return top !== undefined && top >= -2 && top < innerHeight * 0.6;
      }, id),
    )
    .toBe(true);
}

async function expectCurrent(page: Page, label: string): Promise<void> {
  await expect(menu(page).locator('a[aria-current="true"]')).toHaveText([label]);
}

// ------------------------------------------------------------ the menu

test("the side menu holds the five sections in order, each linking to a section of that name", async () => {
  const page = await open();
  await expect(menu(page).locator("a")).toHaveText(SECTIONS.map(([label]) => label));
  await expect(menu(page).locator("a")).toHaveCount(5);
  for (const [label, id] of SECTIONS) {
    await expect(menu(page).locator("a", { hasText: label })).toHaveAttribute("href", `#${id}`);
    await expect(page.locator(`section#${id}`)).toHaveCount(1);
    await expect(page.locator(`section#${id}`).locator("h1, h2").first()).toHaveText(label);
  }
  const order = await page.evaluate(() => Array.from(document.querySelectorAll("section[id]")).map((s) => s.id));
  expect(order).toEqual(SECTIONS.map(([, id]) => id));
  await page.close();
});

test("each menu link brings its section into view and is the one marked current", async () => {
  const page = await open();
  await drawn(page);
  for (const [label, id] of [...SECTIONS].reverse()) {
    await menu(page).locator("a", { hasText: label }).click();
    await expectNearTop(page, id);
    await expectCurrent(page, label);
  }
  // Scrolling back to the top follows too.
  await page.evaluate(() => window.scrollTo(0, 0));
  await expectCurrent(page, "Protection");
  await page.close();
});

for (const [label, id] of [SECTIONS[3], SECTIONS[4]]) {
  test(`opening options.html#${id} lands on the ${label} section, also once the page has drawn`, async () => {
    const page = await open(`#${id}`);
    await drawn(page);
    await expectNearTop(page, id);
    await expectCurrent(page, label);
    await page.close();
  });
}

test("the menu foot reads the installed version, and so does About, and no version is written into the page", async () => {
  const page = await open();
  const version = await page.evaluate(() => chrome.runtime.getManifest().version);
  expect(version).toMatch(/^\d+\.\d+\.\d+/);
  await expect(page.locator("#menu-version")).toHaveText(`v${version} · MIT · open source`);
  await expect(page.locator("#about-version")).toHaveText(version);
  await expect(page.locator("#about")).toContainText(`Version ${version}`);
  // Every regular-expression metacharacter in the version is escaped, not only the dots.
  const literal = new RegExp(`(^|[^0-9.])${version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}($|[^0-9])`);
  for (const file of ["dist/chromium/options.html", "dist/chromium/options.js", "src/options/options.html", "src/options/options.ts"]) {
    expect(readFileSync(resolve(ROOT, file), "utf8"), `${file} holds no version literal`).not.toMatch(literal);
  }
  await page.close();
});

test("About links the licence and the source, each in a new tab without an opener", async () => {
  const page = await open();
  const links = await page.locator("#about a").evaluateAll((as) =>
    as.map((a) => ({ text: a.textContent?.trim(), href: (a as HTMLAnchorElement).href, target: a.getAttribute("target"), rel: a.getAttribute("rel") })),
  );
  const byText = (t: string) => links.find((l) => l.text === t);
  expect(byText("MIT licence")?.href).toBe("https://github.com/whisper-sec/whisper-guard/blob/main/LICENSE");
  expect(byText("Source")?.href).toBe("https://github.com/whisper-sec/whisper-guard");
  for (const l of links) {
    expect(l.target).toBe("_blank");
    expect(l.rel).toBe("noopener");
  }
  await page.close();
});

// ------------------------------------------------- every option is here

const SWITCHES = [
  ["#opt-cloudcheck", "cloudCheck"],
  ["#opt-nearmiss", "nearMiss"],
  ["#opt-cookiedecline", "cookieDecline"],
  ["#opt-corpusupdate", "corpusAutoUpdate"],
  ["#opt-banner", "amberBanner"],
  ["#opt-fieldguard", "fieldGuard"],
  ["#opt-shield", "shield"],
] as const;

test("every id the page carried before the regroup is still on it", async () => {
  const page = await open();
  const ids = [
    "opt-cloudcheck", "account-signedout", "btn-signin", "device-status", "key-input", "btn-savekey",
    "account-signedin", "btn-dashboard", "btn-console", "btn-signout", "btn-egress-dash",
    "opt-shield", "opt-banner", "banner-needs", "opt-fieldguard", "fieldguard-needs",
    "opt-cookiedecline", "cookiedecline-reach", "opt-nearmiss", "opt-allowlist",
    "corpus-info", "opt-corpusupdate", "btn-corpusnow", "corpus-status",
  ];
  for (const id of ids) await expect(page.locator(`#${id}`), `#${id}`).toHaveCount(1);
  for (const [id] of SWITCHES) {
    await expect(page.locator(id)).toHaveAttribute("role", "switch");
    await expect(page.locator(id)).toHaveAttribute("type", "checkbox");
  }
  await page.close();
});

test("each switch writes its own setting, at once, and the trusted sites list writes the allowlist", async () => {
  await setSettings(ext, {
    cloudCheck: true, nearMiss: true, cookieDecline: true, corpusAutoUpdate: true,
    amberBanner: true, fieldGuard: true, shield: true, allowlist: [],
  });
  const page = await open();
  await drawn(page);
  // Shield goes last: switching it off disables the two switches under it.
  for (const [id, key] of SWITCHES) {
    await expect(page.locator(id)).toBeChecked();
    await page.locator(id).click();
    await expect.poll(async () => (await stored(page))[key], { message: `${key} off` }).toBe(false);
    await expect(page.locator(id)).not.toBeChecked();
  }
  await page.locator("#opt-allowlist").fill("Example.org\n\n  other.example  ");
  await page.locator("#opt-allowlist").blur();
  await expect.poll(async () => (await stored(page))["allowlist"]).toEqual(["example.org", "other.example"]);
  await page.close();
});

test("each switch shows the stored state after a reload, and Hold dangerous clicks follows the live check", async () => {
  const cases: [Record<string, unknown>, string, boolean][] = [
    [{ cloudCheck: false, nearMiss: true, cookieDecline: false, corpusAutoUpdate: false, shield: true, amberBanner: false, fieldGuard: true }, "Limited", true],
    [{ cloudCheck: true, nearMiss: false, cookieDecline: true, corpusAutoUpdate: true, shield: false, amberBanner: true, fieldGuard: false }, "On", false],
  ];
  for (const [settings, hold, noteShown] of cases) {
    await setSettings(ext, settings);
    const page = await open();
    await drawn(page);
    const check = async (): Promise<void> => {
      for (const [id, key] of SWITCHES) {
        const want = key === "amberBanner" || key === "fieldGuard" ? settings["shield"] === true && settings[key] === true : settings[key] === true;
        await expect(page.locator(id), `${key}`).toBeChecked({ checked: want });
      }
      await expect(page.locator("#hold-state")).toHaveText(hold);
      if (noteShown) {
        await expect(page.locator("#hold-note")).toHaveText(
          "With Live graph verdict off, it holds only clicks to sites a recent check already flagged.",
        );
      } else {
        await expect(page.locator("#hold-note")).toBeHidden();
      }
    };
    await check();
    await page.reload();
    await drawn(page);
    await check();
    await page.close();
  }
  await setSettings(ext, { cloudCheck: true, nearMiss: false, cookieDecline: true, corpusAutoUpdate: true, shield: false });
});

test("the look-alike row says it is always on and counts the brands the detector loaded", async () => {
  const page = await open();
  await drawn(page);
  const brands = await page.evaluate(async () => {
    const res = (await chrome.runtime.sendMessage({ kind: "getSettings" })) as { corpusBrands: number };
    return res.corpusBrands;
  });
  expect(brands).toBeGreaterThan(0);
  await expect(page.locator("#lookalike-state")).toHaveText("Always on");
  await expect(page.locator("#lookalike-line")).toHaveText(
    `Catches homoglyphs, TLD swaps and combosquats of ${brands.toLocaleString("en")} brands, on this device.`,
  );
  await page.close();
});

// -------------------------------------------------------------- account

const identities = (n: number) => {
  net.clearEndpoints();
  for (let i = 0; i < n; i++) {
    net.addEndpoint({ agent: `agent-e2e-settings-${i}`, address: `2a04:2a01:e2e:${i + 1}::1`, label: `Device ${i + 1}`, device: true, logs: [] });
  }
};

test("signed in, the account says how many identities it holds, with the right singular and plural", async () => {
  await setKey(ext, MOCK_KEY);
  try {
    for (const [n, text] of [[2, "2 identities on the account"], [1, "1 identity on the account"]] as const) {
      identities(n);
      const page = await open();
      await expect(page.locator("#account-signedin")).toBeVisible();
      await expect(page.locator("#account-signedin")).toContainText("Signed in");
      await expect(page.locator("#account-identities")).toHaveText(text);
      await expect(page.locator("#btn-console")).toHaveText("Open console ↗");
      await expect(page.locator("#btn-dashboard")).toHaveText("Open dashboard");
      await expect(page.locator("#btn-signout")).toHaveText("Sign out");
      await page.close();
    }
  } finally {
    net.clearEndpoints();
    await setKey(ext, null);
  }
});

test("signed in, a failed roster read leaves the count out and keeps the rest of the account block", async () => {
  await setKey(ext, MOCK_KEY);
  try {
    const page = await ext.context.newPage();
    // The roster read is answered "not ok" only when the test lets it, so the
    // checks below run with the read really outstanding and then really failed.
    await page.addInitScript(() => {
      const g = { calls: 0, answer: () => undefined as void };
      (window as unknown as { __roster: typeof g }).__roster = g;
      const real = chrome.runtime.sendMessage.bind(chrome.runtime) as (...a: unknown[]) => unknown;
      (chrome.runtime as { sendMessage: unknown }).sendMessage = (m: { kind?: string }, ...rest: unknown[]) => {
        if (m?.kind !== "getFleetReport") return real(m, ...rest);
        g.calls++;
        return new Promise((res) => {
          g.answer = () => res({ ok: false, error: "down" });
        });
      };
    });
    await page.goto(`chrome-extension://${ext.id}/options.html`);
    const calls = () => page.evaluate(() => (window as unknown as { __roster: { calls: number } }).__roster.calls);
    await expect.poll(calls).toBeGreaterThan(0);
    await expect(page.locator("#account-signedin")).toBeVisible();
    await expect(page.locator("#account-identities")).toBeHidden();
    await page.evaluate(() => (window as unknown as { __roster: { answer: () => void } }).__roster.answer());
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
    await expect(page.locator("#account-signedin")).toContainText("Signed in");
    await expect(page.locator("#btn-signout")).toBeVisible();
    await expect(page.locator("#account-identities")).toBeHidden();
    await expect(page.locator("#account-signedin")).not.toContainText(/identit/i);
    await page.close();
  } finally {
    await setKey(ext, null);
  }
});

// -------------------------------------------------------------- privacy

test("the rows of what leaves this browser name the hosts the README's privacy model names, and never the page", async () => {
  const readme = readFileSync(resolve(ROOT, "README.md"), "utf8");
  const start = readme.indexOf("## Privacy model");
  expect(start).toBeGreaterThan(-1);
  const end = readme.indexOf("\n## ", start + 5);
  const section = readme.slice(start, end === -1 ? undefined : end);
  const HOST = /\b[a-z0-9-]+\.whisper\.(?:online|security)\b/g;
  // edr.whisper.security is the console, a place Guard sends the reader to, not somewhere data goes.
  const named = [...new Set(section.match(HOST) ?? [])].filter((h) => h !== "edr.whisper.security").sort();
  expect(named.length).toBeGreaterThanOrEqual(5);

  const page = await open();
  const rows = await page.locator("#privacy dl.leaves > div").evaluateAll((els) =>
    els.map((e) => ({ what: e.querySelector("dt")?.textContent?.trim() ?? "", where: e.querySelector("dd")?.textContent?.trim() ?? "" })),
  );
  // The graph host has two rows (site names, and the keyed account calls), so the set is compared.
  const shown = [...new Set(rows.map((r) => r.where.match(/\b[a-z0-9-]+\.whisper\.(?:online|security)\b/g) ?? []).flat())].sort();
  expect(shown).toEqual(named);
  const never = rows.filter((r) => r.where === "never");
  expect(never).toHaveLength(1);
  for (const word of ["pages", "paths", "history", "typing"]) expect(never[0]!.what.toLowerCase()).toContain(word);
  expect(rows.map((r) => r.what)).toEqual([
    "Site names, for the live check",
    "Signed in: your account’s devices and routing, with your key, never a site name",
    "Sign-in only",
    "Signed brand-list updates",
    "Your own devices’ addresses, to verify them",
    "Public network statistics, a plain download",
    "Pages, paths, history, typing",
  ]);
  await expect(page.locator("#privacy")).toContainText("“Open console ↗” opens the Whisper console, edr.whisper.security.");
  await expect(page.locator("#privacy")).toContainText("No telemetry, no analytics, no sync.");
  await expect(page.locator("#privacy")).toContainText("A page scan you start sends only the site names it finds on the page.");
  await expect(page.locator("#privacy")).toContainText("With Protect this browser on, your page loads leave through your Whisper address.");
  await page.close();
});

// --------------------------------------------------------------- layout

test("at 390 px the menu sits above the content and the page does not scroll sideways; at 1280 px they sit side by side", async () => {
  const page = await open();
  await drawn(page);
  const boxes = () =>
    page.evaluate(() => {
      const navEl = document.querySelector('nav[aria-label="Settings sections"]')!;
      const nav = navEl.getBoundingClientRect();
      const first = document.getElementById("protection")!.getBoundingClientRect();
      const de = document.documentElement;
      return {
        navBottom: nav.bottom, navRight: nav.right, navLeft: nav.left, firstTop: first.top, firstLeft: first.left,
        position: getComputedStyle(navEl).position,
        overflow: de.scrollWidth - de.clientWidth,
      };
    });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(async () => (await boxes()).navBottom <= (await boxes()).firstTop + 1).toBe(true);
  let b = await boxes();
  expect(b.position).not.toBe("sticky");
  expect(b.overflow).toBeLessThanOrEqual(0);
  expect(b.firstLeft).toBeLessThan(b.navRight);
  await page.setViewportSize({ width: 1280, height: 720 });
  await expect.poll(async () => (await boxes()).navRight <= (await boxes()).firstLeft + 1).toBe(true);
  b = await boxes();
  expect(b.position).toBe("sticky");
  expect(b.navLeft).toBe(0);
  await page.close();
});

// ---------------------------------------------------------------- theme

const pressed = (page: Page) => page.locator("#theme-choice button[aria-pressed='true']");

test("the theme row shows the stored choice on open", async () => {
  for (const [choice, label] of [["light", "Light"], ["dark", "Dark"], ["auto", "Auto"]] as const) {
    await choose(ext, choice);
    const page = await open();
    await expect(page.locator("#theme-choice")).toHaveAttribute("role", "group");
    await expect(page.locator("#theme-choice button")).toHaveText(["Auto", "Light", "Dark"]);
    await expect(pressed(page)).toHaveText([label]);
    await page.close();
  }
});

test("pressing a theme draws it at once, stores it as settings.theme and leaves nothing pending", async () => {
  await choose(ext, "auto");
  const page = await open();
  await page.emulateMedia({ colorScheme: "dark" });
  await page.locator("#theme-choice button", { hasText: "Light" }).click();
  await expectScheme(page, "light");
  await expect(pressed(page)).toHaveText(["Light"]);
  await expect.poll(async () => (await stored(page))["theme"]).toBe("light");
  expect(await page.evaluate((k) => localStorage.getItem(k), MIRROR_KEY)).toBe("light");
  await expect.poll(() => page.evaluate(() => document.documentElement.hasAttribute("data-theme-pending"))).toBe(false);
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.locator("#theme-choice button", { hasText: "Dark" }).click();
  await expectScheme(page, "dark");
  await expect.poll(async () => (await stored(page))["theme"]).toBe("dark");
  await expect(pressed(page)).toHaveText(["Dark"]);
  await page.close();
  await choose(ext, "auto");
});

test("a choice made in the popup shows in an open settings page without a reload", async () => {
  await choose(ext, "auto");
  const page = await open();
  await page.evaluate(() => ((window as unknown as { __kept: boolean }).__kept = true));
  await expect(pressed(page)).toHaveText(["Auto"]);
  const popup = await ext.context.newPage();
  await popup.goto(`chrome-extension://${ext.id}/popup.html`);
  await popup.locator("#btn-theme").click();
  await expect(pressed(page)).toHaveText(["Light"]);
  expect(await page.evaluate(() => (window as unknown as { __kept?: boolean }).__kept)).toBe(true);
  await popup.close();
  await page.close();
  await choose(ext, "auto");
});

// ------------------------------------------------------ this browser

test("the shared protect control is mounted in This browser, and its action opens the dashboard's browser view", async () => {
  const page = await open();
  for (const id of ["btn-protect", "identity-state", "route-line"]) {
    await expect(page.locator(`#browser #${id}`), `#${id} inside This browser`).toHaveCount(1);
  }
  await expect(page.locator("#btn-protect")).toBeVisible();
  await expect(page.locator("#btn-egress-dash")).toHaveText("Open it on the dashboard");
  await expect(page.locator("#browser #btn-egress-dash")).toHaveCount(1);
  const [dash] = await Promise.all([ext.context.waitForEvent("page"), page.locator("#btn-egress-dash").click()]);
  await expect.poll(() => dash.url()).toBe(`chrome-extension://${ext.id}/dashboard.html#browser`);
  await dash.close();
  await page.close();
});

test("a rejected egress status read leaves the control drawn and raises no unhandled rejection", async () => {
  const page = await ext.context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.addInitScript(() => {
    const real = chrome.runtime.sendMessage.bind(chrome.runtime) as (...a: unknown[]) => unknown;
    (chrome.runtime as { sendMessage: unknown }).sendMessage = (m: { kind?: string }, ...rest: unknown[]) =>
      m?.kind === "egressStatus" ? Promise.reject(new Error("the worker stopped mid-request")) : real(m, ...rest);
  });
  await page.goto(`chrome-extension://${ext.id}/options.html`);
  await drawn(page);
  await expect(page.locator("#btn-protect")).toBeVisible();
  await expect(page.locator("#corpus-info")).toHaveText(/.+/);
  // A later frame: any late rejection has had its chance to surface.
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
  expect(errors).toEqual([]);
  await page.close();
});
