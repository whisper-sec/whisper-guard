// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE THEME CHOICE, Auto / Light / Dark, from the popup's header.
//
// Measured against the built extension:
//
//   - the button names the current choice, a press moves Auto, Light, Dark,
//     Auto, and the keyboard does the same with focus staying put;
//   - the choice is kept in local extension storage, never in synced storage,
//     and a stored value that is not a choice reads as Auto;
//   - every page draws the chosen scheme in its first frame, and an open page
//     follows a change without a reload;
//   - on Auto the page follows the system live; on Light or Dark it ignores it.
//
// Every test leaves the choice on Auto: many specs flip the system scheme
// with emulateMedia, and a leftover forced choice would measure the wrong
// palette.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import { launchExtension, markHostBlocked, openDashboard, type Extension } from "./helpers/extension";
import { choose, expectScheme, palette, schemeOf, MIRROR_KEY, type Scheme } from "./helpers/theme";
import { settledLayout, twoFrames } from "./helpers/popup-fit";

let net: E2ENetwork;
let ext: Extension;

const STOPPED_HOST = "theme-choice-stopped-guard-e2e.com";
const NO_BLOCK_HOST = "theme-choice-open-guard-e2e.com";

/** Every page, the warning page once per tone. */
const ADDRESSES = [
  "popup.html",
  "options.html",
  "dashboard.html",
  "firstrun.html",
  "check-link.html",
  `warning.html?host=${STOPPED_HOST}`,
  `warning.html?host=${NO_BLOCK_HOST}`,
];

type Palette = Record<string, string>;
const refs: Partial<Record<Scheme, Palette>> = {};

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort });
  await markHostBlocked(ext, STOPPED_HOST);
  // What each scheme draws on the popup, read from the popup itself on Auto.
  const scratch = await ext.context.newPage();
  await scratch.goto(`chrome-extension://${ext.id}/popup.html`);
  for (const scheme of ["dark", "light"] as const) {
    await scratch.emulateMedia({ colorScheme: scheme });
    await expect.poll(() => scratch.evaluate(() => matchMedia("(prefers-color-scheme: light)").matches)).toBe(scheme === "light");
    await twoFrames(scratch);
    refs[scheme] = await palette(scratch);
  }
  await scratch.close();
});
test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});
test.afterEach(async () => {
  await choose(ext, "auto");
});

// ---------------------------------------------------------------- helpers

async function openPopup(system: Scheme = "dark"): Promise<Page> {
  const popup = await ext.context.newPage();
  await popup.emulateMedia({ colorScheme: system, reducedMotion: "reduce" });
  await popup.goto(`chrome-extension://${ext.id}/popup.html`);
  return popup;
}

/** The popup draws `scheme`: its whole palette is the one Auto draws under that system scheme. */
async function expectDrawn(page: Page, scheme: Scheme, message: string): Promise<void> {
  await expectScheme(page, scheme, message);
  expect(await palette(page), message).toEqual(refs[scheme]);
}

async function stored(): Promise<unknown> {
  return ext.sw.evaluate(async () => ((await chrome.storage.local.get("settings"))["settings"] as { theme?: unknown } | undefined)?.theme);
}

/**
 * Init script: every value `data-theme` on <html> takes is kept (as the old
 * value of each change, so changes made in one task are not merged).
 */
function recordThemeSequence(): void {
  const old: (string | null)[] = [];
  (window as unknown as { __themeOld: (string | null)[] }).__themeOld = old;
  new MutationObserver((records) => {
    for (const r of records) old.push(r.oldValue);
  }).observe(document, { attributes: true, subtree: true, attributeFilter: ["data-theme"], attributeOldValue: true });
}

/** The values `data-theme` has had, in order, each once in a row, ending on what it is now. */
async function themeSequence(page: Page): Promise<string[]> {
  const raw = await page.evaluate(() => [
    ...(window as unknown as { __themeOld: (string | null)[] }).__themeOld,
    document.documentElement.getAttribute("data-theme"),
  ]);
  const seq: string[] = [];
  for (const v of raw) if (v !== null && seq[seq.length - 1] !== v) seq.push(v);
  return seq;
}

/**
 * Init script: `setSettings` messages are held until the test releases them,
 * in the order they were sent. Every change of the theme in local storage the
 * page hears is recorded in order (other areas, other keys and writes that do
 * not change the theme are not), so a test waits for the exact list it expects
 * rather than for a count. This listener is added before the page's own, so
 * once a value is in the list and a frame has been drawn, the page's own
 * handler has run for it.
 */
function holdSettingsWrites(): void {
  const w = window as unknown as { __held: (() => void)[]; __release: (n: number) => void; __heard: unknown[] };
  w.__held = [];
  w.__heard = [];
  chrome.storage.onChanged.addListener((changes, area) => {
    const c = changes["settings"];
    if (area !== "local" || !c) return;
    const was = (c.oldValue as { theme?: unknown } | undefined)?.theme;
    const now = (c.newValue as { theme?: unknown } | undefined)?.theme;
    if (now !== was) w.__heard.push(now);
  });
  const orig = chrome.runtime.sendMessage.bind(chrome.runtime) as (m: unknown) => Promise<unknown>;
  (chrome.runtime as unknown as { sendMessage: (m: { kind?: string }) => Promise<unknown> }).sendMessage = (m) =>
    m?.kind === "setSettings" ? new Promise((done) => w.__held.push(() => done(orig(m)))) : orig(m);
  w.__release = (n) => {
    for (let i = 0; i < n; i++) w.__held.shift()?.();
  };
}

test("control: the two schemes really draw different palettes", () => {
  expect(refs.dark).toBeDefined();
  expect(Object.keys(refs.dark!).length).toBeGreaterThan(40);
  expect(refs.light).not.toEqual(refs.dark);
});

// ------------------------------------------------------- the control itself

test("a fresh profile names the button Theme: Auto, stores nothing, and Tab goes Re-check, Theme, Settings", async () => {
  // Its own browser profile: the shared one has been through other tests.
  const fresh = await launchExtension({ proxyPort: net.proxyPort });
  try {
    const popup = await fresh.context.newPage();
    await popup.goto(`chrome-extension://${fresh.id}/popup.html`);
    const btn = popup.locator("#btn-theme");
    await expect(btn).toHaveAttribute("aria-label", "Theme: Auto");
    await expect(btn).toHaveAttribute("title", "Theme: Auto (follows your system)");
    await expect(popup.getByRole("button", { name: "Theme: Auto" })).toHaveCount(1);
    await twoFrames(popup);
    const settings = await fresh.sw.evaluate(async () => (await chrome.storage.local.get("settings"))["settings"] as { theme?: unknown } | undefined);
    expect(settings?.theme, "nothing was stored for the theme by opening the popup").toBeUndefined();

    await popup.locator("#btn-refresh").focus();
    await popup.keyboard.press("Tab");
    await expect(btn).toBeFocused();
    await popup.keyboard.press("Tab");
    await expect(popup.locator("#btn-settings")).toBeFocused();
  } finally {
    await fresh.close();
  }
});

test("a press moves Auto, Light, Dark, Auto; the name, the title, the palette and Auto's following all agree", async () => {
  const popup = await openPopup("dark");
  const btn = popup.locator("#btn-theme");
  await expectDrawn(popup, "dark", "Auto under a dark system");

  await btn.click();
  await expect(btn).toHaveAttribute("aria-label", "Theme: Light");
  await expect(btn).toHaveAttribute("title", "Theme: Light");
  await expectDrawn(popup, "light", "Light under a dark system");
  await expect.poll(stored).toBe("light");

  await popup.emulateMedia({ colorScheme: "light" });
  await btn.click();
  await expect(btn).toHaveAttribute("aria-label", "Theme: Dark");
  await expectDrawn(popup, "dark", "Dark under a light system");
  await expect.poll(stored).toBe("dark");

  await btn.click();
  await expect(btn).toHaveAttribute("aria-label", "Theme: Auto");
  await expect(btn).toHaveAttribute("title", "Theme: Auto (follows your system)");
  await expectDrawn(popup, "light", "Auto under a light system");
  await expect.poll(stored).toBe("auto");

  // Auto follows the system again, live.
  await popup.emulateMedia({ colorScheme: "dark" });
  await expectDrawn(popup, "dark", "Auto followed the system to dark");
  await popup.emulateMedia({ colorScheme: "light" });
  await expectDrawn(popup, "light", "Auto followed the system to light");
  await popup.close();
});

test("Enter and Space each advance the choice, focus stays on the button, and the live region says the new name", async () => {
  const popup = await openPopup("dark");
  const btn = popup.locator("#btn-theme");
  const live = popup.locator("#theme-live");
  await expect(live).toHaveAttribute("aria-live", "polite");
  await expect(live).toHaveText("");

  await btn.focus();
  await popup.keyboard.press("Enter");
  await expect(btn).toHaveAttribute("aria-label", "Theme: Light");
  await expect(live).toHaveText("Theme: Light");
  expect(await popup.evaluate(() => document.activeElement?.id)).toBe("btn-theme");

  await popup.keyboard.press("Space");
  await expect(btn).toHaveAttribute("aria-label", "Theme: Dark");
  await expect(live).toHaveText("Theme: Dark");
  expect(await popup.evaluate(() => document.activeElement?.id)).toBe("btn-theme");

  await popup.keyboard.press("Enter");
  await expect(btn).toHaveAttribute("aria-label", "Theme: Auto");
  await expect(live).toHaveText("Theme: Auto");
  expect(await popup.evaluate(() => document.activeElement?.id)).toBe("btn-theme");
  await popup.close();
});

test("three presses with no wait between them end on Auto, in storage and on screen, and the page never steps back", async () => {
  const popup = await ext.context.newPage();
  await popup.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await popup.addInitScript(recordThemeSequence);
  await popup.addInitScript(holdSettingsWrites);
  await popup.goto(`chrome-extension://${ext.id}/popup.html`);
  await popup.locator("#btn-theme").evaluate((b) => {
    for (let i = 0; i < 3; i++) (b as HTMLButtonElement).click();
  });
  // Let the three writes go, and wait until the page has heard storage change
  // for each of them: the echoes of the first two are in by then.
  await popup.evaluate(() => (window as unknown as { __release: (n: number) => void }).__release(3));
  await expect.poll(stored).toBe("auto");
  await expect
    .poll(() => popup.evaluate(() => (window as unknown as { __heard: unknown[] }).__heard))
    .toEqual(["light", "dark", "auto"]);
  await twoFrames(popup);
  await expect(popup.locator("#btn-theme")).toHaveAttribute("aria-label", "Theme: Auto");
  await expectDrawn(popup, "dark", "three presses end on Auto, which follows the dark system");
  expect(await themeSequence(popup), "the page went Light, Dark, Auto and never back").toEqual(["auto", "light", "dark", "auto"]);
  await popup.close();
});

test("a late echo of an earlier press does not step the page back", async () => {
  const popup = await ext.context.newPage();
  await popup.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await popup.addInitScript(recordThemeSequence);
  await popup.addInitScript(holdSettingsWrites);
  await popup.goto(`chrome-extension://${ext.id}/popup.html`);
  const btn = popup.locator("#btn-theme");
  const release = (n: number): Promise<void> =>
    popup.evaluate((n) => (window as unknown as { __release: (n: number) => void }).__release(n), n);
  const heard = (): Promise<unknown[]> => popup.evaluate(() => (window as unknown as { __heard: unknown[] }).__heard);

  await btn.click();
  await btn.click();
  await expect(btn).toHaveAttribute("aria-label", "Theme: Dark");
  // The first write lands and its echo reaches the page while the second is still held.
  await release(1);
  await expect.poll(stored).toBe("light");
  await expect.poll(heard).toEqual(["light"]);
  await twoFrames(popup);
  await expect(btn, "the echo of the first press moved the name").toHaveAttribute("aria-label", "Theme: Dark");
  expect(await schemeOf(popup), "the echo of the first press moved the page").toBe("dark");

  await btn.click();
  await expect(btn).toHaveAttribute("aria-label", "Theme: Auto");
  await release(2);
  await expect.poll(stored).toBe("auto");
  await expect.poll(heard).toEqual(["light", "dark", "auto"]);
  await twoFrames(popup);
  await expect(btn).toHaveAttribute("aria-label", "Theme: Auto");
  await expectDrawn(popup, "dark", "after the last write, Auto follows the dark system");
  expect(await themeSequence(popup), "the page never stepped back").toEqual(["auto", "light", "dark", "auto"]);
  await popup.close();
});

test("a change made in another page applies when this page has no write in flight", async () => {
  const popup = await openPopup("dark");
  await expectDrawn(popup, "dark", "before");
  await choose(ext, "light");
  await expectDrawn(popup, "light", "another page's choice reaches an idle page");
  await expect(popup.locator("#btn-theme")).toHaveAttribute("aria-label", "Theme: Light");
  await popup.close();
});

test("pressing through all three choices sends nothing over the network", async () => {
  const popup = await openPopup("dark");
  // Whatever the popup asks for on opening has been answered once the readout is settled.
  await expect(popup.locator("#scale, #ineligible, #checking-view").first()).toBeAttached();
  await settledLayout(popup);
  net.clearLog();
  const btn = popup.locator("#btn-theme");
  for (const name of ["Light", "Dark", "Auto"]) {
    await btn.click();
    await expect(btn).toHaveAttribute("aria-label", `Theme: ${name}`);
    await expect.poll(stored).toBe(name.toLowerCase());
  }
  expect(net.log, "a press sent a request").toEqual([]);
  await popup.close();
});

test("two presses with no wait between them end on Dark, in storage and on screen", async () => {
  const popup = await openPopup("light");
  await popup.locator("#btn-theme").evaluate((b) => {
    for (let i = 0; i < 2; i++) (b as HTMLButtonElement).click();
  });
  await expect.poll(stored).toBe("dark");
  await expectDrawn(popup, "dark", "two presses end on Dark");
  await expect(popup.locator("#btn-theme")).toHaveAttribute("aria-label", "Theme: Dark");
  await popup.close();
});

// ---------------------------------------------------------------- storage

test("a stored value that is not a choice is read as Auto by the background and by the page", async () => {
  await choose(ext, "purple");
  const popup = await openPopup("light");
  await expect(popup.locator("#btn-theme")).toHaveAttribute("aria-label", "Theme: Auto");
  await expectDrawn(popup, "light", "a stored purple draws what Auto draws");
  expect(await popup.evaluate(() => document.documentElement.dataset["theme"])).toBe("auto");
  const reply = await popup.evaluate(
    () => chrome.runtime.sendMessage({ kind: "getSettings" }) as Promise<{ settings: { theme: unknown } }>,
  );
  expect(reply.settings.theme, "the background reads it as auto").toBe("auto");
  await popup.close();
});

test("a patch that is not a choice never sticks", async () => {
  const popup = await openPopup("light");
  await popup.evaluate(() => chrome.runtime.sendMessage({ kind: "setSettings", patch: { theme: "purple" } }));
  const reply = await popup.evaluate(
    () => chrome.runtime.sendMessage({ kind: "getSettings" }) as Promise<{ settings: { theme: unknown } }>,
  );
  expect(reply.settings.theme).toBe("auto");
  expect(await stored()).toBe("auto");
  await popup.close();
});

test("the choice is in local storage and nothing is written to synced storage", async () => {
  const popup = await openPopup("dark");
  const syncBefore = await popup.evaluate(() => chrome.storage.sync.get(null));
  await popup.locator("#btn-theme").click();
  await expect.poll(stored).toBe("light");
  const syncAfter = await popup.evaluate(() => chrome.storage.sync.get(null));
  expect(syncAfter).toEqual(syncBefore);
  expect(Object.keys(syncAfter).join(","), "no theme key in synced storage").not.toContain("theme");
  expect(JSON.stringify(syncAfter)).not.toContain("light");
  await popup.close();
});

test("a pick survives closing and reopening the popup, and Re-check", async () => {
  const first = await openPopup("dark");
  await first.locator("#btn-theme").click();
  await expect.poll(stored).toBe("light");
  await first.close();

  const popup = await openPopup("dark");
  await expect(popup.locator("#btn-theme")).toHaveAttribute("aria-label", "Theme: Light");
  await expectDrawn(popup, "light", "reopened");
  await Promise.all([popup.waitForEvent("load"), popup.locator("#btn-refresh").click()]);
  await expect(popup.locator("#btn-theme")).toHaveAttribute("aria-label", "Theme: Light");
  await expectDrawn(popup, "light", "after Re-check");
  await popup.close();
});

// -------------------------------------------------------------- first frame

type FirstFrame = {
  /** What `data-scheme` was when the recorder ran: null, because the page's own scripts had not run yet. */
  atInit: string | null;
  /** The body did not exist yet when the recorder ran. */
  bodyAtInit: boolean;
  atBody: string | null | undefined;
  frame: boolean;
  frameScheme: string | null;
  frameBg: string;
  bodyAtFrame: boolean;
};

/**
 * Notes what the page looks like when its body is inserted and in its first
 * animation frame. It is an init script, so it is in place before any script
 * of the page runs.
 */
function recordFirstFrame(): void {
  const rec: FirstFrame = {
    atInit: document.documentElement?.getAttribute("data-scheme") ?? null,
    bodyAtInit: !!document.body,
    atBody: undefined,
    frame: false,
    frameScheme: null,
    frameBg: "",
    bodyAtFrame: false,
  };
  (window as unknown as { __first: FirstFrame }).__first = rec;
  new MutationObserver(() => {
    if (rec.atBody === undefined && document.body) rec.atBody = document.documentElement.getAttribute("data-scheme");
  }).observe(document, { childList: true, subtree: true });
  requestAnimationFrame(() => {
    const root = document.documentElement;
    rec.frameScheme = root.getAttribute("data-scheme");
    rec.frameBg = getComputedStyle(root).getPropertyValue("--w-bg").trim();
    rec.bodyAtFrame = !!document.body;
    rec.frame = true;
  });
}

for (const [pick, system] of [["light", "dark"], ["dark", "light"]] as const) {
  test(`every page already draws ${pick} before its body is parsed and in its first frame, on a ${system} system`, async () => {
    await choose(ext, pick);
    for (const address of ADDRESSES) {
      const page = await ext.context.newPage();
      await page.emulateMedia({ colorScheme: system, reducedMotion: "reduce" });
      await page.addInitScript(recordFirstFrame);
      await page.goto(`chrome-extension://${ext.id}/${address}`);
      await expect.poll(() => page.evaluate(() => (window as unknown as { __first?: FirstFrame }).__first?.frame), { message: address }).toBe(true);
      const rec = await page.evaluate(() => (window as unknown as { __first: FirstFrame }).__first);
      expect([rec.atInit, rec.bodyAtInit], `${address}: control: the recorder ran before the boot script and before the body`).toEqual([null, false]);
      expect(rec.atBody, `${address}: the scheme when the body was inserted`).toBe(pick);
      expect(rec.frameScheme, `${address}: the scheme in the first frame`).toBe(pick);
      expect(rec.frameBg, `${address}: the background token in the first frame`).toBe(refs[pick]!["--w-bg"]);
      expect(rec.frameBg, `${address}: control: not the other scheme's background`).not.toBe(refs[system]!["--w-bg"]);
      await page.close();
    }
  });
}

// ------------------------------------------------------------- live follow

test("open settings, dashboard and first-run pages follow a press in the popup without a reload, and the dashboard repaints", async () => {
  const dash = await openDashboard(ext, "browser");
  const others = [await ext.context.newPage(), await ext.context.newPage()];
  await others[0]!.goto(`chrome-extension://${ext.id}/options.html`);
  await others[1]!.goto(`chrome-extension://${ext.id}/firstrun.html`);
  const open = [dash, ...others];
  const was = new Map<Page, Palette>();
  for (const p of open) {
    await p.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
    await expectScheme(p, "dark", "before the press");
    await p.evaluate(() => ((window as unknown as { __kept: boolean }).__kept = true));
    was.set(p, await palette(p));
  }
  await dash.evaluate(() => {
    const w = window as unknown as { __repaints: number };
    w.__repaints = 0;
    const orig = chrome.runtime.sendMessage.bind(chrome.runtime) as (m: unknown) => Promise<unknown>;
    (chrome.runtime as unknown as { sendMessage: (m: { kind?: string }) => Promise<unknown> }).sendMessage = (m) => {
      if (m?.kind === "getBrowserReport") w.__repaints++;
      return orig(m);
    };
  });
  const asked = (): Promise<number> => dash.evaluate(() => (window as unknown as { __repaints: number }).__repaints);
  const before = await asked();

  const popup = await openPopup("dark");
  await popup.locator("#btn-theme").click();
  for (const p of open) {
    await expectScheme(p, "light", "an open page follows the press");
    expect(await palette(p), "the palette changed with it").not.toEqual(was.get(p));
    expect(await p.evaluate(() => (window as unknown as { __kept?: boolean }).__kept), "the page was not reloaded").toBe(true);
  }
  await expect.poll(asked, { message: "the dashboard redrew for the new scheme" }).toBeGreaterThan(before);

  await popup.locator("#btn-theme").click();
  for (const p of open) await expectScheme(p, "dark", "an open page follows the second press");
  await popup.close();
  for (const p of open) await p.close();
});

test("the dashboard's chart is drawn again in the new palette when the choice changes, with nothing else prompting it", async () => {
  const dash = await ext.context.newPage();
  await dash.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  // Every report read answers with the same one destination.
  await dash.addInitScript(() => {
    const report = {
      ok: true,
      report: {
        hosts: [{ host: "theme-choice-guard-e2e.com", owner: "MediaCo plc", category: "media", verdict: "NONE", q: 3, lastAt: 0 }],
        totals: { destinations: 1, companies: 1, countries: 0, networks: 0, lookups: 3, flagged: 0 },
        generatedAt: 0,
      },
    };
    const orig = chrome.runtime.sendMessage.bind(chrome.runtime) as (m: unknown) => Promise<unknown>;
    (chrome.runtime as unknown as { sendMessage: (m: { kind?: string }) => Promise<unknown> }).sendMessage = async (m) =>
      m?.kind === "getBrowserReport" ? report : orig(m);
  });
  await dash.goto(`chrome-extension://${ext.id}/dashboard.html#browser`);

  /** What the media category's token resolves to on this page now, and what the legend's dot was drawn with. */
  const read = (): Promise<{ token: string; dot: string | null }> =>
    dash.evaluate(() => {
      const probe = document.createElement("span");
      probe.style.background = "var(--w-cat-media)";
      document.body.append(probe);
      const token = getComputedStyle(probe).backgroundColor;
      probe.remove();
      const dot = document.querySelector<HTMLElement>("#b-donut-legend .w-dot");
      return { token, dot: dot ? getComputedStyle(dot).backgroundColor : null };
    });

  // Drawn in Dark first: the chart's colour lookup now holds the Dark palette.
  await expect.poll(async () => { const r = await read(); return r.dot === r.token && r.dot !== null; }, { message: "the dot was not drawn in the dark palette" }).toBe(true);
  const dark = await read();

  await choose(ext, "light");
  await expectScheme(dash, "light", "the dashboard follows the change");
  await expect
    .poll(async () => { const r = await read(); return r.dot === r.token; }, { message: "the dot was not redrawn in the light palette" })
    .toBe(true);
  const light = await read();
  expect(light.token, "control: the two palettes differ for this category").not.toBe(dark.token);
  expect(light.dot).not.toBe(dark.dot);
  await dash.close();
});

// -------------------------------------------------- Auto follows, forced ignores

test("on Auto every page follows the system live; on Light or Dark an emulated flip leaves it as it was", async () => {
  const drawn: Record<string, Record<Scheme, Palette>> = {};
  for (const address of ADDRESSES) {
    await choose(ext, "auto");
    const page = await ext.context.newPage();
    await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
    await page.goto(`chrome-extension://${ext.id}/${address}`);
    drawn[address] = { dark: {}, light: {} };
    for (const scheme of ["dark", "light", "dark"] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await expectScheme(page, scheme, `${address}: Auto follows ${scheme}`);
      drawn[address]![scheme] = await palette(page);
    }
    expect(drawn[address]!.light, `${address}: control: the schemes differ`).not.toEqual(drawn[address]!.dark);

    for (const [pick, system, flipped] of [["light", "dark", "light"], ["dark", "light", "dark"]] as const) {
      await page.emulateMedia({ colorScheme: system });
      await choose(ext, pick);
      await expectScheme(page, pick, `${address}: ${pick} under a ${system} system`);
      // The palette under a forced choice is the palette Auto draws under that scheme.
      expect(await palette(page), `${address}: forced ${pick} draws ${pick}`).toEqual(drawn[address]![pick]);
      await page.emulateMedia({ colorScheme: flipped });
      await twoFrames(page);
      await page.emulateMedia({ colorScheme: system });
      await twoFrames(page);
      expect(await schemeOf(page), `${address}: ${pick} ignores a flip of the system`).toBe(pick);
      expect(await palette(page)).toEqual(drawn[address]![pick]);
    }
    await page.close();
  }
});

test("the copy the pages read first is kept in step: it holds the pick, and a later page reconciles a stale one", async () => {
  const popup = await openPopup("dark");
  await popup.locator("#btn-theme").click();
  await expect.poll(stored).toBe("light");
  expect(await popup.evaluate((k) => localStorage.getItem(k), MIRROR_KEY)).toBe("light");
  await popup.close();

  // The copy says Dark, storage says Light: storage is the truth, and the
  // page corrects itself and the copy once it has read it.
  const page = await ext.context.newPage();
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.goto(`chrome-extension://${ext.id}/theme.css`);
  await page.evaluate((k) => localStorage.setItem(k, "dark"), MIRROR_KEY);
  await page.goto(`chrome-extension://${ext.id}/options.html`);
  await expectScheme(page, "light", "storage wins over a stale copy");
  await expect.poll(() => page.evaluate((k) => localStorage.getItem(k), MIRROR_KEY)).toBe("light");
  await page.close();
});
