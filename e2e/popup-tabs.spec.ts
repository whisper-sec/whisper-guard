// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE POPUP FRAME AND ITS THREE TABS.
//
// The popup is a fixed 400 x 600 frame: a header, a tab bar, one scrolling
// content region and a footer pinned to the bottom edge, with the panel's
// blocks split over This site, This page and This browser. Each claim is
// measured against the built extension:
//
//   - the frame holds its size and only the content region scrolls;
//   - every block still exists, under the tab that holds it, with no id twice;
//   - the tabs follow the WAI-ARIA pattern (roles, arrow keys, Tab order);
//   - a tab with nothing to show says why, in one sentence;
//   - the frame holds in the dark and the light scheme;
//   - the header is one header, whatever the tab;
//   - a panel that was shown once does not replay its entrance animations;
//   - a soft fade above the footer shows while content runs on below.
//
// That choosing a tab sends nothing is proved at the message layer in
// firefox-render.spec.ts. The popup is opened here as a page of the
// extension, not as a toolbar window, so the sizes are those of its own box.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY } from "./helpers/servers";
import {
  launchExtension,
  openPopup,
  selectPopupTab,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
  type PopupTab,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const HOST = "tabs-full-guard-e2e.com";
const SLOW = "tabs-slow-guard-e2e.com";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(HOST, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setEnrich(HOST, {
    ip: "198.51.100.40",
    city: "London, GB",
    country: "GB",
    asn: "AS64540",
    owner: "MediaCo plc",
    asnName: "MEDIACO - MediaCo plc",
    prefix: "198.51.100.0/24",
    threatNeighbors: 0,
    prevalence: 812,
    verdict: "NONE",
  });
  net.setIdentify(HOST, [
    {
      host: HOST,
      canonical_name: "MediaCo",
      category: "media",
      roles: ["DNS_OPERATOR", "ORIGIN_AS"],
      confidence: 0.85,
      host_class: "single_tenant",
      evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco"],
    },
  ]);
  net.setPresence("AS64540", {
    facilities: ["Example Carrier Hotel LON1", "Example Colo LON2"],
    exchanges: ["Example Exchange LON"],
    facilityCount: 14,
    exchangeCount: 4,
  });
  net.setVerdict(SLOW, { band: "NONE", coverage: "known-clean", label: "clean" });
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.graphMode = "mock";
  net.graphDelayMs = 0;
  net.clearLog();
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

// -------------------------------------------------------------- the helpers

const LIVE_RUNG = "#chain-mount .ch-rung.ch-live";

/** A popup on a clean host with the chain drawn, on This site. */
async function openSite(opts: { colorScheme?: "dark" | "light" } = {}): Promise<{ popup: Page; page: Page; tabId: number }> {
  const { page, tabId } = await visit(ext, `https://${HOST}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  const popup = await openPopup(ext, tabId);
  if (opts.colorScheme) await popup.emulateMedia({ colorScheme: opts.colorScheme });
  await popup.locator(LIVE_RUNG).first().waitFor({ timeout: 20_000 });
  return { popup, page, tabId };
}

/** A popup for a page it cannot check: one of the extension's own pages. */
async function openUncheckable(): Promise<{ popup: Page; page: Page }> {
  // The extension has no tabs permission, so the tab is found by creation.
  const { page, tabId } = await visit(ext, `chrome-extension://${ext.id}/options.html`);
  const popup = await openPopup(ext, tabId);
  await expect(popup.locator("#ineligible")).toBeVisible();
  return { popup, page };
}

interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
  bottom: number;
}

async function box(popup: Page, selector: string): Promise<Box> {
  return popup.locator(selector).evaluate((e) => {
    const r = e.getBoundingClientRect();
    return { x: r.x, y: r.y, width: r.width, height: r.height, bottom: r.bottom };
  });
}

async function frame(popup: Page): Promise<{ body: Box; header: Box; tabs: Box; footer: Box; region: Box }> {
  return {
    body: await box(popup, "body"),
    header: await box(popup, ".pp-header"),
    tabs: await box(popup, "#tab-bar"),
    footer: await box(popup, ".pp-footer"),
    region: await box(popup, "#tab-content"),
  };
}

const selected = (popup: Page): Promise<string[]> =>
  popup.locator('[role="tab"][aria-selected="true"]').evaluateAll((els) => els.map((e) => e.id));

// ------------------------------------------------------------------------ T1

test("the popup is a fixed 400 x 600 frame and only the content region scrolls", async () => {
  const { popup, page } = await openUncheckable();

  for (const size of [null, { width: 400, height: 600 }]) {
    if (size) await popup.setViewportSize(size);
    const f = await frame(popup);
    expect([f.body.width, f.body.height]).toEqual([400, 600]);
    expect(f.header.height).toBe(52);
    expect(f.header.y).toBe(0);
    expect(f.footer.bottom).toBe(600);
    await expect(popup.locator("#tab-site")).toHaveAttribute("aria-selected", "true");
    await expect(popup.locator("#panel-site")).toBeVisible();
    await expect(popup.locator("#panel-page")).toBeHidden();
    await expect(popup.locator("#panel-browser")).toBeHidden();
  }

  // A short panel fills the region to its foot, and nothing scrolls.
  const fit = await popup.evaluate(() => {
    const region = document.getElementById("tab-content") as HTMLElement;
    const panel = document.getElementById("panel-site") as HTMLElement;
    const cs = getComputedStyle(region);
    const floor = region.getBoundingClientRect().bottom - parseFloat(cs.paddingBottom) - parseFloat(cs.borderBottomWidth);
    return { gap: Math.abs(panel.getBoundingClientRect().bottom - floor), over: region.scrollHeight - region.clientHeight };
  });
  expect(fit.gap).toBeLessThanOrEqual(1);
  expect(fit.over).toBeLessThanOrEqual(0);

  // Make it overflow, by a device of the test: one tall element.
  await popup.locator("#panel-site").evaluate((p) => {
    const tall = document.createElement("div");
    tall.style.height = "1000px";
    tall.id = "test-tall";
    p.appendChild(tall);
  });
  const before = await frame(popup);
  const overflow = await popup.locator("#tab-content").evaluate((r) => ({
    scrollable: r.scrollHeight > r.clientHeight,
    overflowY: getComputedStyle(r).overflowY,
  }));
  expect(overflow.scrollable, "control: the region really overflows").toBe(true);
  expect(overflow.overflowY).toBe("auto");

  // A real wheel over the region scrolls it (a copy of an `overflow: hidden`
  // frame would not, though a click would still scroll its target into view).
  await popup.mouse.move(200, 300);
  await popup.mouse.wheel(0, 300);
  await expect.poll(() => popup.locator("#tab-content").evaluate((r) => r.scrollTop)).toBeGreaterThan(0);

  const after = await frame(popup);
  for (const part of ["header", "tabs", "footer"] as const) expect(after[part]).toEqual(before[part]);
  expect(await popup.evaluate(() => window.scrollY)).toBe(0);

  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T2

// Block id -> the panel that holds it (header and footer ids are in none).
const HOMES: Record<string, string | null> = {
  "host-row": "panel-site",
  lookalike: "panel-site",
  "blocked-card": "panel-site",
  "graph-error": "panel-site",
  "chain-card": "panel-site",
  "protect-card": "panel-site",
  expanders: "panel-site",
  "exp-why": "panel-site",
  "exp-who": "panel-site",
  "exp-neighborhood": "panel-site",
  "exp-session": "panel-site",
  ineligible: "panel-site",
  "linkscan-card": "panel-page",
  "iocscan-card": "panel-page",
  "page-empty": "panel-page",
  "identity-card": "panel-browser",
  "signin-pitch": "panel-browser",
  "tier-meter": "panel-browser",
  "btn-dashboard": "panel-browser",
  "footer-actions": null,
  "privacy-line": null,
  "scale": null,
  "btn-refresh": null,
  "btn-settings": null,
};

test("every block sits under the tab that holds it, and no id occurs twice", async () => {
  const { popup, page } = await openSite();
  const homes = await popup.evaluate((ids) => {
    const out: Record<string, string | null> = {};
    for (const id of ids) {
      const node = document.getElementById(id);
      out[id] = node ? (node.closest('[role="tabpanel"]')?.id ?? null) : "MISSING";
    }
    return out;
  }, Object.keys(HOMES));
  expect(homes).toEqual(HOMES);

  const twice = await popup.evaluate(() => {
    const seen = new Map<string, number>();
    for (const e of document.querySelectorAll("[id]")) seen.set(e.id, (seen.get(e.id) ?? 0) + 1);
    return [...seen].filter(([, n]) => n > 1).map(([id]) => id);
  });
  expect(twice).toEqual([]);

  await selectPopupTab(popup, "site");
  for (const id of ["host-row", "chain-card", "protect-card", "expanders"]) {
    await expect(popup.locator(`#${id}`), `#${id} on This site`).toBeVisible();
  }
  await selectPopupTab(popup, "page");
  for (const id of ["linkscan-card", "iocscan-card"]) await expect(popup.locator(`#${id}`)).toBeVisible();
  await selectPopupTab(popup, "browser");
  await expect(popup.locator("#signin-pitch")).toBeVisible();
  await expect(popup.locator("#btn-dashboard")).toBeVisible();
  await popup.close();
  await page.close();
});

test("signed in, This browser holds the identity and the activity", async () => {
  await setKey(ext, MOCK_API_KEY);
  const { popup, page } = await openSite();
  await selectPopupTab(popup, "browser");
  await expect(popup.locator("#identity-card")).toBeVisible({ timeout: 15_000 });
  await expect(popup.locator("#signin-pitch")).toBeHidden();
  await expect(popup.locator("#btn-dashboard")).toBeVisible();
  // The footer actions belong to the site, so they sit in its slot only.
  await expect(popup.locator("#footer-actions")).toBeHidden();
  await selectPopupTab(popup, "site");
  await expect(popup.locator("#btn-console")).toBeVisible();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T3

test("the tabs expose the roles and answer the arrow keys, Home and End", async () => {
  const { popup, page } = await openSite();

  const list = popup.getByRole("tablist", { name: "Popup sections" });
  await expect(list).toHaveCount(1);
  const tabs = list.getByRole("tab");
  await expect(tabs).toHaveCount(3);
  await expect(popup.getByRole("tabpanel", { includeHidden: true })).toHaveCount(3);

  const wiring = await popup.locator('[role="tab"]').evaluateAll((els) =>
    els.map((t) => {
      const panel = document.getElementById(t.getAttribute("aria-controls") ?? "");
      return {
        role: panel?.getAttribute("role"),
        back: panel?.getAttribute("aria-labelledby") === t.id,
        selected: t.getAttribute("aria-selected"),
        tabindex: (t as HTMLElement).tabIndex,
      };
    }),
  );
  expect(wiring).toEqual([
    { role: "tabpanel", back: true, selected: "true", tabindex: 0 },
    { role: "tabpanel", back: true, selected: "false", tabindex: -1 },
    { role: "tabpanel", back: true, selected: "false", tabindex: -1 },
  ]);

  const key = async (k: string, want: string, panel: string): Promise<void> => {
    await popup.keyboard.press(k);
    expect(await selected(popup), `${k}`).toEqual([want]);
    expect(await popup.evaluate(() => document.activeElement?.id), `${k} moves focus`).toBe(want);
    await expect(popup.locator(`#${panel}`)).toBeVisible();
  };
  await popup.locator("#tab-site").focus();
  await key("ArrowRight", "tab-page", "panel-page");
  await key("ArrowRight", "tab-browser", "panel-browser");
  await key("ArrowRight", "tab-site", "panel-site");
  await key("ArrowLeft", "tab-browser", "panel-browser");
  await key("Home", "tab-site", "panel-site");
  await key("End", "tab-browser", "panel-browser");

  // Tab leaves the tab bar for the selected panel; Shift+Tab comes back.
  await popup.keyboard.press("Tab");
  expect(await popup.evaluate(() => document.activeElement?.id)).toBe("panel-browser");
  await popup.keyboard.press("Shift+Tab");
  expect(await popup.evaluate(() => document.activeElement?.id)).toBe("tab-browser");

  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T4

const NEEDS_LIVE_CHECK = "The link check and the indicator scan need the live check. Turn it on in settings.";

test("with the live check off, This page says why and its footer takes no space", async () => {
  await setSettings(ext, { cloudCheck: false });
  const { page, tabId } = await visit(ext, `https://${SLOW}/`);
  const popup = await openPopup(ext, tabId, { popupTab: "page" });
  await expect(popup.locator("#page-empty")).toHaveText(NEEDS_LIVE_CHECK);
  await expect(popup.locator("#linkscan-card")).toBeHidden();
  await expect(popup.locator("#iocscan-card")).toBeHidden();
  await expect(popup.locator(".pp-footer")).toBeHidden();
  await selectPopupTab(popup, "site");
  await expect(popup.locator("#privacy-line")).toBeVisible();
  await popup.close();
  await page.close();
});

test("on a page that cannot be checked, This page says so in the words of the site tab's message", async () => {
  const { popup, page } = await openUncheckable();
  const words = ((await popup.locator("#ineligible").textContent()) ?? "").trim();
  expect(words.length).toBeGreaterThan(0);
  await selectPopupTab(popup, "page");
  await expect(popup.locator("#page-empty")).toHaveText(words);
  await expect(popup.locator("#linkscan-card")).toBeHidden();
  await expect(popup.locator(".pp-footer")).toBeHidden();
  await selectPopupTab(popup, "site");
  await expect(popup.locator("#privacy-line")).toBeVisible();
  await popup.close();
  await page.close();
});

test("with the live check on, This page shows both cards and its own footer line", async () => {
  const { popup, page } = await openSite();
  await selectPopupTab(popup, "page");
  await expect(popup.locator("#page-empty")).toBeHidden();
  await expect(popup.locator("#linkscan-card")).toBeVisible();
  await expect(popup.locator("#iocscan-card")).toBeVisible();
  await expect(popup.locator("#footer-page-line")).toBeVisible();
  await expect(popup.locator("#footer-page-line")).toHaveText("Link check sends link hostnames only, never paths or the page.");
  await selectPopupTab(popup, "browser");
  await expect(popup.locator(".pp-footer")).toBeHidden();
  await selectPopupTab(popup, "site");
  await expect(popup.locator("#privacy-line")).toBeVisible();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T5

test("while a check is in flight This page says so, and shows its cards once it settles", async () => {
  net.assessDelayMs.set(SLOW, 60_000);
  const { page, tabId } = await visit(ext, `https://${SLOW}/`);
  await waitForIcon(ext, tabId, ["checking"]);
  const popup = await openPopup(ext, tabId, { popupTab: "page" });
  await expect(popup.locator("#page-empty")).toBeVisible();
  const note = (await popup.locator("#band-note").textContent()) ?? "";
  expect(note.length).toBeGreaterThan(0);
  await expect(popup.locator("#page-empty")).toHaveText(note);
  await expect(popup.locator("#linkscan-card")).toBeHidden();

  await expect(popup.locator("#band-chip")).toHaveText("COULD NOT CHECK", { timeout: 15_000 });
  await expect(popup.locator("#page-empty")).toBeHidden();
  await expect(popup.locator("#linkscan-card")).toBeVisible();
  await expect(popup.locator("#iocscan-card")).toBeVisible();
  await popup.close();
  await page.close();
  net.assessDelayMs.delete(SLOW);
});

// ------------------------------------------------------------------------ T6

async function token(popup: Page, name: string, prop: "color" | "backgroundColor"): Promise<string> {
  return popup.evaluate(
    ([n, p]) => {
      const probe = document.createElement("div");
      probe.style.setProperty(p === "color" ? "color" : "background-color", `var(${n})`);
      document.body.appendChild(probe);
      const v = getComputedStyle(probe)[p as "color"];
      probe.remove();
      return v;
    },
    [name, prop] as const,
  );
}

test("the frame holds in the dark and the light scheme, on every tab", async () => {
  const boxes: Record<string, Awaited<ReturnType<typeof frame>>> = {};
  const grounds: Record<string, string> = {};
  for (const scheme of ["dark", "light"] as const) {
    const { popup, page } = await openSite({ colorScheme: scheme });
    const tabs: PopupTab[] = ["site", "page", "browser"];
    const first = await frame(popup);
    for (const tab of tabs) {
      await selectPopupTab(popup, tab);
      const f = await frame(popup);
      boxes[`${scheme}-${tab}`] = f;
      expect([f.body.width, f.body.height]).toEqual([400, 600]);
      expect(f.header.height).toBe(52);
      expect(f.header.y).toBe(0);
      expect(f.tabs.y).toBe(f.header.bottom);
      expect(f.tabs).toEqual((await frame(popup)).tabs);
      expect(f.tabs).toEqual(first.tabs);
      const footerShown = await popup.locator(".pp-footer").isVisible();
      expect(footerShown, `${tab} footer`).toBe(tab !== "browser");
      if (footerShown) expect(f.footer.bottom).toBe(600);
      else expect(f.region.bottom).toBe(600);
    }

    await selectPopupTab(popup, "site");
    const ink = await popup.evaluate(() => {
      const c = (s: string, p: "backgroundColor" | "borderBottomColor" | "color"): string =>
        getComputedStyle(document.querySelector(s) as Element)[p];
      return {
        body: c("body", "backgroundColor"),
        header: c(".pp-header", "backgroundColor"),
        tabs: c("#tab-bar", "backgroundColor"),
        underline: c("#tab-site", "borderBottomColor"),
        muted: c("#tab-page", "color"),
      };
    });
    expect(ink.body).toBe(await token(popup, "--w-bg", "backgroundColor"));
    expect(ink.header).toBe(await token(popup, "--w-surface", "backgroundColor"));
    expect(ink.tabs).toBe(await token(popup, "--w-surface", "backgroundColor"));
    expect(ink.underline).toBe(await token(popup, "--w-accent-line", "backgroundColor"));
    expect(ink.muted).toBe(await token(popup, "--w-muted", "color"));
    grounds[scheme] = ink.body;
    await popup.close();
    await page.close();
  }
  expect(grounds.dark).not.toBe(grounds.light);
  for (const tab of ["site", "page", "browser"]) {
    expect(boxes[`dark-${tab}`], `${tab}: the same boxes in both schemes`).toEqual(boxes[`light-${tab}`]);
  }
});

// ------------------------------------------------------------------------ T7

test("one header on every tab: its parts sit on one row and Re-check and Settings work", async () => {
  const { popup, page } = await openSite();
  await expect(popup.locator("#scale")).toBeVisible({ timeout: 15_000 });
  await expect(popup.locator("#scale-nodes")).toHaveText(/^\d/);

  const read = (): Promise<{ box: Box; text: string; fits: boolean; row: boolean }> =>
    popup.locator(".pp-header").evaluate((h) => {
      const hb = h.getBoundingClientRect();
      const kids = [...h.children].filter((k) => getComputedStyle(k).display !== "none" && k.getBoundingClientRect().width > 0);
      const mids = kids.map((k) => {
        const r = k.getBoundingClientRect();
        return r.top + r.height / 2;
      });
      return {
        box: { x: hb.x, y: hb.y, width: hb.width, height: hb.height, bottom: hb.bottom },
        // The figure counts up as it arrives; the rest of the text is stable.
        text: (h as HTMLElement).innerText.replace(/[\d.]+[KMBT]?\s*\n?nodes/, "# nodes"),
        fits: h.scrollWidth <= h.clientWidth,
        row:
          kids.every((k) => {
            const r = k.getBoundingClientRect();
            return r.left >= hb.left - 0.5 && r.right <= hb.right + 0.5 && r.top >= hb.top && r.bottom <= hb.bottom;
          }) && Math.max(...mids) - Math.min(...mids) <= 2,
      };
    });
  const site = await read();
  expect(site.fits, "the header overflows sideways").toBe(true);
  expect(site.row, "the header's parts are not on one row inside its box").toBe(true);
  expect(site.box.height).toBe(52);
  for (const tab of ["page", "browser"] as const) {
    await selectPopupTab(popup, tab);
    expect(await read()).toEqual(site);
  }

  // Settings opens the options page.
  await popup.evaluate(() => {
    (window as unknown as { __opened: number }).__opened = 0;
    chrome.runtime.openOptionsPage = (): Promise<void> => {
      (window as unknown as { __opened: number }).__opened++;
      return Promise.resolve();
    };
  });
  await popup.locator("#btn-settings").click();
  expect(await popup.evaluate(() => (window as unknown as { __opened: number }).__opened)).toBe(1);

  // Re-check reloads the popup, and a reload always lands on This site.
  await selectPopupTab(popup, "browser");
  await Promise.all([popup.waitForEvent("load"), popup.locator("#btn-refresh").click()]);
  await expect(popup.locator("#tab-site")).toHaveAttribute("aria-selected", "true");
  await expect(popup.locator("#panel-site")).toBeVisible();

  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ T8

test("a panel shown again does not replay its entrance, and later arrivals still animate", async () => {
  const { popup, page } = await openSite();
  const name = (sel: string): Promise<string> => popup.locator(sel).evaluate((e) => getComputedStyle(e).animationName);

  expect(await name("#band-rail"), "control: the rail grows on arrival").toBe("rail-grow");
  await selectPopupTab(popup, "page");
  await selectPopupTab(popup, "site");
  expect(await name("#band-rail")).toBe("none");
  expect(await name(`${LIVE_RUNG} >> nth=0`)).toBe("none");

  // A rung detail the reader opens afterwards animates as it always did.
  await popup.locator("#chain-mount .ch-rung").filter({ hasText: "NETWORK" }).click();
  await expect(popup.locator(".ch-detail")).toBeVisible();
  expect(await name(".ch-detail")).toBe("ch-detail-open");
  await popup.close();
  await page.close();
});

// ----------------------------------------------------------------- the fade

const fadeShown = (popup: Page): Promise<boolean> => popup.locator("#tab-fade").isVisible();

/** Open every drawer of This site so its panel runs past the region. */
async function overflowSite(popup: Page): Promise<void> {
  for (const id of ["exp-why", "exp-who", "exp-session"]) await popup.locator(`#${id} summary`).click();
  await expect
    .poll(() => popup.locator("#tab-content").evaluate((r) => r.scrollHeight - r.clientHeight))
    .toBeGreaterThan(40);
}

test("a soft fade above the footer shows while the content runs on, and is gone at the end", async () => {
  const { popup, page } = await openSite();
  await overflowSite(popup);

  // At the top of an overflowing panel the fade shows, over the region's foot.
  await expect(popup.locator("#tab-fade")).toBeVisible();
  const fade = await popup.locator("#tab-fade").evaluate((f) => {
    const cs = getComputedStyle(f);
    const r = f.getBoundingClientRect();
    const region = (document.getElementById("tab-content") as HTMLElement).getBoundingClientRect();
    const foot = (document.querySelector(".pp-footer") as HTMLElement).getBoundingClientRect();
    return {
      pointer: cs.pointerEvents,
      hidden: f.getAttribute("aria-hidden"),
      text: f.textContent,
      focusable: f.tabIndex,
      bottomGap: Math.abs(r.bottom - region.bottom),
      aboveFooter: r.bottom <= foot.top + 0.5,
      height: r.height,
      image: cs.backgroundImage,
    };
  });
  expect(fade.pointer).toBe("none");
  expect(fade.hidden).toBe("true");
  expect(fade.text).toBe("");
  expect(fade.focusable).toBe(-1);
  expect(fade.bottomGap).toBeLessThanOrEqual(1);
  expect(fade.aboveFooter).toBe(true);
  expect(fade.height).toBeGreaterThan(0);
  expect(fade.image).toContain("gradient");

  // Scrolled to the end, it is gone, and the last line is fully in view.
  await popup.locator("#tab-content").evaluate((r) => r.scrollTo(0, r.scrollHeight));
  await expect(popup.locator("#tab-fade")).toBeHidden();
  // The last visible leaf of the panel: the one lowest on the page.
  const last = await popup.locator("#panel-site").evaluate((panel) => {
    const region = (document.getElementById("tab-content") as HTMLElement).getBoundingClientRect();
    let end: Element | null = null;
    let low = -Infinity;
    for (const e of panel.querySelectorAll("*")) {
      if (e.children.length > 0) continue;
      // Content of a closed drawer is not drawn; only its summary is.
      const drawer = e.closest("details");
      if (drawer && !drawer.open && !e.closest("summary")) continue;
      const r = e.getBoundingClientRect();
      if (r.width === 0 || r.height === 0 || getComputedStyle(e).visibility === "hidden") continue;
      if (r.bottom >= low) {
        low = r.bottom;
        end = e;
      }
    }
    if (!end) return { found: false, inside: false, hit: false, what: "" };
    const r = end.getBoundingClientRect();
    const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
    return {
      found: true,
      inside: r.bottom <= region.bottom + 0.5 && r.top >= region.top,
      hit: !!hit && (end.contains(hit) || hit.contains(end)),
      what: `${end.tagName.toLowerCase()}${end.id ? `#${end.id}` : ""}`,
    };
  });
  expect(last.found, "control: the panel has a last visible element").toBe(true);
  expect(last.inside, `the last element (${last.what}) is cut off at the end of the scroll`).toBe(true);
  expect(last.hit, `the last element (${last.what}) is covered at the end of the scroll`).toBe(true);

  // Scrolling back up brings it back.
  await popup.locator("#tab-content").evaluate((r) => r.scrollTo(0, 0));
  await expect(popup.locator("#tab-fade")).toBeVisible();
  await popup.close();
  await page.close();
});

test("a panel that fits shows no fade, and switching to one hides it", async () => {
  const { popup, page } = await openSite();
  await overflowSite(popup);
  expect(await fadeShown(popup), "control: the overflowing panel shows the fade").toBe(true);

  await selectPopupTab(popup, "page");
  const fits = await popup.locator("#tab-content").evaluate((r) => r.scrollHeight - r.clientHeight);
  expect(fits, "This page is expected to fit the region").toBeLessThanOrEqual(0);
  await expect(popup.locator("#tab-fade")).toBeHidden();

  await selectPopupTab(popup, "site");
  await expect(popup.locator("#tab-fade")).toBeVisible();
  await popup.close();
  await page.close();
});
