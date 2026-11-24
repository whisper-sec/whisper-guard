// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE THIS PAGE TAB. Two cards, each started only by the reader's click:
// the link check (headline, proportional bar, counts, the three worst
// destinations, "See all") and the indicator scan (its privacy sentence is
// there before and after a scan). With the live check off neither is offered
// and nothing about the page's links or text is sent. After a check the whole
// tab clears the contrast floor in both colour schemes.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openPopup,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const SOURCE = {
  a: "page-a-guard-e2e.com",
  b: "page-b-guard-e2e.com",
  e: "page-e-guard-e2e.com",
  c: "page-c-guard-e2e.com",
  t: "page-t-guard-e2e.com",
  off: "page-off-guard-e2e.com",
};

const A = {
  crit: "crit-a-guard-e2e.com",
  high: "high-a-guard-e2e.com",
  med: "med-a-guard-e2e.com",
  unk: "unk-a-guard-e2e.com",
  low: "low-a-guard-e2e.com",
  clean: "clean-a-guard-e2e.com",
};
const B_CLEAN = "only-b-guard-e2e.com";
const E = {
  med: "med-e-guard-e2e.com",
  unk: "unk-e-guard-e2e.com",
  low: "low-e-guard-e2e.com",
  info: "info-e-guard-e2e.com",
  none: "none-e-guard-e2e.com",
};
const IOC_TEXT_HOST = "ioc-text-guard-e2e.com";
// Named only by the page that is opened with the live check off, so nothing earlier in
// the file can have sent them.
const OFF_LINK = "off-link-guard-e2e.com";
const OFF_TEXT = "off-text-guard-e2e.com";
const C_COUNT = 165;
const C_HOSTS = Array.from({ length: C_COUNT }, (_, i) => `h${String(i + 1).padStart(3, "0")}-c-guard-e2e.com`);

const LINK_NOTE = "Only the link hostnames were checked, never the page, its text, or your history.";
const IOC_NOTE =
  "This reads the page's visible text. Only the hostnames found are checked against Whisper; IP addresses, file hashes and CVE ids are listed as Not assessed and are not sent. The page text itself never leaves your browser.";
const NEEDS_LIVE_CHECK = "The link check and the indicator scan need the live check. Turn it on in settings.";

const links = (...hosts: string[]): string =>
  `<!doctype html><html><head><title>fixture</title></head><body><h1>Links</h1>${hosts
    .map((h) => `<a href="https://${h}/landing">link</a>`)
    .join("")}</body></html>`;

/** True when the text holds the hostname as a whole token, never as part of a longer name. */
function namesHost(text: string, host: string): boolean {
  return text.split(/[^a-z0-9.-]+/i).some((token) => token === host);
}

/** The graph request bodies seen so far, as one list. */
function graphBodies(): string[] {
  return net.requestsTo(GRAPH_READ_HOST).map((r) => r.body);
}

/**
 * Wait until opening has settled: the graph request count reads the same on
 * two reads 500 ms apart, so a request sent late in opening is still seen.
 */
async function openingSettled(): Promise<void> {
  let last = -1;
  await expect
    .poll(
      async () => {
        const n = net.requestsTo(GRAPH_READ_HOST).length;
        const same = n === last;
        last = n;
        return same;
      },
      { message: "opening never settled", intervals: [500] },
    )
    .toBe(true);
}

/** True when any graph request names the host as a whole token. */
function graphNames(host: string): boolean {
  return graphBodies().some((b) => namesHost(b, host));
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  const clean = { band: "NONE", coverage: "known-clean", label: "clean" } as const;
  for (const h of Object.values(SOURCE)) net.setVerdict(h, clean);
  net.setVerdict(A.crit, { band: "CRITICAL", coverage: "known-clean", label: "malicious" });
  net.setVerdict(A.high, { band: "HIGH", coverage: "known-clean", label: "malicious" });
  net.setVerdict(A.med, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setVerdict(A.low, { band: "LOW", coverage: "known-clean", label: "low" });
  net.setVerdict(A.clean, clean);
  // A.unk is left unseeded: the mock graph answers an unseeded host UNKNOWN.
  net.setVerdict(B_CLEAN, clean);
  net.setVerdict(E.med, { band: "MEDIUM", coverage: "partial", label: "suspicious" });
  net.setVerdict(E.low, { band: "LOW", coverage: "known-clean", label: "low" });
  net.setVerdict(E.info, { band: "INFO", coverage: "known-clean", label: "info" });
  net.setVerdict(E.none, clean);

  net.setPage(
    SOURCE.a,
    // Two links to the malicious destination, one to each of the others.
    links(A.crit, A.crit, A.high, A.med, A.unk, A.low, A.clean),
  );
  net.setPage(SOURCE.b, links(B_CLEAN));
  net.setPage(SOURCE.e, links(E.med, E.unk, E.low, E.info, E.none));
  net.setPage(SOURCE.c, links(...C_HOSTS));
  net.setPage(
    SOURCE.off,
    `<!doctype html><html><head><title>off</title></head><body><p>Seen beaconing to ${OFF_TEXT} overnight.</p><a href="https://${OFF_LINK}/x">a link</a></body></html>`,
  );
  net.setPage(
    SOURCE.t,
    `<!doctype html><html><head><title>notes</title></head><body><p>Seen beaconing to ${IOC_TEXT_HOST} overnight.</p></body></html>`,
  );
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

/** Open a fixture page, wait for its own check, and open This page on it. */
async function openOn(host: string): Promise<{ popup: Page; page: Page; tabId: number }> {
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId, { popupTab: "page" });
  await expect(popup.locator("#linkscan-card")).toBeVisible({ timeout: 10_000 });
  return { popup, page, tabId };
}

async function check(popup: Page): Promise<void> {
  await popup.locator("#btn-linkscan").click();
  await expect(popup.locator("#linkscan-count")).not.toHaveText("", { timeout: 20_000 });
}

// ------------------------------------------------------------------------ P1

test("before a link check the card offers the check button and shows no result", async () => {
  const { popup, page } = await openOn(SOURCE.a);
  await expect(popup.locator("#btn-linkscan")).toBeVisible();
  await expect(popup.locator("#btn-linkscan")).toHaveText("Check every link");
  for (const id of ["linkscan-summary", "linkscan-bar", "linkscan-counts", "linkscan-list", "linkscan-age", "linkscan-all"]) {
    await expect(popup.locator(`#${id}`), `#${id} exists`).toHaveCount(1);
    await expect(popup.locator(`#${id}`), `#${id} is hidden`).toBeHidden();
  }
  // Nothing about the page's links has left the browser yet, once opening has settled.
  await openingSettled();
  expect(graphBodies().length, "control: the page's own check reached the graph").toBeGreaterThan(0);
  for (const host of Object.values(A)) expect(graphNames(host), `${host} was sent before the press`).toBe(false);
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ P2

test("after a link check the card shows the headline, the bar, the counts and the worst destinations first", async () => {
  const { popup, page } = await openOn(SOURCE.a);
  await check(popup);

  await expect(popup.locator("#linkscan-summary")).toHaveText("6 destinations, 2 malicious");
  await expect(popup.locator("#linkscan-count")).toHaveText("6");
  expect(await popup.locator("#linkscan-counts .pp-count").allTextContents()).toEqual([
    "2 clean",
    "1 unknown",
    "1 suspicious",
    "2 malicious",
  ]);
  const segs = popup.locator("#linkscan-bar .pp-seg");
  expect(await segs.evaluateAll((els) => els.map((e) => e.className))).toEqual([
    "pp-seg clean",
    "pp-seg unknown",
    "pp-seg suspicious",
    "pp-seg malicious",
  ]);
  expect(await segs.evaluateAll((els) => els.map((e) => getComputedStyle(e).flexGrow))).toEqual(["2", "1", "1", "2"]);

  expect(await popup.locator("#linkscan-list .link-host").allTextContents()).toEqual([A.crit, A.high, A.med]);
  expect(await popup.locator("#linkscan-list .pp-pill").allTextContents()).toEqual(["MALICIOUS", "MALICIOUS", "SUSPICIOUS"]);
  const rows = popup.locator("#linkscan-list .link-row");
  expect(await rows.evaluateAll((els) => els.map((e) => e.classList.contains("bad")))).toEqual([true, true, false]);

  await expect(popup.locator("#linkscan-age")).toHaveText(/^checked (just now|\d+ s ago)$/);
  await expect(popup.locator("#linkscan-age")).toHaveText(/^checked [1-9]\d* s ago$/, { timeout: 8_000 });
  await expect(popup.locator("#btn-linkscan")).toHaveText("Re-check");
  await expect(popup.locator("#linkscan-all")).toHaveText("See all 6 →");
  await expect(popup.locator("#linkscan-all")).toHaveAccessibleName("See all 6");
  await expect(popup.locator("#linkscan-cut")).toBeHidden();
  await expect(popup.locator("#linkscan-note")).toHaveText(LINK_NOTE);
  // The tab's red dot is still fed by the same result.
  await expect(popup.locator("#tab-page")).toHaveAccessibleName("This page 2 malicious links on this page");

  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ P3

test("one destination is named in the singular and nothing malicious reads none malicious", async () => {
  const { popup, page } = await openOn(SOURCE.b);
  await check(popup);
  await expect(popup.locator("#linkscan-summary")).toHaveText("1 destination, none malicious");
  expect(await popup.locator("#linkscan-counts .pp-count").allTextContents()).toEqual(["1 clean"]);
  await expect(popup.locator("#linkscan-bar .pp-seg")).toHaveCount(1);
  await expect(popup.locator("#linkscan-bar .pp-seg.clean")).toHaveCount(1);
  expect(await popup.locator("#linkscan-list .link-host").allTextContents()).toEqual([B_CLEAN]);
  expect(await popup.locator("#linkscan-list .pp-pill").allTextContents()).toEqual(["CLEAN"]);
  await expect(popup.locator("#linkscan-all")).toBeHidden();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ P4

test("See all shows every destination and Show fewer goes back, with no cut sentence when nothing was cut", async () => {
  const { popup, page } = await openOn(SOURCE.e);
  await check(popup);
  await expect(popup.locator("#linkscan-summary")).toHaveText("5 destinations, none malicious");
  expect(await popup.locator("#linkscan-counts .pp-count").allTextContents()).toEqual(["3 clean", "1 unknown", "1 suspicious"]);
  await expect(popup.locator("#linkscan-list .link-row")).toHaveCount(3);
  await expect(popup.locator("#linkscan-all")).toHaveText("See all 5 →");
  await expect(popup.locator("#linkscan-all")).toHaveAttribute("aria-expanded", "false");

  await popup.locator("#linkscan-all").click();
  await expect(popup.locator("#linkscan-list .link-row")).toHaveCount(5);
  expect(await popup.locator("#linkscan-list .pp-pill").allTextContents()).toEqual([
    "SUSPICIOUS",
    "UNKNOWN",
    "CLEAN",
    "CLEAN",
    "CLEAN",
  ]);
  // The worker's order: band, then link count, then name.
  expect(await popup.locator("#linkscan-list .link-host").allTextContents()).toEqual([E.med, E.unk, E.low, E.info, E.none]);
  await expect(popup.locator("#linkscan-all")).toHaveAttribute("aria-expanded", "true");
  await expect(popup.locator("#linkscan-all")).toHaveText("Show fewer");
  expect(await popup.evaluate(() => document.activeElement?.id)).toBe("linkscan-all");
  await expect(popup.locator("#linkscan-cut")).toBeHidden();

  await popup.locator("#linkscan-all").click();
  await expect(popup.locator("#linkscan-list .link-row")).toHaveCount(3);
  await expect(popup.locator("#linkscan-all")).toHaveText("See all 5 →");
  await expect(popup.locator("#linkscan-all")).toHaveAttribute("aria-expanded", "false");
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ P5

test("a page with more destinations than the check keeps says the list is cut, and See all shows every row it kept", async () => {
  const { popup, page } = await openOn(SOURCE.c);
  await check(popup);
  await expect(popup.locator("#linkscan-summary")).toHaveText("160 destinations, none malicious");
  await expect(popup.locator("#linkscan-cut")).toBeVisible();
  await expect(popup.locator("#linkscan-cut")).toHaveText("Showing the 160 busiest destinations; the page links to more.");
  await popup.locator("#linkscan-all").click();
  await expect(popup.locator("#linkscan-list .link-row")).toHaveCount(160);
  await expect(popup.locator("#linkscan-cut")).toBeVisible();
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ P6

test("Scan page sends nothing until it is pressed, and its note is today's sentence before and after", async () => {
  const { popup, page } = await openOn(SOURCE.t);
  await expect(popup.locator("#btn-iocscan")).toHaveText("Scan page");
  await expect(popup.locator("#iocscan-note")).toBeVisible();
  await expect(popup.locator("#iocscan-note")).toHaveText(IOC_NOTE);
  await expect(popup.locator("#btn-iocscan")).toHaveAttribute(
    "title",
    "Read this page's visible text for indicators: addresses, domains, file hashes and CVE ids. Only the hostnames found are checked against the Whisper graph.",
  );
  await openingSettled();
  expect(graphBodies().length, "control: the page's own check reached the graph").toBeGreaterThan(0);
  expect(graphNames(IOC_TEXT_HOST), "an indicator was sent before the press").toBe(false);

  await popup.locator("#btn-iocscan").click();
  await expect(popup.locator("#iocscan-summary")).toContainText("found", { timeout: 20_000 });
  // Control: the press does send the hostname that was in the text.
  await expect.poll(() => graphNames(IOC_TEXT_HOST), { timeout: 10_000 }).toBe(true);
  await expect(popup.locator("#iocscan-note")).toHaveText(IOC_NOTE);
  expect(await popup.locator("#panel-page").innerText()).not.toContain("Only the indicators are sent");
  await popup.close();
  await page.close();
});

// ------------------------------------------------------------------------ P7

test("with the live check off neither check is offered and nothing about the page's links or text is sent", async () => {
  await setSettings(ext, { cloudCheck: false });
  try {
    const { page, tabId } = await visit(ext, `https://${SOURCE.off}/`);
    const popup = await openPopup(ext, tabId, { popupTab: "page" });
    await expect(popup.locator("#page-empty")).toHaveText(NEEDS_LIVE_CHECK);
    await expect(popup.locator("#linkscan-card")).toBeHidden();
    await expect(popup.locator("#iocscan-card")).toBeHidden();
    await expect(popup.locator(".pp-footer")).toBeHidden();
    await popup.evaluate(() => chrome.runtime.sendMessage({ kind: "getSession" }));
    for (const host of [OFF_LINK, OFF_TEXT, SOURCE.off]) {
      expect(graphNames(host), `${host} was sent with the live check off`).toBe(false);
    }
    await popup.close();
    await page.close();
  } finally {
    await setSettings(ext, { cloudCheck: true });
  }
});

// ------------------------------------------------------------------------ P8

interface Sample {
  what: string;
  ratio: number;
  floor: number;
}

/** Every text and every mark of This page, composited against the ground it sits on. */
async function measurePage(popup: Page): Promise<{ text: Sample[]; marks: Sample[] }> {
  await popup.emulateMedia({ reducedMotion: "reduce" });
  return popup.evaluate(() => {
    const px = (c: string): number[] => {
      const m = c.match(/-?[\d.]+/g);
      if (!m) return [0, 0, 0, 1];
      const raw = m.map(Number);
      const scale = c.startsWith("color(") ? 255 : 1;
      return [raw[0]! * scale, raw[1]! * scale, raw[2]! * scale, raw[3] ?? 1];
    };
    const over = (fg: number[], bg: number[]): number[] => {
      const a = fg[3]!;
      return [0, 1, 2].map((i) => fg[i]! * a + bg[i]! * (1 - a)).concat(1);
    };
    const lum = (c: number[]): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * f(c[0]!) + 0.7152 * f(c[1]!) + 0.0722 * f(c[2]!);
    };
    const groundOf = (el: Element): number[] => {
      const stack: number[][] = [];
      for (let n: Element | null = el; n; n = n.parentElement) {
        const c = px(getComputedStyle(n).backgroundColor);
        if (c[3]! > 0) stack.push(c);
        if (c[3] === 1) break;
      }
      let out = [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i]!, out);
      return out;
    };
    const ratioOf = (a: number[], b: number[]): number => {
      const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
      return (hi! + 0.05) / (lo! + 0.05);
    };
    const name = (el: Element): string =>
      `<${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${
        typeof el.className === "string" && el.className ? `.${el.className.trim().split(/\s+/).join(".")}` : ""
      }>`;

    const text: { what: string; ratio: number; floor: number }[] = [];
    const roots = [document.getElementById("panel-page"), document.getElementById("footer-page")];
    for (const root of roots) {
      if (!root) continue;
      for (const el of Array.from(root.querySelectorAll<HTMLElement>("*"))) {
        const own = Array.from(el.childNodes)
          .filter((n) => n.nodeType === Node.TEXT_NODE)
          .map((n) => n.textContent ?? "")
          .join("")
          .trim();
        if (own === "") continue;
        const cs = getComputedStyle(el);
        if (cs.visibility === "hidden" || cs.display === "none") continue;
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;
        if ((el as HTMLButtonElement).disabled) continue;
        let alpha = 1;
        for (let n: Element | null = el; n; n = n.parentElement) alpha *= Number(getComputedStyle(n).opacity);
        const fg = px(cs.color);
        fg[3] = fg[3]! * alpha;
        const ground = groundOf(el);
        const size = parseFloat(cs.fontSize);
        const large = size >= 24 || (size >= 18.66 && (Number(cs.fontWeight) || 400) >= 700);
        text.push({ what: `${name(el)} "${own.slice(0, 40)}"`, ratio: ratioOf(over(fg, ground), ground), floor: large ? 3 : 4.5 });
      }
    }

    const marks: { what: string; ratio: number; floor: number }[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("#panel-page .pp-seg, #panel-page .pp-swatch"))) {
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;
      const ink = px(getComputedStyle(el).backgroundColor);
      marks.push({ what: name(el), ratio: ratioOf(over(ink, groundOf(el.parentElement!)), groundOf(el.parentElement!)), floor: 3 });
    }
    for (const el of Array.from(document.querySelectorAll<SVGElement>("#cookie-line svg"))) {
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;
      const ink = px(getComputedStyle(el).color);
      const ground = groundOf(el.parentElement!);
      marks.push({ what: "the cookie icon", ratio: ratioOf(over(ink, ground), ground), floor: 3 });
    }
    return { text, marks };
  });
}

test("This page after a link check clears the contrast floor in the dark and the light scheme", async () => {
  const { popup, page, tabId } = await openOn(SOURCE.a);
  await check(popup);
  // The cookie line is part of the tab: have Guard record a declined prompt on this page.
  await ext.sw.evaluate(async (id: number) => {
    await chrome.scripting.executeScript({
      target: { tabId: id },
      func: () => chrome.runtime.sendMessage({ kind: "consentDeclined" }),
    });
  }, tabId);
  await expect(popup.locator("#cookie-line")).toBeVisible({ timeout: 10_000 });

  for (const scheme of ["dark", "light"] as const) {
    await popup.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await expect
      .poll(() => popup.evaluate((d) => matchMedia("(prefers-color-scheme: dark)").matches === d, scheme === "dark"))
      .toBe(true);
    const { text, marks } = await measurePage(popup);
    expect(text.length, `${scheme}: too little text was measured`).toBeGreaterThan(10);
    // Control: the bar, its swatches and the cookie icon were all found.
    expect(marks.length, `${scheme}: the marks were not found`).toBeGreaterThanOrEqual(9);
    const bad = [...text, ...marks]
      .filter((s) => s.ratio < s.floor)
      .map((s) => `    ${s.ratio.toFixed(2)}:1 (needs ${s.floor}) ${s.what}`);
    expect(bad, `${scheme}: under the floor:\n${bad.join("\n")}`).toEqual([]);
  }
  await popup.close();
  await page.close();
});
