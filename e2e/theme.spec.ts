// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// EVERY SURFACE, BOTH THEMES.
//
// The panel learned to follow the reader's colour scheme; the dashboard,
// settings, first-run, the pre-click window and the full-page warning did
// not, and two of them carried a whole dark palette in literal hex, where
// no change to the shared theme could ever reach them. That is a defect
// that hides perfectly: every screenshot in the repo was captured dark, so
// nothing was ever wrong in any picture anyone looked at.
//
// So this pins the structural half from the outside:
//
//   1. every extension page declares `color-scheme: light dark` and links
//      the shared theme;
//   2. no stylesheet but theme.css defines a literal colour - the surfaces
//      draw with tokens, and the tokens flip in one place;
//   3. the palette really does flip: the same page rendered under each
//      scheme reports a different background AND a different ink;
//   4. and EVERY piece of text actually on screen clears the WCAG AA
//      floor in both schemes - measured on the rendered elements, each
//      composited against the real ground behind it, rather than on the
//      token table. A token audit passes a page that draws a readable
//      token on an unreadable ground; this does not.

import { test, expect } from "@playwright/test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, openDashboard, openPopup, setKey, visit, waitForIcon, type Extension } from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(HERE, "../src");
const DIST = resolve(HERE, "../dist/chromium");

/** Every page the extension can put on screen. */
const PAGES = ["popup.html", "dashboard.html", "options.html", "firstrun.html", "check-link.html", "warning.html"];

// ------------------------------------------------------------ structure

test("every page declares both schemes and links the shared theme", () => {
  for (const page of PAGES) {
    const html = readFileSync(join(DIST, page), "utf8");
    expect(html, `${page} must declare both colour schemes`).toContain(
      '<meta name="color-scheme" content="light dark">',
    );
    expect(html, `${page} must link the shared theme`).toContain('href="theme.css"');
  }
});

test("no stylesheet but theme.css defines a literal colour", () => {
  const sheets: [string, string][] = [];
  for (const dir of ["popup", "pages", "options", "shared"]) {
    for (const f of readdirSync(join(SRC, dir))) {
      if (f.endsWith(".css") && f !== "theme.css") sheets.push([`${dir}/${f}`, readFileSync(join(SRC, dir, f), "utf8")]);
    }
  }
  // CONTROL: the sweep has to be looking at real files, or "no literal
  // colour anywhere" is a statement about an empty list.
  expect(sheets.length, "the stylesheet sweep found nothing to check").toBeGreaterThan(3);

  for (const [name, css] of sheets) {
    const literals = [...css.matchAll(/#[0-9a-fA-F]{3,8}\b|\brgba?\([^)]*\)|\bhsla?\([^)]*\)/g)]
      .map((m) => m[0])
      // #fff on a solid crit plate is the one deliberate fixed colour: a
      // filled verdict badge carries white text in both themes, and it is
      // measured (6.4:1 dark, 6.7:1 light) rather than inherited.
      .filter((c) => c.toLowerCase() !== "#fff" && c.toLowerCase() !== "#ffffff");
    expect(literals, `${name} defines colours of its own; use a token from theme.css`).toEqual([]);
  }
});

// ------------------------------------------------------------ behaviour

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort });
});
test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

interface TextSample {
  /** A short description of the element, for the failure message. */
  what: string;
  /** The rendered ink, composited over its ground. */
  ratio: number;
  /** The AA floor this sample has to clear (3.0 for large text). */
  floor: number;
}

/**
 * Walk everything the page actually PAINTS and measure it.
 *
 * This runs in the page because contrast is a property of what rendered,
 * not of what was written: the ink may be translucent, the ground may be
 * three ancestors up or a color-mix(), and either may come from a token
 * that has just flipped. Composite both and compare.
 */
async function measure(tab: import("@playwright/test").Page): Promise<TextSample[]> {
  // Controls carry a 120ms colour transition, so a sample taken too soon
  // after a scheme flip reads an ink part-way between the two palettes on a
  // ground that has already snapped - which measured as 2.30:1 on a button
  // that is 5.80:1 at rest. Ask for reduced motion, which the product's own
  // stylesheet answers by switching every transition off, and measure the
  // resting state on purpose rather than whatever the clock happened to
  // catch.
  await tab.emulateMedia({ reducedMotion: "reduce" });
  return tab.evaluate(() => {
    const px = (c: string): number[] => {
      const m = c.match(/-?[\d.]+/g);
      if (!m) return [0, 0, 0, 1];
      const raw = m.map(Number);
      // Chromium serialises a computed colour on two DIFFERENT scales:
      // `rgb(233, 204, 207)` is 0-255 while a color-mix() result comes back
      // as `color(srgb 0.913725 0.8 0.812549)`, 0-1.
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

    /** The first opaque ground behind `el`, composited down from the page. */
    const groundOf = (el: Element): number[] => {
      const stack: number[][] = [];
      for (let n: Element | null = el; n; n = n.parentElement) {
        const c = px(getComputedStyle(n).backgroundColor);
        if (c[3]! > 0) stack.push(c);
        if (c[3] === 1) break;
      }
      // Nothing opaque anywhere: the browser paints white behind the page.
      let out = [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i]!, out);
      return out;
    };

    const out: { what: string; ratio: number; floor: number }[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("body *"))) {
      // Only elements with their OWN visible text; a container's colour is
      // measured on whichever child actually paints the glyphs.
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
      // A disabled control is allowed to look disabled.
      if ((el as HTMLButtonElement).disabled) continue;
      if (el.closest("[disabled]")) continue;

      // Element opacity multiplies the ink's alpha.
      let alpha = 1;
      for (let n: Element | null = el; n; n = n.parentElement) alpha *= Number(getComputedStyle(n).opacity);
      const fg = px(cs.color);
      fg[3] = fg[3]! * alpha;

      const ground = groundOf(el);
      const ink = over(fg, ground);
      const [hi, lo] = [lum(ink), lum(ground)].sort((a, b) => b - a);
      const ratio = (hi! + 0.05) / (lo! + 0.05);

      const size = parseFloat(cs.fontSize);
      const weight = Number(cs.fontWeight) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      out.push({
        what: `<${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${
          el.className && typeof el.className === "string" ? `.${el.className.trim().split(/\s+/).join(".")}` : ""
        }> "${own.slice(0, 40)}"`,
        ratio,
        floor: large ? 3 : 4.5,
      });
    }
    return out;
  });
}

test("the palette really flips, and every rendered glyph clears AA in both schemes", async () => {
  for (const page of PAGES) {
    const tab = await ext.context.newPage();
    await tab.goto(`chrome-extension://${ext.id}/${page}`);
    await tab.waitForTimeout(400);

    const grounds: Record<string, string> = {};
    for (const scheme of ["dark", "light"] as const) {
      await tab.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await tab.waitForTimeout(250);
      grounds[scheme] = await tab.evaluate(
        () => `${getComputedStyle(document.body).backgroundColor}|${getComputedStyle(document.body).color}`,
      );

      const samples = await measure(tab);
      // CONTROL: a page that rendered nothing has no failing sample either,
      // and every one of these pages paints text before any data arrives.
      expect(samples.length, `${page} ${scheme}: nothing rendered, so nothing was measured`).toBeGreaterThan(3);
      const bad = samples
        .filter((s) => s.ratio < s.floor)
        .map((s) => `    ${s.ratio.toFixed(2)}:1 (needs ${s.floor}) ${s.what}`);
      expect(bad, `${page} ${scheme}: text under the AA floor:\n${bad.join("\n")}`).toEqual([]);
    }

    // 3. The palette flipped: not the same ground, not the same ink.
    expect(grounds["dark"], `${page} renders identically in both schemes`).not.toBe(grounds["light"]);
    await tab.close();
  }
});

/**
 * The pages above are measured cold, before any data arrives, which
 * leaves out exactly the elements most at risk: the verdict chips, the
 * status dots' sentences, the ledger rows and the identity card, all of
 * which are drawn in the saturated half of the palette. So measure them
 * POPULATED too, against a real verdict from the mock graph.
 */
test("a populated panel and dashboard clear AA in both schemes", async () => {
  const CLEAN = "intranet-tools-vendor.com";
  const BAD = "paypa1-secure-login.com";
  net.setVerdict(CLEAN, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setIdentify(CLEAN, [{ host: CLEAN, canonical_name: "Intranet Tools", category: "work", roles: [] }]);
  net.setEnrich(CLEAN, {
    ip: "203.0.113.12", city: "Amsterdam, NL", country: "NL", asn: "AS64500",
    owner: "Intranet Tools B.V.", asnName: "INTRANET - Intranet Tools B.V.",
    verdict: "NONE", prefix: "203.0.113.0/24",
  });
  net.setVerdict(BAD, { band: "CRITICAL", coverage: "malicious-evidenced", label: "credential-phishing suspect" });
  net.setEnrich(BAD, {
    ip: "192.0.2.66", city: "Montreal, CA", country: "CA", asn: "AS64550",
    owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC",
    verdict: "CRITICAL", prefix: "192.0.2.0/24",
  });
  net.setIdentify(BAD, [{ host: BAD, canonical_name: "Bad Hosting", category: "unresolved", roles: [] }]);
  await setKey(ext, MOCK_KEY);

  const checked: [string, import("@playwright/test").Page][] = [];
  for (const host of [CLEAN, BAD]) {
    const { tabId } = await visit(ext, `https://${host}/`);
    await waitForIcon(ext, tabId, ["benign", "malicious", "suspicious", "unknown"]);
    const popup = await openPopup(ext, tabId);
    await popup.waitForTimeout(900);
    checked.push([`panel:${host}`, popup]);
  }
  const dash = await openDashboard(ext, "browser");
  await dash.waitForTimeout(2500);
  checked.push(["dashboard:browser", dash]);

  for (const [what, page] of checked) {
    for (const scheme of ["dark", "light"] as const) {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await page.waitForTimeout(250);
      const samples = await measure(page);
      // CONTROL: these surfaces carry a verdict chip, a hostname and at
      // least one sentence; a handful of samples means nothing painted and
      // the sweep below would pass on an empty list.
      expect(samples.length, `${what} ${scheme}: too little rendered to be measuring the real surface`).toBeGreaterThan(10);
      const bad = samples
        .filter((s) => s.ratio < s.floor)
        .map((s) => `    ${s.ratio.toFixed(2)}:1 (needs ${s.floor}) ${s.what}`);
      expect(bad, `${what} ${scheme}: text under the AA floor:\n${bad.join("\n")}`).toEqual([]);
    }
    await page.close();
  }
});
