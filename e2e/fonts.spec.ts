// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE UI KIT: COLOURS AND FONTS, ON EVERY SURFACE.
//
// Three claims, each proved from the outside against the built extension:
//
//   1. COLOUR. Every page resolves the kit's dark palette and the light
//      popup board's palette (board 3a / board 5d dark, board 3d light), read
//      both as the resolved tokens and as what an element actually paints.
//   2. FONTS RENDER. Text is set in Lato and a measured value (a name, an
//      address, a number) in JetBrains Mono, and the faces are really loaded
//      and applied: a width probe against the fallback, not only a name in a
//      font-family list that a missing file would silently skip past.
//   3. NO FONT LEAVES THE BROWSER. Every font the pages load comes from the
//      extension's own origin, and the capture log (the complete record of
//      what left the browser) holds no font file and no font service.
//
// And the package carries what the stylesheet names: every url() in the
// built @font-face rules resolves, in both builds, next to its licence.
// Canvas text follows too: a drawing made before the mono face arrived is
// drawn again once, and a face that fails to load cannot make it loop.

import { test, expect, type Page, type Request } from "@playwright/test";
import { build } from "esbuild";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { E2ENetwork } from "./helpers/servers";
import { launchExtension, type Extension } from "./helpers/extension";
import { expectScheme } from "./helpers/theme";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

const PAGES = [
  "popup.html",
  "dashboard.html",
  "options.html",
  "firstrun.html",
  "check-link.html",
  "warning.html?host=fonts-probe-guard-e2e.com",
];

// ----------------------------------------------------------------- colour

/** `#rrggbb` as the `rgb(r, g, b)` a computed colour serialises to. */
function rgb(hex: string): string {
  const n = (i: number): number => parseInt(hex.slice(i, i + 2), 16);
  return `rgb(${n(1)}, ${n(3)}, ${n(5)})`;
}

const PALETTE = {
  dark: { bg: "#06060c", card: "#0d0d1a", text: "#eeeef0", muted: "#8888a0", accent: "#b49cf5", accentLine: "#7d5ce0" },
  light: { bg: "#f4f4f8", card: "#ffffff", text: "#1a1a2e", muted: "#5f5f70", accent: "#5b3fc4", accentLine: "#6a4bd6" },
} as const;

// ------------------------------------------------------------ the browser

let net: E2ENetwork;
let ext: Extension;
const fontRequests: string[] = [];

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort });
});
test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function open(page: string): Promise<Page> {
  const tab = await ext.context.newPage();
  // Finished or failed: a font the page asked for is on the record either
  // way, so one that was refused somewhere else is checked too.
  const record = (r: Request): void => {
    if (r.resourceType() === "font") fontRequests.push(r.url());
  };
  tab.on("requestfinished", record);
  tab.on("requestfailed", record);
  await tab.goto(`chrome-extension://${ext.id}/${page}`);
  await tab.emulateMedia({ reducedMotion: "reduce" });
  return tab;
}

test("every page paints the kit palette in dark and the light board's palette in light", async () => {
  for (const page of PAGES) {
    const tab = await open(page);
    for (const scheme of ["dark", "light"] as const) {
      await tab.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await expectScheme(tab, scheme, `${page} follows the ${scheme} system`);
      const want = PALETTE[scheme];
      const got = await tab.evaluate(() => {
        const tok = (n: string): string => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
        // Probes use the shared classes (a page may restyle a class of its own, so the
        // muted ink is read through the token it is drawn with).
        const host = document.createElement("div");
        host.innerHTML =
          '<div class="w-card"></div><span style="color: var(--w-muted)">n</span><a href="#">a</a><button class="w-btn primary">b</button>';
        document.body.append(host);
        const cs = (sel: string): CSSStyleDeclaration => getComputedStyle(host.querySelector(sel) as Element);
        const out = {
          tokens: {
            bg: tok("--w-bg"),
            card: tok("--w-card"),
            text: tok("--w-text"),
            muted: tok("--w-muted"),
            accent: tok("--w-accent"),
            accentLine: tok("--w-accent-line"),
          },
          bodyBg: getComputedStyle(document.body).backgroundColor,
          bodyInk: getComputedStyle(document.body).color,
          cardBg: cs(".w-card").backgroundColor,
          mutedInk: cs("span").color,
          linkInk: cs("a").color,
          lineEdge: cs(".w-btn.primary").borderTopColor,
        };
        host.remove();
        return out;
      });
      const label = `${page} ${scheme}`;
      expect(got.tokens, `${label}: resolved tokens`).toEqual(want);
      // The warning page tints its own ground from the alarm hue and sets its own
      // quiet ink on that ground (its stylesheet says why), so on that one page the
      // ground and the muted ink are the page's, not the shared tokens'.
      const tinted = page.startsWith("warning.html");
      if (!tinted) {
        expect(got.bodyBg, `${label}: page ground`).toBe(rgb(want.bg));
        expect(got.mutedInk, `${label}: muted ink`).toBe(rgb(want.muted));
      }
      expect(got.bodyInk, `${label}: body ink`).toBe(rgb(want.text));
      expect(got.cardBg, `${label}: card`).toBe(rgb(want.card));
      expect(got.linkInk, `${label}: link ink`).toBe(rgb(want.accent));
      expect(got.lineEdge, `${label}: accent line`).toBe(rgb(want.accentLine));
    }
    await tab.close();
  }
});

// ------------------------------------------------------------------ fonts

test("text renders in Lato and measured values in JetBrains Mono, with the faces loaded", async () => {
  for (const page of PAGES) {
    const tab = await open(page);
    const got = await tab.evaluate(async () => {
      const host = document.createElement("div");
      // Three widths of one string per family. "X, serif" falls back to serif
      // when face X is not applied, so it can only differ from the bare serif
      // probe when the bundled face really drew the glyphs. And the page's own
      // stack has to draw the string exactly as wide as the bundled face does,
      // or the page is being set in something else further down the stack.
      const text = "Whisper Guard 0123456789 wmi.:";
      host.innerHTML =
        `<span id="p-sans">${text}</span>` +
        `<span id="p-sans-face" style="font-family: Lato, serif">${text}</span>` +
        `<span id="p-mono" class="w-mono">${text}</span>` +
        `<span id="p-mono-face" style="font-family: 'JetBrains Mono', serif">${text}</span>` +
        `<span id="p-fb" style="font-family: serif">${text}</span>` +
        `<span id="p-bold" style="font-weight: 700">${text}</span>`;
      // The probes share one size and weight, so only the face can change a width.
      for (const s of Array.from(host.querySelectorAll("span"))) {
        s.style.fontSize = "16px";
        if (s.id !== "p-bold") s.style.fontWeight = "400";
        s.style.whiteSpace = "nowrap";
      }
      document.body.append(host);
      // Lay the probes out first: a face starts loading when text that needs it is laid out.
      void host.getBoundingClientRect();
      await document.fonts.ready;
      const w = (id: string): number => (host.querySelector(`#${id}`) as HTMLElement).getBoundingClientRect().width;
      const fam = (el: Element): string => getComputedStyle(el).fontFamily;
      const loaded = [...document.fonts].filter((f) => f.status === "loaded").map((f) => `${f.family.replace(/"/g, "")} ${f.weight}`);
      const out = {
        bodyFamily: fam(document.body),
        monoFamily: fam(host.querySelector("#p-mono") as Element),
        sansWidth: w("p-sans"),
        sansFaceWidth: w("p-sans-face"),
        monoWidth: w("p-mono"),
        monoFaceWidth: w("p-mono-face"),
        fallbackWidth: w("p-fb"),
        loaded,
        checks: {
          lato: document.fonts.check("400 12px Lato", "Whisper"),
          latoBold: document.fonts.check("700 12px Lato", "Whisper"),
          mono: document.fonts.check("400 12px 'JetBrains Mono'", "0123"),
        },
      };
      host.remove();
      return out;
    });
    expect(got.bodyFamily, `${page}: body font stack`).toMatch(/^"?Lato"?,/);
    expect(got.monoFamily, `${page}: mono font stack`).toMatch(/^"?JetBrains Mono"?,/);
    expect(got.loaded, `${page}: Lato 400 is a loaded face`).toContain("Lato 400");
    expect(got.loaded, `${page}: Lato 700 is a loaded face`).toContain("Lato 700");
    expect(got.loaded, `${page}: JetBrains Mono 400 is a loaded face`).toContain("JetBrains Mono 400");
    expect(got.checks, `${page}: document.fonts.check`).toEqual({ lato: true, latoBold: true, mono: true });
    // CONTROL: the bundled faces draw this string at a different width from the
    // fallback, or the comparisons below could not tell them apart.
    expect(Math.abs(got.sansFaceWidth - got.fallbackWidth), `${page}: Lato is not applied`).toBeGreaterThan(1);
    expect(Math.abs(got.monoFaceWidth - got.fallbackWidth), `${page}: JetBrains Mono is not applied`).toBeGreaterThan(1);
    expect(got.sansWidth, `${page}: the page's text stack draws in Lato`).toBeCloseTo(got.sansFaceWidth, 1);
    expect(got.monoWidth, `${page}: the page's mono stack draws in JetBrains Mono`).toBeCloseTo(got.monoFaceWidth, 1);
    await tab.close();
  }
});

test("no font leaves the browser: every font is the extension's own file and the capture log holds none", async () => {
  // Every page is opened here, with text in both families on it, so this
  // test stands on its own; font loads recorded by the tests above count too.
  for (const page of PAGES) {
    const tab = await open(page);
    await tab.evaluate(async () => {
      const probe = document.createElement("div");
      probe.innerHTML = '<span>Whisper Guard</span><span class="w-mono">203.0.113.12</span>';
      document.body.append(probe);
      void probe.getBoundingClientRect();
      await document.fonts.ready;
      probe.remove();
    });
    await tab.close();
  }
  expect(fontRequests.length, "CONTROL: the pages loaded fonts, so there is something to check").toBeGreaterThan(0);
  const own = `chrome-extension://${ext.id}/`;
  for (const url of fontRequests) {
    expect(url.startsWith(own), `a font came from outside the extension: ${url}`).toBe(true);
  }
  // The capture is the complete record of what left the browser.
  const fontLike = net.log.filter((r) =>
    /\.(woff2?|ttf|otf|eot)(\?|$)/i.test(r.path) ||
    /fonts\.(googleapis|gstatic)\.com|fonts\.bunny\.net|use\.typekit\.net|fontshare|fontsource|jsdelivr|cdnjs|unpkg/i.test(r.host),
  );
  expect(fontLike, "a font request reached the network").toEqual([]);
});

// ----------------------------------------------------- canvas text redraw

/**
 * A <canvas> keeps whatever face it was drawn with, so a drawing made before
 * the mono face arrived is drawn once more when it does. The helper is driven
 * here for real: the REAL src/shared/theme.ts, bundled, under a fake
 * `document.fonts`, with a drawing that registers itself again on every draw
 * exactly as the product's two canvas drawings do.
 */
test("a canvas drawing is redrawn once when the mono face arrives, and never in a loop when it fails", async ({}, testInfo) => {
  const outfile = join(testInfo.outputPath(), "theme.mjs");
  await build({
    entryPoints: [join(ROOT, "src/shared/theme.ts")],
    bundle: true,
    format: "esm",
    platform: "node",
    outfile,
    logLevel: "silent",
  });
  const g = globalThis as Record<string, unknown>;
  const before = g["document"];

  const turn = (): Promise<void> => new Promise((r) => setImmediate(r));

  /** Draw once under the given font behaviour and report how many redraws followed. */
  async function redraws(name: string, fonts: { check: () => boolean; load: () => Promise<unknown> }): Promise<number> {
    let measuring = true;
    g["document"] = { fonts: { check: () => !measuring || fonts.check(), load: fonts.load } };
    // A fresh module per case: the helper remembers that the face settled.
    const mod = (await import(`${pathToFileURL(outfile).href}?case=${name}`)) as {
      redrawWhenMonoLoads: (canvas: unknown, redraw: () => void) => void;
    };
    const canvas = {};
    let n = 0;
    const draw = (): void => {
      mod.redrawWhenMonoLoads(canvas, () => {
        n++;
        draw();
      });
    };
    draw();
    // Give a runaway loop every chance to show itself: many full turns of the
    // event loop, each of which would run another load-and-redraw cycle.
    for (let i = 0; i < 50; i++) await turn();
    // A loop still running ends at its next check, so it cannot outlive the case.
    measuring = false;
    return n;
  }

  try {
    let loaded = false;
    expect(
      await redraws("arrives", {
        check: () => loaded,
        load: async () => {
          await turn();
          loaded = true;
        },
      }),
      "the face arrived after the first draw: one redraw",
    ).toBe(1);

    expect(
      await redraws("fails", {
        check: () => false,
        // Settles on a later turn, as a real font load does.
        load: async () => {
          await turn();
          throw new Error("font file missing");
        },
      }),
      "the face never loads: one redraw, then the drawing keeps the face it has",
    ).toBe(1);

    expect(
      await redraws("ready", { check: () => true, load: async () => undefined }),
      "the face was already loaded: nothing to redraw",
    ).toBe(0);
  } finally {
    if (before === undefined) delete g["document"];
    else g["document"] = before;
  }
});

// ---------------------------------------------------------------- package

/** Every @font-face rule of a stylesheet: family, weight, range, file. */
function faces(css: string): { family: string; weight: string; range: string; urls: string[] }[] {
  return [...css.matchAll(/@font-face\s*\{([^}]*)\}/g)].map((m) => {
    const body = m[1]!;
    return {
      family: /font-family:\s*"?([^";]+)"?\s*;/.exec(body)?.[1]?.trim() ?? "",
      weight: /font-weight:\s*(\d+)/.exec(body)?.[1] ?? "",
      range: /unicode-range:\s*([^;]+);/.exec(body)?.[1]?.trim() ?? "",
      urls: [...body.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/g)].map((u) => u[1]!),
    };
  });
}

test("the stylesheet declares the five faces, each with its own subset ranges", () => {
  const css = readFileSync(join(ROOT, "src/shared/theme.css"), "utf8");
  const all = faces(css);
  const key = (f: { family: string; weight: string }): string => `${f.family} ${f.weight}`;
  const count = (k: string): number => all.filter((f) => key(f) === k).length;
  // Latin and Latin Extended for each weight.
  for (const k of ["Lato 400", "Lato 700", "Lato 900", "JetBrains Mono 400", "JetBrains Mono 700"]) {
    expect(count(k), `${k}: one face per subset`).toBe(2);
  }
  expect(all.length).toBe(10);
  for (const f of all) {
    expect(f.range, `${key(f)} declares a unicode-range`).toMatch(/^U\+/);
    expect(f.urls.length, `${key(f)} names a file`).toBe(1);
    expect(f.urls[0]!, `${key(f)} loads a bundled file`).toMatch(/^fonts\/[\w.-]+\.woff2$/);
  }
});

for (const target of ["chromium", "firefox"] as const) {
  test(`the ${target} build ships every declared font file beside its licence`, () => {
    const dist = join(ROOT, "dist", target);
    const all = faces(readFileSync(join(dist, "theme.css"), "utf8"));
    expect(all.length, "the built theme.css declares fonts").toBe(10);
    for (const f of all) {
      for (const u of f.urls) {
        const p = join(dist, u);
        expect(existsSync(p), `${target}: ${u} is declared but not shipped`).toBe(true);
        expect(statSync(p).size, `${target}: ${u} is empty`).toBeGreaterThan(1000);
        // woff2 magic number
        expect(readFileSync(p).subarray(0, 4).toString("latin1"), `${target}: ${u} is not a woff2 file`).toBe("wOF2");
      }
    }
    for (const lic of ["OFL-Lato.txt", "OFL-JetBrainsMono.txt"]) {
      const p = join(dist, "fonts", lic);
      expect(existsSync(p), `${target}: fonts/${lic} missing`).toBe(true);
      expect(readFileSync(p, "utf8"), `${target}: fonts/${lic} is not the licence`).toMatch(/SIL OPEN FONT LICENSE Version 1\.1/);
    }
  });
}

test("NOTICE names both font families, their licence, version and source", () => {
  // Hard-wrapped prose: compare with the line breaks folded to spaces.
  const notice = readFileSync(join(ROOT, "NOTICE"), "utf8").replace(/\s+/g, " ");
  for (const needle of ["Lato", "JetBrains Mono", "SIL Open Font License", "@fontsource/lato", "@fontsource/jetbrains-mono", "assets/fonts"]) {
    expect(notice, `NOTICE should mention ${needle}`).toContain(needle);
  }
  expect(notice).toMatch(/Copyright.*tyPoland/);
  expect(notice).toMatch(/Copyright.*JetBrains Mono Project Authors/);
});
