// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE POPUP WITH A VISIBLE SCROLLBAR.
//
// The popup is one scroll, so on a system that draws a classic scrollbar (the
// default on Windows and Linux, and with "always show scroll bars" elsewhere)
// the gutter is there at all times and takes its width from every part. The
// rest of the suite runs headless Chromium, which hides scrollbars, so none of
// it can see that. This one launches without that default and checks what
// must still hold with the bar: the site name is never cut (a name near the
// edge may take one more line, which the annotations record), the facts rows
// keep the heights they have with no bar, the seven facts stay clear of the
// fade on the tightest first screen, and nothing scrolls sideways. The
// baseline is the same popup with its bar taken away by a style of the test.
//
// A system with overlay scrollbars (macOS by default) draws no gutter, so
// there the gutter is stood in for by the width one takes on Linux, as extra
// padding, and the annotation says so. Linux headless Chromium, which CI
// uses, draws the real one. Both schemes are measured, as drawn and with
// every glyph wider.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY } from "./helpers/servers";
import { launchExtension, openPopup, setKey, setSettings, visit, waitForIcon, type Extension } from "./helpers/extension";
import { WIDER_EM, expectFirstScreen, settledLayout, withWiderGlyphs } from "./helpers/popup-fit";

// 30 characters: the length of the longest name the other specs measure. With the bar and wider glyphs
// it breaks to two lines; that is the known cost of the stable gutter, recorded here, never avoided.
const HOST = "scrollbar-gutter-guard-e2e.com";
const LONG = "a-name-far-too-long-to-fit-the-card-on-one-line-guard-e2e.com";
/** The thin scrollbar's width on a system that draws one in Chromium, in px. */
const THIN_GUTTER = 10;

interface Lines {
  gutter: number;
  /** Each facts row's height, so a row that wrapped is a taller one. */
  rows: number[];
  name: number;
  nameLine: number;
  regionOverflow: boolean;
  cardOverflow: boolean;
  textColumn: number;
  nameText: string;
  nameCut: boolean;
}

async function read(popup: Page): Promise<Lines> {
  return popup.evaluate((): Lines => {
    const region = document.getElementById("popup-scroll") as HTMLElement;
    const name = document.getElementById("hostname") as HTMLElement;
    const card = document.getElementById("host-row") as HTMLElement;
    return {
      gutter: region.offsetWidth - region.clientWidth,
      rows: [...document.querySelectorAll("#chain-mount .ch-rung")].map((e) => Math.round(e.getBoundingClientRect().height * 10) / 10),
      name: name.getBoundingClientRect().height,
      nameLine: parseFloat(getComputedStyle(name).lineHeight),
      regionOverflow: region.scrollWidth > region.clientWidth,
      cardOverflow: card.scrollWidth > card.clientWidth,
      nameText: name.textContent ?? "",
      nameCut: name.scrollWidth > name.clientWidth,
      textColumn: (card.querySelector(".pp-verdict-text") as HTMLElement).getBoundingClientRect().width,
    };
  });
}

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const host of [HOST, LONG]) {
    // As this-site.spec.ts seeds them: the 30-character host has a LOW verdict with a label (the longest
    // reason line), both carry the popularity feed and an age, so the verdict card has its age line.
    const low = host === HOST;
    net.setVerdict(host, low ? { band: "LOW", coverage: "known-clean", label: "shared hosting provider" } : { band: "NONE", coverage: "known-clean", label: "clean" });
    net.setExplain(host, [{ score: 0, sources: [{ feedId: "tranco" }] }]);
    const created = new Date(Date.now() - 800 * 86_400_000).toISOString();
    net.setHistory(host, [{ createDate: created, updateDate: created }]);
    net.setEnrich(host, {
      ip: "198.51.100.77",
      city: "London, GB",
      country: "GB",
      asn: "AS64540",
      owner: "MediaCo plc",
      asnName: "MEDIACO - MediaCo plc",
      prefix: "198.51.100.0/24",
      threatNeighbors: 0,
      prevalence: 812,
      verdict: low ? "LOW" : "NONE",
    });
    net.setIdentify(host, [
      { host, canonical_name: "MediaCo", category: "media", roles: ["DNS_OPERATOR"], confidence: 0.85, host_class: "single_tenant", evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco"] },
    ]);
  }
  net.setPresence("AS64540", { facilities: ["Example Carrier Hotel LON1"], exchanges: ["Example Exchange LON"], facilityCount: 14, exchangeCount: 4 });
  ext = await launchExtension({ proxyPort: net.proxyPort, showScrollbars: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

/** The popup's lines as drawn and with every glyph wider, with the region's bar as shipped and taken away. */
async function measured(
  host: string,
  scheme: "dark" | "light",
): Promise<{ bare: Lines; shipped: Lines; bareWider: Lines; shippedWider: Lines; simulated: boolean }> {
  // Signed in: the footer holds its button row, the least room the first screen ever has.
  await setKey(ext, MOCK_API_KEY);
  await setSettings(ext, { cloudCheck: true });
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  const popup = await openPopup(ext, tabId);
  await popup.emulateMedia({ colorScheme: scheme });
  await popup.setViewportSize({ width: 400, height: 600 });
  await popup.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 20_000 });
  await expect(popup.locator("#chain-mount .ch-rung")).toHaveCount(7);
  // The tightest first screen is measured only once it is all drawn: the
  // footer's button row and the name's age line arrive after the verdict.
  await expect(popup.locator("#btn-dossier")).toBeVisible();
  await expect(popup.locator("#band-age")).toBeVisible();
  await settledLayout(popup);

  // The baseline: the same popup with the region's bar taken away.
  const none = await popup.addStyleTag({
    content: "#popup-scroll { scrollbar-width: none !important; scrollbar-gutter: auto !important; }",
  });
  const bare = await read(popup);
  const bareWider = await withWiderGlyphs(popup, WIDER_EM, () => read(popup));
  await none.evaluate((e) => (e as Element).remove());

  let shipped = await read(popup);
  let simulated = false;
  if (shipped.gutter === 0) {
    // Overlay scrollbars: no gutter is drawn. Stand one in, of the width Linux draws.
    simulated = true;
    await popup.addStyleTag({ content: `#popup-scroll { padding-right: calc(var(--pp-pad) + ${THIN_GUTTER}px) !important; }` });
    shipped = await read(popup);
    shipped.gutter = THIN_GUTTER;
  }
  const shippedWider = await withWiderGlyphs(popup, WIDER_EM, () => read(popup));
  // With the bar, the first screen is still clear of the fade, as drawn and wider.
  await expectFirstScreen(popup, `first-screen-with-bar-${scheme}`);
  await popup.close();
  await page.close();
  return { bare, shipped, bareWider, shippedWider, simulated };
}

for (const scheme of ["dark", "light"] as const) {
  test(`with a visible scrollbar the name is never cut, the facts rows keep their heights, the seven facts stay clear of the fade, and nothing scrolls sideways (${scheme})`, async () => {
    for (const host of [HOST, LONG]) {
      const m = await measured(host, scheme);
      const at = `${host === HOST ? "a name that fits" : "a long name"}, ${scheme}`;
      test.info().annotations.push({
        type: `gutter ${at}`,
        description: `${m.shipped.gutter} px (${m.simulated ? "stood in for: this system draws overlay scrollbars" : "drawn by the browser"}); text column ${m.shipped.textColumn.toFixed(1)} px against ${m.bare.textColumn.toFixed(1)} px without it`,
      });
      const lines = (l: Lines): number => Math.round(l.name / l.nameLine);
      test.info().annotations.push({
        type: `name lines ${at}`,
        description: `${lines(m.bare)} without the bar, ${lines(m.shipped)} with it as drawn; ${lines(m.bareWider)} without, ${lines(m.shippedWider)} with it ${WIDER_EM}em wider`,
      });
      // Control: a bar takes room, and the baseline really has none.
      expect(m.shipped.gutter, `${at}: no gutter, so nothing was measured`).toBeGreaterThan(0);
      expect(m.bare.gutter, `${at}: the baseline still has a gutter`).toBe(0);
      expect(m.shipped.textColumn, `${at}: the bar took no room from the text column`).toBeLessThan(m.bare.textColumn);
      for (const [how, withBar, without] of [
        ["as drawn", m.shipped, m.bare],
        [`${WIDER_EM}em wider`, m.shippedWider, m.bareWider],
      ] as const) {
        expect(withBar.rows, `${at}, ${how}: a facts row changed height with the bar`).toEqual(without.rows);
        // The name is never cut, whatever lines it takes.
        expect(withBar.nameText, `${at}, ${how}: the name was cut`).toBe(host);
        expect(withBar.nameCut, `${at}, ${how}: the name is wider than its box`).toBe(false);
        expect(withBar.regionOverflow, `${at}, ${how}: the popup scrolls sideways`).toBe(false);
        expect(withBar.cardOverflow, `${at}, ${how}: the verdict card is wider than itself`).toBe(false);
      }
    }
  });
}
