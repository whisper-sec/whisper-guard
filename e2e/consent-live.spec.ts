// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// real-world probe: the cookie auto-decline against the REAL internet
// with the real built extension, on the sites that motivated the change.
//
// Not part of `npm run e2e` and it must never be. It depends on live
// third-party pages whose markup and business models change without notice.
// Run it deliberately with `npm run e2e:consent-live` and read what it prints.
//
// WHAT IT ASSERTS, and why that is not the decline count. The number of
// publishers declined is a fact about the web, not about this extension: a
// wall that offers "Reject all and subscribe" and nothing else is a paywall,
// and refusing to click it is the contract working. Pinning that number would
// make a publisher's pricing decision look like our regression, and worse, it
// would tempt the next person to loosen a safety gate to make a test go green.
//
// So the assertion is the capability, which IS ours: the pass reaches the
// frame where a consent platform actually renders its wall, including the ones
// that commit after the page did. Everything else is reported and left to a
// human to read.
//
// THE MEASUREMENT THAT MOTIVATED, taken before the change with this
// method (broad grant, Active Shield on, cookieDecline on, ~12s per site):
//
//   bbc.com/news                  DECLINED
//   theguardian.com/international no decline, 2 iframes
//   lemonde.fr                    no decline, 3 iframes
//   spiegel.de                    no decline, 2 iframes
//   zeit.de                       no decline, 2 iframes
//   heise.de                      no decline
//   stackoverflow.com             no banner (the control)
//
// AND WHAT THE PER-FRAME PROBE FOUND AFTERWARDS, which is the useful part: on
// theguardian.com and spiegel.de the Sourcepoint frame is where the wall is,
// the pass reaches it now, and its buttons are "Accept all" / "Reject all and
// subscribe" and "Consent and continue" / "Subscribe now". Neither offers a
// plain decline. Those two are consent-or-pay, and leaving them alone is
// correct, not a miss.

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { launchExtension, makeShieldDist, setSettings, visit, type Extension } from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const EVIDENCE = resolve(HERE, "../e2e-artifacts/consent-live-evidence.md");

/**
 * The German pass. A publisher serves the wall in the browser's language, so
 * a probe that always browses in English exercises only the English decline
 * vocabulary however many languages the module speaks - which is exactly the
 * blind spot the vocabulary work was fixing. These run a second time with a
 * German browser, and the artifact records the labels each one offered so the
 * outcome is a reason rather than a number.
 */
const GERMAN_SITES = [
  "https://www.heise.de/",
  "https://www.spiegel.de/",
  "https://www.zeit.de/index",
];

const SITES = [
  "https://www.bbc.com/news",
  "https://www.theguardian.com/international",
  "https://www.lemonde.fr/",
  "https://www.spiegel.de/",
  "https://www.zeit.de/index",
  "https://www.heise.de/",
  "https://stackoverflow.com/", // the control: a page with no consent wall
];

const SETTLE_MS = 12_000;

let ext: Extension;
const lines: string[] = [];
function note(s: string): void {
  lines.push(s);
  console.log(s);
}

async function winCount(): Promise<number> {
  const rec = await ext.sw.evaluate(async () => {
    const s = await chrome.storage.local.get("wins");
    return (s["wins"] ?? null) as { counts?: Record<string, number> } | null;
  });
  return rec?.counts?.["cookieDecline"] ?? 0;
}

interface FrameArming {
  frameId: number;
  url: string;
  consent: boolean;
  preempt: boolean;
}

async function frameArming(tabId: number): Promise<FrameArming[]> {
  return ext.sw.evaluate(async (id: number) => {
    const frames = (await chrome.webNavigation.getAllFrames({ tabId: id })) ?? [];
    const out: FrameArming[] = [];
    for (const f of frames) {
      let r: { armed?: boolean; consent?: boolean } | undefined;
      try {
        r = (await chrome.tabs.sendMessage(
          id,
          { kind: "whisper-preempt-ping" },
          { frameId: f.frameId },
        )) as { armed?: boolean; consent?: boolean } | undefined;
      } catch {
        r = undefined;
      }
      out.push({
        frameId: f.frameId,
        url: (f.url ?? "").slice(0, 90),
        consent: r?.consent === true,
        preempt: r?.armed === true,
      });
    }
    return out;
  }, tabId) as Promise<FrameArming[]>;
}

/**
 * The visible button labels inside anything consent-shaped, per frame.
 *
 * "declined 1 of 7" is a number, not evidence. Without the labels there is
 * no way to tell the two possible reasons apart - the wall offered no plain
 * refusal (correct, leave it), or it offered one we could not read (a
 * defect) - and those need opposite responses. The artifact is only worth
 * writing if it distinguishes them.
 *
 * Read-only: it never clicks. Playwright reaches every frame directly, so
 * this needs nothing from the extension.
 */
async function consentButtons(page: import("@playwright/test").Page): Promise<string[]> {
  const out: string[] = [];
  for (const frame of page.frames()) {
    let labels: string[] = [];
    try {
      labels = await frame.evaluate(() => {
        const SEL = [
          "[role='dialog']", "[role='alertdialog']", "[aria-modal='true']",
          "[id*='cookie' i]", "[class*='cookie' i]", "[id*='consent' i]",
          "[class*='consent' i]", "[id*='gdpr' i]", "[class*='gdpr' i]",
          "[class*='sp_message' i]", "[class*='message-component' i]",
        ].join(",");
        const seen = new Set<string>();
        for (const root of document.querySelectorAll(SEL)) {
          for (const b of root.querySelectorAll("button,[role='button'],input[type='button'],input[type='submit'],a[href]")) {
            const el = b as HTMLElement;
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) continue;
            const text = (el.textContent ?? (el as HTMLInputElement).value ?? "").replace(/\s+/g, " ").trim();
            if (text === "" || text.length > 64) continue;
            seen.add(`${text}${el.tagName === "A" ? " [link]" : ""}`);
            if (seen.size >= 12) break;
          }
          if (seen.size >= 12) break;
        }
        return [...seen];
      });
    } catch {
      // cross-origin frame that refused evaluation, or gone
      labels = [];
    }
    for (const l of labels) if (!out.includes(l)) out.push(l);
  }
  return out.slice(0, 16);
}

test.beforeAll(async () => {
  ext = await launchExtension({ dist: makeShieldDist() });
  await setSettings(ext, { shield: true, cookieDecline: true, cloudCheck: true });
  note(`# real-world consent probe`);
  note(``);
  note(`- run: ${new Date().toISOString()}`);
  note(`- build: dist/chromium with the broad grant, Active Shield on, cookieDecline on`);
  note(`- settle: ${SETTLE_MS / 1000}s per site`);
  note(``);
});

test.afterAll(async () => {
  mkdirSync(dirname(EVIDENCE), { recursive: true });
  writeFileSync(EVIDENCE, lines.join("\n") + "\n", "utf8");
  await ext?.close();
});

test("the pass reaches the frame where a real CMP renders its wall", async () => {
  test.setTimeout(SITES.length * (SETTLE_MS + 40_000));

  const outcome: string[] = [`| site | sub-frames | armed | declined |`, `|---|---|---|---|`];
  const detail: string[] = [];
  let declined = 0;
  let subFramesSeen = 0;
  let subFramesArmed = 0;
  let topArmed = 0;
  let preemptOutsideTop = 0;

  for (const url of SITES) {
    const before = await winCount();
    let arming: FrameArming[] = [];
    let buttons: string[] = [];
    try {
      const { page, tabId } = await visit(ext, url);
      await page.waitForTimeout(SETTLE_MS);
      arming = await frameArming(tabId);
      buttons = await consentButtons(page);
      await page.close();
    } catch (e) {
      outcome.push(`| ${url} | ? | ? | UNREACHABLE (${e instanceof Error ? e.message.slice(0, 50) : "?"}) |`);
      continue;
    }
    const won = (await winCount()) - before;
    if (won > 0) declined += 1;

    const subs = arming.filter((f) => f.frameId !== 0);
    const armedSubs = subs.filter((f) => f.consent);
    subFramesSeen += subs.length;
    subFramesArmed += armedSubs.length;
    if (arming.some((f) => f.frameId === 0 && f.consent)) topArmed += 1;
    preemptOutsideTop += arming.filter((f) => f.frameId !== 0 && f.preempt).length;

    outcome.push(
      `| ${url} | ${subs.length} | ${armedSubs.length} | ${won > 0 ? "YES" : "no"} |`,
    );
    detail.push(`### ${url}`);
    detail.push(``);
    detail.push(`| frame | consent armed | click guard | url |`);
    detail.push(`|---|---|---|---|`);
    for (const f of arming) {
      detail.push(
        `| ${f.frameId} | ${f.consent ? "yes" : "NO"} | ${f.preempt ? "yes" : "no"} | ${f.url} |`,
      );
    }
    // The labels the wall actually offered. This is the line that turns
    // "no" into a reason, and it is the whole point of writing the file.
    detail.push(``);
    detail.push(
      buttons.length > 0
        ? `**Buttons on offer:** ${buttons.map((b) => `\`${b}\``).join(" · ")}`
        : `**Buttons on offer:** none found in a consent-shaped container.`,
    );
    detail.push(``);
  }

  note(`## Outcome`);
  note(``);
  for (const l of outcome) note(l);
  note(``);
  note(`declined ${declined} of ${SITES.length}, sub-frames ${subFramesArmed}/${subFramesSeen} armed`);
  note(``);
  note(`## Per frame`);
  note(``);
  for (const l of detail) note(l);

  // CONTROL first, so nothing below can pass on a run where the browser never
  // loaded anything: the top document was armed on more than one site, and
  // real pages brought real sub-frames.
  expect(topArmed, "the pass did not arm even in the top document").toBeGreaterThan(1);
  expect(subFramesSeen, "no sub-frames at all: this run measured nothing").toBeGreaterThan(2);

  // THE ASSERTION. Every sub-frame that exists is reached, including the ones
  // a consent platform injects after the page has loaded, which is where the
  // wall lives and which a one-shot injection at nav time could never see.
  expect(
    subFramesArmed,
    "sub-frames were not reached: that is the behaviour this fixed, whatever the decline count says",
  ).toBe(subFramesSeen);

  // And the bound holds on the real web too: widening where the module RUNS
  // did not widen what it may INTERCEPT.
  expect(preemptOutsideTop, "the click guard escaped the top document").toBe(0);
});

test("the German pass: the wall is read in the language the publisher serves", async () => {
  test.setTimeout(GERMAN_SITES.length * (SETTLE_MS + 40_000) + 60_000);

  // A second browser, in German. The extension under test is the same build;
  // only Accept-Language and navigator.language differ, which is what makes
  // the publisher serve a German wall.
  const de = await launchExtension({ dist: makeShieldDist(), locale: "de-DE" });
  await setSettings(de, { shield: true, cookieDecline: true, cloudCheck: true });

  const germanWins = async (): Promise<number> => {
    const rec = await de.sw.evaluate(async () => {
      const st = await chrome.storage.local.get("wins");
      return (st["wins"] ?? null) as { counts?: Record<string, number> } | null;
    });
    return rec?.counts?.["cookieDecline"] ?? 0;
  };

  const rows: string[] = [`| site | declined | buttons on offer |`, `|---|---|---|`];
  let declined = 0;
  try {
    for (const url of GERMAN_SITES) {
      const before = await germanWins();
      let buttons: string[] = [];
      try {
        const { page } = await visit(de, url);
        await page.waitForTimeout(SETTLE_MS);
        buttons = await consentButtons(page);
        await page.close();
      } catch (e) {
        rows.push(`| ${url} | UNREACHABLE | ${e instanceof Error ? e.message.slice(0, 60) : "?"} |`);
        continue;
      }
      const won = (await germanWins()) - before;
      if (won > 0) declined += 1;
      rows.push(
        `| ${url} | ${won > 0 ? "YES" : "no"} | ${
          buttons.length > 0 ? buttons.map((b) => `\`${b}\``).join(" · ") : "none found"
        } |`,
      );
    }
  } finally {
    await de.close();
  }

  note(``);
  note(`## German pass (Accept-Language: de-DE)`);
  note(``);
  for (const r of rows) note(r);
  note(``);
  note(
    `declined ${declined} of ${GERMAN_SITES.length}. A "no" beside a button list ` +
      `whose only refusal costs money is the contract working, not a miss.`,
  );

  // The assertion is the CAPABILITY, not the count, for the same reason as
  // the pass above: how many German publishers offer a free refusal is a
  // fact about the German press, and pinning it would turn a publisher's
  // pricing decision into our regression. What must hold is that the probe
  // really ran in German and really saw walls.
  const sawSomething = rows.filter((r) => r.includes("`")).length;
  expect(sawSomething, "the German pass observed no consent wall at all; it measured nothing").toBeGreaterThan(0);
});
