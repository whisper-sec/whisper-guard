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
    try {
      const { page, tabId } = await visit(ext, url);
      await page.waitForTimeout(SETTLE_MS);
      arming = await frameArming(tabId);
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
