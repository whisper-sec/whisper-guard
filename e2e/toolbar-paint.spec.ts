// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// One paint sets the tile, clears the badge text and sets the title, in that
// order, and the title is last. No state sets badge text or a badge colour.
// The REAL src/background/icon-state.ts is bundled with esbuild and loaded
// under a fake `browser.action` that records every call, so the branches
// Chromium never takes (a rejected badge clear, a tab that moved on mid-paint)
// are exercised hermetically. No browser, no network.

import { test, expect } from "@playwright/test";
import { build } from "esbuild";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(HERE, "../src/background/icon-state.ts");

type Call = [string, unknown];

interface Fake {
  calls: Call[];
  action: Record<string, unknown>;
}

interface PaintModule {
  paintIcon: (tabId: number, state: string) => Promise<void>;
  forgetTab: (tabId: number) => void;
}

const g = globalThis as Record<string, unknown>;

function fake(): Fake {
  const calls: Call[] = [];
  const rec = (name: string) => async (arg: unknown) => {
    calls.push([name, arg]);
  };
  const action: Record<string, unknown> = {
    setIcon: rec("setIcon"),
    setBadgeBackgroundColor: rec("setBadgeBackgroundColor"),
    setBadgeTextColor: rec("setBadgeTextColor"),
    setBadgeText: rec("setBadgeText"),
    setTitle: rec("setTitle"),
  };
  g["browser"] = { action };
  g["chrome"] = { action };
  return { calls, action };
}

async function load(outPath: string): Promise<PaintModule> {
  const outfile = join(outPath, "icon-state.mjs");
  await build({
    entryPoints: [ENTRY],
    bundle: true,
    format: "esm",
    platform: "node",
    outfile,
    logLevel: "silent",
  });
  return (await import(pathToFileURL(outfile).href)) as PaintModule;
}

const names = (f: Fake) => f.calls.map(([n]) => n);
const argOf = (f: Fake, name: string) => f.calls.find(([n]) => n === name)?.[1] as Record<string, unknown>;

test.afterEach(() => {
  delete g["browser"];
  delete g["chrome"];
});

const ALL_STATES = ["benign", "suspicious", "malicious", "unknown", "checking", "signedout", "neutral"];

const TITLES: Record<string, string> = {
  benign: "Whisper Guard: no known threat on this site",
  suspicious: "Whisper Guard: be careful on this site",
  malicious: "Whisper Guard: STOP, this site is a known threat",
  unknown: "Whisper Guard: new or low-coverage site, not confirmed either way",
  checking: "Whisper Guard: checking this site",
  signedout: "Whisper Guard: on-device protection active; sign in for the live signal",
  neutral: "Whisper Guard",
};

test("every state paints the tile, clears the badge text and sets the title last", async ({}, testInfo) => {
  for (const [i, state] of ALL_STATES.entries()) {
    const f = fake();
    const m = await load(testInfo.outputPath(`s${i}`));
    await m.paintIcon(1, state);

    expect(names(f), state).toEqual(["setIcon", "setBadgeText", "setTitle"]);
    expect(argOf(f, "setIcon"), state).toEqual({
      tabId: 1,
      path: {
        "16": `icons/${state}-16.png`,
        "32": `icons/${state}-32.png`,
        "48": `icons/${state}-48.png`,
        "128": `icons/${state}-128.png`,
      },
    });
    expect(argOf(f, "setBadgeText"), state).toEqual({ tabId: 1, text: "" });
    expect(argOf(f, "setTitle"), state).toEqual({ tabId: 1, title: TITLES[state] });
  }
});

test("a state's title is the last call and names the state in words", async ({}, testInfo) => {
  const f = fake();
  const m = await load(testInfo.outputPath());
  await m.paintIcon(1, "benign");
  expect(argOf(f, "setTitle")).toEqual({ tabId: 1, title: "Whisper Guard: no known threat on this site" });
  expect(f.calls[f.calls.length - 1]![0]).toBe("setTitle");
});

test("no state makes a badge colour call, even where the browser offers them", async ({}, testInfo) => {
  for (const [i, state] of ALL_STATES.entries()) {
    const f = fake();
    const m = await load(testInfo.outputPath(`c${i}`));
    await m.paintIcon(2, state);
    expect(names(f).filter((n) => n.includes("Color")), state).toEqual([]);
  }
});

test("a rejected badge clear does not stop the title", async ({}, testInfo) => {
  const f = fake();
  f.action["setBadgeText"] = async () => {
    throw new Error("the browser refused");
  };
  const m = await load(testInfo.outputPath());
  await m.paintIcon(4, "malicious");

  expect(names(f)).toEqual(["setIcon", "setTitle"]);
  expect(argOf(f, "setTitle")).toEqual({ tabId: 4, title: "Whisper Guard: STOP, this site is a known threat" });
});

test("a neutral paint clears the text and sets the neutral title", async ({}, testInfo) => {
  const f = fake();
  const m = await load(testInfo.outputPath());
  await m.paintIcon(2, "neutral");

  expect(names(f)).toEqual(["setIcon", "setBadgeText", "setTitle"]);
  expect(argOf(f, "setBadgeText")).toEqual({ tabId: 2, text: "" });
  expect(argOf(f, "setTitle")).toEqual({ tabId: 2, title: "Whisper Guard" });
});

test("a tab that is forgotten while the tile is being set gets no badge clear and no title", async ({}, testInfo) => {
  const f = fake();
  let release: () => void = () => undefined;
  f.action["setIcon"] = (arg: unknown) =>
    new Promise<void>((resolve) => {
      f.calls.push(["setIcon", arg]);
      release = resolve;
    });
  const m = await load(testInfo.outputPath());
  const painting = m.paintIcon(5, "benign");
  // The tile call is pending; the tab commits a new page meanwhile.
  while (!names(f).includes("setIcon")) await new Promise((r) => setTimeout(r, 5));
  m.forgetTab(5);
  release();
  await painting;

  expect(names(f)).toEqual(["setIcon"]);
});
