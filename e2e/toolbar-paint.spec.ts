// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// One paint sets the tile, the badge and the title, in that order, and the
// title is last. The REAL src/background/icon-state.ts is bundled with esbuild
// and loaded under a fake `browser.action` that records every call, so the
// branches Chromium never takes (a missing text-colour call, a rejected badge
// call, a tab that moved on mid-paint) are exercised hermetically. No browser,
// no network.

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

test("a verdict paint sets the tile, then the badge ground, text colour and text, and the title last", async ({}, testInfo) => {
  const f = fake();
  const m = await load(testInfo.outputPath());
  await m.paintIcon(1, "benign");

  expect(names(f)).toEqual([
    "setIcon",
    "setBadgeBackgroundColor",
    "setBadgeTextColor",
    "setBadgeText",
    "setTitle",
  ]);
  expect(argOf(f, "setIcon")).toEqual({
    tabId: 1,
    path: {
      "16": "icons/benign-16.png",
      "32": "icons/benign-32.png",
      "48": "icons/benign-48.png",
      "128": "icons/benign-128.png",
    },
  });
  expect(argOf(f, "setBadgeText")).toEqual({ tabId: 1, text: "✓" });
  expect(argOf(f, "setTitle")).toEqual({ tabId: 1, title: "Whisper Guard: no known threat on this site" });
});

test("a state without a badge clears the text and makes no colour call", async ({}, testInfo) => {
  const f = fake();
  const m = await load(testInfo.outputPath());
  await m.paintIcon(2, "neutral");

  expect(names(f)).toEqual(["setIcon", "setBadgeText", "setTitle"]);
  expect(argOf(f, "setBadgeText")).toEqual({ tabId: 2, text: "" });
});

test("with no text-colour call in the browser the text and the title are still set", async ({}, testInfo) => {
  const f = fake();
  delete f.action["setBadgeTextColor"];
  const m = await load(testInfo.outputPath());
  await m.paintIcon(3, "suspicious");

  expect(names(f)).toEqual(["setIcon", "setBadgeBackgroundColor", "setBadgeText", "setTitle"]);
  expect(argOf(f, "setBadgeText")).toEqual({ tabId: 3, text: "!" });
});

test("a rejected badge call does not stop the text or the title", async ({}, testInfo) => {
  const f = fake();
  f.action["setBadgeBackgroundColor"] = async () => {
    throw new Error("the browser refused");
  };
  const m = await load(testInfo.outputPath());
  await m.paintIcon(4, "malicious");

  expect(names(f)).toEqual(["setIcon", "setBadgeTextColor", "setBadgeText", "setTitle"]);
  expect(argOf(f, "setBadgeText")).toEqual({ tabId: 4, text: "STOP" });
});

test("a tab that is forgotten while the tile is being set gets no badge and no title", async ({}, testInfo) => {
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
