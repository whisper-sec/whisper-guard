// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE CLAIM THIS PROTECTS: we do what the competing threat-intelligence
// extension does, and we cost nothing on a page the reader never scans.
//
// The posture this pins: no static `content_scripts` entry, <all_urls> optional
// rather than required, and nothing injected until the reader asks for it. An
// ordinary page load must cost zero. The budget below is ours and is checked
// against our own build, not against anybody else's.
//
// That is a real advantage and it is one careless commit from gone. Adding a
// `content_scripts` entry is the obvious way to build a page scanner, and the
// page scanner is exactly what we just built. So the architecture is asserted
// here rather than trusted: on-demand injection through chrome.scripting, page
// access on the click, <all_urls> optional forever.
//
// A marketing claim nothing enforces becomes false quietly. This is the enforcement.

import { test, expect } from "@playwright/test";
import { readFileSync, statSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

const DIST = ["dist/chromium", "dist/firefox"];

// Their per-page injection, for the record and for the ratio below.
const COMPETITOR_CONTENT_SCRIPT_BYTES = 12_059_990;
// Generous headroom over today's 552,592, so this fails on a regression in kind
// rather than on ordinary growth.
const WHOLE_EXTENSION_CEILING_BYTES = 3_000_000;

for (const dir of DIST) {
  test(`${dir}: declares no static content script, so an unscanned page costs nothing`, () => {
    const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    const cs = manifest.content_scripts ?? [];
    expect(
      cs,
      "a static content_scripts entry runs on every page load forever. Build page " +
        "features with chrome.scripting on the reader's gesture instead - see " +
        "src/background/page-scan.ts.",
    ).toEqual([]);
  });

  test(`${dir}: <all_urls> stays OPTIONAL, never a required install grant`, () => {
    const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    const required: string[] = manifest.host_permissions ?? [];
    expect(
      required.filter((h) => h === "<all_urls>" || h === "*://*/*"),
      "requiring access to every site at install is the grant we refuse to ask for",
    ).toEqual([]);
    const optional: string[] = manifest.optional_host_permissions ?? [];
    expect(optional).toContain("<all_urls>");
  });

  test(`${dir}: the whole extension stays far under a competitor's single content script`, () => {
    const files: string[] = [];
    const walk = (d: string) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        const p = join(d, e.name);
        if (e.isDirectory()) walk(p);
        else files.push(p);
      }
    };
    walk(dir);
    const total = files.reduce((n, f) => n + statSync(f).size, 0);
    expect(total).toBeLessThan(WHOLE_EXTENSION_CEILING_BYTES);
    // The comparison is the point, so assert it rather than only asserting the
    // absolute size: if this ever stops holding, the listing claim must change.
    expect(total).toBeLessThan(COMPETITOR_CONTENT_SCRIPT_BYTES);
  });
}

test("the page scanner exists and is reached through chrome.scripting, not a manifest entry", () => {
  const src = readFileSync("src/background/page-scan.ts", "utf8");
  expect(src).toContain("chrome.scripting.executeScript");
  // The control: this file must genuinely be the scanner, or the assertion above
  // is satisfied by any file that happens to mention the API.
  expect(src).toContain("extractIocs");
  expect(existsSync("src/shared/ioc.ts")).toBe(true);
});
