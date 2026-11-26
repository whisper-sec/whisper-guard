// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Static checks over the manifests, no browser. Firefox places a new toolbar
// button in the Extensions menu unless the manifest asks for the toolbar.
// Only Firefox reads `default_area`; Chrome cannot pin an extension, so its
// manifest must not carry the key.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (rel: string) => JSON.parse(readFileSync(join(HERE, "..", rel), "utf8"));

// True when any object nested anywhere in `node` has a `default_area` key.
function hasDefaultAreaAnywhere(node: unknown): boolean {
  if (Array.isArray(node)) return node.some(hasDefaultAreaAnywhere);
  if (node && typeof node === "object") {
    return Object.entries(node).some(([k, v]) => k === "default_area" || hasDefaultAreaAnywhere(v));
  }
  return false;
}

const PAIRS = [
  ["source", "manifests/manifest.firefox.json", "manifests/manifest.chromium.json"],
  ["built", "dist/firefox/manifest.json", "dist/chromium/manifest.json"],
] as const;

for (const [kind, firefoxPath, chromiumPath] of PAIRS) {
  test(`${kind} manifests: Firefox action.default_area is "navbar" and the Chromium manifest has no default_area`, () => {
    const firefox = read(firefoxPath);
    const chromium = read(chromiumPath);
    expect(firefox.action.default_area).toBe("navbar");
    expect(chromium.action).not.toHaveProperty("default_area");
    expect(hasDefaultAreaAnywhere(chromium)).toBe(false);
    // The key lives only on the action block, nowhere else in the Firefox manifest.
    const { default_area: _area, ...rest } = firefox.action;
    expect(hasDefaultAreaAnywhere({ ...firefox, action: rest })).toBe(false);
  });
}

test("Firefox source manifest action keeps its title, popup and icons apart from default_area", () => {
  const { default_area: _area, ...rest } = read("manifests/manifest.firefox.json").action;
  expect(rest).toEqual({
    default_title: "Whisper Guard",
    default_popup: "popup.html",
    default_icon: {
      "16": "icons/neutral-16.png",
      "32": "icons/neutral-32.png",
      "48": "icons/neutral-48.png",
      "128": "icons/neutral-128.png",
    },
  });
});
