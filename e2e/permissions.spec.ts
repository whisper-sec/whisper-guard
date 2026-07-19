// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Manifest-shape regression guards for the permission model, split by engine.
//
//   proxy is REQUIRED on Chromium (Chrome forbids it in optional_permissions;
//   chrome.permissions.request({permissions:['proxy']}) throws synchronously,
//   which is what made the "Route traffic through Whisper" toggle a dead
//   no-op). Firefox DOES allow proxy as optional, so it stays there.
//
//   The page-link sweep and the egress route BOTH acquire host access on a
//   user gesture from optional_host_permissions (<all_urls>): no broad host
//   access is taken at install, on either engine.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const load = (target: string) =>
  JSON.parse(readFileSync(resolve(HERE, `../dist/${target}/manifest.json`), "utf8"));

test("chromium: proxy is a REQUIRED permission, never optional", () => {
  const m = load("chromium");
  expect(m.permissions).toContain("proxy");
  expect(m.optional_permissions ?? []).not.toContain("proxy");
  // The rest of the egress set stays optional (Chrome grants them at runtime).
  for (const p of ["webRequest", "webRequestAuthProvider", "privacy"]) {
    expect(m.optional_permissions).toContain(p);
  }
});

test("firefox: proxy stays OPTIONAL (Firefox permits it), never required", () => {
  const m = load("firefox");
  expect(m.optional_permissions ?? []).toContain("proxy");
  expect(m.permissions).not.toContain("proxy");
});

test("both engines: activeTab + scripting present, no broad host access at install", () => {
  for (const target of ["chromium", "firefox"]) {
    const m = load(target);
    expect(m.permissions).toContain("activeTab");
    expect(m.permissions).toContain("scripting");
    // Page access (link sweep + egress) is requested on a gesture, not granted
    // at install: <all_urls> lives in optional_host_permissions only.
    expect(m.optional_host_permissions).toContain("<all_urls>");
    expect(m.host_permissions ?? []).not.toContain("<all_urls>");
  }
});
