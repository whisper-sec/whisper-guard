// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e config. Each spec launches its own persistent context with the real
// built extension (a browser profile cannot be shared), so specs run with
// one worker each and full parallelism comes from the file level.

import { defineConfig } from "@playwright/test";

/** The specs that need the real network (and, for live.spec.ts, a key). */
export const LIVE_SPECS = ["**/live.spec.ts", "**/consent-live.spec.ts"];

export default defineConfig({
  testDir: "./e2e",
  // Two projects, because a config-level testIgnore is applied AFTER the
  // command line: `playwright test e2e/live.spec.ts` with the live specs in a
  // top-level testIgnore reported "No tests found", and the release gate
  // (`npm run e2e:live`) silently ran nothing.
  //
  // hermetic: EVERY spec in testDir except the live ones. Do not enumerate
  //   specs in package.json: a hand-written list silently drops each new
  //   file, and a spec that never runs is worse than no spec (it reads as
  //   coverage).
  // live: only the specs that need the real network and a key. Their
  //   scripts select this project by name.
  projects: [
    { name: "hermetic", testIgnore: LIVE_SPECS },
    { name: "live", testMatch: LIVE_SPECS },
  ],
  timeout: 90_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "e2e-report" }]],
  use: {
    trace: "retain-on-failure",
  },
});
