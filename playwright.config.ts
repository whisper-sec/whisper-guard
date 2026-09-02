// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e config. Each spec launches its own persistent context with the real
// built extension (a browser profile cannot be shared), so specs run with
// one worker each and full parallelism comes from the file level.

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  // Run EVERY spec in testDir. Do not enumerate specs in package.json: a hand-written
  // list silently drops each new file, and a spec that never runs is worse than no spec
  // (it reads as coverage). The live specs are the only exclusions; they need the
  // network and a key, and have their own scripts.
  testIgnore: ["**/live.spec.ts", "**/consent-live.spec.ts"],
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
