// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// A feature that ships and can never run is the defect this codebase produces
// most, and this one nearly went out that way: scanTabIocs was written, tested,
// committed and reported as built while nothing in the extension called it. The
// unit tests all passed, because they imported the module directly and never
// asked whether production reaches it.
//
// So this asserts the WIRING, not the behaviour: the message kind exists, the
// background dispatcher handles it, and the handler actually calls the scanner.
// Remove any of the three and this fails.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";

test("the ioc scan is reachable from the message surface, not just defined", () => {
  const messages = readFileSync("src/shared/messages.ts", "utf8");
  expect(messages, "no scanIocs message kind - nothing could ask for a scan").toContain('kind: "scanIocs"');

  const bg = readFileSync("src/background/index.ts", "utf8");
  expect(bg, "the dispatcher does not handle scanIocs").toContain('case "scanIocs"');
  expect(bg, "the handler does not call the scanner").toContain("scanTabIocs(");
  expect(bg, "the scanner is not imported into the dispatcher").toMatch(
    /import\s*\{[^}]*scanTabIocs[^}]*\}\s*from\s*["']\.\/page-scan["']/,
  );
});

test("the control: the scanner exists and is the thing being wired", () => {
  // Without this, the assertions above are satisfied by any file that happens
  // to contain the string.
  const scan = readFileSync("src/background/page-scan.ts", "utf8");
  expect(scan).toContain("export async function scanTabIocs");
  expect(scan).toContain("chrome.scripting.executeScript");
});
