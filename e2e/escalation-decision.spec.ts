// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// unit coverage: the calm escalation ladder is pure data + pure
// functions, exercised here directly (no browser needed) so the decision
// table itself is pinned. Kept in the e2e suite so `npx playwright test`
// covers everything in one pass. Also pins the manifests: these stories
// must add NO permission, so the exact permission sets are asserted.

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  RUNGS,
  atLeast,
  decide,
  severity,
  type Moment,
  type Rung,
  type Signal,
} from "../src/shared/escalation";
import { shouldInterrupt } from "../src/shared/preempt";

const MOMENTS: Moment[] = ["page", "action", "credential", "win"];

// ------------------------------------------------------------ the spectrum

test("the spectrum reads silent -> ambient -> pre-emptive -> conversational -> blocking, and atLeast follows it", () => {
  expect(RUNGS).toEqual(["silent", "ambient", "preemptive", "conversational", "blocking"]);
  for (let i = 0; i < RUNGS.length; i++) {
    for (let j = 0; j < RUNGS.length; j++) {
      expect(atLeast(RUNGS[i], RUNGS[j])).toBe(i >= j);
    }
  }
});

// ----------------------------------------------------------- the decisions

test("evidenced malice: blocks the page, pre-empts the action, converses at a password field, never toasts a win", () => {
  for (const sig of [
    { band: "CRITICAL" },
    { band: "HIGH" },
    { band: "LOW", label: "malicious" }, // an explicit malicious label IS evidence, any band
  ] satisfies Signal[]) {
    expect(severity(sig)).toBe("evidenced");
    expect(decide(sig, "page")).toBe("blocking");
    expect(decide(sig, "action")).toBe("preemptive");
    expect(decide(sig, "credential")).toBe("conversational");
    expect(decide(sig, "win")).toBe("silent");
  }
});

test("a MEDIUM flag or an on-device look-alike converses on the page but NEVER interrupts the user's own action", () => {
  for (const sig of [
    { band: "MEDIUM" },
    { band: null, lookalike: true },
    { band: "UNKNOWN", lookalike: true },
  ] satisfies Signal[]) {
    expect(decide(sig, "page")).toBe("conversational");
    expect(decide(sig, "action")).toBe("silent");
    expect(decide(sig, "credential")).toBe("conversational");
    expect(decide(sig, "win")).toBe("silent");
  }
});

test("clean, unknown, and unassessed are silent in EVERY moment: the common case raises no UI at all", () => {
  for (const sig of [
    { band: "NONE" },
    { band: "LOW" },
    { band: "INFO" },
    { band: "UNKNOWN" },
    { band: null },
  ] satisfies Signal[]) {
    for (const moment of MOMENTS) {
      expect(decide(sig, moment)).toBe("silent");
    }
  }
});

test("the win moment is silent at every severity: quiet wins are counted, never announced", () => {
  for (const sig of [
    { band: "CRITICAL" },
    { band: "HIGH", label: "malicious" },
    { band: "MEDIUM" },
    { band: null, lookalike: true },
    { band: "NONE" },
    { band: null },
  ] satisfies Signal[]) {
    expect(decide(sig, "win")).toBe("silent");
  }
});

test("most of the table is silent (calm by construction)", () => {
  const signals: Signal[] = [
    { band: "CRITICAL" }, // evidenced
    { band: "MEDIUM" }, // flagged
    { band: null, lookalike: true }, // lookalike
    { band: null }, // none
  ];
  const cells: Rung[] = [];
  for (const sig of signals) for (const moment of MOMENTS) cells.push(decide(sig, moment));
  const silent = cells.filter((r) => r === "silent").length;
  expect(cells).toHaveLength(16);
  expect(silent).toBeGreaterThanOrEqual(9); // 9 of 16 cells, and the "none" row (real traffic's bulk) is all-silent
});

test("shouldInterrupt is the ladder's action row, not a private threshold", () => {
  expect(shouldInterrupt({ band: "CRITICAL" })).toBe(true);
  expect(shouldInterrupt({ band: "HIGH" })).toBe(true);
  expect(shouldInterrupt({ band: "LOW", label: "malicious" })).toBe(true);
  expect(shouldInterrupt({ band: "MEDIUM" })).toBe(false);
  expect(shouldInterrupt({ band: "UNKNOWN" })).toBe(false);
  expect(shouldInterrupt(null)).toBe(false);
  for (const sig of [{ band: "CRITICAL" }, { band: "MEDIUM" }, { band: "NONE" }]) {
    expect(shouldInterrupt(sig)).toBe(decide(sig, "action") === "preemptive");
  }
});

// ---------------------------------------------- no new manifest permission

const HERE = dirname(fileURLToPath(import.meta.url));

test("NO new capability: the permission sets are exactly the pre-existing ones, and the host list is pinned", () => {
  // add no permission at all: the API permission arrays below are
  // byte-for-byte the pre-existing sets, and the in-page layers ride the existing
  // injection model. host_permissions is pinned rather than frozen because
  // does change it, by exactly one Whisper endpoint (the keyed control plane),
  // which is a re-consent prompt for every installed user and must never happen
  // by accident.
  const chromium = JSON.parse(
    readFileSync(join(HERE, "../manifests/manifest.chromium.json"), "utf8"),
  );
  const firefox = JSON.parse(
    readFileSync(join(HERE, "../manifests/manifest.firefox.json"), "utf8"),
  );

  expect(chromium.permissions).toEqual([
    "activeTab",
    "webNavigation",
    "storage",
    "scripting",
    "contextMenus",
    "declarativeNetRequest",
    "alarms",
    "proxy",
  ]);
  expect(firefox.permissions).toEqual([
    "activeTab",
    "webNavigation",
    "storage",
    "scripting",
    "contextMenus",
    "declarativeNetRequest",
    "alarms",
  ]);
  for (const m of [chromium, firefox]) {
    expect(m.manifest_version).toBe(3);
    // ONE graph host, serving both arms - the reads a browsing hostname
    // may reach and the keyed control plane - and nothing else. Adding a host
    // here is a re-consent prompt for every installed user, so the list is
    // pinned, not merely bounded.
    //
    // nic.whisper.online is the fifth, added deliberately and at that price:
    // it serves the public network statistics document, which is how the
    // live size of the graph reaches the surfaces instead of being written
    // into the build as a constant that is stale the day after it ships. It
    // is a plain GET of a public file - no query string, no header, no body,
    // no cookie - which the wire-capture invariant in consent.spec.ts
    // asserts rather than assumes.
    expect(m.host_permissions).toEqual([
      "https://graph.whisper.online/*",
      "https://console.whisper.security/*",
      "https://get.whisper.online/*",
      "https://nic.whisper.online/*",
      "https://rdap.whisper.online/*",
    ]);
    expect(m.optional_host_permissions).toEqual(["<all_urls>"]);
    // The wins tally and the ladder need no notifications surface at all.
    expect(JSON.stringify(m)).not.toContain("notifications");
  }
  expect(chromium.optional_permissions).toEqual(["webRequest", "webRequestAuthProvider", "privacy"]);
  expect(firefox.optional_permissions).toEqual(["proxy"]);
});
