// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE ANSWER TO THE PROXY'S CHALLENGE MUST BE ARMED IN THE WORKER'S FIRST TURN.
//
// The proxy setting outlives the service worker. `proxy` is a required
// permission, the setting is written with scope "regular", and so a browser
// that was routing through egress yesterday is routing through egress again
// the instant it starts today, before a single line of our code has run.
//
// What does not outlive the worker is the listener that answers the proxy's
// 407. In MV3 Chromium decides whether to wake a dormant worker from the
// listeners it saw registered in that worker's FIRST TURN, and a listener
// added after an await is not in that record. Register it one await too
// late and the browser comes back routed, unanswered, and asking the human
// for a password we already hold. That is issue #29: the routing was right,
// the credentials were right, and we were simply asleep.
//
// The ordering is invisible in review. It reads as one more line in an async
// resume function, which is exactly where it was, and it costs nothing at
// runtime until the day the browser restarts. So it is checked here instead.
//
// The check is only worth having if it can fail, so it is mutation tested
// below against four planted regressions, including the precise one that
// shipped.

import { test, expect } from "@playwright/test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

interface Verdict {
  ok: boolean;
  why: string;
}

const OK: Verdict = { ok: true, why: "" };

/**
 * Does the arming survive a restart? Two halves have to hold: the function
 * must reach addListener without awaiting, and something must call it at the
 * top level of the worker before anything else awaits.
 */
function armedInFirstTurn(egressSrc: string, indexSrc: string): Verdict {
  const decl = /(?:^|\n)(?:export\s+)?(async\s+)?function armEgressAuth\s*\(/.exec(egressSrc);
  if (!decl) return { ok: false, why: "egress.ts declares no armEgressAuth" };
  if (decl[1]) {
    return { ok: false, why: "armEgressAuth is async, so it cannot register in the first turn" };
  }

  const bodyStart = decl.index + decl[0].length;
  const register = egressSrc.indexOf("onAuthRequired.addListener", bodyStart);
  if (register === -1) {
    return { ok: false, why: "armEgressAuth never registers onAuthRequired" };
  }
  const preamble = egressSrc.slice(bodyStart, register);
  if (/\bawait\b/.test(preamble)) {
    return { ok: false, why: "armEgressAuth awaits before it registers, so the listener is late" };
  }

  // A call at column 0 is a statement of the module body. One indented is
  // inside something, and something is always reached later than now.
  const call = /^armEgressAuth\(\);$/m.exec(indexSrc);
  if (!call) {
    return { ok: false, why: "nothing calls armEgressAuth at the top level of the worker" };
  }
  if (/^await\b/m.test(indexSrc.slice(0, call.index))) {
    return { ok: false, why: "a top-level await precedes the call, which defers it past the first turn" };
  }
  return OK;
}

const egressSrc = readFileSync(join(ROOT, "src/background/egress.ts"), "utf8");
const indexSrc = readFileSync(join(ROOT, "src/background/index.ts"), "utf8");

test("the proxy auth answer is armed in the worker's first turn", () => {
  const v = armedInFirstTurn(egressSrc, indexSrc);
  expect(v.why).toBe("");
  expect(v.ok).toBe(true);
});

test("the check can fail: each planted regression is caught", () => {
  // The one that shipped: arming moved behind a storage read.
  const late = egressSrc.replace(
    "  const attempts = new Map<string, number>();",
    "  const attempts = new Map<string, number>();\n  const s = await getStored();\n  if (!s.on) return;",
  );
  expect(armedInFirstTurn(late, indexSrc).ok).toBe(false);

  // Declared async, which defers registration whatever the body does.
  const asyncFn = egressSrc.replace("export function armEgressAuth", "export async function armEgressAuth");
  expect(armedInFirstTurn(asyncFn, indexSrc).ok).toBe(false);

  // Armed only from the enable path, never at startup.
  const uncalled = indexSrc.replace(/^armEgressAuth\(\);$/m, "// armEgressAuth();");
  expect(armedInFirstTurn(egressSrc, uncalled).ok).toBe(false);

  // A top-level await ahead of it pushes the whole module body out of the
  // first turn, so the call is top-level and still too late.
  const deferred = indexSrc.replace(/^armEgressAuth\(\);$/m, "await Promise.resolve();\narmEgressAuth();");
  expect(armedInFirstTurn(egressSrc, deferred).ok).toBe(false);

  // And it still passes what actually ships.
  expect(armedInFirstTurn(egressSrc, indexSrc).ok).toBe(true);
});

test("the shipped bundle registers with no await, when a build is present", () => {
  const bundle = join(ROOT, "dist/chromium/background.js");
  test.skip(!existsSync(bundle), "no chromium build in dist; run npm run build:chromium");
  const built = readFileSync(bundle, "utf8");

  const decl = /\n(async\s+)?function armEgressAuth\s*\(/.exec(built);
  expect(decl, "armEgressAuth is not in the bundle").not.toBeNull();
  expect(decl?.[1], "armEgressAuth is async in the bundle").toBeUndefined();

  const register = built.indexOf("onAuthRequired.addListener", (decl as RegExpExecArray).index);
  expect(register).toBeGreaterThan(-1);
  const preamble = built.slice((decl as RegExpExecArray).index, register);
  expect(/\bawait\b/.test(preamble), "the bundle awaits before registering").toBe(false);

  // Bundled, the top-level call is still a statement of the module body.
  expect(/^armEgressAuth\(\);$/m.test(built), "the bundle never arms at the top level").toBe(true);
  const callAt = built.search(/^armEgressAuth\(\);$/m);
  expect(/^await\b/m.test(built.slice(0, callAt)), "a top-level await precedes it").toBe(false);
});
