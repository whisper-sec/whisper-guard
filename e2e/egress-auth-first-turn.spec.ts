// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THIS PLATFORM'S EGRESS HOOK MUST BE ARMED IN THE WORKER'S FIRST TURN.
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
// FIREFOX FAILS THE OTHER WAY, AND MORE QUIETLY (#30). It has no persisted
// proxy setting, so it cannot come back already routed; instead its
// proxy.onRequest handler decides the route for every request, and until that
// handler is registered there is nobody to ask, so the request goes DIRECT.
// Chromium's lateness asks the human for a password. Firefox's lateness
// leaks the route: traffic leaves without the identity it exists to carry,
// and nothing anywhere says so. Both hooks are therefore armed from one call
// in the module body, and both are checked here.
//
// The check is only worth having if it can fail, so it is mutation tested
// below against the planted regressions, including the precise one that
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
/** No `await` between a function's opening brace and its addListener call. */
function registersWithoutAwaiting(src: string, fnName: string, event: string): Verdict {
  const decl = new RegExp(`(?:^|\\n)(?:export\\s+)?(async\\s+)?function ${fnName}\\s*\\(`).exec(src);
  if (!decl) return { ok: false, why: `egress.ts declares no ${fnName}` };
  if (decl[1]) return { ok: false, why: `${fnName} is async, so it cannot register in the first turn` };

  const bodyStart = decl.index + decl[0].length;
  const register = src.indexOf(event, bodyStart);
  if (register === -1) return { ok: false, why: `${fnName} never registers ${event}` };
  if (/\bawait\b/.test(src.slice(bodyStart, register))) {
    return { ok: false, why: `${fnName} awaits before it registers ${event}, so the listener is late` };
  }
  return OK;
}

/**
 * Does the arming survive a restart? Three things have to hold: the one entry
 * point must reach each platform's hook without awaiting, each hook must
 * reach addListener without awaiting, and something must call the entry point
 * at the top level of the worker before anything else awaits.
 */
function armedInFirstTurn(egressSrc: string, indexSrc: string): Verdict {
  const entry = registersWithoutAwaiting(egressSrc, "armEgressRouting", "installChromiumAuthListener");
  if (!entry.ok) return entry;
  if (!/function armEgressRouting\([^)]*\)\s*:\s*void\s*\{[\s\S]{0,400}?installFirefoxProxy\(\)/.test(egressSrc)) {
    return { ok: false, why: "armEgressRouting never reaches the Firefox hook, so Firefox arms late (#30)" };
  }

  /* Chromium answers a challenge; Firefox answers a routing question. */
  const chromium = registersWithoutAwaiting(egressSrc, "installChromiumAuthListener", "onAuthRequired.addListener");
  if (!chromium.ok) return chromium;
  const firefox = registersWithoutAwaiting(egressSrc, "installFirefoxProxy", "onRequest.addListener");
  if (!firefox.ok) return firefox;

  // A call at column 0 is a statement of the module body. One indented is
  // inside something, and something is always reached later than now.
  const call = /^armEgressRouting\(\);$/m.exec(indexSrc);
  if (!call) {
    return { ok: false, why: "nothing calls armEgressRouting at the top level of the worker" };
  }
  if (/^await\b/m.test(indexSrc.slice(0, call.index))) {
    return { ok: false, why: "a top-level await precedes the call, which defers it past the first turn" };
  }
  return OK;
}

const egressSrc = readFileSync(join(ROOT, "src/background/egress.ts"), "utf8");
const indexSrc = readFileSync(join(ROOT, "src/background/index.ts"), "utf8");

test("this platform's egress hook is armed in the worker's first turn", () => {
  const v = armedInFirstTurn(egressSrc, indexSrc);
  expect(v.why).toBe("");
  expect(v.ok).toBe(true);
});

test("the check can fail: each planted regression is caught", () => {
  // The one that shipped on Chromium: arming moved behind a storage read.
  const late = egressSrc.replace(
    "  const attempts = new Map<string, number>();",
    "  const attempts = new Map<string, number>();\n  const s = await getStored();\n  if (!s.on) return;",
  );
  expect(armedInFirstTurn(late, indexSrc).ok).toBe(false);

  // #30, the quiet one: Firefox's route handler registered after a read.
  const ffLate = egressSrc.replace(
    "  const proxyApi = (globalThis as { browser?: { proxy?: FirefoxProxyApi } }).browser?.proxy;",
    "  const s = await getStored();\n  const proxyApi = (globalThis as { browser?: { proxy?: FirefoxProxyApi } }).browser?.proxy;",
  );
  expect(armedInFirstTurn(ffLate, indexSrc).ok).toBe(false);

  // Firefox dropped from the entry point, so only Chromium is armed early.
  const ffDropped = egressSrc.replace("    installFirefoxProxy();\n    return;", "    return;");
  expect(armedInFirstTurn(ffDropped, indexSrc).ok).toBe(false);

  // Declared async, which defers registration whatever the body does.
  const asyncFn = egressSrc.replace(
    "export function armEgressRouting",
    "export async function armEgressRouting",
  );
  expect(armedInFirstTurn(asyncFn, indexSrc).ok).toBe(false);

  // Armed only from the enable path, never at startup.
  const uncalled = indexSrc.replace(/^armEgressRouting\(\);$/m, "// armEgressRouting();");
  expect(armedInFirstTurn(egressSrc, uncalled).ok).toBe(false);

  // A top-level await ahead of it pushes the whole module body out of the
  // first turn, so the call is top-level and still too late.
  const deferred = indexSrc.replace(
    /^armEgressRouting\(\);$/m,
    "await Promise.resolve();\narmEgressRouting();",
  );
  expect(armedInFirstTurn(egressSrc, deferred).ok).toBe(false);

  // And it still passes what actually ships.
  expect(armedInFirstTurn(egressSrc, indexSrc).ok).toBe(true);
});

test("the shipped bundle registers with no await, when a build is present", () => {
  const bundle = join(ROOT, "dist/chromium/background.js");
  test.skip(!existsSync(bundle), "no chromium build in dist; run npm run build:chromium");
  const built = readFileSync(bundle, "utf8");

  const decl = /\n(async\s+)?function installChromiumAuthListener\s*\(/.exec(built);
  expect(decl, "the Chromium auth listener is not in the bundle").not.toBeNull();
  expect(decl?.[1], "the Chromium auth listener is async in the bundle").toBeUndefined();

  const register = built.indexOf("onAuthRequired.addListener", (decl as RegExpExecArray).index);
  expect(register).toBeGreaterThan(-1);
  const preamble = built.slice((decl as RegExpExecArray).index, register);
  expect(/\bawait\b/.test(preamble), "the bundle awaits before registering").toBe(false);

  // Bundled, the top-level call is still a statement of the module body.
  expect(/^armEgressRouting\(\);$/m.test(built), "the bundle never arms at the top level").toBe(true);
  const callAt = built.search(/^armEgressRouting\(\);$/m);
  expect(/^await\b/m.test(built.slice(0, callAt)), "a top-level await precedes it").toBe(false);
});
