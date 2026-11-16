// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Harness for the page-side halves of the stale-check guards, which the
// background's own "is this check still current" test normally hides:
//
//   - makeShieldProbeDist(): a shield dist that also carries the real
//     src/background/shield.ts as a standalone module, so a test can run the
//     real redirect for one host against a tab that shows another, without the
//     background check in front of it.
//   - the call spy: wraps the service worker's own chrome.scripting.executeScript
//     and chrome.tabs.sendMessage, logs every call and its settlement, and can
//     hold one call open until the test lets it go. That keeps a check
//     suspended at a chosen step while the tab moves on, with no sleep and no
//     change to product code.

import { build } from "esbuild";
import { resolve } from "node:path";
import { makeShieldDist, DIST_CHROMIUM, type Extension } from "./extension";

const ROOT = resolve(DIST_CHROMIUM, "../..");

/** The module file name inside the probe dist. */
export const SHIELD_PROBE_FILE = "shield-probe.js";

/** A shield dist plus the real shield module bundled as an importable ES module. */
export async function makeShieldProbeDist(): Promise<string> {
  const dir = makeShieldDist();
  await build({
    entryPoints: [resolve(ROOT, "src/background/shield.ts")],
    outfile: resolve(dir, SHIELD_PROBE_FILE),
    bundle: true,
    minify: false,
    sourcemap: false,
    target: ["es2022"],
    platform: "browser",
    logLevel: "warning",
    format: "esm",
    define: { __FIREFOX__: "false" },
  });
  return dir;
}

// ------------------------------------------------------------------ call spy

export interface SpyEntry {
  n: number;
  ev: "call" | "held" | "settled" | "committed";
  /** What was called, e.g. "exec content.js top", "msg whisper-preempt-config". */
  label: string;
  tabId: number;
  frameId: number | null;
}

export interface SpyMatch {
  /** Substring of the label the held call must carry. */
  label: string;
  tabId?: number;
}

/**
 * Install the spy in the worker. It records, per call, a "call" entry, a
 * "settled" entry (resolved or rejected) and, for webNavigation commits, a
 * "committed" entry registered AFTER the product's own listener, so seeing it
 * means the product's handler for the same event has already run.
 */
export async function installCallSpy(ext: Extension): Promise<void> {
  await ext.sw.evaluate(() => {
    type Holds = { label: string; tabId?: number; gate: Promise<void>; open: () => void; taken: boolean };
    const g = globalThis as unknown as {
      __spy?: {
        log: unknown[];
        holds: Holds[];
        restore: () => void;
      };
    };
    if (g.__spy) g.__spy.restore();

    const log: unknown[] = [];
    const holds: Holds[] = [];
    let n = 0;
    const push = (ev: string, label: string, tabId: number, frameId: number | null): void => {
      log.push({ n: ++n, ev, label, tabId, frameId });
    };

    const scripting = chrome.scripting as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const tabsApi = chrome.tabs as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const origExec = scripting["executeScript"]!;
    const origMsg = tabsApi["sendMessage"]!;

    const wrap = (
      orig: (...a: unknown[]) => Promise<unknown>,
      self: unknown,
      label: string,
      tabId: number,
      frameId: number | null,
      args: unknown[],
    ): Promise<unknown> => {
      const run = async (): Promise<unknown> => {
        push("call", label, tabId, frameId);
        const hold = holds.find((h) => !h.taken && label.includes(h.label) && (h.tabId === undefined || h.tabId === tabId));
        if (hold) {
          hold.taken = true;
          push("held", label, tabId, frameId);
          await hold.gate;
        }
        try {
          return await orig.apply(self, args);
        } finally {
          push("settled", label, tabId, frameId);
        }
      };
      return run();
    };

    scripting["executeScript"] = function (this: unknown, ...args: unknown[]): Promise<unknown> {
      const inj = args[0] as {
        target: { tabId: number; allFrames?: boolean; frameIds?: number[] };
        files?: string[];
        func?: unknown;
      };
      const where = inj.target.allFrames
        ? "all"
        : inj.target.frameIds
          ? `frame ${inj.target.frameIds.join(",")}`
          : "top";
      const what = inj.files ? inj.files.join(",") : "func";
      return wrap(origExec, scripting, `exec ${what} ${where}`, inj.target.tabId, null, args);
    };
    tabsApi["sendMessage"] = function (this: unknown, ...args: unknown[]): Promise<unknown> {
      const tabId = args[0] as number;
      const msg = args[1] as { kind?: string } | undefined;
      const opts = args[2] as { frameId?: number } | undefined;
      return wrap(origMsg, tabsApi, `msg ${msg?.kind ?? "?"}`, tabId, opts?.frameId ?? null, args);
    };

    const onCommitted = (d: { tabId: number; frameId: number; url: string }): void => {
      push("committed", `${d.frameId === 0 ? "main" : "sub"} ${d.url}`, d.tabId, d.frameId);
    };
    chrome.webNavigation.onCommitted.addListener(onCommitted);

    g.__spy = {
      log,
      holds,
      restore: () => {
        scripting["executeScript"] = origExec;
        tabsApi["sendMessage"] = origMsg;
        chrome.webNavigation.onCommitted.removeListener(onCommitted);
        for (const h of holds) h.open();
        delete g.__spy;
      },
    };
  });
}

/** Make the next call whose label contains `match.label` wait until released. */
export async function holdNextCall(ext: Extension, match: SpyMatch): Promise<void> {
  await ext.sw.evaluate((m: SpyMatch) => {
    const spy = (globalThis as unknown as { __spy: { holds: unknown[] } }).__spy;
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    spy.holds.push({ ...m, gate, open, taken: false });
  }, match);
}

/** Let every held call go. */
export async function releaseHeldCalls(ext: Extension): Promise<void> {
  await ext.sw.evaluate(() => {
    const spy = (globalThis as unknown as { __spy: { holds: { open: () => void }[] } }).__spy;
    for (const h of spy.holds) h.open();
  });
}

export async function spyLog(ext: Extension): Promise<SpyEntry[]> {
  return ext.sw.evaluate(
    () => [...(globalThis as unknown as { __spy: { log: unknown[] } }).__spy.log] as SpyEntry[],
  );
}

/** Take the spy down (restores the real functions and lets any held call go). */
export async function removeCallSpy(ext: Extension): Promise<void> {
  await ext.sw.evaluate(() => {
    (globalThis as unknown as { __spy?: { restore: () => void } }).__spy?.restore();
  });
}

/** Poll the spy log until an entry matches; returns that entry. */
export async function waitForSpyEntry(
  ext: Extension,
  pred: (e: SpyEntry) => boolean,
  what: string,
  timeoutMs = 10_000,
): Promise<SpyEntry> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const hit = (await spyLog(ext)).find(pred);
    if (hit) return hit;
    if (Date.now() > deadline) throw new Error(`never saw: ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}
