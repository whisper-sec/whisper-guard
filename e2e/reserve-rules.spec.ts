// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The rules of the address reservation, fast: the REAL src/background/egress.ts
// (bundled as each build does) under a fake browser, with only the control
// plane replaced. The reservation's own timers (its two waits and the deadline
// of one try) are recorded and let through at once instead of waited out; no
// other timer is touched. What is proved here: one registration per
// reservation, with every later try only re-reading the account; which
// failures are tried again and which are final; the waits between tries; the
// hard deadline of a try; and that only one reservation runs at a time. The browser tests in reserve-retry.spec.ts prove the same flow
// end to end.

import { test, expect } from "@playwright/test";
import { build } from "esbuild";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const g = globalThis as Record<string, unknown>;

type Row = Record<string, unknown>;
type Handler = (args: Row) => Promise<{ columns: string[]; rows: Row[] }>;

const LABEL = "This browser (Whisper Guard)";
const ADDRESS = "2001:db8::77";
/** A listed row: always an address and the state active. */
const LISTED: Row = { item: { label: LABEL, state: "active", agent: "ag-1", address: ADDRESS } };
/** What the service answers to a registration: the address, never the device's id. */
const REGISTERED = { columns: ["address", "label"], rows: [{ address: ADDRESS, label: LABEL }] as Row[] };
const none = { columns: [], rows: [] as Row[] };
const roster = (rows: Row[]) => ({ columns: [], rows });

const GRAPH_CLIENT = join(HERE, "../src/background/graph-client.ts");
const CONTROL_STUB = `
import { GraphError } from ${JSON.stringify(GRAPH_CLIENT)};
export { GraphError };
export class ControlError extends Error {
  constructor(status, message, retryAfter = null, code = null, retryable = null) {
    super(message); this.status = status; this.retryAfter = retryAfter; this.code = code; this.retryable = retryable;
  }
}
globalThis.__errors = { GraphError, ControlError };
export async function controlCall(op, args) {
  const h = globalThis.__control?.[op];
  if (!h) throw new ControlError(0, "no stub for " + op);
  return h(args);
}
`;
const RDAP_STUB = `
export const rdapIpUrl = (ip) => "https://rdap.example/ip/" + ip;
export async function verifyIdentity() { return null; }
`;

let loads = 0;

interface Mod {
  enrollBrowser: () => Promise<{ address: string }>;
  egressStatus: () => Promise<{ reserving: { attempt: number; of: number } | null; reserveFailed: boolean; enrolled: boolean }>;
  egressEnable: () => Promise<{ on: boolean }>;
  ReservationExhausted: new () => Error;
  forgetReserveFailure: () => void;
}

async function load(outPath: string, control: Record<string, Handler>, stored?: Record<string, unknown>) {
  const dir = join(outPath, `load-${loads++}`);
  mkdirSync(dir, { recursive: true });
  const stub = join(dir, "control-stub.mjs");
  const rdap = join(dir, "rdap-stub.mjs");
  writeFileSync(stub, CONTROL_STUB);
  writeFileSync(rdap, RDAP_STUB);
  const outfile = join(dir, "egress.mjs");
  await build({
    entryPoints: [join(HERE, "../src/background/egress.ts")],
    bundle: true,
    format: "esm",
    platform: "node",
    outfile,
    define: { __FIREFOX__: "false" },
    logLevel: "silent",
    plugins: [
      {
        name: "stubs",
        setup(b) {
          b.onResolve({ filter: /^\.\/control$/ }, () => ({ path: stub }));
          b.onResolve({ filter: /^\.\/rdap$/ }, () => ({ path: rdap }));
        },
      },
    ],
  });
  const state: Record<string, unknown> = stored ? { egress: stored } : {};
  g["__control"] = control;
  g["chrome"] = {
    storage: {
      local: {
        get: async (k: string) => ({ [k]: structuredClone(state[k]) }),
        set: async (patch: Record<string, unknown>) => Object.assign(state, structuredClone(patch)),
      },
    },
    runtime: {},
    permissions: { contains: async () => true },
    extension: { isAllowedIncognitoAccess: async () => false },
    proxy: {
      settings: {
        get: (_d: unknown, cb: (r: unknown) => void) => cb({ levelOfControl: "controllable_by_this_extension" }),
        set: async () => undefined,
        clear: async () => undefined,
      },
    },
    privacy: { network: { webRTCIPHandlingPolicy: { set: async () => undefined, clear: async () => undefined } } },
  };
  const mod = (await import(pathToFileURL(outfile).href)) as Mod;
  return { mod, state };
}

/**
 * Let the reservation's own timers through at once and record them. `waits`
 * is the two waits between tries; the module-level `deadlines` collects the
 * per-try deadlines, which only fire at once when `fireDeadlines` is set.
 */
let deadlines: number[] = [];
function recordTimers(fireDeadlines = false): number[] {
  const waits: number[] = [];
  deadlines = [];
  const real = globalThis.setTimeout;
  g["__realSetTimeout"] = real;
  g["setTimeout"] = ((fn: () => void, ms?: number, ...rest: unknown[]) => {
    if (ms === 2000 || ms === 4000) {
      waits.push(ms);
      return real(fn, 0);
    }
    if (ms === 45000) {
      deadlines.push(ms);
      return fireDeadlines ? real(fn, 0) : real(fn, ms, ...rest);
    }
    return real(fn, ms, ...rest);
  }) as unknown;
  return waits;
}
const restoreTimers = (): void => {
  if (g["__realSetTimeout"]) g["setTimeout"] = g["__realSetTimeout"];
};

test.afterEach(() => {
  restoreTimers();
  delete g["__realSetTimeout"];
  delete g["chrome"];
  delete g["__control"];
});

interface ErrorClasses {
  GraphError: new (r: string, m: string) => Error;
  ControlError: new (status: number, m: string, retryAfter?: number | null, code?: string | null, retryable?: boolean | null) => Error;
}
/** The error classes of the bundle just loaded: the very ones egress.ts tests against. */
const classes = (): ErrorClasses => g["__errors"] as ErrorClasses;

/** A roster that shows this browser's device from the n-th read on (1 = the first read). */
function rosterFromRead(n: number): { reads: () => number; list: Handler } {
  let reads = 0;
  return { reads: () => reads, list: async () => roster(++reads >= n ? [LISTED] : []) };
}

test("one registration, then the account is read again at once: the usual enrolment ends on try 1 with no wait", async ({}, testInfo) => {
  let registers = 0;
  const r = rosterFromRead(2); // the first read is before the registration
  const { mod } = await load(testInfo.outputPath(), { list: r.list, register: async () => (registers++, REGISTERED) });
  const waits = recordTimers();
  const enrollment = await mod.enrollBrowser();
  expect(enrollment.address).toBe(ADDRESS);
  expect(registers).toBe(1);
  expect(r.reads(), "one read before the registration, one right after it").toBe(2);
  expect(waits, "no wait at all").toEqual([]);
  expect((await mod.egressStatus()).reserveFailed).toBe(false);
});

test("the device listed on the second try or the third: still one registration, the waits are 2 s then 4 s", async ({}, testInfo) => {
  for (const [from, expected] of [
    [3, [2000]],
    [4, [2000, 4000]],
  ] as const) {
    let registers = 0;
    const r = rosterFromRead(from);
    const { mod } = await load(testInfo.outputPath(), { list: r.list, register: async () => (registers++, REGISTERED) });
    const waits = recordTimers();
    const enrollment = await mod.enrollBrowser();
    expect(enrollment.address).toBe(ADDRESS);
    expect(registers, `listed from read ${from}`).toBe(1);
    expect(waits, `listed from read ${from}`).toEqual(expected);
    restoreTimers();
  }
});

test("three tries with the device never listed: one registration, 2 s and 4 s waits, a typed failure and a status that says so", async ({}, testInfo) => {
  let registers = 0;
  let lists = 0;
  const { mod } = await load(testInfo.outputPath(), {
    list: async () => (lists++, none),
    register: async () => (registers++, REGISTERED),
  });
  const waits = recordTimers();
  await expect(mod.enrollBrowser()).rejects.toBeInstanceOf(mod.ReservationExhausted);
  expect(registers, "never a second registration in the same reservation").toBe(1);
  expect(lists, "read before, right after, and on each later try").toBe(4);
  expect(waits).toEqual([2000, 4000]);
  const status = await mod.egressStatus();
  expect(status.reserveFailed).toBe(true);
  expect(status.reserving).toBe(null);
  expect(status.enrolled).toBe(false);
});

test("the address in the registration answer must match the listed device", async ({}, testInfo) => {
  let reads = 0;
  const { mod } = await load(testInfo.outputPath(), {
    list: async () => {
      // Only the read right after the registration is address-checked.
      reads++;
      return reads === 2 ? roster([{ item: { label: LABEL, state: "active", agent: "ag-9", address: "2001:db8::99" } }]) : none;
    },
    register: async () => REGISTERED,
  });
  recordTimers();
  await expect(mod.enrollBrowser()).rejects.toBeInstanceOf(mod.ReservationExhausted);
});

test("the status names the try while it runs", async ({}, testInfo) => {
  const seen: Array<{ attempt: number; of: number } | null> = [];
  let mod!: Mod;
  const r = rosterFromRead(4);
  ({ mod } = await load(testInfo.outputPath(), {
    list: async () => {
      seen.push((await mod.egressStatus()).reserving);
      return r.list({});
    },
    register: async () => REGISTERED,
  }));
  recordTimers();
  await mod.enrollBrowser();
  // before, right after (both try 1), then try 2, then try 3
  expect(seen).toEqual([
    { attempt: 1, of: 3 },
    { attempt: 1, of: 3 },
    { attempt: 2, of: 3 },
    { attempt: 3, of: 3 },
  ]);
});

test("a device already listed without an address is not registered: that try is not ready yet", async ({}, testInfo) => {
  let registers = 0;
  let lists = 0;
  const { mod } = await load(testInfo.outputPath(), {
    list: async () => (lists++, roster([{ item: { label: LABEL, state: "active" } }])),
    register: async () => (registers++, REGISTERED),
  });
  recordTimers();
  await expect(mod.enrollBrowser()).rejects.toBeInstanceOf(mod.ReservationExhausted);
  expect(registers, "the device exists already: never a second one").toBe(0);
  expect(lists, "each try looked at the account").toBe(3);
});

test("after a registration failed in a way worth retrying, later tries only re-read the account", async ({}, testInfo) => {
  const failures: Array<[string, (c: ErrorClasses) => Error]> = [
    ["timeout", (c) => new c.GraphError("timeout", "slow")],
    ["connect", (c) => new c.GraphError("connect", "down")],
    ["server", (c) => new c.GraphError("server", "5xx")],
    ["plane says retryable (a registration in progress)", (c) => new c.ControlError(409, "in progress", null, "REGISTER_IN_PROGRESS", true)],
    ["already registered: the device exists and is not listed yet", (c) => new c.ControlError(409, "exists", null, "ALREADY_REGISTERED", false)],
  ];
  for (const [label, make] of failures) {
    let registers = 0;
    // The first read is before the registration; the device is listed from the next read, on try 2.
    const r = rosterFromRead(2);
    const { mod } = await load(testInfo.outputPath(), {
      list: r.list,
      register: async () => {
        registers++;
        throw make(classes());
      },
    });
    const waits = recordTimers();
    const enrollment = await mod.enrollBrowser();
    expect(enrollment.address, label).toBe(ADDRESS);
    expect(registers, `${label}: never sent again`).toBe(1);
    expect(waits, label).toEqual([2000]);
    restoreTimers();
  }
});

test("any other answer to a registration is final: surfaced at once, one call, no wait", async ({}, testInfo) => {
  const final: Array<[string, (c: ErrorClasses) => Error]> = [
    ["device limit", (c) => new c.ControlError(403, "over the limit", null, "AGENT_LIMIT", false)],
    ["refusal with no flag", (c) => new c.ControlError(409, "conflict")],
    ["status 0 is not a reason to retry", (c) => new c.ControlError(0, "odd")],
    ["signed out", (c) => new c.GraphError("nokey", "sign in")],
    ["rejected key", (c) => new c.GraphError("auth", "bad key")],
    ["quota", (c) => new c.GraphError("quota", "spent")],
    ["malformed answer", (c) => new c.GraphError("parse", "garbled")],
  ];
  for (const [label, make] of final) {
    let registers = 0;
    let thrown: Error | null = null;
    const { mod } = await load(testInfo.outputPath(), {
      list: async () => none,
      register: async () => {
        registers++;
        thrown = make(classes());
        throw thrown;
      },
    });
    const waits = recordTimers();
    const outcome = await mod.enrollBrowser().then(() => null, (e: unknown) => e);
    expect(outcome, `${label}: the very error the plane gave`).toBe(thrown);
    expect(registers, `${label}: one call`).toBe(1);
    expect(waits, `${label}: no wait`).toEqual([]);
    expect((await mod.egressStatus()).reserveFailed, `${label}: not the "all tries used" state`).toBe(false);
    restoreTimers();
  }
});

test("a final error on the account read after a registration is not swallowed", async ({}, testInfo) => {
  for (const [label, failAtRead] of [
    ["right after the registration", 2],
    ["on a later try", 3],
  ] as const) {
    let reads = 0;
    let thrown: Error | null = null;
    const { mod } = await load(testInfo.outputPath(), {
      list: async () => {
        if (++reads === failAtRead) {
          thrown = new (classes().GraphError)("nokey", "signed out between tries");
          throw thrown;
        }
        return none;
      },
      register: async () => REGISTERED,
    });
    recordTimers();
    const outcome = await mod.enrollBrowser().then(() => null, (e: unknown) => e);
    expect(outcome, label).toBe(thrown);
    expect((await mod.egressStatus()).reserveFailed, `${label}: not the "all tries used" state`).toBe(false);
    restoreTimers();
  }
});

test("an account read that fails after a registration went out never leads to a second registration", async ({}, testInfo) => {
  let registers = 0;
  let lists = 0;
  const { mod } = await load(testInfo.outputPath(), {
    list: async () => {
      if (lists++ === 0) return none;
      throw new (classes().GraphError)("connect", "roster unreachable");
    },
    register: async () => (registers++, REGISTERED),
  });
  recordTimers();
  await expect(mod.enrollBrowser()).rejects.toBeInstanceOf(mod.ReservationExhausted);
  expect(registers).toBe(1);
  expect(lists).toBe(4);
});

test("an account read that fails on the very first try still falls through to register", async ({}, testInfo) => {
  let registers = 0;
  const { mod } = await load(testInfo.outputPath(), {
    list: async () => {
      throw new (classes().GraphError)("connect", "roster unreachable");
    },
    register: async () => (registers++, { columns: [], rows: [{ agent: "ag-1", address: ADDRESS }] }),
  });
  recordTimers();
  const enrollment = await mod.enrollBrowser();
  expect(enrollment.address).toBe(ADDRESS);
  expect(registers).toBe(1);
});

test("a call that never settles is a failed try: the reservation always settles, and never registers twice", async ({}, testInfo) => {
  // The registration never answers; the device shows on the list from the third read.
  let registers = 0;
  const r = rosterFromRead(3);
  const { mod } = await load(testInfo.outputPath(), {
    list: r.list,
    register: () => (registers++, new Promise(() => undefined)),
  });
  recordTimers(true);
  const enrollment = await mod.enrollBrowser();
  expect(enrollment.address).toBe(ADDRESS);
  expect(registers).toBe(1);
  expect(deadlines.length, "every try is given a deadline of about 45 s").toBeGreaterThanOrEqual(2);
  restoreTimers();

  // And when nothing is ever listed, it still ends, with the typed failure.
  registers = 0;
  const stuck = await load(testInfo.outputPath(), {
    list: async () => none,
    register: () => (registers++, new Promise(() => undefined)),
  });
  recordTimers(true);
  await expect(stuck.mod.enrollBrowser()).rejects.toBeInstanceOf(stuck.mod.ReservationExhausted);
  expect(registers).toBe(1);
  const status = await stuck.mod.egressStatus();
  expect(status.reserving, "nothing is left running").toBe(null);
  expect(status.reserveFailed).toBe(true);
});

test("a request made while one runs joins it: one registration, one result", async ({}, testInfo) => {
  let registers = 0;
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const r = rosterFromRead(2);
  const { mod } = await load(testInfo.outputPath(), {
    list: r.list,
    register: async () => {
      registers++;
      await gate;
      return REGISTERED;
    },
  });
  const first = mod.enrollBrowser();
  await expect.poll(async () => (await mod.egressStatus()).reserving).toEqual({ attempt: 1, of: 3 });
  const second = mod.enrollBrowser();
  release();
  const [a, b] = await Promise.all([first, second]);
  expect(a.address).toBe(b.address);
  expect(registers).toBe(1);
});

test("with an identity already stored, enabling never reports a reservation and leaves an earlier failure alone", async ({}, testInfo) => {
  const identity = { agent: "ag-1", address: ADDRESS, label: LABEL, fqdn: null };
  const seen: unknown[] = [];
  let mod!: Mod;
  let state!: Record<string, unknown>;
  let registers = 0;
  ({ mod, state } = await load(testInfo.outputPath(), {
    list: async () => none,
    register: async () => (registers++, REGISTERED),
    connect: async () => {
      seen.push((await mod.egressStatus()).reserving);
      return { columns: [], rows: [{ http_proxy: "https://w:tok@egress.example:443" }] };
    },
  }));
  // An earlier reservation used all its tries.
  recordTimers();
  await expect(mod.enrollBrowser()).rejects.toBeInstanceOf(mod.ReservationExhausted);
  expect((await mod.egressStatus()).reserveFailed).toBe(true);
  // The identity is stored later (for example by another surface's adoption).
  state["egress"] = { on: false, identity, config: null, error: null };
  registers = 0;

  const polled: unknown[] = [];
  const watch = setInterval(() => void mod.egressStatus().then((st) => polled.push(st.reserving)), 0);
  const status = await mod.egressEnable();
  clearInterval(watch);
  expect(status.on).toBe(true);
  expect(registers).toBe(0);
  expect(seen).toEqual([null]);
  expect(polled.every((r) => r === null)).toBe(true);
  expect((await mod.egressStatus()).reserveFailed, "returning a stored identity does not clear it").toBe(true);
});

test("a remembered failure can be forgotten, for example on a sign-out", async ({}, testInfo) => {
  const { mod } = await load(testInfo.outputPath(), { list: async () => none, register: async () => REGISTERED });
  recordTimers();
  await expect(mod.enrollBrowser()).rejects.toBeInstanceOf(mod.ReservationExhausted);
  expect((await mod.egressStatus()).reserveFailed).toBe(true);
  mod.forgetReserveFailure();
  expect((await mod.egressStatus()).reserveFailed).toBe(false);
});
