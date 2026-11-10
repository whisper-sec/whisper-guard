// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The Firefox route decision, driven for real and hermetically: the REAL
// src/background/egress.ts is bundled with esbuild exactly as the Firefox build
// does (__FIREFOX__ = true), loaded under a fake `browser` (storage, a captured
// proxy.onRequest listener, a dns.resolve spy), and the listener it registers
// is called the way Firefox calls it. No browser, no network: this is the only
// proof of Firefox's per-request decision that runs in CI (the web-ext gate
// proves the install, not the decision).

import { test, expect } from "@playwright/test";
import { build } from "esbuild";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(HERE, "../src/background/egress.ts");

interface Answer {
  type: string;
  host?: string;
  port?: number;
  proxyAuthorizationHeader?: string;
}
type Listener = (details: { url: string }) => Promise<Answer>;

interface Harness {
  ask: (url: string) => Promise<Answer>;
  /** Every name dns.resolve was asked for, and the flags it was given. */
  lookups: Array<{ name: string; flags: unknown }>;
  store: { egress: { on: boolean; config: Record<string, unknown> | null } };
  /** What dns.resolve does next. */
  dns: (name: string) => Promise<{ addresses: string[] }>;
}

const CONFIG = { scheme: "https", host: "egress.example", port: 443, username: "w", token: "tok-1" };
const g = globalThis as Record<string, unknown>;

async function load(outPath: string): Promise<Harness> {
  const outfile = join(outPath, "egress-ff.mjs");
  await build({
    entryPoints: [ENTRY],
    bundle: true,
    format: "esm",
    platform: "node",
    outfile,
    define: { __FIREFOX__: "true" },
    logLevel: "silent",
  });

  const store = {
    egress: { on: true, identity: null as unknown, config: { ...CONFIG } as Record<string, unknown> | null, error: null as unknown },
  };
  const lookups: Harness["lookups"] = [];
  const h = { dns: (async () => ({ addresses: [] })) as Harness["dns"] };
  const storage = {
    local: {
      get: async (k: string) => ({ [k]: structuredClone((store as Record<string, unknown>)[k]) }),
      set: async () => undefined,
    },
  };
  let listener: Listener | null = null;
  g["chrome"] = { storage, runtime: {} };
  g["browser"] = {
    storage,
    runtime: { getBrowserInfo: () => undefined },
    proxy: { onRequest: { addListener: (cb: Listener) => (listener = cb) } },
    dns: {
      // Called with exactly what the code passes: no flags.
      resolve: (name: string, ...rest: unknown[]) => {
        lookups.push({ name, flags: rest.length ? rest[0] : undefined });
        return h.dns(name);
      },
    },
  };
  const mod = (await import(pathToFileURL(outfile).href)) as { armEgressRouting: () => void };
  mod.armEgressRouting();
  if (!listener) throw new Error("the proxy.onRequest listener was not installed");
  const fire = listener as Listener;
  return {
    ask: (url) => fire({ url }),
    lookups,
    store: store as Harness["store"],
    get dns() {
      return h.dns;
    },
    set dns(fn) {
      h.dns = fn;
    },
  };
}

test.afterEach(() => {
  delete g["chrome"];
  delete g["browser"];
});

const answers = (...addresses: string[]) => async () => ({ addresses });
// A bound on waiting for a condition, not a sleep standing in for one: the
// await it races returns the moment the condition holds, and only a lookup that
// never starts turns into this failure instead of a hung test.
const giveUpAfter = (ms: number, what: string) =>
  new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error(what)), ms).unref();
  });
const ROUTED = (a: Answer) => a.type === "https" && a.host === "egress.example" && a.port === 443;

test("routing off: every request is direct and nothing is looked up", async ({}, testInfo) => {
  const f = await load(testInfo.outputPath());
  f.store.egress.on = false;
  f.dns = answers("203.0.113.9");
  for (const url of ["https://box.t.ts.net/", "https://example.com/", "http://192.168.1.1/"]) {
    expect((await f.ask(url)).type, url).toBe("direct");
  }
  expect(f.lookups).toEqual([]);
});

test("a ts.net name that resolves into the tailnet goes direct; the lookup carries no flags", async ({}, testInfo) => {
  const f = await load(testInfo.outputPath());
  for (const addr of ["100.64.0.7", "fd7a:115c:a1e0::7"]) {
    f.lookups.length = 0;
    f.dns = answers(addr);
    expect((await f.ask("https://box.t.ts.net:8443/")).type, addr).toBe("direct");
    expect(f.lookups).toEqual([{ name: "box.t.ts.net", flags: undefined }]);
  }
});

test("a Funnel host, a mixed answer, NXDOMAIN and a hung lookup all stay routed, within a time budget", async ({}, testInfo) => {
  const f = await load(testInfo.outputPath());

  f.dns = answers("203.0.113.9");
  expect(ROUTED(await f.ask("https://funnel.other.ts.net/")), "public Funnel answer").toBe(true);

  f.dns = answers("100.64.0.7", "203.0.113.9");
  expect(ROUTED(await f.ask("https://mixed.other.ts.net/")), "mixed answer").toBe(true);

  f.dns = async () => {
    throw new Error("NS_ERROR_UNKNOWN_HOST");
  };
  expect(ROUTED(await f.ask("https://gone.other.ts.net/")), "NXDOMAIN").toBe(true);

  f.dns = answers();
  expect(ROUTED(await f.ask("https://empty.other.ts.net/")), "no answer").toBe(true);

  // A lookup that never answers must not hold the request forever: the bound is
  // 1500 ms, and the request then takes the route.
  f.dns = () => new Promise(() => undefined);
  const started = Date.now();
  let giveUp: ReturnType<typeof setTimeout> | undefined;
  const hung = await Promise.race([
    f.ask("https://hung.other.ts.net/"),
    new Promise<Answer>((resolve) => {
      giveUp = setTimeout(() => resolve({ type: "STILL PENDING" }), 4000);
    }),
  ]);
  clearTimeout(giveUp);
  const took = Date.now() - started;
  expect(ROUTED(hung), "hung lookup").toBe(true);
  expect(took, `settled in ${took} ms`).toBeLessThan(4000);
  expect(took, `waited for the bound (${took} ms)`).toBeGreaterThanOrEqual(1000);
});

test("literals, intranet names and IPv6 literals go direct with no lookup; public names are routed with no lookup", async ({}, testInfo) => {
  const f = await load(testInfo.outputPath());
  f.dns = answers("100.64.0.7");
  for (const url of [
    "http://192.168.1.1:8080/",
    "http://10.0.0.5/",
    "http://100.64.0.1/",
    "http://printer.local:631/",
    "http://intranet/",
    "http://nas.home.arpa/",
    "http://[fd00::1]:3000/",
    "http://[::1]/",
    "ws://intranet:9000/socket",
  ]) {
    expect((await f.ask(url)).type, url).toBe("direct");
  }
  for (const url of ["https://example.com/", "http://8.8.8.8/", "http://172.32.0.1/", "wss://example.com/socket", "not a url"]) {
    expect(ROUTED(await f.ask(url)), url).toBe(true);
  }
  expect(f.lookups, "only a *.ts.net name is ever looked up").toEqual([]);
});

test("the routed answer carries the credential and is built from the config at the moment of the decision", async ({}, testInfo) => {
  const f = await load(testInfo.outputPath());
  const routed = await f.ask("https://example.com/");
  expect(routed.proxyAuthorizationHeader).toBe(`Basic ${Buffer.from("w:tok-1").toString("base64")}`);

  // The token is refreshed while a lookup is in flight: the new one is used.
  let release: (() => void) | undefined;
  let started: () => void = () => undefined;
  const lookupStarted = new Promise<void>((r) => (started = r));
  f.dns = () =>
    new Promise((resolve) => {
      release = () => resolve({ addresses: ["203.0.113.9"] });
      started();
    });
  const pending = f.ask("https://funnel.other.ts.net/");
  await Promise.race([lookupStarted, giveUpAfter(2000, "no lookup was made")]);
  f.store.egress.config = { ...CONFIG, token: "tok-2" };
  release!();
  const answer = await pending;
  expect(ROUTED(answer)).toBe(true);
  expect(answer.proxyAuthorizationHeader).toBe(`Basic ${Buffer.from("w:tok-2").toString("base64")}`);
});

test("routing turned off while a lookup is in flight: the request goes direct, not through the route", async ({}, testInfo) => {
  const f = await load(testInfo.outputPath());
  let release: (() => void) | undefined;
  let started: () => void = () => undefined;
  const lookupStarted = new Promise<void>((r) => (started = r));
  f.dns = () =>
    new Promise((resolve) => {
      release = () => resolve({ addresses: ["198.51.100.4"] });
      started();
    });
  const pending = f.ask("https://funnel.other.ts.net/");
  await Promise.race([lookupStarted, giveUpAfter(2000, "no lookup was made")]);
  f.store.egress.on = false; // the user turns routing off meanwhile
  release!();
  expect((await pending).type).toBe("direct");
});
