// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The egress endpoint's life cycle, hermetic: the REAL src/background/egress.ts
// (bundled as each build does, Chromium and Firefox) under a fake browser, with
// only the control-plane module stubbed. A stored or provisioned endpoint that
// is not a plain host and port must NEVER reach a PAC directive or a Firefox
// route, and the state must not keep saying Protected over a proxy that was
// never set: routing goes off, the error is honest, and any half-applied
// setting (and the WebRTC policy that rode with it) is cleared.

import { test, expect } from "@playwright/test";
import { build } from "esbuild";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { egressPacScript } from "../src/shared/direct-destinations";

const HERE = dirname(fileURLToPath(import.meta.url));
const g = globalThis as Record<string, unknown>;

type Stored = { on: boolean; identity: unknown; config: Record<string, unknown> | null; error: string | null };
type Row = Record<string, unknown>;

const IDENTITY = { agent: "ag-1", address: "2001:db8::77", label: "This browser (Whisper Guard)", fqdn: null };
const GOOD = { scheme: "https", host: "egress.example", port: 443, username: "w", token: "t" };
const FRESH_ROW: Row = { http_proxy: "https://w:fresh@egress.example:443" };

// The one thing replaced: the control plane. egress.ts itself is real.
const CONTROL_STUB = `
export class ControlError extends Error {
  constructor(status, message, retryAfter = null, code = null, retryable = null) {
    super(message); this.status = status; this.retryAfter = retryAfter; this.code = code; this.retryable = retryable;
  }
}
export async function controlCall(op) {
  const h = globalThis.__control?.[op];
  if (!h) throw new ControlError(0, "no stub for " + op);
  return h();
}
`;

let loads = 0;

async function load(
  outPath: string,
  stored: Stored,
  opts: { firefox?: boolean; connect?: Row; setRejects?: boolean; incognitoAllowed?: boolean } = {},
) {
  const dir = join(outPath, `load-${loads++}`);
  mkdirSync(dir, { recursive: true });
  const stub = join(dir, "control-stub.mjs");
  writeFileSync(stub, CONTROL_STUB);
  const outfile = join(dir, "egress.mjs");
  await build({
    entryPoints: [join(HERE, "../src/background/egress.ts")],
    bundle: true,
    format: "esm",
    platform: "node",
    outfile,
    define: { __FIREFOX__: opts.firefox ? "true" : "false" },
    logLevel: "silent",
    plugins: [
      {
        name: "stub-control",
        setup(b) {
          b.onResolve({ filter: /^\.\/control$/ }, () => ({ path: stub }));
        },
      },
    ],
  });
  const state = { egress: stored };
  const calls = { set: [] as unknown[], clear: [] as unknown[], webrtcSet: 0, webrtcClear: 0, connect: 0 };
  g["__control"] = {
    connect: async () => (calls.connect++, { columns: [], rows: [opts.connect ?? FRESH_ROW] }),
    list: async () => ({ columns: [], rows: [] }),
  };
  const storage = {
    local: {
      get: async (k: string) => ({ [k]: structuredClone((state as Record<string, unknown>)[k]) }),
      set: async (patch: Record<string, unknown>) => Object.assign(state, structuredClone(patch)),
    },
  };
  const api = {
    storage,
    runtime: {},
    permissions: { contains: async () => true },
    extension: { isAllowedIncognitoAccess: async () => opts.incognitoAllowed === true },
    proxy: {
      settings: {
        set: async (v: unknown) => {
          if (opts.setRejects) throw new Error("set refused");
          calls.set.push(v);
        },
        clear: async (v: unknown) => void calls.clear.push(v),
        get: (_d: unknown, cb: (r: unknown) => void) => cb({ levelOfControl: "controllable_by_this_extension" }),
      },
    },
    privacy: {
      network: {
        webRTCIPHandlingPolicy: {
          set: async () => void calls.webrtcSet++,
          clear: async () => void calls.webrtcClear++,
        },
      },
    },
  };
  g["chrome"] = api;
  if (opts.firefox) {
    g["browser"] = {
      ...api,
      runtime: { getBrowserInfo: () => undefined },
      proxy: { onRequest: { addListener: () => undefined } },
    };
  }
  const mod = (await import(pathToFileURL(outfile).href)) as {
    resumeEgress: () => Promise<void>;
    egressEnable: () => Promise<{
      on: boolean;
      error: string | null;
      webrtcHardened: boolean | null;
      privateWindowsRouted: boolean;
    }>;
  };
  return { mod, state, calls };
}

test.afterEach(() => {
  delete g["chrome"];
  delete g["browser"];
  delete g["__control"];
});

const stored = (config: Record<string, unknown> | null, on = true): Stored => ({ on, identity: IDENTITY, config, error: null });

// Endpoints that must never be applied: a second PAC directive, a bad port, and
// a wrong-shape value that a stored config can hold after a bad write.
const BAD_CONFIGS: Array<Record<string, unknown>> = [
  { ...GOOD, host: 'x.example";return "DIRECT' },
  { ...GOOD, host: "a;b" },
  { ...GOOD, port: 0 },
  { ...GOOD, port: 65536 },
  { ...GOOD, port: 1.5 },
  { ...GOOD, host: 12345 },
  { ...GOOD, port: "443" },
  { ...GOOD, host: "egress.1" },
  // A transport the proxy does not take, or none: on Firefox the route would go
  // out as the wrong type, or direct, while the state says Protected.
  { ...GOOD, scheme: "socks5" },
  { ...GOOD, scheme: "" },
  { ...GOOD, scheme: undefined },
  // A Basic credential must be printable ASCII; btoa throws on anything else,
  // which Firefox turns into a direct connection.
  { ...GOOD, token: "t\u00f6k" },
  { ...GOOD, username: "w\u00e9" },
  { ...GOOD, token: 7 },
];

test("resume applies a valid stored endpoint as a MANDATORY PAC script built by the shared generator", async ({}, testInfo) => {
  const { mod, state, calls } = await load(testInfo.outputPath(), stored(GOOD));
  await mod.resumeEgress();
  expect(calls.set).toHaveLength(1);
  const value = (calls.set[0] as { value: { mode: string; pacScript: { data: string; mandatory: boolean } } }).value;
  expect(value.mode).toBe("pac_script");
  expect(value.pacScript.mandatory).toBe(true);
  expect(value.pacScript.data).toBe(egressPacScript({ scheme: "https", host: "egress.example", port: 443 }));
  expect(state.egress.on).toBe(true);
});

test("resume refuses a stored endpoint that could carry a second PAC directive: nothing applied, routing off, setting and WebRTC cleared", async ({}, testInfo) => {
  for (const bad of BAD_CONFIGS) {
    const { mod, state, calls } = await load(testInfo.outputPath(), stored(bad));
    await mod.resumeEgress();
    const label = JSON.stringify(bad);
    expect(calls.set, `no setting applied for ${label}`).toEqual([]);
    expect(calls.clear, `any half-applied setting cleared for ${label}`).toHaveLength(1);
    expect(calls.webrtcClear, `the WebRTC policy that rides the toggle is cleared for ${label}`).toBe(1);
    expect(state.egress.on, `state must not say Protected for ${label}`).toBe(false);
    expect(state.egress.config, "the bad endpoint is forgotten, so the next enable re-provisions").toBe(null);
    expect(state.egress.error, "an honest error is recorded").toContain("not a plain host and port");
  }
});

test("Firefox resume guards too: a stored bad or wrong-shape endpoint turns routing off with an honest error", async ({}, testInfo) => {
  for (const bad of BAD_CONFIGS) {
    const { mod, state, calls } = await load(testInfo.outputPath(), stored(bad), { firefox: true });
    await mod.resumeEgress();
    const label = JSON.stringify(bad);
    expect(state.egress.on, `Firefox must not stay Protected on ${label}`).toBe(false);
    expect(state.egress.config, "the bad endpoint is forgotten").toBe(null);
    expect(state.egress.error, "an honest error is recorded").toContain("not a plain host and port");
    expect(calls.set, "Firefox sets no proxy setting").toEqual([]);
  }
  // CONTROL: a valid stored endpoint is kept on Firefox, so the guard above is not "always off".
  const ok = await load(testInfo.outputPath(), stored(GOOD), { firefox: true });
  await ok.mod.resumeEgress();
  expect(ok.state.egress.on).toBe(true);
  expect(ok.state.egress.config).toEqual(GOOD);
  expect(ok.state.egress.error).toBe(null);
  expect(ok.calls.set, "Firefox sets no proxy setting").toEqual([]);
});

test("resume turns off 'on' with no stored config at all, on both builds", async ({}, testInfo) => {
  for (const firefox of [false, true]) {
    const label = firefox ? "firefox" : "chromium";
    const { mod, state, calls } = await load(testInfo.outputPath(), stored(null, true), { firefox });
    await mod.resumeEgress();
    expect(state.egress.on, `${label}: must not stay Protected with nothing to route through`).toBe(false);
    expect(state.egress.error, `${label}: an honest error`).toContain("not a plain host and port");
    expect(calls.set, `${label}: nothing applied`).toEqual([]);
  }
});

test("enable: the WebRTC status is pinned on Chromium and reported as not pinned on Firefox", async ({}, testInfo) => {
  const chromium = await load(testInfo.outputPath(), stored(null, false));
  // After load(): protect-control reads the browser global when it is first imported.
  const { routeLineText } = await import("../src/shared/protect-control");
  const c = await chromium.mod.egressEnable();
  expect(c.on).toBe(true);
  expect(c.webrtcHardened, "Chromium pins WebRTC to proxied-only").toBe(true);
  expect(chromium.calls.webrtcSet).toBe(1);
  expect(routeLineText(c)).not.toContain("is not pinned");

  const firefox = await load(testInfo.outputPath(), stored(null, false), { firefox: true });
  const f = await firefox.mod.egressEnable();
  expect(f.on).toBe(true);
  expect(f.webrtcHardened, "Firefox does not pin WebRTC, and says so rather than claiming it").toBe(null);
  expect(routeLineText(f)).toContain("is not pinned");
  expect(firefox.calls.webrtcSet).toBe(0);
});

test("status: private windows are reported routed only when Whisper Guard is allowed in them, on both builds", async ({}, testInfo) => {
  // The route line drops its private-window limit only on this value, so a
  // status that claimed "routed" without asking the browser would make the
  // line say every window leaves from the address while private ones do not.
  for (const firefox of [false, true]) {
    for (const allowed of [false, true]) {
      const label = `${firefox ? "firefox" : "chromium"}, allowed in private windows: ${allowed}`;
      const { mod } = await load(testInfo.outputPath(), stored(null, false), { firefox, incognitoAllowed: allowed });
      const { routeLineText } = await import("../src/shared/protect-control");
      const status = await mod.egressEnable();
      expect(status.on, label).toBe(true);
      expect(status.privateWindowsRouted, label).toBe(allowed);
      expect(routeLineText(status).includes("Private windows are not routed"), label).toBe(!allowed);
    }
  }
});

test("enable never reuses a stored bad endpoint: Chromium provisions a fresh one and applies a valid PAC", async ({}, testInfo) => {
  for (const bad of BAD_CONFIGS) {
    const { mod, state, calls } = await load(testInfo.outputPath(), stored(bad, false));
    const status = await mod.egressEnable();
    const label = JSON.stringify(bad);
    expect(calls.connect, `a fresh endpoint was provisioned over ${label}`).toBe(1);
    expect(calls.set, `one PAC applied for ${label}`).toHaveLength(1);
    const data = (calls.set[0] as { value: { pacScript: { data: string } } }).value.pacScript.data;
    expect(data).toBe(egressPacScript({ scheme: "https", host: "egress.example", port: 443 }));
    expect(status.on, label).toBe(true);
    expect(state.egress.on).toBe(true);
    expect((state.egress.config as { token: string }).token, "the stored config is the fresh one").toBe("fresh");
  }
  // CONTROL: a valid stored endpoint IS reused (no provisioning round trip).
  const ok = await load(testInfo.outputPath(), stored(GOOD, false));
  await ok.mod.egressEnable();
  expect(ok.calls.connect).toBe(0);
  expect(ok.calls.set).toHaveLength(1);
});

test("enable never reuses a stored bad endpoint: Firefox turns on only with a freshly provisioned valid one", async ({}, testInfo) => {
  for (const bad of BAD_CONFIGS) {
    const { mod, state, calls } = await load(testInfo.outputPath(), stored(bad, false), { firefox: true });
    const status = await mod.egressEnable();
    const label = JSON.stringify(bad);
    expect(calls.connect, `a fresh endpoint was provisioned over ${label}`).toBe(1);
    expect(status.on, label).toBe(true);
    expect(calls.set, "Firefox sets no proxy setting").toEqual([]);
    expect(state.egress.config, "the stored config is the fresh, valid one").toEqual({
      scheme: "https",
      host: "egress.example",
      port: 443,
      username: "w",
      token: "fresh",
    });
  }
  // And when the fresh one is bad too, Firefox stays OFF rather than going live on the old one.
  const bad = { ...GOOD, host: "a;DIRECT;b" };
  const dead = await load(testInfo.outputPath(), stored(bad, false), {
    firefox: true,
    connect: { http_proxy: "https://w:t@egress.example;DIRECT:443" },
  });
  const status = await dead.mod.egressEnable();
  expect(status.on).toBe(false);
  expect(dead.state.egress.on).toBe(false);
  expect(status.error).toBe("connect returned no egress endpoint");
});

test("a connect reply whose only endpoints are invalid gives 'no egress endpoint' and sets nothing, on both builds", async ({}, testInfo) => {
  const reply: Row = {
    http_proxy: "https://w:tok@egress.example;DIRECT:443",
    https_proxy: "https://w:tok@egress.example:0",
    connection_string: 'socks5h://w:tok@egress."example:1080',
    socks5_endpoint: "socks5h://w:tok@egress.example\n;DIRECT:1080",
  };
  for (const firefox of [false, true]) {
    for (const row of [
      reply,
      { http_proxy: "https://w:tok@egress.example;DIRECT:443" },
      { https_proxy: "https://w:tok@egress.example:0" },
      { http_proxy: 'https://w:tok@egress."example:443' },
      { http_proxy: "https://w:tok@egress.example\n;DIRECT:443" },
      // Percent-encoded credentials decode to non-ASCII, which no Basic
      // credential can carry (btoa throws, and Firefox then goes direct while
      // the state says Protected): refused on the HTTP(S) path and on the
      // SOCKS5 rewrite alike.
      { http_proxy: "https://w:t%C3%B6k@egress.example:443" },
      { http_proxy: "https://w%C3%A9:tok@egress.example:443" },
      { connection_string: "socks5h://w:t%C3%B6k@egress.example:1080" },
    ]) {
      const label = `${firefox ? "firefox" : "chromium"} ${JSON.stringify(row)}`;
      const { mod, state, calls } = await load(testInfo.outputPath(), stored(null, false), { firefox, connect: row });
      const status = await mod.egressEnable();
      expect(status.on, label).toBe(false);
      expect(status.error, label).toBe("connect returned no egress endpoint");
      expect(calls.set, `nothing set for ${label}`).toEqual([]);
      expect(state.egress.config, `nothing stored for ${label}`).toBe(null);
      expect(state.egress.on, label).toBe(false);
    }
  }
});

test("a connect reply whose first endpoint is unusable falls through to a usable SOCKS5 string and provisions that, on both builds", async ({}, testInfo) => {
  // An unusable candidate is skipped, not fatal: the next one the platform
  // returned is tried, as an invalid host already was.
  const row: Row = {
    http_proxy: "https://w:t%C3%B6k@egress.example:443",
    connection_string: "socks5h://w:tok@egress.example:443",
  };
  const expected = { scheme: "https", host: "egress.example", port: 443, username: "w", token: "tok" };
  for (const firefox of [false, true]) {
    const label = firefox ? "firefox" : "chromium";
    const { mod, state, calls } = await load(testInfo.outputPath(), stored(null, false), { firefox, connect: row });
    const status = await mod.egressEnable();
    expect(status.on, label).toBe(true);
    expect(status.error, label).toBe(null);
    expect(state.egress.config, `the rewritten SOCKS5 endpoint is stored for ${label}`).toEqual(expected);
    if (firefox) {
      expect(calls.set, "Firefox sets no proxy setting").toEqual([]);
    } else {
      expect(calls.set).toHaveLength(1);
      const value = (calls.set[0] as { value: { mode: string; pacScript: { data: string; mandatory: boolean } } }).value;
      expect(value.mode).toBe("pac_script");
      expect(value.pacScript.mandatory).toBe(true);
      expect(value.pacScript.data).toBe(egressPacScript({ scheme: "https", host: "egress.example", port: 443 }));
    }
  }
});

test("enable: when proxy.settings.set rejects, the half-applied setting and the WebRTC policy are cleared and routing is off", async ({}, testInfo) => {
  const { mod, state, calls } = await load(testInfo.outputPath(), stored(null, false), { setRejects: true });
  const status = await mod.egressEnable();
  expect(status.on).toBe(false);
  expect(state.egress.on, "state must not say Protected").toBe(false);
  expect(state.egress.error, "an honest error").toContain("set refused");
  expect(calls.clear, "the setting is cleared once").toHaveLength(1);
  expect(calls.webrtcClear, "the WebRTC policy is cleared").toBe(1);
  expect(calls.webrtcSet, "WebRTC was never pinned").toBe(0);
});
