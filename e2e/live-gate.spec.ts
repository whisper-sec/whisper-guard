// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The live gate's own guard, hermetic: no browser, no key, no network.
//
// Three defects kept the release gate from ever running, and each one read
// as something other than a failure:
//   1. a top-level testIgnore dropped e2e/live.spec.ts even when it was named
//      on the command line, so `npm run e2e:live` found no tests;
//   2. the subject came from a download that was retired (HTTP 410), and the
//      suite then SKIPPED every test instead of failing;
//   3. the teardown awaited `localServer?.close(r)` for a server setup never
//      created, a promise that never settles, so the run hung.
// Each test below is written against the defect, not the fix's shape.

import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import * as http from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  closeQuietly,
  graphReader,
  isLiveGate,
  isUsableHost,
  MAX_PAGES_PER_FEED,
  NoLiveSubjectError,
  pickCriticalSubject,
  SUBJECT_FEEDS,
  type GraphRead,
} from "./helpers/live-gate";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * `playwright test --list` with the given args; returns the listed test
 * count. Playwright exits non-zero on "No tests found", which is exactly the
 * outcome these tests look for, so the count is read from its output either way.
 */
function listed(args: string[]): number {
  let out: string;
  try {
    out = execFileSync(process.execPath, [resolve(ROOT, "node_modules/@playwright/test/cli.js"), "test", "--list", ...args], {
      cwd: ROOT,
      // A key in the environment changes nothing about listing, and the gate
      // marker would turn a keyless list into a load error; keep both out.
      env: { ...process.env, WHISPER_GUARD_E2E_KEY: "listing-only", npm_lifecycle_event: "", WHISPER_GUARD_LIVE_GATE: "" },
      encoding: "utf8",
      stdio: "pipe",
    });
  } catch (e) {
    const x = e as { stdout?: string; stderr?: string };
    out = `${x.stdout ?? ""}${x.stderr ?? ""}`;
    if (!/No tests found/.test(out)) throw e;
  }
  const m = /Total: (\d+) tests? in/.exec(out);
  return m ? Number(m[1]) : 0;
}

test.describe("defect 1: the gate's script finds the live spec", () => {
  test("the e2e:live invocation lists the live suite's tests", () => {
    // Exactly the arguments package.json passes, read from it so the test
    // follows the script rather than a copy of it.
    const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")) as { scripts: Record<string, string> };
    const script = pkg.scripts["e2e:live"] ?? "";
    expect(script.startsWith("playwright test ")).toBe(true);
    const n = listed(script.slice("playwright test ".length).split(/\s+/).filter(Boolean));
    expect(n).toBeGreaterThan(0);
  });

  test("the hermetic suite still excludes the live specs", () => {
    expect(listed(["--project=hermetic", "e2e/live.spec.ts"])).toBe(0);
    expect(listed(["--project=hermetic", "e2e/consent-live.spec.ts"])).toBe(0);
  });
});

function fakeGraph(pages: Record<string, Record<string, unknown>[][]>): { read: GraphRead; calls: string[] } {
  const calls: string[] = [];
  const read: GraphRead = async (_q, p) => {
    const feed = String(p["feed"]);
    const page = Number(p["skip"]) / Number(p["limit"]);
    calls.push(`${feed}#${page}`);
    return pages[feed]?.[page] ?? [];
  };
  return { read, calls };
}

const crit = (host: string) => ({ host, label: "malicious", band: "CRITICAL", coverage: "malicious-evidenced" });

test.describe("defect 2: no subject is a failure, never a skip", () => {
  test("an empty graph throws NoLiveSubjectError naming every feed searched", async () => {
    const { read, calls } = fakeGraph({});
    const err = await pickCriticalSubject(read).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NoLiveSubjectError);
    for (const f of SUBJECT_FEEDS) expect(String((err as Error).message)).toContain(f);
    expect(String((err as Error).message)).toContain("not a skip");
    expect(calls.length).toBe(SUBJECT_FEEDS.length * MAX_PAGES_PER_FEED);
  });

  test("a graph error propagates instead of being read as no subject", async () => {
    const read: GraphRead = async () => {
      throw new Error("graph down");
    };
    await expect(pickCriticalSubject(read)).rejects.toThrow("graph down");
  });

  test("the first usable CRITICAL host wins, in name order, deterministically", async () => {
    const { read } = fakeGraph({
      [SUBJECT_FEEDS[0]!]: [[], [crit("zz.example"), crit("192.0.2.1"), crit("*.wild.example"), crit("aa.example")]],
    });
    const a = await pickCriticalSubject(read);
    const b = await pickCriticalSubject(read);
    expect(a.host).toBe("aa.example");
    expect(a.feed).toBe(SUBJECT_FEEDS[0]);
    expect(b.host).toBe(a.host);
  });

  test("a later feed is searched when the first has nothing usable", async () => {
    const { read } = fakeGraph({ [SUBJECT_FEEDS[1]!]: [[crit("later.example")]] });
    expect((await pickCriticalSubject(read)).feed).toBe(SUBJECT_FEEDS[1]);
  });

  test("rows that are not CRITICAL are never taken, even if the query misbehaves", async () => {
    const { read } = fakeGraph({ [SUBJECT_FEEDS[0]!]: [[{ host: "high.example", band: "HIGH" }]] });
    await expect(pickCriticalSubject(read)).rejects.toBeInstanceOf(NoLiveSubjectError);
  });

  test("usable hosts are pinnable LDH names, not addresses or patterns", () => {
    expect(isUsableHost("bad.example.com")).toBe(true);
    expect(isUsableHost("192-0-2-1.example.net")).toBe(true);
    for (const h of ["", "192.0.2.1", "localhost", "*.wild.example", "a.example/path", "UPPER.example", "-a.example", "a..example"]) {
      expect(isUsableHost(h), h).toBe(false);
    }
  });

  test("the reader throws on a non-2xx and on a body without rows", async () => {
    const r401 = graphReader("https://g.invalid/q", "k", (async () => new Response("no", { status: 401 })) as typeof fetch);
    await expect(r401("q", {})).rejects.toThrow("HTTP 401");
    const rErr = graphReader(
      "https://g.invalid/q",
      "k",
      (async () => new Response(JSON.stringify({ error: "bad query" }), { status: 200 })) as typeof fetch,
    );
    await expect(rErr("q", {})).rejects.toThrow("bad query");
  });

  test("the gate is recognised from the npm script name, and an ordinary run is not the gate", () => {
    expect(isLiveGate({ npm_lifecycle_event: "e2e:live" })).toBe(true);
    expect(isLiveGate({ WHISPER_GUARD_LIVE_GATE: "1" })).toBe(true);
    expect(isLiveGate({ npm_lifecycle_event: "e2e" })).toBe(false);
    expect(isLiveGate({})).toBe(false);
  });

  test("the gate without a key fails at load rather than skipping", () => {
    let out = "";
    let failed = false;
    try {
      execFileSync(
        process.execPath,
        [resolve(ROOT, "node_modules/@playwright/test/cli.js"), "test", "--list", "--project=live", "e2e/live.spec.ts"],
        {
          cwd: ROOT,
          env: { ...process.env, WHISPER_GUARD_E2E_KEY: "", npm_lifecycle_event: "e2e:live" },
          encoding: "utf8",
          stdio: "pipe",
        },
      );
    } catch (e) {
      failed = true;
      const x = e as { stdout?: string; stderr?: string };
      out = `${x.stdout ?? ""}${x.stderr ?? ""}`;
    }
    expect(failed).toBe(true);
    expect(out).toContain("does not skip");
  });
});

test.describe("defect 3: teardown is safe when setup never ran", () => {
  test("closing an absent server settles at once", async () => {
    // The old teardown, for the record: this promise never settles.
    const old = (s: http.Server | undefined) => new Promise((r) => s?.close(r));
    const winner = await Promise.race([old(undefined).then(() => "settled"), new Promise((r) => setTimeout(() => r("hung"), 200))]);
    expect(winner).toBe("hung");

    const fixed = await Promise.race([
      closeQuietly(undefined).then(() => "settled"),
      new Promise((r) => setTimeout(() => r("hung"), 200)),
    ]);
    expect(fixed).toBe("settled");
    await closeQuietly(null);
  });

  test("a server created but never listening closes without hanging", async () => {
    const s = http.createServer();
    await closeQuietly(s);
  });

  test("a listening server is really closed", async () => {
    const s = http.createServer();
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
    expect(s.listening).toBe(true);
    await closeQuietly(s);
    expect(s.listening).toBe(false);
  });
});
