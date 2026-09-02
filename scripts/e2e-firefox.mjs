// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Firefox cross-engine check, two gates:
//   1. web-ext lint     the AMO validator against dist/firefox: zero errors
//   2. web-ext run      load the built extension into a real headless
//                       Firefox as a temporary add-on and require a clean
//                       install (the same mechanism AMO reviewers use)
//
// FIREFOX_BIN overrides the binary; otherwise the system firefox is used,
// falling back to Playwright's bundled build.

import { execFileSync, execSync, spawn } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = join(ROOT, "dist", "firefox");
const WEB_EXT = join(ROOT, "node_modules", ".bin", "web-ext");

if (!existsSync(DIST)) {
  console.error("e2e-firefox: dist/firefox missing; run npm run build first");
  process.exit(1);
}

function findFirefox() {
  if (process.env.FIREFOX_BIN) return process.env.FIREFOX_BIN;
  for (const p of ["/usr/bin/firefox", "/usr/bin/firefox-esr", "/snap/bin/firefox"]) {
    if (existsSync(p)) return p;
  }
  const cache = join(homedir(), ".cache", "ms-playwright");
  if (existsSync(cache)) {
    const ff = readdirSync(cache)
      .filter((d) => d.startsWith("firefox-"))
      .sort()
      .reverse();
    for (const d of ff) {
      const bin = join(cache, d, "firefox", "firefox");
      if (existsSync(bin)) return bin;
    }
  }
  return null;
}

// ------------------------------------------------------------ gate 1: lint
console.log("gate 1: web-ext lint (AMO validation) ...");
execFileSync(WEB_EXT, ["lint", "--source-dir", DIST, "--no-config-discovery"], {
  stdio: "inherit",
});

// ------------------------------------------------------- gate 2: load test
const firefox = findFirefox();
if (!firefox) {
  console.error("e2e-firefox: no Firefox binary found (set FIREFOX_BIN)");
  process.exit(1);
}
console.log(`gate 2: temporary-install into headless Firefox (${firefox}) ...`);

/**
 * Every Firefox from THIS install that is already running, before we start
 * one of our own.
 *
 * The teardown reaps the difference. web-ext starts Firefox as its own
 * child and that child escapes both `child.kill()` and a process-group
 * signal, so without this the browser simply stays running: five orphans
 * were found on this machine, the oldest two days and five hours old, one
 * of them holding a profile lock inside the browser INSTALL directory,
 * which then made every later Playwright launch of that same Firefox fail
 * with a bare ENOENT on the lock path.
 *
 * A before/after difference is the precise way to do this. It cannot touch
 * a browser that was already running, which on a shared machine is somebody
 * else's, and it needs nothing from web-ext, whose own --firefox-profile is
 * ignored for the temporary-install flow.
 */
const firefoxPids = () => {
  try {
    return new Set(
      execSync(`pgrep -f ${JSON.stringify(firefox)} || true`, { encoding: "utf8" })
        .split("\n")
        .map((x) => Number(x.trim()))
        .filter((n) => Number.isInteger(n) && n > 0),
    );
  } catch {
    return new Set();
  }
};
const preexisting = firefoxPids();

const child = spawn(
  WEB_EXT,
  [
    "run",
    "--source-dir", DIST,
    "--firefox", firefox,
    "--no-config-discovery",
    "--no-input",
    "--arg=-headless",
  ],
  // OWN PROCESS GROUP. web-ext spawns Firefox as its own child, so killing
  // web-ext alone leaves a headless Firefox running forever: one was found
  // still alive two days and five hours after the run that started it,
  // holding a profile lock in the browser install directory that then broke
  // every later attempt to launch that same Firefox. Detaching lets the
  // teardown below signal the whole group and reap the grandchild too.
  { stdio: ["ignore", "pipe", "pipe"], detached: true },
);

let out = "";
let done = false;
/**
 * Reap this run's browser, and only this run's.
 *
 * Three steps, cheapest first: the child, then its process group, then any
 * Firefox still holding OUR profile directory. The third is the one that
 * actually catches it, and it is safe precisely because the profile path is
 * ours and unique - it can never match a browser someone else is running.
 */
const killTree = (signal) => {
  try {
    child.kill(signal);
  } catch {
    // already gone
  }
  try {
    process.kill(-child.pid, signal);
  } catch {
    // no group, or already gone
  }
  for (const pid of firefoxPids()) {
    if (preexisting.has(pid) || pid === process.pid) continue;
    try {
      process.kill(pid, signal);
    } catch {
      // gone between listing and signalling
    }
  }
};

const finish = (ok, msg) => {
  if (done) return;
  done = true;
  console.log(msg);
  killTree("SIGTERM");
  const bail = () => {
    killTree("SIGKILL");
    process.exit(ok ? 0 : 1);
  };
  setTimeout(bail, 3000).unref();
  setTimeout(bail, 5000);
};

// A Ctrl-C or a killed CI job must not leave the browser behind either.
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    killTree("SIGKILL");
    process.exit(1);
  });
}

const watch = (chunk) => {
  out += chunk.toString();
  if (/Installed .* as a temporary add-on/i.test(out) || /The extension will reload/i.test(out)) {
    finish(true, "e2e-firefox: PASS, extension installed cleanly into Firefox");
  }
  if (/error/i.test(chunk.toString()) && !/WebExtension/.test(chunk.toString())) {
    // keep collecting; web-ext prints benign lines too
  }
};
child.stdout.on("data", watch);
child.stderr.on("data", watch);

setTimeout(() => {
  finish(false, `e2e-firefox: FAIL, no clean install within 60s.\n---\n${out.slice(-2000)}`);
}, 60_000);

child.on("exit", (code) => {
  if (!done) finish(false, `e2e-firefox: FAIL, web-ext exited early (${code}).\n---\n${out.slice(-2000)}`);
});
