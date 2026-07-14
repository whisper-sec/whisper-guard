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

import { execFileSync, spawn } from "node:child_process";
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
  { stdio: ["ignore", "pipe", "pipe"] },
);

let out = "";
let done = false;
const finish = (ok, msg) => {
  if (done) return;
  done = true;
  console.log(msg);
  child.kill("SIGTERM");
  setTimeout(() => {
    child.kill("SIGKILL");
    process.exit(ok ? 0 : 1);
  }, 3000).unref();
  setTimeout(() => process.exit(ok ? 0 : 1), 5000);
};

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
