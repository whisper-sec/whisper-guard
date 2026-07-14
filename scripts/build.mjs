// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Build one target: node scripts/build.mjs <chromium|firefox>
// Bundles the TypeScript with esbuild, copies static pages / styles /
// icons, stamps the manifest with the package version, and then VERIFIES
// the output: a dist that is missing any file the manifest references
// fails the build instead of shipping broken.

import { build } from "esbuild";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const target = process.argv[2];
if (target !== "chromium" && target !== "firefox") {
  console.error("usage: node scripts/build.mjs <chromium|firefox>");
  process.exit(1);
}
const OUT = join(ROOT, "dist", target);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

// 1) Bundles.
const common = {
  bundle: true,
  minify: false,
  sourcemap: false,
  target: ["es2022"],
  platform: "browser",
  logLevel: "warning",
};

await build({
  ...common,
  entryPoints: [join(ROOT, "src/background/index.ts")],
  outfile: join(OUT, "background.js"),
  format: "esm",
});

for (const [entry, out] of [
  ["src/popup/popup.ts", "popup.js"],
  ["src/options/options.ts", "options.js"],
  ["src/pages/warning.ts", "warning.js"],
  ["src/pages/check-link.ts", "check-link.js"],
  ["src/content/guard.ts", "content.js"],
]) {
  await build({
    ...common,
    entryPoints: [join(ROOT, entry)],
    outfile: join(OUT, out),
    format: "iife",
  });
}

// 2) Static pages + styles.
for (const [from, to] of [
  ["src/popup/popup.html", "popup.html"],
  ["src/popup/popup.css", "popup.css"],
  ["src/options/options.html", "options.html"],
  ["src/options/options.css", "options.css"],
  ["src/pages/warning.html", "warning.html"],
  ["src/pages/warning.css", "warning.css"],
  ["src/pages/check-link.html", "check-link.html"],
  ["src/pages/check-link.css", "check-link.css"],
]) {
  copyFileSync(join(ROOT, from), join(OUT, to));
}

// 3) Icons.
mkdirSync(join(OUT, "icons"), { recursive: true });
const iconDir = join(ROOT, "icons");
if (!existsSync(iconDir)) {
  console.error("build: icons/ missing; run `npm run icons` first");
  process.exit(1);
}
for (const f of readdirSync(iconDir)) {
  if (f.endsWith(".png")) copyFileSync(join(iconDir, f), join(OUT, "icons", f));
}

// 4) Manifest, stamped with the package version.
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(ROOT, "manifests", `manifest.${target}.json`), "utf8"));
manifest.version = pkg.version;
writeFileSync(join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

// 5) Self-check: every file the manifest references must exist in dist.
const referenced = new Set(["manifest.json"]);
const addIcons = (m) => Object.values(m ?? {}).forEach((p) => referenced.add(p));
if (manifest.background?.service_worker) referenced.add(manifest.background.service_worker);
for (const s of manifest.background?.scripts ?? []) referenced.add(s);
if (manifest.action?.default_popup) referenced.add(manifest.action.default_popup);
addIcons(manifest.action?.default_icon);
addIcons(manifest.icons);
if (manifest.options_ui?.page) referenced.add(manifest.options_ui.page);
for (const war of manifest.web_accessible_resources ?? []) {
  for (const r of war.resources ?? []) referenced.add(r);
}
// Files the code itself references at runtime.
for (const extra of ["content.js", "check-link.html", "warning.html", "popup.js", "options.js", "warning.js", "check-link.js"]) {
  referenced.add(extra);
}

let missing = 0;
for (const rel of referenced) {
  const p = join(OUT, rel);
  if (!existsSync(p) || statSync(p).size === 0) {
    console.error(`build: MISSING in dist/${target}: ${rel}`);
    missing++;
  }
}
if (missing > 0) {
  console.error(`build: dist/${target} is incomplete (${missing} missing); failing`);
  process.exit(1);
}

const files = readdirSync(OUT).length;
console.log(`build: dist/${target} complete (${files} top-level entries, manifest v${manifest.version}, all references verified)`);
