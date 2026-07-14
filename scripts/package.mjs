// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Zip each built target for store upload:
//   dist/whisper-guard-<target>-<version>.zip
// Uses python3's zipfile (universally present) to avoid a zip dependency.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

for (const target of ["chromium", "firefox"]) {
  const dir = join(ROOT, "dist", target);
  if (!existsSync(dir)) {
    console.error(`package: dist/${target} missing; run npm run build first`);
    process.exit(1);
  }
  const out = join(ROOT, "dist", `whisper-guard-${target}-${pkg.version}.zip`);
  const py = [
    "-c",
    [
      "import os, sys, zipfile",
      "src, dst = sys.argv[1], sys.argv[2]",
      "zf = zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED)",
      "for root, _, files in os.walk(src):",
      "    for f in sorted(files):",
      "        p = os.path.join(root, f)",
      "        zf.write(p, os.path.relpath(p, src))",
      "zf.close()",
      "print('packaged', dst)",
    ].join("\n"),
    dir,
    out,
  ];
  execFileSync("python3", py, { stdio: "inherit" });
}
