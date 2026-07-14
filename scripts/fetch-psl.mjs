// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Refresh the vendored Public Suffix List snapshot (src/shared/psl-data.json).
// The snapshot is checked in so the build is fully offline; run this script
// deliberately when you want a newer list, then commit the diff.
//
// The list itself is maintained by Mozilla and the PSL community and is
// distributed under the Mozilla Public License 2.0 (see NOTICE).

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "shared", "psl-data.json");
const URL = "https://publicsuffix.org/list/public_suffix_list.dat";

const res = await fetch(URL);
if (!res.ok) {
  console.error(`fetch-psl: ${URL} returned HTTP ${res.status}`);
  process.exit(1);
}
const raw = await res.text();

const rules = [];
for (const line of raw.split("\n")) {
  const t = line.trim();
  if (t === "" || t.startsWith("//")) continue;
  rules.push(t.toLowerCase());
}

const snapshot = {
  source: URL,
  license: "MPL-2.0",
  fetched: new Date().toISOString().slice(0, 10),
  rules,
};
writeFileSync(OUT, JSON.stringify(snapshot));
console.log(`fetch-psl: wrote ${rules.length} rules to ${OUT}`);
