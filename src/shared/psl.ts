// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Offline Public Suffix List: registrable-domain (eTLD+1) extraction with
// full wildcard (*.foo) and exception (!bar.foo) rule support, from the
// vendored snapshot. No network, ever.

import pslData from "./psl-data.json";

const exact = new Set<string>();
const wildcard = new Set<string>();
const exception = new Set<string>();

for (const rule of (pslData as { rules: string[] }).rules) {
  if (rule.startsWith("!")) exception.add(rule.slice(1));
  else if (rule.startsWith("*.")) wildcard.add(rule.slice(2));
  else exact.add(rule);
}

/**
 * Length in labels of the public suffix of `host`, per PSL semantics.
 * Unlisted single labels are treated as a suffix of one label (the
 * prevailing default rule "*").
 */
function suffixLabelCount(labels: string[]): number {
  let match = 1;
  for (let i = labels.length - 1; i >= 0; i--) {
    const candidate = labels.slice(i).join(".");
    if (exception.has(candidate)) {
      // An exception rule wins and is itself registrable at this depth:
      // the suffix is one label shorter than the exception.
      return labels.length - i - 1;
    }
    if (exact.has(candidate)) {
      match = Math.max(match, labels.length - i);
    }
    if (i > 0) {
      const parent = labels.slice(i).join(".");
      if (wildcard.has(parent)) {
        match = Math.max(match, labels.length - i + 1);
      }
    }
  }
  return match;
}

/**
 * The registrable domain (eTLD+1) of a lowercase hostname, or null when the
 * host IS a public suffix (or empty). "www.example.co.uk" -> "example.co.uk".
 */
export function registrableDomain(hostname: string): string | null {
  const host = hostname.replace(/\.$/, "").toLowerCase();
  if (host === "") return null;
  const labels = host.split(".");
  const suffix = suffixLabelCount(labels);
  if (labels.length <= suffix) return null;
  return labels.slice(labels.length - suffix - 1).join(".");
}

/**
 * Split a registrable domain into its first label (the "SLD") and the
 * public suffix: "paypal.co.uk" -> { sld: "paypal", suffix: "co.uk" }.
 */
export function splitRegistrable(registrable: string): { sld: string; suffix: string } {
  const i = registrable.indexOf(".");
  if (i < 0) return { sld: registrable, suffix: "" };
  return { sld: registrable.slice(0, i), suffix: registrable.slice(i + 1) };
}
