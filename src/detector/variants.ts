// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Look-alike candidate generation for the KEYED confirmation path: generate
// plausible variants of a host on-device, then confirm each against the
// graph with one batched whisper.assess call. Only registered hosts with a
// suspicious/malicious band become "confirmed active look-alikes"; the
// generator itself proves nothing (candidate generation only).
//
// Pure string work: no graph, no DOM. Bounded so a long label cannot
// explode the set.

const COMMON_TLDS = [
  "com", "net", "org", "co", "io", "app", "info", "biz", "online", "site",
  "xyz", "shop", "store", "live", "vip", "top", "cc", "me", "dev", "us",
  "co.uk", "de", "fr", "nl", "eu",
];

const HOMOGLYPH: Record<string, string> = {
  o: "0", "0": "o", l: "1", "1": "l", i: "1", e: "3", s: "5", a: "4", b: "8", g: "9", t: "7",
};

/**
 * Generate common typo/look-alike variants of a registrable domain.
 * Returns lowercase `label.suffix` strings, deduped, excluding the input,
 * capped. TLD swaps lead (the highest-value gaps), then character edits.
 */
export function generateCandidates(registrable: string, cap: number): string[] {
  const d = registrable.toLowerCase().trim();
  const dot = d.indexOf(".");
  const label = dot < 0 ? d : d.slice(0, dot);
  const suffix = dot < 0 ? "com" : d.slice(dot + 1);
  const out = new Set<string>();

  const add = (l: string, s = suffix) => {
    if (out.size >= cap) return;
    if (!l || l.length < 2 || /[^a-z0-9-]/.test(l) || l.startsWith("-") || l.endsWith("-") || l.includes("--")) {
      return;
    }
    const v = `${l}.${s}`;
    if (v !== d) out.add(v);
  };

  // 1. TLD swaps.
  for (const t of COMMON_TLDS) if (t !== suffix) add(label, t);
  const ch = label.split("");
  // 2. Homoglyph substitution.
  for (let i = 0; i < ch.length; i++) {
    const h = HOMOGLYPH[ch[i]!];
    if (h) add(label.slice(0, i) + h + label.slice(i + 1));
  }
  // 3. Omission.
  for (let i = 0; i < ch.length; i++) add(label.slice(0, i) + label.slice(i + 1));
  // 4. Adjacent transposition.
  for (let i = 0; i < ch.length - 1; i++) {
    add(ch.slice(0, i).join("") + ch[i + 1]! + ch[i]! + ch.slice(i + 2).join(""));
  }
  // 5. Doubling.
  for (let i = 0; i < ch.length; i++) add(label.slice(0, i + 1) + ch[i]! + label.slice(i + 1));
  // 6. Hyphenation.
  for (let i = 1; i < ch.length; i++) add(label.slice(0, i) + "-" + label.slice(i));

  return [...out].slice(0, cap);
}
