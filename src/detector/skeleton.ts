// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Confusable skeleton for hostname labels, in the spirit of UTS #39: map
// visually confusable characters onto one canonical form so that
// "paypa1", "pаypal" (Cyrillic а) and "paypal" all collapse to the same
// skeleton. Pipeline order matters and is IDN-canonical FIRST:
//
//   punycode-decode -> NFC -> lowercase -> NFD (strip marks) -> char map
//   -> multi-char folds
//
// Distance and equality run on skeletons, never on raw bytes. The map is a
// curated, precision-first subset of Unicode confusables covering the
// scripts actually used in look-alike domains (Cyrillic, Greek, Latin
// extended, fullwidth forms, digit stand-ins).

import { labelToUnicode } from "./punycode";

const MAP: Record<string, string> = {
  // Digit and ASCII stand-ins.
  "0": "o",
  "1": "l",
  // Cyrillic lowercase homoglyphs.
  "а": "a", // а
  "е": "e", // е
  "о": "o", // о
  "р": "p", // р
  "с": "c", // с
  "у": "y", // у
  "х": "x", // х
  "і": "i", // і
  "ѕ": "s", // ѕ
  "ј": "j", // ј
  "ԁ": "d", // ԁ
  "һ": "h", // һ
  "к": "k", // к
  "м": "m", // м
  "т": "t", // т
  "в": "b", // в
  "н": "h", // н
  "ё": "e", // ё
  "ї": "i", // ї
  "ӏ": "l", // ӏ palochka
  // Greek lowercase homoglyphs.
  "ο": "o", // ο
  "α": "a", // α
  "ν": "v", // ν
  "ι": "i", // ι
  "κ": "k", // κ
  "ρ": "p", // ρ
  "τ": "t", // τ
  "υ": "u", // υ
  "ε": "e", // ε
  "η": "n", // η
  "ω": "w", // ω
  "ϲ": "c", // ϲ
  "β": "b", // β
  "γ": "y", // γ
  "χ": "x", // χ
  // Latin extended without decomposition.
  "ı": "i", // ı
  "ł": "l", // ł
  "đ": "d", // đ
  "ħ": "h", // ħ
  "ø": "o", // ø
  "ð": "d", // ð
  "ĸ": "k", // ĸ
  "ſ": "s", // long s
};

// Sequences that read as another letter at a glance.
const FOLDS: [RegExp, string][] = [
  [/rn/g, "m"],
  [/vv/g, "w"],
];

/** Skeleton of one label (no dots). Empty input yields an empty skeleton. */
export function skeletonLabel(rawLabel: string): string {
  let s = labelToUnicode(rawLabel).normalize("NFC").toLowerCase();
  // Fullwidth forms -> ASCII.
  s = s.replace(/[\uff01-\uff5e]/g, (ch) =>
    String.fromCharCode(ch.charCodeAt(0) - 0xfee0),
  );
  // Strip combining marks (a-acute -> a, c-cedilla -> c) via NFD.
  s = s.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  let out = "";
  for (const ch of s) out += MAP[ch] ?? ch;
  for (const [re, to] of FOLDS) out = out.replace(re, to);
  return out;
}

/** Damerau-Levenshtein distance, capped at 2 (we only care about 0/1). */
export function damerauLevenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 1) return 2;
  const m = a.length;
  const n = b.length;
  const d: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i]![0] = i;
  for (let j = 0; j <= n; j++) d[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + cost);
      }
    }
  }
  return Math.min(d[m]![n]!, 2);
}
