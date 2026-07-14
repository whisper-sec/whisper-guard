// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Minimal RFC 3492 Punycode DECODER for IDN labels (xn--). Decode-only:
// the detector canonicalizes what the browser gives it (ASCII/ACE labels)
// back to Unicode before confusable skeletonizing. Malformed input returns
// null and the caller falls back to the raw label (liberal-accept: a broken
// label must never crash detection).

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function digitValue(cp: number): number {
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26; // 0..9
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41; // A..Z
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61; // a..z
  return -1;
}

/** Decode one Punycode label body (WITHOUT the xn-- prefix). Null on error. */
export function punycodeDecode(input: string): string | null {
  const output: number[] = [];
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  let basicEnd = input.lastIndexOf("-");
  if (basicEnd < 0) basicEnd = 0;
  for (let j = 0; j < basicEnd; j++) {
    const cp = input.charCodeAt(j);
    if (cp >= 0x80) return null;
    output.push(cp);
  }

  let index = basicEnd > 0 ? basicEnd + 1 : 0;
  while (index < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) return null;
      const digit = digitValue(input.charCodeAt(index++));
      if (digit < 0) return null;
      if (digit > Math.floor((0x7fffffff - i) / w)) return null;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(0x7fffffff / (BASE - t))) return null;
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    if (Math.floor(i / out) > 0x7fffffff - n) return null;
    n += Math.floor(i / out);
    i %= out;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

/** Convert one hostname label to Unicode: decodes xn-- labels, else as-is. */
export function labelToUnicode(label: string): string {
  const l = label.toLowerCase();
  if (!l.startsWith("xn--")) return l;
  const decoded = punycodeDecode(l.slice(4));
  // A null or empty decode means the label is malformed; keep the raw form
  // rather than erasing it (liberal-accept, and never a shorter skeleton).
  return decoded === null || decoded === "" ? l : decoded;
}
