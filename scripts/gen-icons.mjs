// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Toolbar icon state sets: one SVG per state (checked into assets/icons as
// the design source) rasterized to 16/32/48/128 PNGs (checked into icons/,
// shipped in the package). Every state is encoded in three redundant
// channels so hue is never load-bearing: ring COLOR, corner badge SHAPE,
// ring STYLE. The single costliest state, malicious, escalates to a filled
// red plate. Pre-rendered PNGs keep setIcon behaviour identical across
// engines (no OffscreenCanvas).
//
// Requires ImageMagick ("convert") for rasterization. The PNGs are checked
// in, so a normal build never needs this script; re-run it only when the
// icon design changes.

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SVG_DIR = join(ROOT, "assets", "icons");
const PNG_DIR = join(ROOT, "icons");
const SIZES = [16, 32, 48, 128];

const C = {
  bg: "#111827",
  line: "#0b1220",
  mark: "#e5e7eb",
  markDim: "#6b7280",
  green: "#10b981",
  amber: "#f59e0b",
  red: "#dc2626",
  redDark: "#7f1d1d",
  slate: "#6b7280",
  faint: "#475569",
  accent: "#38bdf8",
};

// The "w" mark as a stroked path (no fonts: deterministic everywhere).
function wPath(color, width = 5) {
  return `<path d="M14 24 L21 42 L32 28 L43 42 L50 24" fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round"/>`;
}

function ring(color, width = 4, dash = "") {
  const d = dash === "" ? "" : ` stroke-dasharray="${dash}"`;
  return `<rect x="3" y="3" width="58" height="58" rx="15" fill="none" stroke="${color}" stroke-width="${width}"${d}/>`;
}

function squircle(fill) {
  return `<rect x="6" y="6" width="52" height="52" rx="13" fill="${fill}"/>`;
}

function octagonPoints(cx, cy, r) {
  const pts = [];
  for (let i = 0; i < 8; i++) {
    const a = (Math.PI / 4) * i + Math.PI / 8;
    pts.push(`${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(" ");
}

const BADGES = {
  // benign: green rounded square with a check.
  benign: `<rect x="38" y="38" width="20" height="20" rx="5" fill="${C.green}" stroke="${C.line}" stroke-width="2"/>
    <path d="M43 48 L47 52 L54 44" fill="none" stroke="#ffffff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`,
  // suspicious: amber triangle.
  suspicious: `<polygon points="48,36 60,58 36,58" fill="${C.amber}" stroke="${C.line}" stroke-width="2"/>`,
  // malicious: white octagon (STOP) on the red plate.
  malicious: `<polygon points="${octagonPoints(48, 48, 11)}" fill="#ffffff" stroke="${C.redDark}" stroke-width="2"/>`,
  // unknown: hollow slate circle.
  unknown: `<circle cx="48" cy="48" r="9" fill="${C.bg}" stroke="${C.slate}" stroke-width="3.5"/>`,
  // checking: a small transient dot.
  checking: `<circle cx="48" cy="48" r="5" fill="#94a3b8" stroke="${C.line}" stroke-width="1.5"/>`,
  // signedout: a dim locked-signal square with a keyhole.
  signedout: `<rect x="38" y="38" width="20" height="20" rx="5" fill="#374151" stroke="${C.line}" stroke-width="2"/>
    <circle cx="48" cy="46" r="3" fill="${C.markDim}"/><rect x="46.5" y="47" width="3" height="7" rx="1.5" fill="${C.markDim}"/>`,
};

const STATES = {
  base: squircle(C.bg) + ring(C.accent) + wPath(C.mark),
  benign: squircle(C.bg) + ring(C.green) + wPath(C.mark) + BADGES.benign,
  suspicious: squircle(C.bg) + ring(C.amber) + wPath(C.mark) + BADGES.suspicious,
  malicious:
    `<rect x="2" y="2" width="60" height="60" rx="16" fill="${C.red}"/>` +
    squircle(C.red) +
    ring(C.redDark, 5) +
    wPath("#ffffff", 6) +
    BADGES.malicious,
  unknown: squircle(C.bg) + ring(C.slate, 4, "7 5") + wPath(C.mark) + BADGES.unknown,
  checking: squircle(C.bg) + ring(C.faint, 3, "2 4") + wPath(C.mark) + BADGES.checking,
  signedout: squircle(C.bg) + ring("#374151") + wPath(C.markDim) + BADGES.signedout,
};

mkdirSync(SVG_DIR, { recursive: true });
mkdirSync(PNG_DIR, { recursive: true });

for (const [state, body] of Object.entries(STATES)) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 64 64">${body}</svg>`;
  const svgPath = join(SVG_DIR, `${state}.svg`);
  writeFileSync(svgPath, svg);
  for (const size of SIZES) {
    const out = join(PNG_DIR, `${state}-${size}.png`);
    execFileSync("convert", ["-background", "none", svgPath, "-resize", `${size}x${size}`, out]);
  }
  console.log(`gen-icons: ${state} -> ${SIZES.map((s) => `${s}px`).join(", ")}`);
}
console.log(`gen-icons: wrote ${Object.keys(STATES).length} SVGs + ${Object.keys(STATES).length * SIZES.length} PNGs`);
