// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Toolbar icon state sets, built from the REAL Whisper brand mark: the
// interlocking-rings mark is extracted programmatically from assets/logo.png
// (the canonical brand asset) so the shape is always the brand, never a
// letterform. Every state keeps three redundant channels so hue is never
// load-bearing: ring COLOR, corner badge SHAPE, ring STYLE. The single
// costliest state, malicious, escalates to a filled red plate with a white
// mark. Pre-rendered PNGs keep setIcon behaviour identical across engines
// (no OffscreenCanvas).
//
// Pipeline, per state: plate+ring SVG rendered at 512 -> brand mark
// composited (the brand SILHOUETTE painted via its alpha mask: bold Whisper
// purple in every state, white on the malicious red plate) -> badge overlay
// -> downsampled to 16/32/48/128.
// The per-state SVGs in assets/icons/ are written as self-contained design
// sources with the mark embedded as a data URI.
//
// Requires ImageMagick ("convert") for extraction, recoloring, rasterization
// and compositing. The PNGs are checked in, so a normal build never needs
// this script; re-run it only when the icon design or the brand asset changes.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SVG_DIR = join(ROOT, "assets", "icons");
const PNG_DIR = join(ROOT, "icons");
const LOGO = join(ROOT, "assets", "logo.png");
const SIZES = [16, 32, 48, 128];
const BASE = 512; // working resolution; downsampled per size

const C = {
  bg: "#0d0d1a", // theme --w-card
  line: "#0b1220",
  markDim: "#6b7280",
  green: "#10b981",
  amber: "#f59e0b",
  red: "#dc2626",
  redDark: "#7f1d1d",
  slate: "#6b7280",
  faint: "#475569",
  accent: "#8a5cc7", // theme --w-accent: Whisper violet
  // The MARK's fill: a bold, bright Whisper purple. The interlocking-rings
  // mark from the raw logo is a dark gradient that reads as near-black at
  // 16px on the browser toolbar, so we paint the brand SILHOUETTE in this
  // strong violet instead. High contrast on the dark plate, clearly purple in
  // both light and dark browser chrome. This is the icon's headline colour.
  markPurple: "#7c5cff",
};

const convert = (args) => execFileSync("convert", args);

const WORK = mkdtempSync(join(tmpdir(), "whisper-guard-icons-"));

// 1) Extract the brand mark (the interlocking rings, left of the wordmark)
// from the canonical logo, and prepare its recolored variants. The crop
// stops at x=260: the mark's own bbox ends at ~257 and the wordmark's first
// white stroke starts just past it (a wider crop drags a sliver of it in).
const markBrand = join(WORK, "mark-brand.png");
const markMask = join(WORK, "mark-mask.png");
convert([LOGO, "-crop", "260x250+0+0", "+repage", "-trim", "+repage", markBrand]);
convert([markBrand, "-alpha", "extract", markMask]);
const [markSrcW, markSrcH] = execFileSync("identify", ["-format", "%w %h", markBrand])
  .toString()
  .trim()
  .split(" ")
  .map(Number);

function recolorMark(color, out) {
  // Solid fill shaped by the mark's own alpha: the exact brand silhouette.
  convert([markMask, "-background", color, "-alpha", "shape", out]);
}
const markWhite = join(WORK, "mark-white.png");
const markDim = join(WORK, "mark-dim.png");
const markPurple = join(WORK, "mark-purple.png");
recolorMark("#ffffff", markWhite);
recolorMark(C.markDim, markDim);
// The purple mark gets a proportional stroke-thickening first: the raw ring
// strokes are ~1px at 16px and anti-alias into the dark plate, so we dilate
// the silhouette a touch (a "heavier stroke") so the bold purple still reads
// crisply at toolbar size. Subtle enough to keep the interlocking-rings look.
const markPurpleMask = join(WORK, "mark-purple-mask.png");
convert([markMask, "-morphology", "Dilate", "Disk:4", markPurpleMask]);
convert([markPurpleMask, "-background", C.markPurple, "-alpha", "shape", markPurple]);

// 2) Plate + ring + badge, in the same 64-unit design space as before.
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

// state -> { plate SVG body, badge SVG body, which mark variant }
// The MARK is the bold Whisper purple in every state except malicious (a
// white silhouette on the red stop-plate for maximum contrast). The verdict
// lives in the RING colour (green / amber / red) and the corner badge, never
// in the mark: the mark's job is to be an unmistakably purple, highly visible
// brand anchor at 16px, including the default signed-out state.
const STATES = {
  base: { plate: squircle(C.bg) + ring(C.accent), badge: "", mark: markPurple },
  benign: { plate: squircle(C.bg) + ring(C.green), badge: BADGES.benign, mark: markPurple },
  suspicious: { plate: squircle(C.bg) + ring(C.amber), badge: BADGES.suspicious, mark: markPurple },
  malicious: {
    plate: `<rect x="2" y="2" width="60" height="60" rx="16" fill="${C.red}"/>` + squircle(C.red) + ring(C.redDark, 5),
    badge: BADGES.malicious,
    mark: markWhite,
  },
  unknown: { plate: squircle(C.bg) + ring(C.slate, 4, "7 5"), badge: BADGES.unknown, mark: markPurple },
  checking: { plate: squircle(C.bg) + ring(C.faint, 3, "2 4"), badge: BADGES.checking, mark: markPurple },
  signedout: { plate: squircle(C.bg) + ring("#374151"), badge: BADGES.signedout, mark: markPurple },
};

// Mark geometry in the 64-unit space: 34 units wide, centered at (32, 31)
// so the corner badge keeps its clear bottom-right ground.
const MARK_W = Math.round((34 / 64) * BASE);
const MARK_DY = Math.round((-1 / 64) * BASE);

function svgAt(body, px) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 64 64">${body}</svg>`;
}

mkdirSync(SVG_DIR, { recursive: true });
mkdirSync(PNG_DIR, { recursive: true });

for (const [state, spec] of Object.entries(STATES)) {
  // Render the layers.
  const platePath = join(WORK, `${state}-plate.svg`);
  writeFileSync(platePath, svgAt(spec.plate, BASE));
  const composedPath = join(WORK, `${state}-composed.png`);
  const markResized = join(WORK, `${state}-mark.png`);
  convert([spec.mark, "-resize", `${MARK_W}x${MARK_W}`, markResized]);
  const args = [
    "-background", "none", platePath,
    markResized, "-gravity", "center", "-geometry", `+0${MARK_DY < 0 ? MARK_DY : `+${MARK_DY}`}`, "-composite",
  ];
  if (spec.badge !== "") {
    const badgePath = join(WORK, `${state}-badge.svg`);
    writeFileSync(badgePath, svgAt(spec.badge, BASE));
    args.push(badgePath, "-gravity", "center", "-geometry", "+0+0", "-composite");
  }
  args.push(composedPath);
  convert(args);

  for (const size of SIZES) {
    const out = join(PNG_DIR, `${state}-${size}.png`);
    convert([composedPath, "-resize", `${size}x${size}`, out]);
  }

  // Self-contained design source: the same layers, mark embedded inline.
  const markB64 = readFileSync(join(WORK, `${state}-mark.png`)).toString("base64");
  const markUnits = 34;
  const markUnitsH = (markUnits * markSrcH) / markSrcW;
  const markSvg = `<image x="${32 - markUnits / 2}" y="${31 - markUnitsH / 2}" width="${markUnits}" href="data:image/png;base64,${markB64}"/>`;
  writeFileSync(join(SVG_DIR, `${state}.svg`), svgAt(spec.plate + markSvg + spec.badge, 128));

  console.log(`gen-icons: ${state} -> ${SIZES.map((s) => `${s}px`).join(", ")}`);
}

rmSync(WORK, { recursive: true, force: true });
console.log(`gen-icons: wrote ${Object.keys(STATES).length} SVGs + ${Object.keys(STATES).length * SIZES.length} PNGs from the brand mark`);
