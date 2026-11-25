// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Toolbar icon sets for the three states drawn here, built from the REAL
// Whisper brand mark: the interlocking-rings mark is extracted programmatically
// from assets/logo.png (the canonical brand asset) so the shape is always the
// brand, never a letterform.
//
//   base       the brand resting plate: the listing icon and the pages' favicon.
//   signedout  the same plate, quieter mark, with a lock in the corner: the
//              live check is off, on-device protection still runs.
//   neutral    a muted full-bleed tile, grey mark: a page Guard does not check.
//
// The five verdict tiles (benign, suspicious, malicious, unknown, checking) are
// designer art, committed as delivered and NEVER generated. Their SVG masters
// in assets/icons/ must not be re-rasterised with ImageMagick either: it
// ignores stroke-dasharray and drops the dashes of the unknown tile's rim.
// scripts/icon-targets.mjs lists what may be written, and every write below is
// checked against it first; e2e/icon-art.spec.ts pins the delivered files.
//
// Pre-rendered PNGs keep setIcon behaviour identical across engines (no
// OffscreenCanvas).
//
// Pipeline, per state: tile SVG rendered at 512 -> HERO brand mark composited
// (the brand SILHOUETTE painted via its alpha mask, recoloured per state) ->
// lock overlay (signedout only) -> downsampled to 16/32/48/128. The SVGs
// this script writes (base, neutral, signedout) are self-contained design
// sources with the mark embedded; the verdict masters are designer art.
//
// Requires ImageMagick ("convert"). The PNGs are checked in, so a normal build
// never needs this script; re-run it only when the icon design or the brand
// asset changes.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertGeneratedTarget, GENERATED_STATES, SIZES } from "./icon-targets.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SVG_DIR = join(ROOT, "assets", "icons");
const PNG_DIR = join(ROOT, "icons");
const LOGO = join(ROOT, "assets", "logo.png");
const BASE = 512; // working resolution; downsampled per size

const C = {
  line: "#0b1220",
  // The brand resting plate, the live-check-off plate and the not-checked tile.
  plateDark: "#12101f", // dark with a faint violet cast: the brand resting plate
  plateGray: "#1c2130", // signed-out: muted, protection still on-device
  groundQuiet: "#1a1a2e", // ground of the not-checked tile
  rim: "#8a5cc7", // a faint Whisper-violet rim on the brand resting plate
  slate: "#94a3b8", // the lock on the signed-out tile
  // The MARK fills, drawn flat.
  markViolet: "#8b6bff", // brand mark on the brand resting plate
  markVioletMuted: "#7d74ad", // signed-out: present but quietened
  markNeutral: "#55555d", // not checked: grey at reduced strength
};

/**
 * Every convert in this file strips metadata, and it is done HERE rather
 * than at the one call that happened to be the leak path.
 *
 * assets/logo.png carried Adobe XMP (CreatorTool, document GUIDs) and a
 * "Adobe ImageReady" Software tag. Nothing in this pipeline removed them, so
 * every generated SVG froze a copy inside their embedded base64 PNG -
 * where a sweep over *.png files cannot see them, because they are PNGs
 * inside .svg files. Stripping the source alone would have left the
 * regression armed for the next regeneration; stripping every step means a
 * dirty input cannot become a dirty output.
 */
const convert = (args) => execFileSync("convert", [...args.slice(0, -1), "-strip", args[args.length - 1]]);
const WORK = mkdtempSync(join(tmpdir(), "whisper-guard-icons-"));

// 1) Extract the brand mark from the canonical logo, and prepare recoloured,
// stroke-thickened variants (the raw ring strokes are ~1px at 16px and
// anti-alias away, so we dilate the silhouette a touch so the mark reads
// crisply at toolbar size, HERO-sized).
const markBrand = join(WORK, "mark-brand.png");
const markMask = join(WORK, "mark-mask.png");
convert([LOGO, "-crop", "260x250+0+0", "+repage", "-trim", "+repage", markBrand]);
convert([markBrand, "-alpha", "extract", markMask]);
const [markSrcW, markSrcH] = execFileSync("identify", ["-format", "%w %h", markBrand])
  .toString()
  .trim()
  .split(" ")
  .map(Number);

// Dilate once so the shape stays crisp at 16px; recolour from the fattened mask.
const markMaskFat = join(WORK, "mark-mask-fat.png");
convert([markMask, "-morphology", "Dilate", "Disk:4", markMaskFat]);
function recolorMark(color, out) {
  convert([markMaskFat, "-background", color, "-alpha", "shape", out]);
}
const markViolet = join(WORK, "mark-violet.png");
const markVioletMuted = join(WORK, "mark-violet-muted.png");
const markNeutral = join(WORK, "mark-neutral.png");
recolorMark(C.markViolet, markViolet);
recolorMark(C.markVioletMuted, markVioletMuted);
recolorMark(C.markNeutral, markNeutral);

// 2) Tiles in the 64-unit design space. `plate()` is the inset brand plate
// (60 x 60, a faint violet rim on the calm one): it serves `base` and
// `signedout`. `tile()` is the full-bleed square of the not-checked state.
function plate(fill, { rim = false } = {}) {
  const rimEl = rim
    ? `<rect x="4" y="4" width="56" height="56" rx="14" fill="none" stroke="${C.rim}" stroke-width="1.5" opacity="0.45"/>`
    : "";
  return `<rect x="2" y="2" width="60" height="60" rx="16" fill="${fill}"/>${rimEl}`;
}

function tile(ground) {
  return `<rect x="0" y="0" width="64" height="64" rx="16" fill="${ground}"/>`;
}

// The corner shape of the live-check-off tile.
const BADGES = {
  signedout: `<rect x="39" y="40" width="19" height="18" rx="5" fill="#2a3040" stroke="${C.line}" stroke-width="2"/>
    <path d="M42 40 v-2 a6 6 0 0 1 12 0 v2" fill="none" stroke="${C.slate}" stroke-width="2.6" stroke-linecap="round"/>
    <circle cx="48.5" cy="49" r="2.4" fill="${C.slate}"/>`,
};

// state -> { plate, badge, mark, lift }. Rows marked `lift` keep the mark 2
// units above centre, clear of the lock. Exactly the generated states.
const STATES = {
  base: { plate: plate(C.plateDark, { rim: true }), badge: "", mark: markViolet, lift: true }, // listing icon and favicon: the brand resting plate
  signedout: { plate: plate(C.plateGray), badge: BADGES.signedout, mark: markVioletMuted, lift: true }, // on-device protection still on; sign in for the live signal
  neutral: { plate: tile(C.groundQuiet), badge: "", mark: markNeutral }, // a page Guard does not check
};
if (Object.keys(STATES).sort().join() !== [...GENERATED_STATES].sort().join()) {
  throw new Error("gen-icons: STATES and GENERATED_STATES in icon-targets.mjs differ");
}

// HERO mark geometry: 44 of 64 units, centred, and lifted 2 units on the rows
// marked `lift`, so the lock keeps clear ground at the bottom-right.
const MARK_W = Math.round((44 / 64) * BASE);
const MARK_DY = Math.round((-2 / 64) * BASE);

function svgAt(body, px) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 64 64">${body}</svg>`;
}

// Refuse before anything is written: every target of this run, checked up front.
for (const state of Object.keys(STATES)) {
  assertGeneratedTarget(join(SVG_DIR, `${state}.svg`));
  for (const size of SIZES) assertGeneratedTarget(join(PNG_DIR, `${state}-${size}.png`));
}

mkdirSync(SVG_DIR, { recursive: true });
mkdirSync(PNG_DIR, { recursive: true });

for (const [state, spec] of Object.entries(STATES)) {
  const platePath = join(WORK, `${state}-plate.svg`);
  writeFileSync(platePath, svgAt(spec.plate, BASE));
  const composedPath = join(WORK, `${state}-composed.png`);
  const markResized = join(WORK, `${state}-mark.png`);
  convert([spec.mark, "-resize", `${MARK_W}x${MARK_W}`, markResized]);
  const dy = spec.lift ? MARK_DY : 0;
  const args = [
    "-background", "none", platePath,
    markResized, "-gravity", "center", "-geometry", `+0${dy < 0 ? dy : `+${dy}`}`, "-composite",
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
    assertGeneratedTarget(out);
    convert([composedPath, "-resize", `${size}x${size}`, out]);
  }

  // Self-contained design source: the same layers, mark embedded inline.
  const markB64 = readFileSync(markResized).toString("base64");
  const markUnits = 44;
  const markUnitsH = (markUnits * markSrcH) / markSrcW;
  const markSvg = `<image x="${32 - markUnits / 2}" y="${(spec.lift ? 31 : 32) - markUnitsH / 2}" width="${markUnits}" href="data:image/png;base64,${markB64}"/>`;
  const svgOut = join(SVG_DIR, `${state}.svg`);
  assertGeneratedTarget(svgOut);
  writeFileSync(svgOut, svgAt(spec.plate + markSvg + spec.badge, 128));

  console.log(`gen-icons: ${state} -> ${SIZES.map((s) => `${s}px`).join(", ")}`);
}

rmSync(WORK, { recursive: true, force: true });
console.log(`gen-icons: wrote ${Object.keys(STATES).length} SVGs + ${Object.keys(STATES).length * SIZES.length} PNGs from the brand mark`);
