// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Toolbar icon state sets, built from the REAL Whisper brand mark: the
// interlocking-rings mark is extracted programmatically from assets/logo.png
// (the canonical brand asset) so the shape is always the brand, never a
// letterform.
//
// Design: each state owns its tile, and the whole tile signals.
//   - Ground per state: green, amber, solid red, dark, violet (board 3g) and a
//     muted dark for a page Guard does not check (board 5d). A solid ring (green,
//     amber, violet), a dashed outline (unknown) or none (malicious, not
//     checked) is the second cue, so hue is never the only channel.
//   - The mark is drawn flat in one colour: brand violet on the green, amber and
//     checking tiles, white on the red tile, the violet at reduced strength on
//     unknown, grey at reduced strength on not checked.
//   - The short text badge (check, !, STOP, ?, ...) is set by the background
//     script, not drawn here. Only the live-check-off tile (`signedout`) keeps a
//     corner shape, a lock. `base` is the brand resting plate: the listing icon
//     and the pages' favicon.
// Pre-rendered PNGs keep setIcon behaviour identical across engines (no
// OffscreenCanvas).
//
// Pipeline, per state: tile SVG rendered at 512 -> HERO brand mark composited
// (the brand SILHOUETTE painted via its alpha mask, recoloured per state) ->
// lock overlay (signedout only) -> downsampled to 16/32/48/128. The per-state
// SVGs in assets/icons/ are self-contained design sources with the mark
// embedded.
//
// Requires ImageMagick ("convert"). The PNGs are checked in, so a normal build
// never needs this script; re-run it only when the icon design or the brand
// asset changes.

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
  line: "#0b1220",
  // The brand resting plate and the live-check-off plate.
  plateDark: "#12101f", // dark with a faint violet cast: the brand resting plate
  plateGray: "#1c2130", // signed-out: muted, protection still on-device
  rim: "#8a5cc7", // a faint Whisper-violet rim on the brand resting plate
  slate: "#94a3b8", // the lock on the signed-out tile
  // Tile grounds and outlines of the six redrawn states.
  groundBenign: "#0c3d2e", // ground of the green tile
  ringBenign: "#10b981", // ring of the green tile
  groundSuspicious: "#4a3105", // ground of the amber tile
  ringSuspicious: "#f59e0b", // ring of the amber tile
  groundMalicious: "#b8202a", // the solid red tile
  groundQuiet: "#1a1a2e", // ground of the unknown and not-checked tiles
  dashUnknown: "#8888a0", // dashed outline of the unknown tile
  groundChecking: "#1d1240", // ground of the checking tile
  ringChecking: "#7d5ce0", // ring of the checking tile
  // The MARK fills, drawn flat. Brand violet where it reads, white on the red
  // tile, quietened violet and grey where the tile says "no opinion".
  markViolet: "#8b6bff", // brand mark: green, amber and checking tiles, and base
  markVioletMuted: "#7d74ad", // signed-out: present but quietened
  markUnknown: "#6f57cb", // unknown: the brand violet at reduced strength
  markNeutral: "#55555d", // not checked: grey at reduced strength
  markWhite: "#ffffff", // malicious: on the red tile
};

/**
 * Every convert in this file strips metadata, and it is done HERE rather
 * than at the one call that happened to be the leak path.
 *
 * assets/logo.png carried Adobe XMP (CreatorTool, document GUIDs) and a
 * "Adobe ImageReady" Software tag. Nothing in this pipeline removed them, so
 * all eight generated SVGs froze a copy inside their embedded base64 PNG -
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
const markUnknown = join(WORK, "mark-unknown.png");
const markNeutral = join(WORK, "mark-neutral.png");
const markWhite = join(WORK, "mark-white.png");
recolorMark(C.markViolet, markViolet);
recolorMark(C.markVioletMuted, markVioletMuted);
recolorMark(C.markUnknown, markUnknown);
recolorMark(C.markNeutral, markNeutral);
recolorMark(C.markWhite, markWhite);

// 2) Tiles in the 64-unit design space. `plate()` is the inset brand plate
// (60 x 60, a faint violet rim on the calm one): it serves `base` and
// `signedout` only. `tile()` is the full-bleed square of the six redrawn
// states: a solid ring takes the outer 4 units (1 px at 16, 2 px at 32), a
// dashed outline is drawn over the ground as explicit strokes (the SVG renderer
// does not draw stroke-dasharray), and neither leaves the plain ground.
function plate(fill, { rim = false } = {}) {
  const rimEl = rim
    ? `<rect x="4" y="4" width="56" height="56" rx="14" fill="none" stroke="${C.rim}" stroke-width="1.5" opacity="0.45"/>`
    : "";
  return `<rect x="2" y="2" width="60" height="60" rx="16" fill="${fill}"/>${rimEl}`;
}

// Four corner arcs and one 16-unit dash centred on each side, 8-unit gaps.
const DASHES =
  "M2 16A14 14 0 0 1 16 2 M24 2H40 M48 2A14 14 0 0 1 62 16 M62 24V40 " +
  "M62 48A14 14 0 0 1 48 62 M40 62H24 M16 62A14 14 0 0 1 2 48 M2 40V24";
function tile(ground, { ring = null, dashed = null } = {}) {
  const full = (fill) => `<rect x="0" y="0" width="64" height="64" rx="16" fill="${fill}"/>`;
  if (ring) return full(ring) + `<rect x="4" y="4" width="56" height="56" rx="12" fill="${ground}"/>`;
  if (dashed) return full(ground) + `<path d="${DASHES}" fill="none" stroke="${dashed}" stroke-width="4"/>`;
  return full(ground);
}

// The corner shape of the live-check-off tile. Every other state is told apart
// by tile, outline and the text badge the background script sets.
const BADGES = {
  signedout: `<rect x="39" y="40" width="19" height="18" rx="5" fill="#2a3040" stroke="${C.line}" stroke-width="2"/>
    <path d="M42 40 v-2 a6 6 0 0 1 12 0 v2" fill="none" stroke="${C.slate}" stroke-width="2.6" stroke-linecap="round"/>
    <circle cx="48.5" cy="49" r="2.4" fill="${C.slate}"/>`,
};

// state -> { plate, badge, mark, lift }. The tile carries the signal. Rows
// marked `lift` keep the mark 2 units above centre, clear of the lock.
const STATES = {
  base: { plate: plate(C.plateDark, { rim: true }), badge: "", mark: markViolet, lift: true }, // listing icon and favicon: the brand resting plate
  signedout: { plate: plate(C.plateGray), badge: BADGES.signedout, mark: markVioletMuted, lift: true }, // on-device protection still on; sign in for the live signal
  neutral: { plate: tile(C.groundQuiet), badge: "", mark: markNeutral }, // a page Guard does not check
  benign: { plate: tile(C.groundBenign, { ring: C.ringBenign }), badge: "", mark: markViolet },
  suspicious: { plate: tile(C.groundSuspicious, { ring: C.ringSuspicious }), badge: "", mark: markViolet },
  malicious: { plate: tile(C.groundMalicious), badge: "", mark: markWhite },
  unknown: { plate: tile(C.groundQuiet, { dashed: C.dashUnknown }), badge: "", mark: markUnknown },
  checking: { plate: tile(C.groundChecking, { ring: C.ringChecking }), badge: "", mark: markViolet },
};

// HERO mark geometry: 44 of 64 units, centred on the redrawn tiles and lifted
// 2 units on the rows marked `lift`, so the lock keeps clear ground at the
// bottom-right.
const MARK_W = Math.round((44 / 64) * BASE);
const MARK_DY = Math.round((-2 / 64) * BASE);

function svgAt(body, px) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 64 64">${body}</svg>`;
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
    convert([composedPath, "-resize", `${size}x${size}`, out]);
  }

  // Self-contained design source: the same layers, mark embedded inline.
  const markB64 = readFileSync(markResized).toString("base64");
  const markUnits = 44;
  const markUnitsH = (markUnits * markSrcH) / markSrcW;
  const markSvg = `<image x="${32 - markUnits / 2}" y="${(spec.lift ? 31 : 32) - markUnitsH / 2}" width="${markUnits}" href="data:image/png;base64,${markB64}"/>`;
  writeFileSync(join(SVG_DIR, `${state}.svg`), svgAt(spec.plate + markSvg + spec.badge, 128));

  console.log(`gen-icons: ${state} -> ${SIZES.map((s) => `${s}px`).join(", ")}`);
}

rmSync(WORK, { recursive: true, force: true });
console.log(`gen-icons: wrote ${Object.keys(STATES).length} SVGs + ${Object.keys(STATES).length * SIZES.length} PNGs from the brand mark`);
