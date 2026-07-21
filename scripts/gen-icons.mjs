// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Toolbar icon state sets, built from the REAL Whisper brand mark: the
// interlocking-rings mark is extracted programmatically from assets/logo.png
// (the canonical brand asset) so the shape is always the brand, never a
// letterform.
//
// Design (whisper-guard#18): the WHOLE ICON signals, not a thin ring.
//   - The brand is the RESTING state: a HERO-sized Whisper-violet mark on a
//     dark brand plate (states `neutral`/`base`/`benign`). The mark keeps the
//     brand violet in every calm state.
//   - The PLATE BACKGROUND carries the signal: it stays dark for the calm
//     states and turns AMBER (suspicious) then RED (malicious); the mark flips
//     to a high-contrast fill ONLY on those alarm plates, where brand violet
//     would be illegible. "Keep the brand colour except when really needed to
//     signal."
//   - Hue is still never load-bearing: every state also carries a corner
//     BADGE SHAPE (check / triangle / STOP octagon / hollow circle / dot /
//     lock), the redundant non-colour channel.
// Pre-rendered PNGs keep setIcon behaviour identical across engines (no
// OffscreenCanvas).
//
// Pipeline, per state: plate SVG rendered at 512 -> HERO brand mark composited
// (the brand SILHOUETTE painted via its alpha mask, recoloured per state) ->
// badge overlay -> downsampled to 16/32/48/128. The per-state SVGs in
// assets/icons/ are self-contained design sources with the mark embedded.
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
  // Plates (the signal background). Calm states share a dark brand plate; the
  // alarm states own a full-bleed amber / red plate; the off states are muted.
  plateDark: "#12101f", // dark with a faint violet cast: the brand resting plate
  plateSlate: "#2b3446", // unknown: no-opinion slate, clearly not an alarm
  plateAmber: "#c2760a", // suspicious: a deep, legible amber
  plateRed: "#c81e1e", // malicious: the strongest signal
  plateGray: "#1c2130", // signed-out: muted, protection still on-device
  plateRedDark: "#7f1d1d",
  rim: "#8a5cc7", // theme --w-accent: a faint Whisper-violet rim for polish
  green: "#10b981",
  amber: "#f59e0b",
  slate: "#94a3b8",
  faint: "#64748b",
  // The MARK fills. The brand headline colour is a bold, bright Whisper
  // purple; it stays brand in every calm state and flips only where a coloured
  // alarm plate would drown it.
  markViolet: "#8b6bff", // brand (neutral / benign / checking)
  markVioletMuted: "#7d74ad", // unknown / signed-out: present but quietened
  markDark: "#1a1205", // suspicious: high-contrast on the amber plate
  markWhite: "#ffffff", // malicious: on the red plate
};

const convert = (args) => execFileSync("convert", args);
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
const markDark = join(WORK, "mark-dark.png");
const markWhite = join(WORK, "mark-white.png");
recolorMark(C.markViolet, markViolet);
recolorMark(C.markVioletMuted, markVioletMuted);
recolorMark(C.markDark, markDark);
recolorMark(C.markWhite, markWhite);

// 2) Plate + badge in the 64-unit design space. The plate is full-bleed (no
// ring stealing space from the hero mark); a faint violet rim adds brand
// polish on the calm plates only.
function plate(fill, { rim = false } = {}) {
  const rimEl = rim
    ? `<rect x="4" y="4" width="56" height="56" rx="14" fill="none" stroke="${C.rim}" stroke-width="1.5" opacity="0.45"/>`
    : "";
  return `<rect x="2" y="2" width="60" height="60" rx="16" fill="${fill}"/>${rimEl}`;
}

function octagonPoints(cx, cy, r) {
  const pts = [];
  for (let i = 0; i < 8; i++) {
    const a = (Math.PI / 4) * i + Math.PI / 8;
    pts.push(`${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(" ");
}

// Corner badges (the non-hue redundant channel). On a coloured alarm plate the
// badge is white-bodied with a dark rim so it reads on amber / red; on the calm
// dark plates it keeps its own semantic colour.
const BADGES = {
  benign: `<rect x="38" y="38" width="21" height="21" rx="6" fill="${C.green}" stroke="${C.line}" stroke-width="2"/>
    <path d="M43 48.5 L47 52.5 L54.5 44.5" fill="none" stroke="#ffffff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>`,
  suspicious: `<polygon points="48,35 61,59 35,59" fill="#ffffff" stroke="${C.line}" stroke-width="2" stroke-linejoin="round"/>
    <rect x="46.6" y="43" width="2.8" height="8" rx="1.4" fill="${C.plateAmber}"/><circle cx="48" cy="55" r="1.7" fill="${C.plateAmber}"/>`,
  malicious: `<polygon points="${octagonPoints(48, 48, 12)}" fill="#ffffff" stroke="${C.plateRedDark}" stroke-width="2"/>`,
  unknown: `<circle cx="48" cy="48" r="9.5" fill="${C.plateSlate}" stroke="${C.slate}" stroke-width="3.5"/>`,
  checking: `<circle cx="49" cy="49" r="5.5" fill="#cbd5e1" stroke="${C.line}" stroke-width="1.5"/>`,
  signedout: `<rect x="39" y="40" width="19" height="18" rx="5" fill="#2a3040" stroke="${C.line}" stroke-width="2"/>
    <path d="M42 40 v-2 a6 6 0 0 1 12 0 v2" fill="none" stroke="${C.slate}" stroke-width="2.6" stroke-linecap="round"/>
    <circle cx="48.5" cy="49" r="2.4" fill="${C.slate}"/>`,
};

// state -> { plate, badge, mark }. The plate carries the signal; the mark keeps
// the brand violet in every calm state and flips only on the amber / red plate.
const STATES = {
  neutral: { plate: plate(C.plateDark, { rim: true }), badge: "", mark: markViolet }, // brand resting (signed in, no verdict yet)
  base: { plate: plate(C.plateDark, { rim: true }), badge: "", mark: markViolet }, // extension-listing identity icon = the brand resting
  benign: { plate: plate(C.plateDark, { rim: true }), badge: BADGES.benign, mark: markViolet }, // safe is calm: brand plate + a quiet green check
  suspicious: { plate: plate(C.plateAmber), badge: BADGES.suspicious, mark: markDark },
  malicious: { plate: plate(C.plateRed), badge: BADGES.malicious, mark: markWhite },
  unknown: { plate: plate(C.plateSlate), badge: BADGES.unknown, mark: markVioletMuted },
  checking: { plate: plate(C.plateDark), badge: BADGES.checking, mark: markVioletMuted },
  signedout: { plate: plate(C.plateGray), badge: BADGES.signedout, mark: markVioletMuted }, // on-device protection still on; sign in for the live signal
};

// HERO mark geometry: 44 of 64 units (was 34), lifted 2 units so the corner
// badge keeps clear ground at the bottom-right.
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
  const markB64 = readFileSync(markResized).toString("base64");
  const markUnits = 44;
  const markUnitsH = (markUnits * markSrcH) / markSrcW;
  const markSvg = `<image x="${32 - markUnits / 2}" y="${31 - markUnitsH / 2}" width="${markUnits}" href="data:image/png;base64,${markB64}"/>`;
  writeFileSync(join(SVG_DIR, `${state}.svg`), svgAt(spec.plate + markSvg + spec.badge, 128));

  console.log(`gen-icons: ${state} -> ${SIZES.map((s) => `${s}px`).join(", ")}`);
}

rmSync(WORK, { recursive: true, force: true });
console.log(`gen-icons: wrote ${Object.keys(STATES).length} SVGs + ${Object.keys(STATES).length * SIZES.length} PNGs from the brand mark`);
