// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Compose the Chrome Web Store screenshots from the raw gallery captures:
//   shots/<name>.png  ->  store/cws-screenshots/<NN>-<name>.png
//
// The CWS accepts screenshots at exactly 1280x800, but the raw captures are
// native-sized (a 390px popup, a 1180px dashboard), so each one is scaled to
// the shared 675px panel height and centred on the brand canvas.
//
// This step used to live outside the repo, which is how the store screenshots
// came to show a stale endpoint in their privacy footer while the code had
// already moved on: nothing regenerated them, so nobody noticed. Keeping the
// compositing here means the store assets are reproducible from the build.
//
// Usage: node scripts/frame-store-shots.mjs [name ...]   (default: all mapped)
//
// Requires python3 with Pillow on PATH, which is a local-dev prerequisite and
// deliberately not an npm dependency: this runs only when a maintainer
// regenerates store assets, never in CI and never in the shipped build, so
// adding an image library to the extension's dependency tree for it would be
// the wrong trade.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// Raw capture -> store filename. Only surfaces we actually submit.
// The three page-scale surfaces use their own STORE captures, taken at the
// store's own 1280x800 aspect. Framing a tall full-page capture instead
// scaled it down to a 531px-wide strip with black either side and nothing
// legible in it - which is what shipped, because nobody looked at the framed
// result.
const MAP = {
  "toolbar-states": "01-toolbar-states",
  "popup-keyed-malicious": "02-popup-keyed-malicious",
  "dashboard-this-browser-store": "03-dashboard-this-browser",
  "warning-store": "04-warning",
  "dashboard-endpoint-store": "05-dashboard-endpoint",
};

const wanted = process.argv.slice(2);
const names = wanted.length ? wanted : Object.keys(MAP);
for (const n of names) {
  if (!MAP[n]) {
    console.error(`frame-store-shots: unknown capture "${n}"; known: ${Object.keys(MAP).join(", ")}`);
    process.exit(1);
  }
}

const pairs = [];
for (const n of names) {
  const src = join(ROOT, "shots", `${n}.png`);
  if (!existsSync(src)) {
    console.error(`frame-store-shots: missing ${src}; run npx playwright test e2e/screenshots.spec.ts first`);
    process.exit(1);
  }
  pairs.push(src, join(ROOT, "store", "cws-screenshots", `${MAP[n]}.png`));
}

// The canvas is a radial gradient. Rather than re-guess its maths, sample the
// real profile from an existing composite and extrapolate only the small
// central disc that every panel covers anyway.
const PY = `
import math, sys
from PIL import Image

W, H = 1280, 800
PANEL_TOP, PANEL_H = 62, 675
BORDER = (60, 52, 80)
REF = sys.argv[1]

def profile(ref):
    # Every panel occupies the same vertical band, so the strips above and
    # below it are background in any composite. Sampling only those keeps this
    # independent of how wide the reference screenshot's panel happens to be.
    im = Image.open(ref).convert('RGB'); px = im.load()
    cx, cy = (W - 1) / 2, (H - 1) / 2
    acc = {}
    for y in list(range(0, PANEL_TOP - 1)) + list(range(PANEL_TOP + PANEL_H + 1, H)):
        for x in range(W):
            d = int(round(math.hypot(x - cx, y - cy)))
            r, g, b = px[x, y]
            a = acc.setdefault(d, [0, 0, 0, 0])
            a[0] += r; a[1] += g; a[2] += b; a[3] += 1
    lut = {d: (a[0] / a[3], a[1] / a[3], a[2] / a[3]) for d, a in acc.items()}
    ds = sorted(lut); n = len(ds)
    sx = sum(ds); sxx = sum(d * d for d in ds)
    slope, inter = [], []
    for c in range(3):
        sy = sum(lut[d][c] for d in ds)
        sxy = sum(d * lut[d][c] for d in ds)
        m = (n * sxy - sx * sy) / (n * sxx - sx * sx)
        slope.append(m); inter.append((sy - m * sx) / n)
    return lut, slope, inter

def canvas(lut, slope, inter):
    im = Image.new('RGB', (W, H)); px = im.load()
    cx, cy = (W - 1) / 2, (H - 1) / 2
    cache = {}
    for y in range(H):
        for x in range(W):
            d = int(round(math.hypot(x - cx, y - cy)))
            if d not in cache:
                c = lut[d] if d in lut else tuple(inter[k] + slope[k] * d for k in range(3))
                cache[d] = tuple(max(0, min(255, int(round(v)))) for v in c)
            px[x, y] = cache[d]
    return im

lut, slope, inter = profile(REF)
args = sys.argv[2:]
for src, dst in zip(args[0::2], args[1::2]):
    raw = Image.open(src).convert('RGB')
    pw = max(1, int(round(raw.width * (PANEL_H / raw.height))))
    panel = raw.resize((pw, PANEL_H), Image.LANCZOS)
    out = canvas(lut, slope, inter)
    bordered = Image.new('RGB', (pw + 2, PANEL_H + 2), BORDER)
    bordered.paste(panel, (1, 1))
    out.paste(bordered, ((W - pw) // 2 - 1, PANEL_TOP - 1))
    out.save(dst)
    print('framed %s -> %s (panel %dx%d)' % (src.split('/')[-1], dst.split('/')[-1], pw, PANEL_H))
`;

const ref = join(ROOT, "store", "cws-screenshots", "01-toolbar-states.png");
execFileSync("python3", ["-c", PY, ref, ...pairs], { stdio: "inherit" });
