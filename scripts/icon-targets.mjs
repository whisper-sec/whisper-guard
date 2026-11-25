// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Which toolbar icon files the generator may write. The five verdict tiles are
// designer art, committed as delivered; their masters carry dashes that
// ImageMagick drops when it re-rasterises them. The guard throws before any
// write whose target is not a generated state's tile or master, and refuses a
// symlink or a folder that resolves elsewhere.

import { lstatSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export const SIZES = Object.freeze([16, 32, 48, 128]);
/** States gen-icons.mjs draws. */
export const GENERATED_STATES = Object.freeze(["base", "neutral", "signedout"]);
/** States whose tiles and masters are designer art. */
export const VERDICT_STATES = Object.freeze(["benign", "suspicious", "malicious", "unknown", "checking"]);

const DEFAULT_DIRS = Object.freeze({ png: join(ROOT, "icons"), svg: join(ROOT, "assets", "icons") });

/** The real path of a folder; a folder that does not exist yet keeps its resolved path. */
function real(dir) {
  try {
    return realpathSync(dir);
  } catch {
    return resolve(dir);
  }
}

/**
 * Throw unless `path` is `icons/<generated>-<size>.png` or
 * `assets/icons/<generated>.svg`, is not a symlink, and sits in the real folder.
 * `dirs` exists so a test can aim the guard at a temporary copy.
 */
export function assertGeneratedTarget(path, dirs = DEFAULT_DIRS) {
  const full = resolve(path);
  const name = basename(full);
  const dir = real(dirname(full));
  const states = GENERATED_STATES;
  const okPng = dir === real(dirs.png) && states.some((s) => SIZES.some((z) => name === `${s}-${z}.png`));
  const okSvg = dir === real(dirs.svg) && states.some((s) => name === `${s}.svg`);
  const isLink = lstatSync(full, { throwIfNoEntry: false })?.isSymbolicLink() === true;
  if ((!okPng && !okSvg) || isLink) {
    throw new Error(
      `gen-icons: refusing to write ${path}: only ${states.join(", ")} tiles and masters are generated, as plain files; the verdict tiles are designer art`,
    );
  }
}
