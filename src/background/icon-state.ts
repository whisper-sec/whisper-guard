// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Per-tab toolbar icon painting from pre-rendered PNG state sets (no
// OffscreenCanvas: identical behaviour on every engine). One paint sets a
// pre-rendered tile, clears the badge text and sets the title. The tile carries
// the whole signal: colour, outline and a drawn symbol, so hue is never the
// only channel. No state sets badge text or a badge colour.

import { ext } from "../shared/api";
import type { GraphBand, IconState } from "../shared/types";

const SIZES = [16, 32, 48, 128] as const;

function paths(state: IconState): Record<string, string> {
  const p: Record<string, string> = {};
  for (const s of SIZES) p[String(s)] = `icons/${state}-${s}.png`;
  return p;
}

export function bandToIcon(band: GraphBand): IconState {
  switch (band) {
    case "CRITICAL":
      return "malicious";
    case "HIGH":
    case "MEDIUM":
      return "suspicious";
    case "LOW":
    case "INFO":
    case "NONE":
      return "benign";
    case "UNKNOWN":
      return "unknown";
  }
}

// Mirrors what the browser currently shows for each tab. The browser resets
// per-tab action values on every cross-document main-frame commit, so the
// mirror must be forgotten at commit (forgetTab) as well as at tab close;
// otherwise an identical next paint is skipped and the mark stays default.
const lastState = new Map<number, IconState>();

const titles: Record<IconState, string> = {
  benign: "Whisper Guard: no known threat on this site",
  suspicious: "Whisper Guard: be careful on this site",
  malicious: "Whisper Guard: STOP, this site is a known threat",
  unknown: "Whisper Guard: new or low-coverage site, not confirmed either way",
  checking: "Whisper Guard: checking this site",
  signedout: "Whisper Guard: on-device protection active; sign in for the live signal",
  neutral: "Whisper Guard",
};

/**
 * Clear the tab's badge text. The tile draws the symbol, so nothing is added to
 * the badge; the clear stays so a paint never relies on the browser having reset
 * it. Never throws, so a failed clear never stops the title that follows.
 */
async function clearBadge(tabId: number): Promise<void> {
  try {
    await ext.action.setBadgeText({ tabId, text: "" });
  } catch {
    // best-effort
  }
}

export async function paintIcon(tabId: number, state: IconState): Promise<void> {
  if (lastState.get(tabId) === state) return;
  lastState.set(tabId, state);
  // A newer paint, or a commit that dropped the mirror, takes the tab over.
  const superseded = (): boolean => lastState.get(tabId) !== state;
  try {
    await ext.action.setIcon({ tabId, path: paths(state) });
    if (superseded()) return;
    await clearBadge(tabId);
    if (superseded()) return;
    // Last: tests and screen readers take the title as "the paint is done".
    await ext.action.setTitle({ tabId, title: titles[state] });
  } catch {
    // The tab may be gone; painting is best-effort by design.
  }
}

/** Drop the mirror: on tab close, and when a main frame commits (browser resets the icon). */
export function forgetTab(tabId: number): void {
  lastState.delete(tabId);
}
