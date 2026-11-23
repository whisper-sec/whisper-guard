// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Per-tab toolbar icon painting from pre-rendered PNG state sets (no
// OffscreenCanvas: identical behaviour on every engine). One paint sets a
// pre-rendered tile, a short text badge and the title; states differ in tile
// colour, outline and badge text, so hue is never the only channel.

import { ext } from "../shared/api";
import type { GraphBand, IconState } from "../shared/types";
import { TOOLBAR_BADGE, type ToolbarBadge } from "../shared/toolbar-badge";

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
 * Set the tab's badge: ground, text colour, then text. A state without a badge
 * clears the text and never relies on the browser having reset it. Every call
 * has its own guard, so a failed badge call never stops the title that follows.
 * Never throws.
 */
async function paintBadge(
  tabId: number,
  badge: ToolbarBadge | null,
  superseded: () => boolean,
): Promise<void> {
  if (badge) {
    if (superseded()) return;
    try {
      await ext.action.setBadgeBackgroundColor({ tabId, color: badge.ground });
    } catch {
      // best-effort
    }
    if (superseded()) return;
    // Without the call the browser picks a contrasting text colour itself.
    if (typeof ext.action.setBadgeTextColor === "function") {
      try {
        await ext.action.setBadgeTextColor({ tabId, color: badge.ink });
      } catch {
        // best-effort
      }
    }
    if (superseded()) return;
  }
  try {
    await ext.action.setBadgeText({ tabId, text: badge ? badge.text : "" });
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
    await paintBadge(tabId, TOOLBAR_BADGE[state], superseded);
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
