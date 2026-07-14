// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Per-tab toolbar icon painting from pre-rendered PNG state sets (no
// OffscreenCanvas: identical behaviour on every engine). Each band/state is
// redundantly encoded in the art itself (ring color + badge shape + ring
// style, filled red plate reserved for malicious) so hue is never the only
// channel. A short badge pulse marks the first sighting of a risky host;
// the icon itself never flashes.

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

const lastState = new Map<number, IconState>();

export async function paintIcon(tabId: number, state: IconState): Promise<void> {
  if (lastState.get(tabId) === state) return;
  lastState.set(tabId, state);
  try {
    await ext.action.setIcon({ tabId, path: paths(state) });
    const titles: Record<IconState, string> = {
      benign: "Whisper Guard: no known threat on this site",
      suspicious: "Whisper Guard: be careful on this site",
      malicious: "Whisper Guard: STOP, this site is a known threat",
      unknown: "Whisper Guard: new or low-coverage site, not confirmed either way",
      checking: "Whisper Guard: checking this site",
      signedout: "Whisper Guard: on-device protection active; sign in for the live signal",
      neutral: "Whisper Guard",
    };
    await ext.action.setTitle({ tabId, title: titles[state] });
  } catch {
    // The tab may be gone; painting is best-effort by design.
  }
}

/** One brief badge pulse on the first sighting of a risky host. */
export async function pulseBadge(tabId: number, color: string): Promise<void> {
  try {
    await ext.action.setBadgeBackgroundColor({ tabId, color });
    await ext.action.setBadgeText({ tabId, text: "!" });
    setTimeout(() => {
      ext.action.setBadgeText({ tabId, text: "" }).catch(() => undefined);
    }, 900);
  } catch {
    // best-effort
  }
}

export function forgetTab(tabId: number): void {
  lastState.delete(tabId);
}
