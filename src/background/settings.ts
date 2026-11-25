// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Settings with sensible defaults, stored locally, never synced.

import { normalizeTheme } from "../shared/theme-choice";
import { DEFAULT_SETTINGS, type Settings } from "../shared/types";

let cached: Settings | null = null;

export async function getSettings(): Promise<Settings> {
  if (cached) return cached;
  let next: Settings;
  try {
    const stored = (await chrome.storage.local.get("settings"))["settings"];
    next = { ...DEFAULT_SETTINGS, ...(stored && typeof stored === "object" ? stored : {}) };
    // A stored value that is not a choice reads as Auto.
    next.theme = normalizeTheme(next.theme);
  } catch {
    next = { ...DEFAULT_SETTINGS };
  }
  cached = next;
  return next;
}

// Writes run one after another. Each is a read, a merge and a write, and the
// cache is dropped on every storage change, so two writes in flight could both
// read the same stored copy and the later one would lose the earlier one's patch.
let writes: Promise<unknown> = Promise.resolve();

export function setSettings(patch: Partial<Settings>): Promise<Settings> {
  const run = writes.then(async () => {
    const current = await getSettings();
    // Only a plain object is a patch: spreading a string or an array would store its indexes as keys.
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return current;
    const next = { ...current, ...patch };
    if ("theme" in patch) next.theme = normalizeTheme(patch.theme);
    cached = next;
    try {
      await chrome.storage.local.set({ settings: next });
    } catch {
      // memory-only fallback
    }
    return next;
  });
  writes = run.catch(() => undefined);
  return run;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes["settings"]) cached = null;
});
