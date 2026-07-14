// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Settings with sensible defaults, stored locally, never synced.

import { DEFAULT_SETTINGS, type Settings } from "../shared/types";

let cached: Settings | null = null;

export async function getSettings(): Promise<Settings> {
  if (cached) return cached;
  let next: Settings;
  try {
    const stored = (await chrome.storage.local.get("settings"))["settings"];
    next = { ...DEFAULT_SETTINGS, ...(stored && typeof stored === "object" ? stored : {}) };
  } catch {
    next = { ...DEFAULT_SETTINGS };
  }
  cached = next;
  return next;
}

export async function setSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await getSettings();
  cached = { ...current, ...patch };
  try {
    await chrome.storage.local.set({ settings: cached });
  } catch {
    // memory-only fallback
  }
  return cached;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes["settings"]) cached = null;
});
