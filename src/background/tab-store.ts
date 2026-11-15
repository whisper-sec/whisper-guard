// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Each tab's settled state, mirrored to storage.session so it survives the
// browser stopping the idle MV3 service worker (about 30 s). Without it the
// popup read an empty map after a wake and said "Nothing to check on this
// page" on a site that had been checked.
//
// What is stored: the TabState the worker already holds (a hostname, a
// verdict, the icon). Never a URL. storage.session is in memory, cleared when
// the browser restarts, and closed to page-injected layers by default.
//
// Private-window tabs are never written: the answer comes from
// tabs.get(...).incognito, which needs no "tabs" permission, and a lookup that
// fails does not write (fail closed).

import { ext } from "../shared/api";
import type { TabState } from "../shared/types";

const key = (tabId: number): string => `tabState:${tabId}`;
const STATE_PREFIX = "tabState:";

// tabId -> is it a private-window tab. A tab never changes window kind.
const privateTab = new Map<number, boolean>();

async function isPrivate(tabId: number): Promise<boolean | null> {
  const known = privateTab.get(tabId);
  if (known !== undefined) return known;
  try {
    const tab = await ext.tabs.get(tabId);
    if (typeof tab.incognito !== "boolean") return null; // unknown: fail closed
    privateTab.set(tabId, tab.incognito);
    return tab.incognito;
  } catch {
    return null;
  }
}

/**
 * Save a settled state. `stillCurrent` is re-checked after the window lookup
 * and immediately before the write, so a navigation that committed meanwhile
 * (and cleared the key) is never overwritten by the page it left.
 */
export async function saveTabState(
  tabId: number,
  state: TabState,
  stillCurrent: () => boolean,
): Promise<void> {
  const priv = await isPrivate(tabId);
  if (priv !== false) return; // private, or unknown: never write
  if (!stillCurrent()) return;
  try {
    await ext.storage.session.set({ [key(tabId)]: state });
  } catch {
    // session storage unavailable: memory-only is fine.
  }
}

export async function readTabState(tabId: number): Promise<TabState | null> {
  try {
    const v = (await ext.storage.session.get(key(tabId)))[key(tabId)];
    return v && typeof v === "object" ? (v as TabState) : null;
  } catch {
    return null;
  }
}

/** Drop the saved state only: a committed navigation invalidates it. */
export async function clearTabState(tabId: number): Promise<void> {
  try {
    await ext.storage.session.remove(key(tabId));
  } catch {
    // nothing to clear
  }
}

/**
 * Drop every saved tab state (an account change: each was an answer from the
 * earlier tier). Only `tabState:` keys: the verdict mirror follows its own rules.
 */
export async function clearAllTabStates(): Promise<void> {
  try {
    const all = await ext.storage.session.get(null);
    const keys = Object.keys(all).filter((k) => k.startsWith(STATE_PREFIX));
    if (keys.length > 0) await ext.storage.session.remove(keys);
  } catch {
    // nothing to clear
  }
}

/** The tab closed: drop the saved state and what was remembered about it. */
export async function forgetTabState(tabId: number): Promise<void> {
  privateTab.delete(tabId);
  await clearTabState(tabId);
}
