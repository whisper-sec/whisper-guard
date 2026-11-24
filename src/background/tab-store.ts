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
// Nothing is written for a private-window tab: the answer comes from
// tabs.get(...).incognito, which needs no "tabs" permission, and a lookup that
// fails does not write (fail closed).
//
// A second, smaller record lives beside it: that Guard declined a cookie prompt
// on the tab's current page (shared/tab-flags.ts). It is the value `true` under
// a key made from the tab id alone, with no host and no URL. The same rules
// hold: written only for a tab known to be in a normal window, dropped when the
// tab commits a new page and when it closes. An account change leaves it be.

import { ext } from "../shared/api";
import { cookieDeclinedKey } from "../shared/tab-flags";
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
 * True only for a tab known to be in a normal window. A private-window tab, or
 * a tab whose window kind cannot be read, writes nothing on this device.
 */
export async function mayKeepForTab(tabId: number): Promise<boolean> {
  return (await isPrivate(tabId)) === false;
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

/**
 * Record that Guard declined a cookie prompt on this tab's current page. Like
 * saveTabState it writes only for a tab known to be in a normal window, and only
 * while `stillCurrent` holds, so a page that was already left is never marked.
 */
export async function markCookieDeclined(tabId: number, stillCurrent: () => boolean): Promise<void> {
  const priv = await isPrivate(tabId);
  if (priv !== false) return; // private, or unknown: never write
  if (!stillCurrent()) return;
  try {
    await ext.storage.session.set({ [cookieDeclinedKey(tabId)]: true });
  } catch {
    // session storage unavailable: nothing is kept, and the popup shows no line.
  }
}

/** Drop the declined-prompt record: a new page starts without one. */
export async function clearCookieDeclined(tabId: number): Promise<void> {
  try {
    await ext.storage.session.remove(cookieDeclinedKey(tabId));
  } catch {
    // nothing to clear
  }
}

/** The tab closed: drop the saved state and what was remembered about it. */
export async function forgetTabState(tabId: number): Promise<void> {
  privateTab.delete(tabId);
  await clearTabState(tabId);
  await clearCookieDeclined(tabId);
}
