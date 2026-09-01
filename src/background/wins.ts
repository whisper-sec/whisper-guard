// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The local, keyless daily-wins tally: what Guard quietly handled
// today, counted so the human can SEE the value without ever being nagged
// about it.
//
// Privacy, by construction: these are POLICY EVENTS, NOT BROWSING. The
// only thing this module can store is a category name and a count: the
// API accepts nothing else, so no URL, domain, or hostname can ever land
// here. The record lives in chrome.storage.local (it survives MV3
// service-worker restarts) and is keyed by the local calendar date, so it
// resets daily on its own with nothing to clean up.
//
// Calm, by construction: recording a win raises NO UI: no toast, no
// badge, no notification (the extension holds no notifications permission
// at all). On the escalation ladder (shared/escalation.ts) the "win"
// moment is silent at every severity; the tally shows in exactly one
// place, the popup's "today" card, on the user's own click.

import { WIN_CATEGORIES, type WinCategory, type WinsToday } from "../shared/types";

const KEY = "wins";

function today(): string {
  const d = new Date();
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function zeroCounts(): Record<WinCategory, number> {
  return { preemptBlock: 0, identityVerified: 0, cookieDecline: 0 };
}

async function read(): Promise<WinsToday> {
  let stored: unknown;
  try {
    stored = (await chrome.storage.local.get(KEY))[KEY];
  } catch {
    stored = undefined;
  }
  const date = today();
  const counts = zeroCounts();
  if (stored && typeof stored === "object") {
    const rec = stored as { date?: unknown; counts?: unknown };
    // A record from an earlier day simply reads as zeros: the daily reset
    // is the date key itself, no timer or cleanup involved.
    if (rec.date === date && rec.counts && typeof rec.counts === "object") {
      for (const c of WIN_CATEGORIES) {
        const v = (rec.counts as Record<string, unknown>)[c];
        if (typeof v === "number" && Number.isFinite(v) && v > 0) counts[c] = Math.floor(v);
      }
    }
  }
  const total = WIN_CATEGORIES.reduce((sum, c) => sum + counts[c], 0);
  return { date, total, counts };
}

// Writes serialize on one chain so two wins landing together never lose an
// increment to a read-modify-write race.
let chain: Promise<void> = Promise.resolve();

function enqueue(mutate: (cur: WinsToday) => boolean): Promise<void> {
  chain = chain
    .then(async () => {
      const cur = await read();
      if (!mutate(cur)) return;
      await chrome.storage.local.set({ [KEY]: { date: cur.date, counts: cur.counts } });
    })
    .catch(() => {
      // Storage unavailable: the tally is best-effort by design. Counting
      // must never interfere with protecting.
    });
  return chain;
}

/** Count one quiet win. Category only: nothing else can be recorded. */
export function recordWin(category: WinCategory): Promise<void> {
  return enqueue((cur) => {
    cur.counts[category] += 1;
    return true;
  });
}

/**
 * Count a win at most ONCE per calendar day. For facts observed at display
 * time (the popup and dashboard re-verify the browser's identity on every
 * open), a repeat confirmation the same day is the same fact re-rendered,
 * not a new protective event, so it must not inflate the tally. The dedup
 * key is the day's own count: no address, hostname, or any identifier is
 * stored to achieve it, keeping the record date + counts and nothing else.
 */
export function recordWinOnce(category: WinCategory): Promise<void> {
  return enqueue((cur) => {
    if (cur.counts[category] > 0) return false; // today's win already stands
    cur.counts[category] += 1;
    return true;
  });
}

/** Today's tally for the popup card. */
export function getWins(): Promise<WinsToday> {
  return read();
}
