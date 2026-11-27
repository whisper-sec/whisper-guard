// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The sign-in ask after a held click (board 4e), background half.
//
// When Guard holds a click and the reader goes back, the next popup open on
// that page, for a signed-out reader, leads with one card. This module keeps
// what that card needs and decides, in one step, whether it shows.
//
// Privacy, by construction: the held click is kept as a hostname in
// storage.session, one key per tab. That store is this browser's, ends with
// the browser session, and is never synced. Nothing here is sent anywhere, the
// wins record never learns a host (it stays category and count), and a tab in
// a private window never gets a record. No browser notification is involved:
// the card exists only inside the popup, on the reader's own click.
//
// Once per install: the flag lives in storage.local and is set in the same
// step that answers the ask, so two popups opening together cannot both show it.

import type { SigninAsk } from "../shared/types";
import { hasKey } from "./graph-client";
import { getWins } from "./wins";

const SHOWN_KEY = "signinAskShown";
const heldKey = (tabId: number): string => `heldClick:${tabId}`;

/** What Guard held on a tab's current page. */
interface HeldClick {
  /** The latest held host, its band and its label. */
  host: string;
  band: string;
  label: string | null;
  /** Clicks held on this page since the last Proceed. */
  count: number;
  /** The reader went back from the latest held click. */
  wentBack: boolean;
  /** The reader went back from every held click on this page. */
  eachTime: boolean;
}

function isHeld(v: unknown): v is HeldClick {
  if (!v || typeof v !== "object") return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r["host"] === "string" &&
    typeof r["band"] === "string" &&
    (r["label"] === null || typeof r["label"] === "string") &&
    typeof r["count"] === "number" &&
    typeof r["wentBack"] === "boolean" &&
    typeof r["eachTime"] === "boolean"
  );
}

// Each step below reads a record and writes it back, so two that overlapped
// would keep one of the edits. They run in the order they were asked for.
let last: Promise<unknown> = Promise.resolve();
function inOrder<T>(step: () => Promise<T>): Promise<T> {
  const run = last.then(step, step);
  last = run.catch(() => undefined);
  return run;
}

async function read(tabId: number): Promise<HeldClick | null> {
  try {
    const v = (await chrome.storage.session.get(heldKey(tabId)))[heldKey(tabId)];
    return isHeld(v) ? v : null;
  } catch {
    return null;
  }
}

async function write(tabId: number, rec: HeldClick): Promise<void> {
  try {
    await chrome.storage.session.set({ [heldKey(tabId)]: rec });
  } catch {
    // Best-effort: with no record the ask simply does not show.
  }
}

async function drop(tabId: number): Promise<void> {
  try {
    await chrome.storage.session.remove(heldKey(tabId));
  } catch {
    // Best-effort.
  }
}

/** Guard held a click on this tab's page. The caller passes only a normal-window tab. */
export function noteHeld(tabId: number, held: { host: string; band: string; label: string | null }): Promise<void> {
  return inOrder(async () => {
    const prev = await read(tabId);
    await write(tabId, {
      host: held.host,
      band: held.band,
      label: held.label,
      count: (prev?.count ?? 0) + 1,
      wentBack: false,
      // A hold that was left without going back (or proceeding) means "each time" no longer holds.
      eachTime: prev ? prev.eachTime && prev.wentBack : true,
    });
  });
}

/** The reader went back from the latest held click. Another host, or no record, marks nothing. */
export function noteWentBack(tabId: number, host: string): Promise<void> {
  return inOrder(async () => {
    const rec = await read(tabId);
    if (!rec || rec.host !== host.replace(/\.$/, "").toLowerCase() || rec.wentBack) return;
    await write(tabId, { ...rec, wentBack: true });
  });
}

/** Proceed anyway, a new page in the tab, or the tab closing: the record is gone. */
export function forgetHeld(tabId: number): Promise<void> {
  return inOrder(() => drop(tabId));
}

/**
 * The popup's one question. Answers the ask only for a signed-out reader, when
 * it was never shown on this install and this tab's held click was gone back
 * from; setting the flag happens in the same step. A signed-in reader never
 * gets it, and that counts as shown: after a sign-in it does not come back.
 */
export function takeSigninAsk(tabId: number): Promise<SigninAsk | null> {
  return inOrder(async () => {
    let shown = false;
    try {
      shown = (await chrome.storage.local.get(SHOWN_KEY))[SHOWN_KEY] === true;
    } catch {
      return null;
    }
    if (shown) return null;
    const markShown = async (): Promise<void> => {
      await chrome.storage.local.set({ [SHOWN_KEY]: true });
    };
    if (await hasKey()) {
      await markShown().catch(() => undefined);
      return null;
    }
    const rec = await read(tabId);
    if (!rec || !rec.wentBack) return null;
    try {
      await markShown();
    } catch {
      // The flag could not be kept: showing it could repeat, so it does not show.
      return null;
    }
    return {
      host: rec.host,
      band: rec.band,
      label: rec.label,
      count: rec.count,
      eachTime: rec.eachTime,
      today: await getWins(),
    };
  });
}
