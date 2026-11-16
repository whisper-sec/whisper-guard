// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The session's running list of risky hosts (for the popup's "This session"
// drawer and the optional badge count). Session-scoped storage only: it
// evaporates when the browser closes, is never synced, and never leaves
// the device.

import type { SessionRisk } from "../shared/types";

const MAX = 100;

export async function sessionRisks(): Promise<SessionRisk[]> {
  try {
    const stored = (await chrome.storage.session.get("risks"))["risks"];
    return Array.isArray(stored) ? (stored as SessionRisk[]) : [];
  } catch {
    return [];
  }
}

export async function recordRisk(host: string, reason: string): Promise<boolean> {
  const risks = await sessionRisks();
  if (risks.some((r) => r.host === host)) return false;
  risks.unshift({ host, reason, at: Date.now() });
  if (risks.length > MAX) risks.length = MAX;
  try {
    await chrome.storage.session.set({ risks });
  } catch {
    // best-effort
  }
  return true;
}

/*
 * One list change at a time. Each writer below reads a list, edits it and
 * writes it back, so two that overlapped would keep only one of the edits.
 * They run in the order they were asked for instead.
 */
let lastChange: Promise<void> = Promise.resolve();
function inOrder(change: () => Promise<void>): Promise<void> {
  const run = lastChange.then(change);
  lastChange = run.catch(() => undefined);
  return run;
}

/** Hosts the user chose to trust for this session only ("continue anyway"). */
export async function sessionAllowed(host: string): Promise<boolean> {
  try {
    const stored = (await chrome.storage.session.get("allowed"))["allowed"];
    return Array.isArray(stored) && (stored as string[]).includes(host.toLowerCase());
  } catch {
    return false;
  }
}

export function allowForSession(host: string): Promise<void> {
  const h = host.toLowerCase();
  return inOrder(async () => {
    try {
      const stored = (await chrome.storage.session.get("allowed"))["allowed"];
      const list = Array.isArray(stored) ? (stored as string[]) : [];
      if (!list.includes(h)) list.push(h);
      await chrome.storage.session.set({ allowed: list });
    } catch {
      // best-effort
    }
  });
}

/*
 * The session BLOCK ledger. A session block rule's id is a
 * non-reversible hash of its host, so the hosts cannot be read back out of the
 * rules themselves and this list is the only way back to them. Every writer of
 * such a rule marks here (addBlockRule for the Active-Shield redirect flavor,
 * addPreemptBlock for the no-grant BLOCK flavor) and removeBlockRule unmarks,
 * so the popup can show a "blocked this session" list and offer a per-host
 * clear. A session block must be discoverably reversible, and the no-grant
 * flavor most of all, because there it is a bare ERR_BLOCKED_BY_CLIENT with no
 * page to carry the way out.
 * Keyless, storage.session (worker-wake-durable, cleared with the session), the
 * exact shape as the allowed list above.
 */

/** Hosts blocked for this session by an evidenced pre-emptive interrupt. */
export async function sessionBlockedHosts(): Promise<string[]> {
  try {
    const stored = (await chrome.storage.session.get("blocked"))["blocked"];
    return Array.isArray(stored) ? (stored as string[]) : [];
  } catch {
    return [];
  }
}

export function markBlocked(host: string): Promise<void> {
  const h = host.toLowerCase();
  return inOrder(async () => {
    try {
      const list = await sessionBlockedHosts();
      if (!list.includes(h)) {
        list.push(h);
        await chrome.storage.session.set({ blocked: list });
      }
    } catch {
      // best-effort: the DNR rule is still installed.
    }
  });
}

export function unmarkBlocked(host: string): Promise<void> {
  const h = host.toLowerCase();
  return inOrder(async () => {
    try {
      const list = (await sessionBlockedHosts()).filter((x) => x !== h);
      await chrome.storage.session.set({ blocked: list });
    } catch {
      // best-effort
    }
  });
}
