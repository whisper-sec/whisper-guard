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

/** Hosts the user chose to trust for this session only ("continue anyway"). */
export async function sessionAllowed(host: string): Promise<boolean> {
  try {
    const stored = (await chrome.storage.session.get("allowed"))["allowed"];
    return Array.isArray(stored) && (stored as string[]).includes(host.toLowerCase());
  } catch {
    return false;
  }
}

export async function allowForSession(host: string): Promise<void> {
  const h = host.toLowerCase();
  try {
    const stored = (await chrome.storage.session.get("allowed"))["allowed"];
    const list = Array.isArray(stored) ? (stored as string[]) : [];
    if (!list.includes(h)) list.push(h);
    await chrome.storage.session.set({ allowed: list });
  } catch {
    // best-effort
  }
}
