// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The honest realtime layer. There is no public push wire a browser
// extension can subscribe to, so:
//
//   this browser  genuinely live (local navigation events; the dashboard
//                 port gets a nudge per committed navigation)
//   fleet         op:logs POLLING: a chrome.alarms tick in the background
//                 (eviction-safe; the browser floors alarms at 30s) plus a
//                 tighter interval only while a dashboard tab holds its
//                 port open. Ring + seen-keys persist in session storage.
//
// The feed label degrades live -> polling -> offline and never pretends.

import { FEED_RING_MAX, POLL_ALARM_MINUTES, POLL_OPEN_MS } from "../shared/config";
import type { ActivityRow, FeedStatus } from "../shared/types";
import { hasKey } from "./graph-client";
import { fleetActivity } from "./fleet";

export const FLEET_POLL_ALARM = "whisper-guard-fleet-poll";

interface FeedState {
  ring: ActivityRow[];
  seen: string[];
  updatedAt: number | null;
  lastError: boolean;
}

let state: FeedState | null = null;
let openPorts = 0;
let openTimer: ReturnType<typeof setInterval> | null = null;
let polling = false;

async function load(): Promise<FeedState> {
  if (state) return state;
  try {
    const stored = (await chrome.storage.session.get("fleetFeed"))["fleetFeed"] as
      | FeedState
      | undefined;
    state = stored && Array.isArray(stored.ring) ? stored : { ring: [], seen: [], updatedAt: null, lastError: false };
  } catch {
    state = { ring: [], seen: [], updatedAt: null, lastError: false };
  }
  return state;
}

function persist(): void {
  if (!state) return;
  chrome.storage.session.set({ fleetFeed: state }).catch(() => undefined);
}

function rowKey(r: ActivityRow): string {
  return `${r.ts}|${r.agent}|${r.kind}|${r.target}|${r.qtype ?? ""}`;
}

async function merge(rows: ActivityRow[]): Promise<void> {
  const s = await load();
  const seen = new Set(s.seen);
  const fresh: ActivityRow[] = [];
  for (const r of rows) {
    const k = rowKey(r);
    if (seen.has(k)) continue;
    seen.add(k);
    fresh.push(r);
  }
  if (fresh.length > 0) {
    fresh.sort((a, b) => b.ts - a.ts);
    s.ring = [...fresh, ...s.ring].slice(0, FEED_RING_MAX);
    s.seen = [...seen].slice(-FEED_RING_MAX * 2);
  }
  s.updatedAt = Date.now();
  s.lastError = false;
  persist();
}

/** Feed rows someone else already fetched (the dashboard report path). */
export function ingestFleetRows(rows: ActivityRow[]): void {
  void merge(rows);
}

/** One poll: merge fresh fleet activity into the ring, dedup by row key. */
export async function pollFleetOnce(): Promise<void> {
  if (polling) return;
  if (!(await hasKey())) return;
  polling = true;
  try {
    const activity = await fleetActivity();
    await merge(activity.recent);
  } catch {
    const s = await load();
    s.lastError = true;
    persist();
  } finally {
    polling = false;
  }
}

/** The current feed + its honest liveness. */
export async function getFleetFeed(): Promise<{ rows: ActivityRow[]; status: FeedStatus }> {
  const s = await load();
  const mode: FeedStatus["mode"] = s.lastError ? "offline" : "polling";
  return { rows: s.ring, status: { mode, updatedAt: s.updatedAt } };
}

/** A dashboard tab connected: tighten the cadence while it is open. */
export function dashboardOpened(): void {
  openPorts += 1;
  try {
    chrome.alarms.create(FLEET_POLL_ALARM, { periodInMinutes: POLL_ALARM_MINUTES });
  } catch {
    // alarms unavailable: the open-tab interval still covers the feed
  }
  if (!openTimer) {
    openTimer = setInterval(() => {
      void pollFleetOnce();
    }, POLL_OPEN_MS);
  }
  void pollFleetOnce();
}

export function dashboardClosed(): void {
  openPorts = Math.max(0, openPorts - 1);
  if (openPorts === 0 && openTimer) {
    clearInterval(openTimer);
    openTimer = null;
  }
}

/** Alarm tick (fires even after the worker was evicted). */
export function onPollAlarm(): void {
  void pollFleetOnce();
}

/** Sign-out: stop polling and drop the ring (it belongs to the account). */
export async function resetFeed(): Promise<void> {
  state = { ring: [], seen: [], updatedAt: null, lastError: false };
  persist();
  try {
    await chrome.alarms.clear(FLEET_POLL_ALARM);
  } catch {
    // fine
  }
}
