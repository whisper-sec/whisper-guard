// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The honest realtime layer. There is no public push wire a browser
// extension can subscribe to, so:
//
//   this browser  genuinely live (local navigation events; the dashboard
//                 port gets a nudge per committed navigation)
//   fleet         op:logs POLLING: a chrome.alarms tick (eviction-safe; the
//                 browser floors alarms at 30s) plus a tighter interval, both
//                 only while a dashboard tab holds its port open. The last
//                 port to close clears the alarm, so the worker can sleep, and
//                 a worker that starts with no dashboard clears a leftover one.
//                 The dashboard reconnects its port after a worker restart.
//                 Ring + seen-keys persist in session storage.
//                 This poll is the ONE control-plane read: the dashboard is
//                 told when it lands and reads the snapshot, never its own.
//
// The feed label degrades live -> polling -> offline and never pretends.

import { FEED_RING_MAX, POLL_ALARM_MINUTES, POLL_OPEN_MS } from "../shared/config";
import type { ActivityRow, FeedStatus } from "../shared/types";
import { hasKey } from "./graph-client";
import { fleetActivity, type FleetActivity } from "./fleet";

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

// The latest control-plane read and the one in flight, shared by the poll and
// by a dashboard that needs data before the next tick.
let latest: { at: number; activity: FleetActivity } | null = null;
let inflight: Promise<FleetActivity> | null = null;
const pollListeners = new Set<() => void>();

/** A poll right after the dashboard's own first read reuses that read. */
const OPEN_REUSE_MS = 3000;

// Bumped on every invalidation (roster change, account change, sign-out, last
// dashboard closing). A read that started under an older generation is stale
// when it lands: it never becomes the snapshot and its caller reads again.
let generation = 0;

function invalidateFleet(): void {
  generation += 1;
  latest = null;
  inflight = null;
}

function readFleet(): Promise<FleetActivity> {
  if (inflight) return inflight;
  const gen = generation;
  const read: Promise<FleetActivity> = fleetActivity()
    .then((activity) => {
      // A snapshot is trusted only while a dashboard stays connected; one
      // that lands after the last tab closed would be stale on the next open.
      if (gen === generation) latest = openPorts > 0 ? { at: Date.now(), activity } : null;
      return activity;
    })
    .finally(() => {
      if (inflight === read) inflight = null;
    });
  inflight = read;
  return read;
}

/**
 * The fleet picture without a duplicate read: join a read already in flight,
 * else reuse a snapshot no older than maxAgeMs, else read once. A read that
 * was overtaken by an invalidation while it ran is not returned: the ask is
 * made again, so a revoked endpoint or a signed-out account never comes back.
 * After three overtaken reads it reads once more, directly, and returns that.
 * With no key nothing is served from memory: the read itself reports it.
 */
export async function sharedFleetActivity(maxAgeMs = 0): Promise<FleetActivity> {
  for (let attempt = 0; attempt < 3; attempt++) {
    if (!(await hasKey())) return fleetActivity();
    const gen = generation;
    let activity: FleetActivity;
    if (inflight) activity = await inflight;
    else if (latest && Date.now() - latest.at <= maxAgeMs) return latest.activity;
    else activity = await readFleet();
    if (gen === generation) return activity;
  }
  return fleetActivity();
}

/** The roster or the account changed: drop the snapshot and any read in flight. */
export function forgetFleetSnapshot(): void {
  invalidateFleet();
}

/** Be told each time a poll lands a fresh fleet snapshot. Returns the unsubscribe. */
export function onFleetPolled(cb: () => void): () => void {
  pollListeners.add(cb);
  return () => pollListeners.delete(cb);
}

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

function notifyFleetPolled(): void {
  for (const cb of [...pollListeners]) cb();
}

/** One poll: merge fresh fleet activity into the ring, dedup by row key. */
export async function pollFleetOnce(reuseMs = 0): Promise<void> {
  if (!(await hasKey())) {
    // Signed out: tell the page so it shows the locked state, not old data.
    notifyFleetPolled();
    return;
  }
  try {
    const activity = await sharedFleetActivity(reuseMs);
    await merge(activity.recent);
  } catch {
    const s = await load();
    s.lastError = true;
    persist();
  }
  // Success or failure, the page re-reads the snapshot and the feed status.
  // Only this poll pushes, and the page's read never does, so it cannot loop.
  notifyFleetPolled();
}

/** The current feed + its honest liveness. */
export async function getFleetFeed(): Promise<{ rows: ActivityRow[]; status: FeedStatus }> {
  const s = await load();
  const mode: FeedStatus["mode"] = s.lastError ? "offline" : "polling";
  return { rows: s.ring, status: { mode, updatedAt: s.updatedAt } };
}

let alarmOp: Promise<void> = Promise.resolve();

/**
 * Make the poll alarm match the dashboard ports: present while one is open,
 * gone otherwise. Steps are chained and read openPorts when they run, so a
 * startup clear queued before a reconnecting dashboard can never undo it.
 */
export function syncPollAlarm(): Promise<void> {
  alarmOp = alarmOp.then(async () => {
    try {
      if (openPorts > 0) {
        // Only create when missing: a reconnect must not reset the period.
        if (!(await chrome.alarms.get(FLEET_POLL_ALARM))) {
          await chrome.alarms.create(FLEET_POLL_ALARM, { periodInMinutes: POLL_ALARM_MINUTES });
        }
      } else {
        await chrome.alarms.clear(FLEET_POLL_ALARM);
      }
    } catch {
      // alarms unavailable: the open-tab interval still covers the feed
    }
  });
  return alarmOp;
}

/** A dashboard tab connected: tighten the cadence while it is open. */
export function dashboardOpened(): void {
  openPorts += 1;
  void syncPollAlarm();
  if (!openTimer) {
    openTimer = setInterval(() => {
      void pollFleetOnce();
    }, POLL_OPEN_MS);
  }
  void pollFleetOnce(OPEN_REUSE_MS);
}

export function dashboardClosed(): void {
  openPorts = Math.max(0, openPorts - 1);
  if (openPorts === 0 && openTimer) {
    clearInterval(openTimer);
    openTimer = null;
  }
  if (openPorts === 0) {
    invalidateFleet();
    void syncPollAlarm();
  }
}

/** Alarm tick (fires even after the worker was evicted). */
export function onPollAlarm(): void {
  // A snapshot younger than one open period already covers this tick.
  void pollFleetOnce(POLL_OPEN_MS);
}

/** Sign-out: stop polling and drop the ring (it belongs to the account). */
export async function resetFeed(): Promise<void> {
  state = { ring: [], seen: [], updatedAt: null, lastError: false };
  invalidateFleet();
  persist();
  try {
    await chrome.alarms.clear(FLEET_POLL_ALARM);
  } catch {
    // fine
  }
}
