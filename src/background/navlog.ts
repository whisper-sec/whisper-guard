// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The on-device destination log behind the "This browser" report: which
// hostnames this browser navigated to in the last 24h, how often, and when
// last. Aggregated by hostname only (never URLs), stored locally, pruned on
// a rolling window, and it NEVER leaves the device as a list; single
// hostnames go out one batch at a time for enrichment, to one endpoint.

import { NAVLOG_MAX_HOSTS, NAVLOG_WINDOW_MS } from "../shared/config";

export interface NavEntry {
  host: string;
  q: number;
  lastAt: number;
}

type Stored = Record<string, { q: number; lastAt: number }>;

let mem: Map<string, { q: number; lastAt: number }> | null = null;
let persistTimer: ReturnType<typeof setTimeout> | null = null;
const listeners = new Set<() => void>();

/** Dashboard ports subscribe to know a fresh navigation landed. */
export function onNavRecorded(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

async function load(): Promise<Map<string, { q: number; lastAt: number }>> {
  if (mem) return mem;
  mem = new Map();
  try {
    const stored = (await chrome.storage.local.get("navlog"))["navlog"] as Stored | undefined;
    if (stored && typeof stored === "object") {
      const floor = Date.now() - NAVLOG_WINDOW_MS;
      for (const [host, v] of Object.entries(stored)) {
        if (v && typeof v.lastAt === "number" && v.lastAt >= floor) mem.set(host, v);
      }
    }
  } catch {
    // memory-only fallback is fine
  }
  return mem;
}

function persistSoon(): void {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    if (!mem) return;
    const obj: Stored = {};
    for (const [k, v] of mem) obj[k] = v;
    chrome.storage.local.set({ navlog: obj }).catch(() => undefined);
  }, 1000);
}

function prune(map: Map<string, { q: number; lastAt: number }>): void {
  const floor = Date.now() - NAVLOG_WINDOW_MS;
  for (const [k, v] of map) if (v.lastAt < floor) map.delete(k);
  if (map.size > NAVLOG_MAX_HOSTS) {
    // Drop the quietest, oldest entries beyond the cap.
    const sorted = [...map.entries()].sort(
      (a, b) => b[1].q - a[1].q || b[1].lastAt - a[1].lastAt,
    );
    map.clear();
    for (const [k, v] of sorted.slice(0, NAVLOG_MAX_HOSTS)) map.set(k, v);
  }
}

/** Record one committed main-frame navigation (hostname already parsed). */
export async function recordNav(host: string): Promise<void> {
  const h = host.toLowerCase();
  const map = await load();
  const cur = map.get(h) ?? { q: 0, lastAt: 0 };
  cur.q += 1;
  cur.lastAt = Date.now();
  map.set(h, cur);
  prune(map);
  persistSoon();
  for (const cb of listeners) {
    try {
      cb();
    } catch {
      // subscriber errors never break the pipeline
    }
  }
}

/** Busiest-first destinations in the window. */
export async function getDestinations(): Promise<NavEntry[]> {
  const map = await load();
  prune(map);
  return [...map.entries()]
    .map(([host, v]) => ({ host, q: v.q, lastAt: v.lastAt }))
    .sort((a, b) => b.q - a.q || b.lastAt - a.lastAt);
}
