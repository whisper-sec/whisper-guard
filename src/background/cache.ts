// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Verdict cache: in-memory LRU mirrored to storage.session so a cold
// service worker paints the icon instantly with zero network. Band-aware
// TTLs (malicious verdicts stick longest). Apex inheritance: a benign apex
// answers for its subdomains; a malicious apex marks its children red.

import {
  CACHE_MAX_ENTRIES,
  TTL_BENIGN_MS,
  TTL_MALICIOUS_MS,
  TTL_SUSPICIOUS_MS,
  TTL_UNKNOWN_MS,
} from "../shared/config";
import type { AssessVerdict, GraphBand } from "../shared/types";
import { registrableDomain } from "../shared/psl";

const mem = new Map<string, AssessVerdict>();
let loaded = false;

function ttlFor(band: GraphBand): number {
  switch (band) {
    case "CRITICAL":
      return TTL_MALICIOUS_MS;
    case "HIGH":
    case "MEDIUM":
      return TTL_SUSPICIOUS_MS;
    case "LOW":
    case "INFO":
    case "NONE":
      return TTL_BENIGN_MS;
    case "UNKNOWN":
      return TTL_UNKNOWN_MS;
  }
}

function fresh(v: AssessVerdict): boolean {
  return Date.now() - v.at < ttlFor(v.band);
}

async function load(): Promise<void> {
  if (loaded) return;
  loaded = true;
  try {
    const stored = (await chrome.storage.session.get("verdicts"))["verdicts"];
    if (stored && typeof stored === "object") {
      for (const [k, v] of Object.entries(stored as Record<string, AssessVerdict>)) {
        if (v && typeof v.at === "number") mem.set(k, v);
      }
    }
  } catch {
    // session storage unavailable: memory-only is fine.
  }
}

let persistTimer: ReturnType<typeof setTimeout> | null = null;
function persistSoon(): void {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    const obj: Record<string, AssessVerdict> = {};
    for (const [k, v] of mem) obj[k] = v;
    chrome.storage.session.set({ verdicts: obj }).catch(() => undefined);
  }, 500);
}

export async function cacheGet(host: string): Promise<AssessVerdict | null> {
  await load();
  const h = host.toLowerCase();
  const direct = mem.get(h);
  if (direct && fresh(direct)) {
    // LRU touch.
    mem.delete(h);
    mem.set(h, direct);
    return direct;
  }
  if (direct) mem.delete(h);

  // Apex inheritance: benign apex answers for children; malicious apex
  // taints them. Anything in between (suspicious/unknown) means the child
  // deserves its own query.
  const apex = registrableDomain(h);
  if (apex && apex !== h) {
    const av = mem.get(apex);
    if (av && fresh(av)) {
      const band = av.band;
      if (band === "CRITICAL" || band === "LOW" || band === "INFO" || band === "NONE") {
        return { ...av, host: h };
      }
    }
  }
  return null;
}

export async function cachePut(v: AssessVerdict): Promise<void> {
  await load();
  const h = v.host.toLowerCase();
  mem.delete(h);
  mem.set(h, v);
  while (mem.size > CACHE_MAX_ENTRIES) {
    const oldest = mem.keys().next().value;
    if (oldest === undefined) break;
    mem.delete(oldest);
  }
  persistSoon();
}

export async function cacheClear(): Promise<void> {
  await load();
  mem.clear();
  persistSoon();
}
