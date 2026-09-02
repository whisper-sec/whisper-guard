// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The live size of the graph, and the live pulse of the resolvers that
// answer from it. Both read from the public keyless stats endpoint, every
// time, and never from a constant in this repository.
//
// This is a rule, not a preference. A figure written into a build is stale
// the day after it ships, and a security product quoting a stale figure
// about its own coverage is worse than one quoting none.
//
// The rule stated precisely, because a looser version of it was written
// here first and a test caught the two disagreeing:
//
//   * the figure NEVER comes from a constant in this repository;
//   * a read is reused only inside the endpoint's OWN freshness window,
//     which the document declares as Cache-Control max-age=30 and which
//     SCALE_TTL_MS matches, so the surface is never showing a figure the
//     publisher itself would call stale;
//   * beyond that window, an endpoint that cannot be reached yields NULL
//     and the surface shows no figure at all, rather than an older one;
//   * and the surface discloses when it read, in the tooltip, so a reader
//     who wants the age can have it.
//
// What that adds up to is that the number on screen was measured, recently,
// by us, and never remembered past the point the publisher vouches for.
//
// Nothing about the reader is sent: it is a GET of a public document with
// no query string, no header, and no body.

import type { GraphScale } from "../shared/types";
import { SCALE_MAX_BYTES, SCALE_TIMEOUT_MS, SCALE_TTL_MS, STATS_URL } from "../shared/config";

const num = (v: unknown): number | null =>
  typeof v === "number" && Number.isFinite(v) ? v : null;

let cached: { scale: GraphScale; at: number } | null = null;
let inFlight: Promise<GraphScale | null> | null = null;

function parse(root: unknown): GraphScale | null {
  if (!root || typeof root !== "object") return null;
  const d = root as Record<string, unknown>;
  const graph = (d["graph"] ?? {}) as Record<string, unknown>;
  const totals = (d["totals"] ?? {}) as Record<string, unknown>;
  const latency = (d["latency"] ?? {}) as Record<string, unknown>;
  const series = (d["timeseries"] ?? {}) as Record<string, unknown>;

  const nodes = num(graph["nodes"]);
  const edges = num(graph["edges"]);
  // The three figures are the whole point of the read. Without them there
  // is no scale to show, and a partial parse must not render as a zero.
  if (nodes === null || edges === null) return null;

  const pulse: number[] = [];
  const buckets = Array.isArray(series["queries"]) ? (series["queries"] as unknown[]) : [];
  for (const b of buckets) {
    if (!b || typeof b !== "object") continue;
    let sum = 0;
    for (const [k, v] of Object.entries(b as Record<string, unknown>)) {
      if (k === "t") continue;
      const n = num(v);
      if (n !== null) sum += n;
    }
    pulse.push(sum);
  }

  return {
    nodes,
    edges,
    objects: num(graph["objects"]) ?? 0,
    identities: num(totals["identities"]) ?? 0,
    queries: num(totals["queries"]) ?? 0,
    windowHours: num(d["windowHours"]) ?? 24,
    p50Us: num(latency["p50Us"]),
    p99Us: num(latency["p99Us"]),
    pulse,
    updated: num(d["updated"]) ?? Date.now(),
    degraded: d["degraded"] === true,
  };
}

/**
 * The current scale, or null when the endpoint could not be read. Null is a
 * first-class answer here: the caller renders "scale unavailable", never a
 * remembered or invented figure.
 */
export async function graphScale(): Promise<GraphScale | null> {
  if (cached && Date.now() - cached.at < SCALE_TTL_MS) return cached.scale;
  // One read at a time. Two surfaces opening together (the popup and the
  // dashboard) must cost one request, not two.
  if (inFlight) return inFlight;

  inFlight = (async (): Promise<GraphScale | null> => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), SCALE_TIMEOUT_MS);
    try {
      const res = await fetch(STATS_URL, {
        method: "GET",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal: ctl.signal,
      });
      if (!res.ok) return null;
      const text = await res.text();
      if (text.length > SCALE_MAX_BYTES) return null;
      const scale = parse(JSON.parse(text));
      if (scale) cached = { scale, at: Date.now() };
      return scale;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
      inFlight = null;
    }
  })();
  return inFlight;
}

/** Drop the memo so the next ask goes to the network (used by the tests). */
export function resetScaleCache(): void {
  cached = null;
}
