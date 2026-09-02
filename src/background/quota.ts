// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The keyless budget, read from the graph instead of guessed at.
//
// RULE 14 says a surface is two-tier: everything a reader needs works with
// no account, and a key adds provisioning, governance and egress. The
// honest way to say that in a product is not a pitch. It is a number. The
// graph publishes what an anonymous caller is allowed - a per-hour count,
// a per-day count, and the join depth the tier permits - so Guard shows
// exactly that, live, next to what a key changes.
//
// A reader who never signs in therefore still learns something true about
// where they stand, and a reader who does sign in can see the ceiling move.

import { CONTROL_TIMEOUT_MS } from "../shared/config";
import type { GraphQuota } from "../shared/types";
import { graphQuery } from "./graph-client";

const QUOTA_QUERY = "CALL whisper.quota()";

const asInt = (v: unknown): number | null => {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
};

/**
 * NO TIME-BASED MEMO. The budget is a live counter and the meter's whole
 * claim is that it was measured now.
 *
 * A sixty-second memo plus spend-invalidation looked careful and was not:
 * it knew only about the calls WE make, and the number also moves when
 * another tab spends, when the hour rolls over, or when the tier changes
 * server-side. A capture assertion caught the dashboard showing a figure
 * from a minute earlier, which is a reader being told they have a budget
 * that was never theirs - the same class of error as printing a graph
 * total into the build.
 *
 * So each ask is a read. It costs one call out of a hundred an hour, on a
 * surface that already spends seven, and it buys the only property the
 * meter has. Concurrent asks still share ONE request, so a panel and a
 * dashboard opening together cost one and not two.
 */
let inFlight: Promise<GraphQuota | null> | null = null;

/**
 * The caller's current tier and what is left of it. Null when the graph
 * could not answer: the surface then says the budget is unknown rather
 * than showing a full bar, because a full bar we did not measure is a lie
 * in the one direction that matters.
 */
export async function graphQuota(): Promise<GraphQuota | null> {
  if (inFlight) return inFlight;
  inFlight = (async (): Promise<GraphQuota | null> => {
    try {
      const rows = await graphQuery(QUOTA_QUERY, {}, CONTROL_TIMEOUT_MS);
      // The procedure answers as key/value pairs, one row each.
      const kv = new Map<string, unknown>();
      for (const r of rows) {
        const k = r["key"];
        if (typeof k === "string") kv.set(k, r["value"]);
      }
      if (kv.size === 0) return null;
      return {
        plan: typeof kv.get("plan") === "string" ? (kv.get("plan") as string) : "unknown",
        anonymous: kv.get("isAnonymous") === true || kv.get("isAnonymous") === "true",
        hourlyLimit: asInt(kv.get("hourlyLimit")),
        hourlyRemaining: asInt(kv.get("hourlyRemaining")),
        dailyLimit: asInt(kv.get("dailyLimit")),
        dailyRemaining: asInt(kv.get("dailyRemaining")),
        maxDepth: asInt(kv.get("maxQueryDepth")),
      };
    } catch {
      return null;
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

/** Nothing is remembered, so there is nothing to drop. Kept as the seam the
 *  sign-in path calls, so a future memo cannot reintroduce the bug quietly. */
export function resetQuotaCache(): void {
  inFlight = null;
}
