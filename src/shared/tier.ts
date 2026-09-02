// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE TIER METER: RULE 14's two-tier boundary, measured rather than pitched.
//
// The rule says a surface must work with no account and unlock provisioning,
// governance and egress with one. The dishonest way to say that in a product
// is an advertisement. The honest way is a number: the reader's real
// remaining budget on the public tier, the join depth that tier allows, and
// what an account changes about both - all read from the graph itself
// (CALL whisper.quota) rather than written into this build.
//
// One implementation, mounted by the panel and by the dashboard, for the
// same reason there is one protect control: two copies of a promise are two
// places for it to drift.
//
// A budget we could not measure hides the meter. It never draws a full bar,
// because a full bar nobody measured is a lie in the one direction that
// matters: it tells a reader they have room when they may have none.

import { send } from "./messages";
import type { GraphQuota } from "./types";

export interface TierMeterElements {
  /** The wrapper, unhidden only when a real measurement came back. */
  root: HTMLElement;
  label: HTMLElement;
  count: HTMLElement;
  fill: HTMLElement;
  note: HTMLElement;
}

/**
 * Fill a tier meter from a live quota read. Returns the quota when one was
 * measured, or null when it could not be, so a caller can say something
 * else in that case rather than leaving a blank.
 */
export async function mountTierMeter(els: TierMeterElements): Promise<GraphQuota | null> {
  const res = await send<{ ok: true; quota: GraphQuota | null }>({ kind: "getQuota" });
  if (!res.ok || !res.quota) return null;
  const q = res.quota;
  const limit = q.hourlyLimit;
  const left = q.hourlyRemaining;
  if (limit === null || left === null || limit <= 0) return null;

  els.root.hidden = false;
  els.label.textContent = q.anonymous ? "Keyless tier" : `${q.plan} tier`;
  els.count.textContent = `${left} of ${limit} checks left this hour`;

  const frac = Math.max(0, Math.min(1, left / limit));
  els.fill.className = `tier-fill${frac <= 0.05 ? " out" : frac <= 0.25 ? " low" : ""}`;
  // Set on the next frame so the width actually transitions up from zero
  // rather than being painted at its final value on first layout.
  requestAnimationFrame(() => {
    els.fill.style.width = `${(frac * 100).toFixed(1)}%`;
  });

  const depth = q.maxDepth;
  els.note.textContent =
    depth !== null
      ? `Walks up to ${depth} joins per query on this tier. An account raises both.`
      : "An account raises this ceiling.";
  return q;
}
