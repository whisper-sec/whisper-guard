// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Pre-emptive click / form-submit interruption, background half.
// The content script holds a qualifying outbound action (a link to another
// registrable domain, a form posting off-origin) and asks about the TARGET
// hostname; this decides. Cache first: a cached-malicious target answers
// instantly with zero network. On a miss, ONE keyless assess of the bare
// hostname on a tight budget. Graph slow or down => allow (fail open, the
// user's click is never blocked by an outage). Only evidenced malice
// interrupts: the decision is the calm ladder's (shared/escalation.ts),
// via shouldInterrupt. An interrupt also arms the scoped DNR second line
// and counts one quiet win: category + count only, the hostname
// stays on this machine.

import { PREEMPT_ASSESS_TIMEOUT_MS } from "../shared/config";
import { isPrivateHost } from "../shared/hostname";
import { shouldInterrupt, type PreemptDecision } from "../shared/preempt";
import { assessHostKeyless } from "./assess";
import { cacheGet, cachePut } from "./cache";
import { sessionAllowed } from "./session";
import { getSettings } from "./settings";
import { addPreemptBlock } from "./shield";
import { recordWin } from "./wins";

// One threat stopped counts once. A user who dismisses the interrupt with
// "Go back" (which does not allow the host) and re-clicks the SAME flagged
// link runs preemptCheck again, but that is the same risky click held a
// second time, not a new win. Dedup per host for this service-worker
// lifetime. Hosts live ONLY in this in-memory set, never persisted, so the
// wins record (wins.ts) stays category + count and never learns a hostname.
const countedPreemptHosts = new Set<string>();

export async function preemptCheck(rawHost: string): Promise<PreemptDecision> {
  const host = rawHost.replace(/\.$/, "").toLowerCase();
  if (host === "" || isPrivateHost(host)) return { action: "allow" };
  if (await sessionAllowed(host)) return { action: "allow" };

  let verdict = await cacheGet(host);
  if (!verdict) {
    // Cache miss. The live check honors the same switch as the nav
    // pipeline: cloudCheck off means on-device only, so nothing to ask.
    if (!(await getSettings()).cloudCheck) return { action: "allow" };
    try {
      verdict = await assessHostKeyless(host, PREEMPT_ASSESS_TIMEOUT_MS);
      await cachePut(verdict);
    } catch {
      return { action: "allow" };
    }
  }

  if (shouldInterrupt(verdict)) {
    // The pre-emptive rung fired. Back the in-page hold with the scoped
    // DNR rule (second line; Proceed lifts it) BEFORE answering, so the
    // order is deterministic, then count the quiet win: category only,
    // once per host (a re-click of the same held link is not a new win).
    await addPreemptBlock(host);
    if (!countedPreemptHosts.has(host)) {
      countedPreemptHosts.add(host);
      await recordWin("preemptBlock");
    }
    return {
      action: "interrupt",
      host,
      band: verdict.band,
      label: verdict.label,
      coverage: verdict.coverage,
    };
  }
  return { action: "allow" };
}
