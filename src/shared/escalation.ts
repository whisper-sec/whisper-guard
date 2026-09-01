// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The calm escalation ladder: ONE place that decides how loudly a
// finding may speak. Every surface (the toolbar signal, the pre-emptive
// interstitial, the amber banner, the field guard, the full-page warning,
// the wins tally) asks THIS table instead of carrying its own band
// thresholds, so the product has exactly one voice.
//
// The spectrum, quiet to loud:
//
//   silent          handled at the network/verdict layer; no UI at all
//   ambient         the glanceable channel (toolbar icon + one badge pulse)
//   pre-emptive     hold the user's own in-flight action and show
//                   the receipts BEFORE anything loads
//   conversational  a dismissible in-page word (amber banner, the
//                   password-field caution) that never blocks
//   blocking        the full-page warning: stop, explain, offer the exits
//
// The philosophy: most outcomes are SILENT. Guard escalates only when the
// finding is urgent AND actionable AND the human is the right actor for
// it; everything else stays with the machine. De-noising is transparent
// and reversible by construction: the raw verdict always rides TabState
// verbatim and is one click away in the popup, never hidden or dressed up.
//
// Pure data + two pure functions. No chrome.*, fully unit-testable.

/** The spectrum, in escalation order (index = loudness). */
export const RUNGS = ["silent", "ambient", "preemptive", "conversational", "blocking"] as const;
export type Rung = (typeof RUNGS)[number];

/**
 * The moment being decided: who is acting, and what is at stake.
 *
 *   page        a page verdict landed while the human views the page
 *   action      the human's OWN click/submit is in flight toward the target
 *               (urgent, actionable, and the human is the right actor)
 *   credential  a password field gained focus on a flagged page
 *   win         Guard already handled something autonomously (a counted
 *               outcome, never an announced one)
 */
export type Moment = "page" | "action" | "credential" | "win";

/** What is known about the subject, straight from the verdict layers. */
export interface Signal {
  /** The graph band, verbatim (liberal: any casing, null when absent). */
  band: string | null;
  /** The graph label; "malicious" is load-bearing (evidence, any band). */
  label?: string | null;
  /** True when the on-device look-alike detector hit. */
  lookalike?: boolean;
}

/**
 * The evidence classes the ladder distinguishes. Deliberately few: the
 * graph's evidenced verdicts, its softer flag, the on-device look-alike,
 * and everything else (clean, unknown, unassessed) folded into "none",
 * because none of those may raise UI.
 */
export type Severity = "evidenced" | "flagged" | "lookalike" | "none";

export function severity(signal: Signal): Severity {
  const band = (signal.band ?? "").toUpperCase();
  if (band === "CRITICAL" || band === "HIGH") return "evidenced";
  if ((signal.label ?? "").toLowerCase() === "malicious") return "evidenced";
  if (band === "MEDIUM") return "flagged";
  if (signal.lookalike) return "lookalike";
  return "none";
}

/**
 * THE ladder, as data. Read it as: given this class of evidence, in this
 * moment, this is the loudest Guard may get. Capability gating happens at
 * the surface (the two in-page rungs deliver only under the user's
 * Active-Shield opt-in and degrade to the ambient channel without it);
 * the DECISION lives here and nowhere else.
 */
const LADDER: Record<Severity, Record<Moment, Rung>> = {
  evidenced: { page: "blocking", action: "preemptive", credential: "conversational", win: "silent" },
  flagged: { page: "conversational", action: "silent", credential: "conversational", win: "silent" },
  lookalike: { page: "conversational", action: "silent", credential: "conversational", win: "silent" },
  none: { page: "silent", action: "silent", credential: "silent", win: "silent" },
};

/** The one decision every surface routes through. */
export function decide(signal: Signal, moment: Moment): Rung {
  return LADDER[severity(signal)][moment];
}

/** True when `rung` is at least as loud as `floor` on the spectrum. */
export function atLeast(rung: Rung, floor: Rung): boolean {
  return RUNGS.indexOf(rung) >= RUNGS.indexOf(floor);
}
