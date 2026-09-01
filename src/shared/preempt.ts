// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Pre-emptive click / form-submit interruption: the pure decision
// core, shared by the content script (which target needs vetting) and the
// background (which verdict interrupts). No chrome.* here, fully
// unit-testable.
//
// The privacy invariant holds by construction: both target extractors run
// the candidate URL through extractHostname(), so the ONLY thing the
// vetting path can ever hand to the background (and from there, to the
// graph) is a bare hostname. Paths, query strings, fragments, and
// form-field values are discarded at parse time, in-page. (Resuming a
// held middle/modifier click passes the destination URL to the background
// purely so tabs.create can honor the native disposition; that URL is
// consumed on this machine and never goes to the wire.)

import { decide } from "./escalation";
import { extractHostname } from "./hostname";
import { registrableDomain } from "./psl";

/** What the background hands back when a held action must be interrupted. */
export interface PreemptEvidence {
  host: string;
  band: string;
  label: string | null;
  coverage: string | null;
}

export type PreemptDecision = { action: "allow" } | ({ action: "interrupt" } & PreemptEvidence);

/** Where a MODIFIED link activation natively lands (see below). */
export type PreemptDisposition = "background-tab" | "foreground-tab" | "window";

/**
 * The native disposition of a modified link activation: the one part of a
 * resume that a synthetic click cannot reproduce, because untrusted events
 * never trigger modified navigation. Middle- or Ctrl/Cmd-click opens a
 * BACKGROUND tab (the user keeps their place), adding Shift foregrounds
 * the tab, and Shift alone opens a new window. Null means a plain
 * activation (primary button or keyboard, no modifiers): that resume is
 * re-dispatched on the anchor itself instead.
 */
export function modifiedDisposition(ev: {
  middle: boolean;
  ctrl: boolean;
  meta: boolean;
  shift: boolean;
}): PreemptDisposition | null {
  if (ev.middle || ev.ctrl || ev.meta) return ev.shift ? "foreground-tab" : "background-tab";
  return ev.shift ? "window" : null;
}

/**
 * The hostname a LINK click must be vetted for, or null when the click is
 * not ours to hold: same registrable domain (PSL) as the page, an in-page
 * or out-of-scope destination (non-http(s), private, an IP literal).
 */
export function linkTarget(pageHost: string, href: string): string | null {
  const target = extractHostname(href);
  if (!target) return null;
  const source = pageHost.replace(/\.$/, "").toLowerCase();
  if (target === source) return null;
  const sourceReg = registrableDomain(source) ?? source;
  const targetReg = registrableDomain(target) ?? target;
  return sourceReg === targetReg ? null : target;
}

/**
 * The hostname a FORM submit must be vetted for, or null when the action
 * posts same-origin (scheme + host + port) or out of scope. Stricter than
 * the link rule on purpose: credentials and card numbers ride submits, so
 * even a sibling subdomain gets a look (and a clean verdict waves it on).
 */
export function submitTarget(pageOrigin: string, actionUrl: string): string | null {
  let action: URL;
  try {
    action = new URL(actionUrl);
  } catch {
    return null;
  }
  if (action.origin === pageOrigin) return null;
  return extractHostname(action.href);
}

/**
 * The calm ladder decides: ONLY evidenced malice (CRITICAL/HIGH,
 * or an explicit malicious label) interrupts a user's action. MEDIUM and
 * below, UNKNOWN, and no-verdict never do; the ambient icon and the amber
 * layer carry those. Fail open by default.
 */
export function shouldInterrupt(
  v: { band: string; label?: string | null } | null | undefined,
): boolean {
  return v != null && decide({ band: v.band, label: v.label ?? null }, "action") === "preemptive";
}
