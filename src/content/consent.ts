// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Cookie-consent auto-decline: when a consent banner appears, click
// its REJECT / "necessary only" control so the page starts in its most
// private configuration. If there is any doubt at all, do NOTHING.
//
// The safety contract, in order of importance:
//
//   1. NEVER a false accept, and never a click on a non-consent control.
//      The only controls this module will ever click are (a) a decline
//      control a known CMP itself defines (its published reject-all
//      id/class), or (b) a button whose visible label matches a strict
//      decline pattern AND fails an accept/manage veto, inside a
//      banner-sized container whose own text says cookie/consent/gdpr
//      outright AND which also offers an accept-style choice (a genuine
//      cookie banner always presents accept next to reject). A lone
//      decline verb in a privacy-mentioning modal (a session-expiry
//      "Decline and log out", a notification "Deny access") has no
//      accept sibling and no cookie word, and is left alone. Anything
//      short of that certainty: leave the page untouched.
//   2. LOCAL, always. Detection and the click happen entirely on-device;
//      this module performs no fetch, opens no connection, and the one
//      message it ever sends (a successful decline) goes to the extension's
//      own background carrying a category only: no host, no URL, nothing
//      read from the page. The hostname-only-on-wire invariant is untouched.
//      (The decline click runs the SITE's own consent handler, exactly as a
//      human clicking "Reject all" would. That is the page's own traffic
//      rather than the extension's, and is strictly more private than the banner's
//      accept-by-default.)
//   3. ONE click per DOCUMENT, at most. Per document rather than per page,
//      because this pass runs frame-locally: a page whose publisher shows a
//      banner in the top document AND frames a CMP wall can legitimately
//      produce a decline in each. A decline that does not dismiss the banner
//      is never retried into a click loop.
//   4. Bounded. The late-banner MutationObserver disconnects after a short
//      window or on the first successful decline, whichever comes first.
//
// Scope, and the one limit that is left:
//
//   * EVERY FRAME, light DOM only. This module is injected into
//     sub-frames as well as the top document and scans each one locally,
//     which is the only place a frame's own DOM can be read at all. It has
//     to be: sampling six large publishers with the real built extension,
//     one in six was declined and every single miss was an iframe wall
//     (Sourcepoint-shaped), not a shadow root. Nothing about the contract
//     changes per frame. A sub-frame needs the same CMP-published handle,
//     the same known CMP root, or the same strict generic rule with its
//     cookie word AND accept sibling AND banner-scale bounds. A frame is a
//     smaller document, not a laxer one. The one-click-per-document budget
//     is per frame because it is a property of a document; the WIN counts
//     once per page, de-duplicated in the background where the page
//     identity lives.
//   * SHADOW ROOTS are still out of reach: querySelectorAll crosses no
//     shadow boundary, open or closed. Walking element.shadowRoot for open
//     roots would be cheap, and it is deliberately NOT here: in the same
//     six-publisher sample the only shadow hosts found were media players
//     and widgets, so it would buy nothing measured. It should ship when a
//     measurement asks for it, not for symmetry with the line above.
//   * English decline labels for the generic pass (the CMP-specific
//     selectors are language-independent, and cover the banner's own
//     wording in any language).
//
// Both fail toward doing nothing, which is the contract.

import { CONSENT_RESCAN_DEBOUNCE_MS, CONSENT_SCAN_WINDOW_MS } from "../shared/config";

/**
 * Decline-intent labels, matched case-insensitively against the visible
 * text. Deliberately strict: full decline phrases only, nothing fuzzy.
 */
const DECLINE_RE = new RegExp(
  "\\b(?:" +
    [
      "reject\\s+all(?:\\s+cookies)?",
      "reject\\s+non-?essential(?:\\s+cookies)?",
      "reject(?:\\s+cookies)?",
      "decline\\s+all(?:\\s+cookies)?",
      "decline(?:\\s+cookies)?",
      "refuse(?:\\s+all)?(?:\\s+cookies)?",
      "deny(?:\\s+all)?(?:\\s+cookies)?",
      "disagree(?:\\s+and\\s+close)?",
      "(?:strictly\\s+)?(?:necessary|essential)(?:\\s+cookies)?\\s+only",
      "only\\s+(?:strictly\\s+)?(?:necessary|essential)(?:\\s+cookies)?",
      "use\\s+(?:necessary|essential)\\s+cookies\\s+only",
      "continue\\s+without\\s+(?:agreeing|accepting)",
    ].join("|") +
    ")\\b",
  "i",
);

/**
 * The veto: any hint that a control accepts, saves, opens a preferences
 * panel, or navigates means it is NOT a plain decline. Never click it.
 * (\bagree\b does not match inside "disagree": no word boundary there.)
 */
const ACCEPT_VETO_RE =
  /\b(accept|agree|allow|enable|consent|got\s+it|ok(?:ay)?|yes|save|confirm|submit|subscribe|sign\s+(?:in|up)|manage|settings|preferences|options|customi[sz]e|choose|select|learn\s+more|more\s+(?:info|information)|policy)\b/i;

/** A visible decline label is a short imperative, never a paragraph. */
const MAX_LABEL_LENGTH = 64;

/**
 * Decline controls the big CMPs publish themselves. The selector IS the
 * consent-context signal here, and it is language-independent: these ids
 * and classes are the CMPs' own reject-all handles.
 */
const CMP_DECLINE_SELECTORS = [
  "#onetrust-reject-all-handler", // OneTrust banner: Reject All
  ".ot-pc-refuse-all-handler", // OneTrust preference center: Reject All
  "#CybotCookiebotDialogBodyButtonDecline", // Cookiebot: Decline
  "#didomi-notice-disagree-button", // Didomi: Disagree
  ".didomi-continue-without-agreeing", // Didomi: Continue without agreeing
].join(",");

/**
 * Known CMP roots: inside these, a decline-labelled button needs no further
 * context (the root itself is the signal). Covers Quantcast/TCF, whose
 * reject button carries no stable id and lives in the summary button row.
 */
const CMP_ROOT_SELECTORS = [
  "#qc-cmp2-ui", // Quantcast Choice (TCF)
  ".qc-cmp2-summary-buttons", // Quantcast banner button row
  "#onetrust-banner-sdk",
  "#onetrust-pc-sdk",
  "#CybotCookiebotDialog",
  "#didomi-host",
].join(",");

/**
 * Generic candidates for a consent container: dialogs and elements that
 * name themselves cookie/consent/gdpr. A match here is only HALF the
 * signal. The container's own text must also talk about cookies/consent
 * (checked in consentContext) before any button inside is considered.
 */
const GENERIC_CONTAINER_SELECTORS = [
  "[role='dialog']",
  "[role='alertdialog']",
  "[aria-modal='true']",
  "[id*='cookie' i]",
  "[class*='cookie' i]",
  "[id*='consent' i]",
  "[class*='consent' i]",
  "[id*='gdpr' i]",
  "[class*='gdpr' i]",
  "[aria-label*='cookie' i]",
  "[aria-label*='consent' i]",
].join(",");

/**
 * The textual consent-context signal a generic container must carry: an
 * unambiguous cookie word, nothing softer. "privacy" and "tracking" are
 * deliberately NOT here. Session-expiry, notification and unsaved-changes
 * modals routinely mention a privacy policy while offering destructive
 * "Decline"/"Deny" buttons that have nothing to do with cookies.
 */
const CONTEXT_RE = /\b(cookies?|consent|gdpr)\b/i;

/**
 * Accept-style labels, for CORROBORATION only (such a button is never
 * clicked): the generic pass refuses to act unless the container also
 * offers an accept-style choice, because a genuine cookie banner always
 * presents accept next to reject. Every word here is also in
 * ACCEPT_VETO_RE, so no control can be both a decline candidate and its
 * own corroborating accept.
 */
const ACCEPT_STYLE_RE = /\b(accept|agree|allow|enable|consent|got\s+it|ok(?:ay)?|yes)\b/i;

/** Clickables considered in the generic pass: buttons only, never links. */
const BUTTON_SELECTORS = "button,[role='button'],input[type='button'],input[type='submit']";

// Bounded work per scan, even on pathological pages.
const MAX_CONTAINERS_PER_SCAN = 30;
const MAX_BUTTONS_PER_CONTAINER = 50;

// Banner-scale bounds: a genuine consent banner is a strip or a modal,
// never a page-scale region. A cookie/consent token on a whole-app wrapper
// (<div id="app" class="cookie-consent-active">) must not turn the generic
// pass into a page-wide button hunt, so any container bigger than a
// plausible banner (by viewport share, by DOM weight, or by text volume)
// is disqualified outright. CMP walls that exceed these bounds are still
// handled by the CMP-specific passes, which are size-independent.
const MAX_CONTAINER_VIEWPORT_FRACTION = 0.85;
const MAX_CONTAINER_ELEMENTS = 300;
const MAX_CONTAINER_TEXT_CHARS = 4000;

let armed = false;
let done = false;
let observer: MutationObserver | null = null;
let stopTimer: ReturnType<typeof setTimeout> | null = null;
let rescanTimer: ReturnType<typeof setTimeout> | null = null;

/** The visible label of a control: rendered text, else its accessible name. */
function labelOf(el: HTMLElement): string {
  if (el instanceof HTMLInputElement) {
    return (el.value || el.getAttribute("aria-label") || "").replace(/\s+/g, " ").trim();
  }
  const text = (el.textContent ?? "").replace(/\s+/g, " ").trim();
  if (text !== "") return text;
  return (el.getAttribute("aria-label") ?? "").replace(/\s+/g, " ").trim();
}

function isVisible(el: HTMLElement): boolean {
  if (!el.isConnected) return false;
  if (el.closest("[hidden],[aria-hidden='true']")) return false;
  if (el.getClientRects().length === 0) return false;
  const cs = getComputedStyle(el);
  if (cs.visibility === "hidden" || cs.display === "none" || cs.opacity === "0") return false;
  const r = el.getBoundingClientRect();
  return r.width >= 8 && r.height >= 8;
}

function isEnabled(el: HTMLElement): boolean {
  if (el.getAttribute("aria-disabled") === "true") return false;
  if ((el as HTMLButtonElement | HTMLInputElement).disabled === true) return false;
  return true;
}

/** The strict generic rule: decline label, accept veto, short, no link. */
function isDeclineButton(el: HTMLElement): boolean {
  if (!isVisible(el) || !isEnabled(el)) return false;
  // Never anything that navigates: a decline is a click, not a link away.
  if (el.closest("a[href]")) return false;
  const label = labelOf(el);
  if (label === "" || label.length > MAX_LABEL_LENGTH) return false;
  return DECLINE_RE.test(label) && !ACCEPT_VETO_RE.test(label);
}

/**
 * Accept-style corroboration (never clicked, only counted): visible,
 * enabled, short-labelled, and accept-worded. Links are allowed here,
 * because banners often render their accept as an <a role="button"> and
 * this is evidence rather than a click target.
 */
function isAcceptStyleButton(el: HTMLElement): boolean {
  if (!isVisible(el) || !isEnabled(el)) return false;
  const label = labelOf(el);
  if (label === "" || label.length > MAX_LABEL_LENGTH) return false;
  return ACCEPT_STYLE_RE.test(label);
}

/** A generic container qualifies only when its own text talks cookies. */
function consentContext(container: HTMLElement): boolean {
  if (container === document.body || container === document.documentElement) return false;
  const text = (container.textContent ?? "").slice(0, MAX_CONTAINER_TEXT_CHARS);
  return CONTEXT_RE.test(text);
}

/**
 * A generic container must also be banner-SIZED: bounded viewport share,
 * bounded element count, bounded text. Anything page-scale is not a banner
 * no matter what its class list says, and is left alone.
 */
function isBannerScale(container: HTMLElement): boolean {
  const rect = container.getBoundingClientRect();
  const viewport = Math.max(1, window.innerWidth * window.innerHeight);
  if (rect.width * rect.height > viewport * MAX_CONTAINER_VIEWPORT_FRACTION) return false;
  if (container.querySelectorAll("*").length > MAX_CONTAINER_ELEMENTS) return false;
  return (container.textContent ?? "").length <= MAX_CONTAINER_TEXT_CHARS;
}

/**
 * Find the one control this page's consent UI offers for declining, in
 * confidence order: a CMP's own reject handle, then a decline-labelled
 * button inside a known CMP root, then the strict generic pass. Null when
 * nothing meets the bar, in which case the caller does nothing.
 */
function findDeclineControl(): HTMLElement | null {
  // 1) CMP-published decline controls: the id/class is the semantics. The
  // accept veto still applies, so a page squatting an accept-labelled
  // element on a CMP id is left alone (belt and braces).
  for (const el of document.querySelectorAll<HTMLElement>(CMP_DECLINE_SELECTORS)) {
    if (isVisible(el) && isEnabled(el) && !ACCEPT_VETO_RE.test(labelOf(el))) return el;
  }

  // 2) Known CMP roots (Quantcast has no stable reject id): a decline-
  // labelled button inside one needs no further context signal.
  let roots = 0;
  for (const root of document.querySelectorAll<HTMLElement>(CMP_ROOT_SELECTORS)) {
    if (++roots > MAX_CONTAINERS_PER_SCAN) break;
    let buttons = 0;
    for (const el of root.querySelectorAll<HTMLElement>(BUTTON_SELECTORS)) {
      if (++buttons > MAX_BUTTONS_PER_CONTAINER) break;
      if (isDeclineButton(el)) return el;
    }
  }

  // 3) Generic pass: a plausible consent container (named or dialog-role)
  // that is banner-SIZED, whose own text says cookie/consent/gdpr outright,
  // holding BOTH a strict-decline button and an accept-style sibling. All
  // four signals required, a genuine cookie banner always presents accept
  // next to reject, so a lone decline verb in a privacy-mentioning modal
  // (session expiry, notifications, unsaved changes) never qualifies.
  let containers = 0;
  const seen = new Set<HTMLElement>();
  for (const container of document.querySelectorAll<HTMLElement>(GENERIC_CONTAINER_SELECTORS)) {
    if (seen.has(container)) continue;
    seen.add(container);
    if (++containers > MAX_CONTAINERS_PER_SCAN) break;
    if (!isVisible(container) || !isBannerScale(container) || !consentContext(container)) continue;
    let buttons = 0;
    let decline: HTMLElement | null = null;
    let acceptSibling = false;
    for (const el of container.querySelectorAll<HTMLElement>(BUTTON_SELECTORS)) {
      if (++buttons > MAX_BUTTONS_PER_CONTAINER) break;
      if (decline === null && isDeclineButton(el)) {
        decline = el;
      } else if (!acceptSibling && isAcceptStyleButton(el)) {
        // Cannot be the decline itself: every ACCEPT_STYLE_RE word is in
        // ACCEPT_VETO_RE, so a decline candidate never matches both.
        acceptSibling = true;
      }
      if (decline !== null && acceptSibling) return decline;
    }
  }
  return null;
}

function teardown(): void {
  observer?.disconnect();
  observer = null;
  if (stopTimer !== null) clearTimeout(stopTimer);
  stopTimer = null;
  if (rescanTimer !== null) clearTimeout(rescanTimer);
  rescanTimer = null;
}

/**
 * Report the one successful decline to the background: a category-only
 * quiet win. Nothing about the page rides along, the message has
 * no fields to carry it. Best-effort: a dead worker loses the count, never
 * the decline.
 */
function reportWin(): void {
  try {
    chrome.runtime.sendMessage({ kind: "consentDeclined" }, () => {
      void chrome.runtime.lastError; // read it: no unchecked-error noise
    });
  } catch {
    // Extension context gone (update/reload race): the decline stands.
  }
}

function scan(): void {
  if (done) return;
  const control = findDeclineControl();
  if (!control) return; // uncertain or nothing there: leave the page alone
  // Latch BEFORE clicking: the click mutates the DOM, the observer fires,
  // and nothing may ever click twice.
  done = true;
  teardown();
  try {
    control.click();
  } catch {
    // A page handler misbehaved; the decline click was still delivered.
  }
  reportWin();
}

function scheduleScan(): void {
  if (done || rescanTimer !== null) return;
  rescanTimer = setTimeout(() => {
    rescanTimer = null;
    scan();
  }, CONSENT_RESCAN_DEBOUNCE_MS);
}

/**
 * Arm the auto-decline on this page: scan now, then watch briefly for a
 * late-injected banner (most CMPs mount asynchronously). Idempotent; the
 * observer disconnects after CONSENT_SCAN_WINDOW_MS or on the first
 * successful decline.
 */
export function armConsent(): void {
  if (armed) return;
  armed = true;
  const start = (): void => {
    scan();
    if (done) return;
    observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      // Banners often pre-exist hidden and are shown by a class/style flip.
      attributes: true,
      attributeFilter: ["class", "style", "hidden"],
    });
    stopTimer = setTimeout(teardown, CONSENT_SCAN_WINDOW_MS);
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
}
