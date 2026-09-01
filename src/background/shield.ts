// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Active Shield: the opt-in on-page layer. The banner, the password-field
// caution and the automatic full-page warning all require the runtime
// broad-host grant (chrome.permissions.request from the options page);
// without it the ambient icon, the popup and the pre-click check still
// deliver the full signal.
//
// Two layers here are deliberately NOT gated on that grant, because they
// need no broad host access to work: the pre-emptive click/form guard
// and the cookie-consent decline are simply ATTEMPTED,
// and the browser's own permission model decides where they land - under
// the broad grant everywhere, otherwise on the one tab the user invoked
// Guard on (activeTab), and nowhere else. So "no grant" means less page
// injection, never none: see armPreempt and armConsent below.
//
// Evidenced-malicious hosts get the full-page warning two ways:
//   cached-bad  -> a DNR session rule redirects the request pre-render
//   novel-bad   -> tabs.update on verdict (brief paint, still pre-credential)
// Amber (suspicious / look-alike) never blocks: a dismissible banner plus a
// password-field caution, injected only on flagged hosts.

import { ext } from "../shared/api";
import type { DetectorHit } from "../shared/types";
import { sessionAllowed, markBlocked, unmarkBlocked } from "./session";
import { getSettings } from "./settings";

const RULE_OFFSET = 77000;

export async function shieldGranted(): Promise<boolean> {
  try {
    return await ext.permissions.contains({ origins: ["<all_urls>"] });
  } catch {
    return false;
  }
}

function ruleIdFor(host: string): number {
  // Stable small hash of the host -> DNR rule id space.
  let h = 5381;
  for (let i = 0; i < host.length; i++) h = ((h << 5) + h + host.charCodeAt(i)) >>> 0;
  return RULE_OFFSET + (h % 100000);
}

function warningUrl(host: string, brand?: DetectorHit | null): string {
  const p = new URLSearchParams({ host });
  if (brand) {
    p.set("brand", brand.brand);
    p.set("brandDomain", brand.brandDomain);
  }
  return chrome.runtime.getURL(`warning.html?${p.toString()}`);
}

/** Pre-render block for a KNOWN-bad host: a DNR session redirect rule. */
export async function addBlockRule(host: string, hit: DetectorHit | null): Promise<void> {
  if (!(await shieldGranted())) return;
  if (await sessionAllowed(host)) return;
  try {
    await ext.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [ruleIdFor(host)],
      addRules: [
        {
          id: ruleIdFor(host),
          priority: 1,
          action: {
            type: "redirect" as chrome.declarativeNetRequest.RuleActionType,
            redirect: { url: warningUrl(host, hit) },
          },
          condition: {
            urlFilter: `||${host}^`,
            resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType],
          },
        },
      ],
    });
  } catch {
    // DNR unavailable (engine parity): the tabs.update path still covers it.
  }
  // mirror the block into the session ledger so the popup can list it and
  // offer a clear - the DNR rule id is a non-reversible hash, so this is the only
  // way back to the hostname.
  await markBlocked(host);
}

export async function removeBlockRule(host: string): Promise<void> {
  try {
    await ext.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleIdFor(host)] });
  } catch {
    // fine
  }
  await unmarkBlocked(host); // keep the session ledger in lock-step with the DNR rules
}

/** Novel-bad path: move the already-committed tab to the warning page. */
export async function redirectToWarning(tabId: number, host: string, hit: DetectorHit | null): Promise<void> {
  if (await sessionAllowed(host)) return;
  const url = warningUrl(host, hit);
  try {
    // location.replace, not tabs.update: it REPLACES the dangerous page's
    // history entry, so one Back from the warning returns to the last safe
    // page instead of bouncing off the block again.
    await ext.scripting.executeScript({
      target: { tabId },
      func: (u: string) => {
        window.location.replace(u);
      },
      args: [url],
    });
    return;
  } catch {
    // Page not scriptable (race, browser UI): fall back to a plain move.
  }
  try {
    await ext.tabs.update(tabId, { url });
  } catch {
    // tab gone; nothing to protect
  }
}

/**
 * Arm the pre-emptive click/form-submit guard on an eligible
 * page. Armed on every eligible page (not just flagged ones) because the
 * risk lives in the TARGET of a click, not the page. Deliberately NOT
 * gated on the broad Active-Shield grant: the injection is simply
 * attempted, and the browser's permission model decides. It succeeds
 * under the broad grant, under a scoped grant, or under the user's own
 * activeTab invocation (opening the popup on the tab), and fails silently
 * everywhere else. No grant is ever widened here and no new permission is
 * involved; users who never opted into Active Shield still get pre-click
 * protection on the tab they invoked Guard on.
 */
export async function armPreempt(tabId: number, host: string): Promise<void> {
  try {
    await ext.scripting.executeScript({
      target: { tabId },
      files: ["content.js"],
    });
    // frameId 0, explicitly. tabs.sendMessage with no frameId goes to EVERY
    // frame, and since the consent pass injects content.js into
    // sub-frames, so an unpinned config would arm the click guard in every
    // iframe on the page as a side effect of a change about cookie banners.
    // Widening where a module RUNS must never widen what it may intercept,
    // so the pre-emptive layer's scope is stated here rather than inherited
    // from whichever injection happened to run last.
    await ext.tabs.sendMessage(tabId, { kind: "whisper-preempt-config", host }, { frameId: 0 });
  } catch {
    // Page not injectable (no access on this tab, browser UI page, race
    // with navigation): fine, the nav pipeline still covers whatever the
    // click lands on.
  }
}

/**
 * Arm the cookie-consent auto-decline on an eligible page, honoring
 * its opt-out. Rides exactly the pre-emptive layer's capability model: the
 * injection is simply attempted and the browser's permission model decides
 * (broad Active-Shield grant, a scoped grant, or the user's own activeTab
 * invocation). No grant is widened and no new permission exists. The module
 * itself is fully local: detection and the one decline click happen
 * on-device, and nothing about the page ever reaches the network.
 *
 * ALL FRAMES, and only for this pass. A consent wall rendered in an
 * iframe was invisible to the module, because document.querySelectorAll
 * crosses no frame boundary, and "invisible" turned out to be where most of
 * the large publishers keep theirs: sampling six of them, one in six was
 * declined and every miss was an iframe wall. So the scan now runs
 * frame-locally in each frame, which is the only place a frame's own
 * document can be read at all.
 *
 * Three things this deliberately does NOT do:
 *
 *   - it adds no permission. allFrames reaches the frames the extension may
 *     already script and no others, so the answer to "where does this run"
 *     is still the browser's, exactly as it was before;
 *   - it widens nothing but this pass. armPreempt above pins its own config
 *     to frameId 0 for precisely this reason;
 *   - it relaxes no safety gate. Every frame runs the same contract, so a
 *     sub-frame still needs a CMP-published handle, a known CMP root, or the
 *     strict generic rule with its cookie word AND accept sibling AND
 *     banner-scale bounds. A frame is a smaller document, not a laxer one.
 *
 * The win still counts once per PAGE rather than once per frame; that is
 * enforced in the background, where the page identity lives.
 */
export async function armConsent(tabId: number): Promise<void> {
  if (!(await getSettings()).cookieDecline) return;
  try {
    await ext.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ["content.js"],
    });
    // No frameId here: this one really is for every frame.
    await ext.tabs.sendMessage(tabId, { kind: "whisper-consent-config" });
  } catch {
    // Page not injectable (no access on this tab, browser UI page, race
    // with navigation): fine, the page simply keeps its banner.
  }
}

/**
 * Arm the consent pass in ONE sub-frame that committed after the page did.
 *
 * executeScript is a one-shot: it reaches the frames that exist when it runs
 * and nothing that arrives later. Measured against the real internet, later is
 * exactly when a CMP frame arrives. On theguardian.com the Sourcepoint frame
 * (sourcepoint.theguardian.com/index.html) and on spiegel.de its equivalent
 * (sp-spiegel-de.spiegel.de/index.html) both reported the pass NOT armed after
 * a 12 second settle, while every frame that existed at nav time was armed.
 * The wall a publisher shows you is injected by script after the page loads,
 * which is the whole point of a consent platform, so a one-shot at nav time is
 * guaranteed to miss the frame that matters.
 *
 * Same capability model as everything else here: attempted, and the browser
 * decides. No grant is widened. The caller gates this on the page having been
 * armed at all, so a frame is only reached on a page the nav pipeline already
 * decided was eligible.
 */
export async function armConsentFrame(tabId: number, frameId: number): Promise<void> {
  if (!(await getSettings()).cookieDecline) return;
  try {
    await ext.scripting.executeScript({
      target: { tabId, frameIds: [frameId] },
      files: ["content.js"],
    });
    await ext.tabs.sendMessage(tabId, { kind: "whisper-consent-config" }, { frameId });
  } catch {
    // Frame gone, not injectable, or already navigated away: leave it be.
  }
}

/**
 * The scoped second line behind a pre-emptive interrupt: a session
 * DNR rule for THIS host only, so a navigation that slips past the
 * in-page hold (another tab, a page-driven redirect, a re-click after the
 * script is gone) is still stopped pre-flight. With the broad
 * Active-Shield grant the rule redirects to the explanatory warning page;
 * without it the platform forbids redirect rules (they need host
 * permissions), so a plain BLOCK rule, which needs no host permission at
 * all, protects instead. That no-grant flavor is the opaque one: a LATER
 * direct navigation to the host is a pre-commit browser block
 * (ERR_BLOCKED_BY_CLIENT) with no Whisper page to carry the explanation.
 * So it is exactly the flavor that MUST reach the session block ledger: the
 * rule id is a non-reversible hash of the host, so the ledger is the only
 * way back to the hostname, and it is what the popup lists and clears. Both
 * flavors therefore mark the block (the granted one inside addBlockRule,
 * this one here), and both exits (the interstitial's Proceed and the
 * popup's Clear) lift it through removeBlockRule. Nothing here touches the
 * network.
 */
export async function addPreemptBlock(host: string): Promise<void> {
  if (await sessionAllowed(host)) return;
  if (await shieldGranted()) {
    await addBlockRule(host, null);
    return;
  }
  try {
    await ext.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [ruleIdFor(host)],
      addRules: [
        {
          id: ruleIdFor(host),
          priority: 1,
          action: { type: "block" as chrome.declarativeNetRequest.RuleActionType },
          condition: {
            urlFilter: `||${host}^`,
            resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType],
          },
        },
      ],
    });
  } catch {
    // DNR unavailable (engine parity): the in-page guard still holds, and
    // with no rule installed there is nothing to list or to clear.
    return;
  }
  await markBlocked(host);
}

/**
 * Inject the amber banner / password-field guard on a flagged host.
 *
 * A session-allowed host normally gets neither: the user answered the page
 * verdict and Guard does not re-litigate it. `afterAllow` is the ONE
 * exception, and it is the ladder's, not an ad-hoc one: the
 * credential moment is its own cell in the table, so a user who clicked
 * through an evidenced-malicious warning still gets the non-blocking
 * password caution when a password field takes focus. The caller sends
 * `banner: false` with it - the page verdict stays answered, only the
 * credential moment speaks.
 */
export async function injectGuard(
  tabId: number,
  payload: {
    host: string;
    severity: "high" | "medium";
    brand: string | null;
    brandDomain: string | null;
    banner: boolean;
    fieldGuard: boolean;
    band?: string | null;
    graphLabel?: string | null;
    afterAllow?: boolean;
  },
): Promise<void> {
  if (!(await shieldGranted())) return;
  if (payload.afterAllow !== true && (await sessionAllowed(payload.host))) return;
  try {
    await ext.scripting.executeScript({
      target: { tabId },
      files: ["content.js"],
    });
    await ext.tabs.sendMessage(tabId, { kind: "whisper-guard-config", ...payload });
  } catch {
    // Page not injectable (browser UI page, race with navigation): fine.
  }
}
