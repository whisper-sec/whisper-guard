// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Active Shield: the opt-in on-page layer. Requires the runtime broad-host
// grant (chrome.permissions.request from the options page); without it the
// ambient icon + popup + pre-click check still deliver the full signal with
// zero page injection.
//
// Evidenced-malicious hosts get the full-page warning two ways:
//   cached-bad  -> a DNR session rule redirects the request pre-render
//   novel-bad   -> tabs.update on verdict (brief paint, still pre-credential)
// Amber (suspicious / look-alike) never blocks: a dismissible banner plus a
// password-field caution, injected only on flagged hosts.

import { ext } from "../shared/api";
import type { DetectorHit } from "../shared/types";
import { sessionAllowed } from "./session";

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
}

export async function removeBlockRule(host: string): Promise<void> {
  try {
    await ext.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleIdFor(host)] });
  } catch {
    // fine
  }
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

/** Inject the amber banner / password-field guard on a flagged host. */
export async function injectGuard(
  tabId: number,
  payload: { host: string; severity: "high" | "medium"; brand: string | null; brandDomain: string | null; banner: boolean; fieldGuard: boolean },
): Promise<void> {
  if (!(await shieldGranted())) return;
  if (await sessionAllowed(payload.host)) return;
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
