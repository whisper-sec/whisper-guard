// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The MV3 service worker: navigation pipeline, per-tab state, icon
// painting, and the message router for the popup / options / pages.
//
// The hot path, per main-frame navigation:
//   parse URL locally -> hostname only -> on-device detector (always)
//   -> cache -> (keyed, miss) ONE whisper.assess -> paint the icon.
// Everything else (explain / identify / candidates / report) fires lazily
// on popup interaction. Graph slow or down => fail open: UNKNOWN icon,
// on-device checks keep running, browsing is never blocked.

import { ext } from "../shared/api";
import { NAV_DEBOUNCE_MS } from "../shared/config";
import { extractHostname } from "../shared/hostname";
import { registrableDomain } from "../shared/psl";
import type { BgRequest, BgResponse, CheckHostResult } from "../shared/messages";
import type { AssessVerdict, TabState } from "../shared/types";
import { detect } from "../detector/detector";
import { assessHost } from "./assess";
import { cacheGet, cachePut } from "./cache";
import {
  cancelDeviceFlow,
  deviceFlowState,
  onAuthChanged,
  resumeDeviceFlow,
  saveKey,
  signOut,
  startDeviceFlow,
} from "./device-flow";
import { GraphError, hasKey } from "./graph-client";
import { bandToIcon, forgetTab, paintIcon, pulseBadge } from "./icon-state";
import { installContextMenu, onMenuClicked } from "./context-menu";
import { CORPUS_ALARM, scheduleCorpusUpdates, updateCorpusNow } from "./corpus-updater";
import { confirmLookalikes, explainHost, identifyHost, reportHost } from "./cognition";
import { getSettings, setSettings } from "./settings";
import { allowForSession, recordRisk, sessionAllowed, sessionRisks } from "./session";
import { addBlockRule, injectGuard, redirectToWarning, removeBlockRule, shieldGranted } from "./shield";

// ---------------------------------------------------------------- tab state

const tabs = new Map<number, TabState>();
const debounce = new Map<number, ReturnType<typeof setTimeout>>();
// Last committed URL per tab, learned from webNavigation (the extension has
// no "tabs" permission, so tabs.query cannot see URLs; this map is what
// lets sign-in/sign-out repaint already-open tabs).
const lastUrl = new Map<number, string>();

function blankState(): TabState {
  return {
    hostname: null,
    registrable: null,
    eligible: false,
    signedIn: false,
    icon: "neutral",
    verdict: null,
    detector: null,
    graphError: null,
    shieldOn: false,
  };
}

async function evaluate(tabId: number, url: string): Promise<void> {
  const state = blankState();
  state.signedIn = await hasKey();
  state.shieldOn = (await getSettings()).shield && (await shieldGranted());

  const hostname = extractHostname(url);
  if (!hostname) {
    state.icon = "neutral";
    tabs.set(tabId, state);
    await paintIcon(tabId, "neutral");
    return;
  }
  state.hostname = hostname;
  state.registrable = registrableDomain(hostname);
  state.eligible = true;

  const settings = await getSettings();

  // 1) The keyless hero: the on-device detector, before anything keyed.
  state.detector = await detect(hostname, settings.nearMiss, settings.allowlist);

  // 2) Keyed ambient band, cache first.
  let verdict: AssessVerdict | null = null;
  if (state.signedIn) {
    verdict = await cacheGet(hostname);
    if (!verdict) {
      // Show progress honestly while the one assess call runs; keep the
      // last-known band via cache when there was one.
      tabs.set(tabId, { ...state, icon: "checking" });
      await paintIcon(tabId, "checking");
      try {
        verdict = await assessHost(hostname);
        await cachePut(verdict);
      } catch (e) {
        state.graphError =
          e instanceof GraphError && e.reason === "auth"
            ? "the graph rejected the key; sign in again"
            : "could not reach Whisper; showing on-device checks only";
        verdict = null;
      }
    }
  }
  state.verdict = verdict;

  // 3) Fold the two tiers into one icon. The filled red plate is reserved
  // for evidenced-malicious; a keyless look-alike hit is an amber nudge.
  if (verdict && verdict.band === "CRITICAL") {
    state.icon = "malicious";
  } else if ((verdict && (verdict.band === "HIGH" || verdict.band === "MEDIUM")) || state.detector) {
    state.icon = "suspicious";
  } else if (verdict) {
    state.icon = bandToIcon(verdict.band);
  } else {
    state.icon = state.signedIn ? "unknown" : "signedout";
  }
  tabs.set(tabId, state);
  await paintIcon(tabId, state.icon);

  // 4) Session log + one-time pulse for risky sightings.
  if (state.icon === "malicious" || state.icon === "suspicious") {
    const reason =
      state.icon === "malicious"
        ? (verdict?.label ?? "known threat")
        : state.detector
          ? `looks like ${state.detector.brandDomain}`
          : (verdict?.label ?? "flagged by the graph");
    const first = await recordRisk(hostname, reason);
    if (first) await pulseBadge(tabId, state.icon === "malicious" ? "#DC2626" : "#F59E0B");
  }

  // 5) Active Shield (opt-in): full-page warning for evidenced-malicious,
  // banner + password-field guard for amber. Never for benign/unknown.
  if (state.shieldOn && !(await sessionAllowed(hostname))) {
    if (state.icon === "malicious") {
      await addBlockRule(hostname, state.detector);
      await redirectToWarning(tabId, hostname, state.detector);
    } else if (state.icon === "suspicious" && (settings.amberBanner || settings.fieldGuard)) {
      await injectGuard(tabId, {
        host: hostname,
        severity: state.detector?.severity ?? "medium",
        brand: state.detector?.brand ?? null,
        brandDomain: state.detector?.brandDomain ?? null,
        banner: settings.amberBanner,
        fieldGuard: settings.fieldGuard,
      });
    }
  }
}

function scheduleEvaluate(tabId: number, url: string): void {
  const t = debounce.get(tabId);
  if (t) clearTimeout(t);
  debounce.set(
    tabId,
    setTimeout(() => {
      debounce.delete(tabId);
      evaluate(tabId, url).catch(() => undefined);
    }, NAV_DEBOUNCE_MS),
  );
}

// ------------------------------------------------------------- wiring

ext.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  lastUrl.set(details.tabId, details.url);
  scheduleEvaluate(details.tabId, details.url);
});

ext.tabs.onActivated.addListener(({ tabId }) => {
  const state = tabs.get(tabId);
  // Repaint from state; a brand-new tab stays neutral until it navigates.
  paintIcon(tabId, state?.icon ?? "neutral").catch(() => undefined);
});

ext.tabs.onRemoved.addListener((tabId) => {
  tabs.delete(tabId);
  lastUrl.delete(tabId);
  forgetTab(tabId);
  const t = debounce.get(tabId);
  if (t) {
    clearTimeout(t);
    debounce.delete(tabId);
  }
});

ext.runtime.onInstalled.addListener((details) => {
  installContextMenu();
  scheduleCorpusUpdates();
  // First install only (never on update/reload): the two-card welcome with
  // the privacy promise and the honest scope. Protection is already on.
  if (details.reason === "install") {
    ext.tabs.create({ url: chrome.runtime.getURL("firstrun.html") }).catch(() => undefined);
  }
});
ext.runtime.onStartup?.addListener(() => {
  installContextMenu();
  scheduleCorpusUpdates();
});

ext.contextMenus.onClicked.addListener((info) => onMenuClicked(info));

// Sign-in / sign-out repaints every open http(s) tab right away: the band
// goes live on the current tab the moment the console approves (and dims
// back to the keyless state on sign-out), no re-navigation needed.
onAuthChanged(() => {
  for (const [tabId, url] of lastUrl) {
    if (/^https?:/i.test(url)) scheduleEvaluate(tabId, url);
  }
});

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CORPUS_ALARM) updateCorpusNow().catch(() => undefined);
});

void resumeDeviceFlow();

// ---------------------------------------------------------- message router

async function checkHost(rawHost: string): Promise<CheckHostResult> {
  const host = rawHost.toLowerCase();
  const settings = await getSettings();
  const detector = await detect(host, settings.nearMiss, settings.allowlist);
  const signedIn = await hasKey();
  let verdict: CheckHostResult["verdict"] = null;
  let graphError: string | null = null;
  if (signedIn) {
    const cached = await cacheGet(host);
    if (cached) {
      verdict = { band: cached.band, label: cached.label, coverage: cached.coverage };
    } else {
      try {
        const v = await assessHost(host);
        await cachePut(v);
        verdict = { band: v.band, label: v.label, coverage: v.coverage };
      } catch {
        graphError = "could not reach Whisper; showing on-device checks only";
      }
    }
  }
  return { host, detector, verdict, signedIn, graphError };
}

async function handle(msg: BgRequest): Promise<BgResponse> {
  switch (msg.kind) {
    case "getTabState": {
      const state = tabs.get(msg.tabId) ?? blankState();
      state.signedIn = await hasKey();
      return { ok: true, tabState: state };
    }
    case "getSession":
      return { ok: true, session: await sessionRisks() };
    case "getSettings": {
      const stored = await chrome.storage.local.get(["corpus", "corpusUpdated"]);
      const corpus = stored["corpus"] as { version?: number } | undefined;
      return {
        ok: true,
        settings: await getSettings(),
        signedIn: await hasKey(),
        corpusVersion: corpus?.version ?? 1,
        corpusUpdated: (stored["corpusUpdated"] as string | undefined) ?? "bundled",
      };
    }
    case "setSettings":
      await setSettings(msg.patch);
      return { ok: true };
    case "signInStart":
      return { ok: true, device: await startDeviceFlow() };
    case "signInStatus":
      return { ok: true, device: deviceFlowState() };
    case "signInCancel":
      cancelDeviceFlow();
      return { ok: true };
    case "signOut":
      await signOut();
      return { ok: true };
    case "saveKey":
      await saveKey(msg.key);
      return { ok: true };
    case "explain":
      return { ok: true, explain: await explainHost(msg.host) };
    case "identify":
      return { ok: true, explain: await identifyHost(msg.host) };
    case "report":
      return { ok: true, explain: await reportHost(msg.host, msg.note) };
    case "confirmLookalikes":
      try {
        return { ok: true, candidates: await confirmLookalikes(msg.host) };
      } catch {
        return { ok: false, error: "could not reach Whisper; try again" };
      }
    case "checkHost":
      return { ok: true, check: await checkHost(msg.host) };
    case "allowHost": {
      await allowForSession(msg.host);
      await removeBlockRule(msg.host);
      if (!msg.session) {
        const s = await getSettings();
        if (!s.allowlist.includes(msg.host)) {
          await setSettings({ allowlist: [...s.allowlist, msg.host] });
        }
      }
      return { ok: true };
    }
    case "dismissWarning":
      await removeBlockRule(msg.host);
      return { ok: true };
    case "updateCorpusNow": {
      const r = await updateCorpusNow();
      return r.updated ? { ok: true } : { ok: false, error: r.reason };
    }
  }
}

ext.runtime.onMessage.addListener((msg: BgRequest, _sender, sendResponse: (r: BgResponse) => void) => {
  handle(msg)
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e instanceof Error ? e.message : e) }));
  return true; // async response
});
