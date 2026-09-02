// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The MV3 service worker: navigation pipeline, per-tab state, icon
// painting, and the message router for the popup / options / pages /
// dashboard.
//
// The hot path, per main-frame navigation:
//   parse URL locally -> hostname only -> on-device detector (always)
//   -> record in the on-device destination log -> cache -> (miss, live
//   check on) ONE whisper.assess (keyless or keyed) -> paint the icon.
// Everything else (the composed protection picture, explain / identify /
// variants, the dashboard reports) fires lazily on interaction. Graph slow
// or down => fail open: UNKNOWN icon, on-device checks keep running,
// browsing is never blocked.

import { ext } from "../shared/api";
import { NAV_DEBOUNCE_MS } from "../shared/config";
import { atLeast, decide } from "../shared/escalation";
import { extractHostname } from "../shared/hostname";
import { registrableDomain } from "../shared/psl";
import type { BgRequest, BgResponse, CheckHostResult, EndpointDetail } from "../shared/messages";
import type { AssessVerdict, TabState } from "../shared/types";
import { computeEndpointHealth, isFlagged, reportTotals } from "../shared/report";
import { detect } from "../detector/detector";
import { assessHost } from "./assess";
import { cacheClear, cacheGet, cachePut } from "./cache";
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
import { explainHost, identifyHost, reportHost } from "./cognition";
import { getSettings, setSettings } from "./settings";
import { allowForSession, recordRisk, sessionAllowed, sessionBlockedHosts, sessionRisks } from "./session";
import { addBlockRule, armConsent, armConsentFrame, armPreempt, injectGuard, redirectToWarning, removeBlockRule, shieldGranted } from "./shield";
import { preemptCheck } from "./preempt";
import { chainFor, resetChainCache, rungDetailFor } from "./chain-cache";
import { graphScale } from "./scale";
import { graphQuota, resetQuotaCache } from "./quota";
import { protectHost, variantNeighborhood } from "./protect";
import { getDestinations, onNavRecorded, recordNav } from "./navlog";
import { enrichDestinations } from "./enrich";
import { COHOST_QUERY } from "../shared/config";
import { graphQuery } from "./graph-client";
import { endpointCounters, endpointLogs, fleetActivity, listEndpoints } from "./fleet";
import {
  dashboardClosed,
  dashboardOpened,
  FLEET_POLL_ALARM,
  getFleetFeed,
  ingestFleetRows,
  onPollAlarm,
  resetFeed,
} from "./monitor";
import { egressDisable, egressEnable, egressStatus, enrollBrowser, forgetIdentity, resumeEgress } from "./egress";
import { readDevicePolicy, revokeEndpoint, writeDevicePolicy } from "./govern";
import { scanTabLinks } from "./link-scan";
import { scanTabIocs } from "./page-scan";
import { rdapIpUrl, verifyIdentity } from "./rdap";
import { getWins, recordWin, recordWinOnce } from "./wins";

// ---------------------------------------------------------------- tab state

const tabs = new Map<number, TabState>();
const debounce = new Map<number, ReturnType<typeof setTimeout>>();
/**
 * The page a tab's cookie-decline win has already been counted for.
 *
 * Since the consent pass runs in every frame, one page can produce more than
 * one decline: the publisher's own banner in the top document and a CMP wall
 * in an iframe, or two walls in two frames. Each is a real decline and each is
 * worth making, but the tally counts what Guard HANDLED FOR YOU, and a person
 * who saw one prompt disappear did not have two handled. A per-frame count
 * would inflate the only number this feature ever shows.
 *
 * Keyed by tab, valued by the URL that was armed, so re-arming the same page
 * (the nav pipeline is debounced and can evaluate a URL more than once) does
 * not re-open the count, while a genuine navigation does. The URL never leaves
 * the background and is never sent anywhere; it is the page identity the
 * background already holds, which is exactly why the de-duplication lives here
 * and not in the content script, where a frame knows nothing of its siblings.
 */
const consentArmedUrl = new Map<number, string>();
const consentCountedUrl = new Map<number, string>();
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

  // The on-device destination log behind the "This browser" report.
  void recordNav(hostname);

  // 1) The on-device detector, before anything that touches the network.
  state.detector = await detect(hostname, settings.nearMiss, settings.allowlist);

  // 2) The live graph band, cache first: keyless or keyed, unless the user
  // switched the live check off.
  let verdict: AssessVerdict | null = null;
  if (settings.cloudCheck) {
    verdict = await cacheGet(hostname);
    if (!verdict) {
      // Show progress honestly while the one assess call runs.
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

  // 3) ONE calm-escalation ladder decides how loudly this sighting
  // may speak; the icon art then encodes the class it landed in. The
  // filled red plate is reserved for the blocking rung; the conversational
  // rung reads as the amber nudge. De-noising stays transparent and
  // reversible: the RAW verdict rides TabState verbatim and is one click
  // away in the popup, never hidden.
  const signal = {
    band: verdict?.band ?? null,
    label: verdict?.label ?? null,
    lookalike: state.detector !== null,
  };
  const rung = decide(signal, "page");
  if (rung === "blocking") {
    state.icon = "malicious";
  } else if (atLeast(rung, "ambient")) {
    state.icon = "suspicious";
  } else if (verdict) {
    state.icon = bandToIcon(verdict.band);
  } else {
    state.icon = settings.cloudCheck ? "unknown" : "signedout";
  }
  tabs.set(tabId, state);
  await paintIcon(tabId, state.icon);

  // 4) Ambient rung and up: session log + one-time badge pulse. Below it,
  // silence: the network/verdict layer already handled the outcome.
  if (atLeast(rung, "ambient")) {
    const reason =
      state.icon === "malicious"
        ? (verdict?.label ?? "known threat")
        : state.detector
          ? `looks like ${state.detector.brandDomain}`
          : (verdict?.label ?? "flagged by the graph");
    const first = await recordRisk(hostname, reason);
    if (first) await pulseBadge(tabId, state.icon === "malicious" ? "#DC2626" : "#F59E0B");
  }

  // 5) The page layer delivers the two loud rungs, and ONLY under the
  // user's Active-Shield opt-in; without it the ambient icon carries the
  // signal and the popup carries the receipts. Never for silent rungs.
  if (state.shieldOn) {
    if (!(await sessionAllowed(hostname))) {
      if (rung === "blocking") {
        await addBlockRule(hostname, state.detector);
        await redirectToWarning(tabId, hostname, state.detector);
      } else if (rung === "conversational" && (settings.amberBanner || settings.fieldGuard)) {
        await injectGuard(tabId, {
          host: hostname,
          severity: state.detector?.severity ?? "medium",
          brand: state.detector?.brand ?? null,
          brandDomain: state.detector?.brandDomain ?? null,
          banner: settings.amberBanner,
          fieldGuard: settings.fieldGuard,
          band: verdict?.band ?? null,
          graphLabel: verdict?.label ?? null,
        });
      }
    } else if (settings.fieldGuard && rung === "blocking") {
      // 5b) The CREDENTIAL moment, the ladder's own column and the
      // one place a session-allow does not silence Guard: the page moment
      // rang BLOCKING and the human clicked through it, and the credential
      // cell for that same evidence still says conversational - a
      // dismissible word, never a block.
      //
      // The condition used to also test atLeast(decide(signal,"credential"),
      // "conversational"), which reads like the table being consulted and is
      // not: rung === "blocking" can only come from severity "evidenced",
      // and that row's credential cell IS "conversational", so the second
      // half was true whenever the first was. It looked like a guard, it
      // tested nothing, and a test asserting "the credential column is
      // consulted here" would have passed against a build that had deleted
      // the column. The invariant is now pinned where it belongs, on the
      // ladder itself (e2e/escalation-decision.spec.ts). The page
      // verdict stays answered (no re-block, no banner, no second
      // warning); only the credential moment speaks, because typing a
      // password into a site the graph calls malicious is a different
      // moment with a different actor. Without it, the loudest verdict
      // Guard has produced LESS credential protection than a mere
      // look-alike does, since the amber path above was the only thing
      // that ever armed the field guard. A softer page verdict the user
      // waved through stays fully silent: they said the site is fine, and
      // on a look-alike that is much likelier to be true.
      await injectGuard(tabId, {
        host: hostname,
        severity: "high",
        brand: state.detector?.brand ?? null,
        brandDomain: state.detector?.brandDomain ?? null,
        banner: false,
        fieldGuard: true,
        band: verdict?.band ?? null,
        graphLabel: verdict?.label ?? null,
        afterAllow: true,
      });
    }
  }

  // 6) The pre-emptive rung, armed on EVERY eligible page
  // (benign included): the risk it guards against lives in the target of
  // a click, not the page itself. A blocking-rung page was already moved
  // to the warning above; skip it. Arming needs NO broad grant: under the
  // Active-Shield opt-in it lands everywhere; without any grant the
  // attempt succeeds exactly where the user's own activeTab invocation
  // (or a scoped grant) allows, and fails silently elsewhere. A user who
  // holds the broad grant but switched Active Shield OFF opted the page
  // layer out: no automatic injection for them (popup-open arming still
  // works, being an explicit invocation).
  if (rung !== "blocking" && (state.shieldOn || !(await shieldGranted()))) {
    await armPreempt(tabId, hostname);
    // The cookie-consent auto-decline rides the same arming moment
    // and capability model; its own opt-out is honored inside armConsent.
    // Remember which page was armed so the win can be counted once for it
    // however many frames it turns out to have.
    consentArmedUrl.set(tabId, url);
    await armConsent(tabId);
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
  if (details.frameId !== 0) {
    // A SUB-frame committed. The consent pass is injected once at nav
    // time, which reaches the frames that exist then and nothing that arrives
    // later, and later is exactly when a consent platform injects its wall.
    // Measured on the real internet: theguardian.com's Sourcepoint frame and
    // spiegel.de's equivalent both reported the pass unarmed after a 12 second
    // settle, while every frame that existed at nav time was armed. A one-shot
    // was always going to miss the frame that matters.
    //
    // Gated on the page having been armed at all, so this decides nothing on
    // its own: it extends an eligibility the nav pipeline already granted to
    // the frames that showed up afterwards.
    if (consentArmedUrl.has(details.tabId)) {
      armConsentFrame(details.tabId, details.frameId).catch(() => undefined);
    }
    return;
  }
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
  // the per-page consent ledger is per tab, so it goes with the tab.
  // Left behind it would be an unbounded map keyed by ids that never repeat.
  consentArmedUrl.delete(tabId);
  consentCountedUrl.delete(tabId);
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
  // First install only (never on update/reload): the welcome page with the
  // privacy promise and the honest scope. Protection is already on.
  if (details.reason === "install") {
    ext.tabs.create({ url: chrome.runtime.getURL("firstrun.html") }).catch(() => undefined);
  }
});
ext.runtime.onStartup?.addListener(() => {
  installContextMenu();
  scheduleCorpusUpdates();
});

ext.contextMenus.onClicked.addListener((info) => onMenuClicked(info));

// Sign-in / sign-out repaints every open http(s) tab right away: the keyed
// tier lights up the moment the console approves, no re-navigation needed.
onAuthChanged(() => {
  // Drop every cached answer first. A keyless verdict and a keyed one are
  // answers from different tiers of the graph, and re-evaluating without
  // clearing simply re-read the same cached rows: signing in lit up the
  // chrome and changed none of the verdicts until each TTL expired, up to
  // twenty-four hours later. The chain and the quota are tier-shaped too.
  cacheClear();
  resetChainCache();
  resetQuotaCache();
  for (const [tabId, url] of lastUrl) {
    if (/^https?:/i.test(url)) scheduleEvaluate(tabId, url);
  }
});

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CORPUS_ALARM) updateCorpusNow().catch(() => undefined);
  if (alarm.name === FLEET_POLL_ALARM) onPollAlarm();
});

// The dashboard holds a port while open: live per-navigation nudges for the
// "This browser" view and the tighter fleet-poll cadence.
ext.runtime.onConnect.addListener((port) => {
  if (port.name !== "dashboard") return;
  dashboardOpened();
  const unsubscribe = onNavRecorded(() => {
    try {
      port.postMessage({ kind: "nav" });
    } catch {
      // port already gone
    }
  });
  port.onDisconnect.addListener(() => {
    unsubscribe();
    dashboardClosed();
  });
});

void resumeDeviceFlow();
void resumeEgress();

// ---------------------------------------------------------- message router

async function checkHost(rawHost: string): Promise<CheckHostResult> {
  const host = rawHost.toLowerCase();
  const settings = await getSettings();
  const detector = await detect(host, settings.nearMiss, settings.allowlist);
  const signedIn = await hasKey();
  let verdict: CheckHostResult["verdict"] = null;
  let graphError: string | null = null;
  if (settings.cloudCheck) {
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

async function endpointDetail(agent: string): Promise<EndpointDetail> {
  const endpoints = await listEndpoints();
  const endpoint = endpoints.find((e) => e.agent === agent);
  if (!endpoint) throw new Error(`no endpoint ${agent} on this account`);

  const [counters, verification, activity] = await Promise.all([
    endpointCounters(agent).catch(() => null),
    verifyIdentity(endpoint.address),
    endpointLogs(agent).catch(() => []),
  ]);

  // Busiest destinations for THIS endpoint, enriched like everything else.
  const byHost = new Map<string, { q: number; lastAt: number }>();
  for (const r of activity) {
    const cur = byHost.get(r.target) ?? { q: 0, lastAt: 0 };
    cur.q += 1;
    if (r.ts > cur.lastAt) cur.lastAt = r.ts;
    byHost.set(r.target, cur);
  }
  const topHosts = await enrichDestinations(
    [...byHost.entries()]
      .map(([host, v]) => ({ host, q: v.q, lastAt: v.lastAt }))
      .sort((a, b) => b.q - a.q)
      .slice(0, 60),
  ).catch(() => []);

  const health = computeEndpointHealth({
    isWhisperAgent: verification?.isWhisperAgent,
    daneOk: verification?.daneOk ?? undefined,
    jwsOk: verification?.jwsOk ?? undefined,
    rpki: null,
    flaggedDestinations: topHosts.filter((h) => isFlagged(h.verdict)).length,
    threatLoaded: topHosts.length > 0 || activity.length === 0,
    state: endpoint.state,
  });

  return {
    endpoint,
    counters,
    verification,
    health,
    activity: activity.slice(0, 200),
    topHosts,
    rdapUrl: rdapIpUrl(endpoint.address),
  };
}

function nokeyResponse(e: unknown): BgResponse | null {
  if (e instanceof GraphError && e.reason === "nokey") {
    return { ok: false, error: "Sign in to unlock your fleet.", nokey: true };
  }
  return null;
}

async function handle(msg: BgRequest, sender?: chrome.runtime.MessageSender): Promise<BgResponse> {
  switch (msg.kind) {
    case "getTabState": {
      // A COPY. Writing signedIn through to the stored object made the
      // answer to a read mutate the thing being read, so a later paint could
      // observe a field this handler set rather than one evaluate() decided.
      const state = { ...(tabs.get(msg.tabId) ?? blankState()) };
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
      await resetFeed();
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
        const hood = await variantNeighborhood(msg.host);
        return { ok: true, candidates: hood.flagged };
      } catch {
        return { ok: false, error: "could not reach Whisper; try again" };
      }
    case "checkHost":
      return { ok: true, check: await checkHost(msg.host) };
    case "getProtection":
      return { ok: true, protection: await protectHost(msg.host, msg.withVariants ?? false) };
    case "getBrowserReport": {
      const destinations = await getDestinations();
      const wanted = msg.limit ? destinations.slice(0, msg.limit) : destinations;
      const hosts = await enrichDestinations(wanted);
      return { ok: true, report: { hosts, totals: reportTotals(hosts), generatedAt: Date.now() } };
    }
    case "getFleetReport": {
      try {
        const activity = await fleetActivity();
        // Merge into the ring for polling continuity, but render the feed
        // from the rows we just fetched so the first paint is never empty.
        ingestFleetRows(activity.recent);
        const hosts = await enrichDestinations(activity.destinations);
        const feed = await getFleetFeed();
        const rows = activity.recent.length > 0 ? activity.recent : feed.rows;
        return {
          ok: true,
          fleet: {
            endpoints: activity.endpoints,
            hosts,
            totals: reportTotals(hosts),
            feed: rows.slice(0, 200),
            feedStatus: { mode: feed.status.mode === "offline" ? "offline" : "polling", updatedAt: Date.now() },
            silent: activity.silent,
            generatedAt: Date.now(),
          },
        };
      } catch (e) {
        return nokeyResponse(e) ?? { ok: false, error: "could not reach the control plane; try again" };
      }
    }
    case "getEndpointDetail":
      try {
        return { ok: true, endpoint: await endpointDetail(msg.agent) };
      } catch (e) {
        return (
          nokeyResponse(e) ?? {
            ok: false,
            error: String(e instanceof Error ? e.message : e),
          }
        );
      }
    case "getDevicePolicy":
      try {
        return { ok: true, policy: await readDevicePolicy(msg.agent) };
      } catch (e) {
        return nokeyResponse(e) ?? { ok: false, error: String(e instanceof Error ? e.message : e) };
      }
    case "setDevicePolicy":
      try {
        return { ok: true, policy: await writeDevicePolicy(msg.agent, msg.policy) };
      } catch (e) {
        return nokeyResponse(e) ?? { ok: false, error: String(e instanceof Error ? e.message : e) };
      }
    case "revokeEndpoint":
      try {
        const revoked = await revokeEndpoint(msg.agent);
        // If the browser just revoked ITSELF, drop the stored identity and
        // disengage routing so nothing keeps claiming the retired /128.
        // Both selector forms are checked: the id the caller named and the
        // id the engine echoed back (they differ when revoking by address).
        if (revoked.status === "revoked") {
          await forgetIdentity(revoked.agent);
          await forgetIdentity(msg.agent);
        }
        return { ok: true, revoked };
      } catch (e) {
        return nokeyResponse(e) ?? { ok: false, error: String(e instanceof Error ? e.message : e) };
      }
    case "getDestinationDrill": {
      try {
        const rows = await graphQuery(COHOST_QUERY, { h: msg.host.toLowerCase() });
        const row = rows[0] ?? {};
        const num = (v: unknown): number | null =>
          typeof v === "number" && Number.isFinite(v) ? v : null;
        const str = (v: unknown): string | null =>
          typeof v === "string" && v !== "" ? v : null;
        return {
          ok: true,
          drill: {
            host: msg.host.toLowerCase(),
            ip: str(row["ip"]),
            cohosted: num(row["cohosted"]),
            prefix: str(row["prefix"]),
            threatNeighbors: num(row["threatNeighbors"]),
          },
        };
      } catch {
        return { ok: false, error: "the destination drill needs the deeper graph tier" };
      }
    }
    case "openDashboard": {
      const suffix = msg.view ? `#${msg.view}` : "";
      await ext.tabs.create({ url: chrome.runtime.getURL(`dashboard.html${suffix}`) });
      return { ok: true };
    }
    case "egressStatus":
      return { ok: true, egress: await egressStatus() };
    case "egressEnable":
      return { ok: true, egress: await egressEnable() };
    case "egressDisable":
      return { ok: true, egress: await egressDisable() };
    case "enroll":
      // ENROLL alone: reserve + verify the browser's identity. Control
      // plane only; works whenever signed in, no proxy permission involved.
      try {
        return { ok: true, enrollment: await enrollBrowser() };
      } catch (e) {
        if (e instanceof GraphError && e.reason === "nokey") {
          return {
            ok: false,
            error: "Sign in first; this browser's identity lives on your Whisper account.",
            nokey: true,
          };
        }
        return { ok: false, error: String(e instanceof Error ? e.message : e) };
      }
    case "scanIocs":
      // Same shape as scanLinks deliberately, including the host-access
      // recovery: both inject on the reader's gesture, and both dead-end the
      // same way without access to this tab, so they must fail the same way too.
      try {
        return { ok: true, scan: await scanTabIocs(msg.tabId, msg.ignore ?? []) };
      } catch (e) {
        const m = String(e instanceof Error ? e.message : e);
        if (/cannot access|host permission|permission to access|missing host/i.test(m)) {
          return { ok: false, nohost: true, error: m };
        }
        return { ok: false, error: m };
      }
    case "scanLinks":
      try {
        return { ok: true, scan: await scanTabLinks(msg.tabId) };
      } catch (e) {
        const m = String(e instanceof Error ? e.message : e);
        // The reader could not access the page: the popup opened without host
        // access to this tab. Flag it so the UI can ask for this-site access
        // on the next click, rather than dead-ending on an opaque error.
        if (/cannot access|host permission|permission to access|missing host/i.test(m)) {
          return {
            ok: false,
            nohost: true,
            error: "Whisper Guard needs your OK to read this page's link addresses (this site only, never the page).",
          };
        }
        return {
          ok: false,
          error: m.includes("links")
            ? m
            : "could not reach Whisper for the link sweep; try again",
        };
      }
    case "verifyIdentity": {
      const verification = await verifyIdentity(msg.ip);
      // A confirmed Whisper endpoint identity is a countable quiet win, but
      // this handler also runs at DISPLAY time (every popup open and every
      // dashboard chip refresh re-verifies the same identity), so it counts
      // at most once per day: the first confirmation is the day's win, and a
      // re-render of the same fact is not another one. Category and count
      // only, the address is never stored.
      if (verification?.isWhisperAgent === true) await recordWinOnce("identityVerified");
      return { ok: true, verification };
    }
    case "preemptCheck":
      return { ok: true, preempt: await preemptCheck(msg.host) };
    case "preemptArm": {
      // Popup-open arming: opening the popup is a real extension
      // invocation, so activeTab makes THIS tab scriptable even without
      // the broad Active-Shield grant. Arm the pre-emptive guard there; a
      // page we still cannot script fails silently (nothing to lose). A
      // blocking-rung page is not armed: the warning layer owns it.
      const st = tabs.get(msg.tabId);
      if (st?.eligible && st.hostname && st.icon !== "malicious") {
        await armPreempt(msg.tabId, st.hostname);
        await armConsent(msg.tabId);
        // RECORD THE PAGE. The consent pass runs in every frame, so the win
        // tally de-duplicates a decline once per PAGE using this map. Arming
        // from the popup without writing to it meant every decline on a
        // popup-armed page took the "no page known" path and skipped the
        // de-duplication entirely - the exact per-frame inflation the map
        // exists to prevent, on the one arming route that has no other.
        const url = lastUrl.get(msg.tabId);
        if (url !== undefined) consentArmedUrl.set(msg.tabId, url);
      }
      return { ok: true };
    }
    // The join path behind one hostname. Built on the reader's ask, never
    // on navigation: the public tier allows a hundred graph calls an hour
    // from one address, the chain costs seven of them, and browsing must
    // not spend the budget that the verdict needs.
    case "getChain":
      return { ok: true, chain: await chainFor(msg.host) };
    case "getRungDetail":
      return { ok: true, detail: await rungDetailFor(msg.host, msg.rung) };
    // The live scale, and the live pulse. null when the endpoint could not
    // be read, which the surface renders as "unavailable" rather than as a
    // remembered figure.
    case "getScale":
      return { ok: true, scale: await graphScale() };
    case "getQuota":
      return { ok: true, quota: await graphQuota() };
    case "getWins":
      return { ok: true, wins: await getWins() };
    case "listBlocked":
      // the hosts blocked this session, so the popup can list them and
      // clear per-host (clear is the existing allowHost{session:true} = unblock).
      return { ok: true, hosts: await sessionBlockedHosts() };
    case "consentDeclined": {
      // Cookie-consent auto-decline: the content module clicked a
      // banner's decline control. On the calm ladder this is a WIN
      // moment, and the win row is silent at every severity, so there is
      // nothing to raise: no toast, no badge, no notification (the
      // extension holds no notifications permission at all). The COUNT is
      // not a surface and is therefore not gated on the rung: the ladder
      // decides how loudly Guard may speak, never whether the tally is
      // kept. Gating it would mean a future ladder edit silently empties
      // the popup card instead of quieting it, and would make this
      // category behave differently from the other two, which count
      // unconditionally (preempt.ts, verifyIdentity). The message carries
      // no host or URL by construction: category and count, nothing else.
      //
      // Once per PAGE, not once per frame. The consent pass runs in
      // every frame now, so a page whose publisher banner sits in the top
      // document and whose CMP wall sits in an iframe can legitimately
      // decline twice. Both declines are worth making; only one prompt was
      // handled from where the person is sitting. The page identity comes
      // from the background's own arming record, so nothing new is read from
      // the page and the message still carries neither host nor URL.
      const declTab = sender?.tab?.id;
      if (declTab !== undefined) {
        const page = consentArmedUrl.get(declTab);
        if (page !== undefined && consentCountedUrl.get(declTab) === page) {
          return { ok: true }; // a sibling frame already counted this page
        }
        if (page !== undefined) consentCountedUrl.set(declTab, page);
      }
      await recordWin("cookieDecline");
      return { ok: true };
    }
    case "preemptAllow":
      // Proceed on the inline interstitial: the same honest one-click-
      // through as the full-page warning, allowed for this session only,
      // and any lingering DNR block rule for the target is lifted so the
      // resumed navigation is not re-blocked.
      // Future: route Proceed through the per-device policy decision before
      // honoring it. The hook belongs here rather than in govern.ts, which
      // stays untouched until that decision is wired.
      await allowForSession(msg.host);
      await removeBlockRule(msg.host);
      return { ok: true };
    case "preemptOpen": {
      // Resume of a held middle-/modifier-click: a synthetic click
      // cannot carry the user's modifiers (untrusted events never trigger
      // modified navigation) and window.open always FOREGROUNDS, so the
      // faithful resume is opened here with the native disposition: a
      // genuine background tab for middle/Ctrl/Cmd, foreground with Shift
      // added, a new window for Shift alone. The URL is consumed by
      // tabs.create / windows.create on this machine only; nothing beyond
      // the bare hostname (preemptCheck) ever went to the network.
      if (!/^https?:\/\//i.test(msg.url)) {
        return { ok: false, error: "only http(s) destinations can be resumed" };
      }
      if (msg.disposition === "window") {
        await ext.windows.create({ url: msg.url });
        return { ok: true };
      }
      const active = msg.disposition === "foreground-tab";
      const opener = sender?.tab;
      try {
        await ext.tabs.create(
          opener?.id !== undefined
            ? { url: msg.url, active, openerTabId: opener.id, index: opener.index + 1 }
            : { url: msg.url, active },
        );
      } catch {
        // The opener tab vanished mid-flight: still honor the intent.
        await ext.tabs.create({ url: msg.url, active });
      }
      return { ok: true };
    }
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
    default: {
      // Falling off the end called sendResponse(undefined), which is not a
      // BgResponse at all: a stale content script from a previous version,
      // or another extension probing, got a shape no caller can narrow. Say
      // so instead, and say what would help.
      const unknown = msg as { kind?: unknown };
      return {
        ok: false,
        error: `Whisper Guard does not handle "${String(unknown.kind)}". This usually means a page is running an older content script; reload the tab.`,
      };
    }
  }
}

ext.runtime.onMessage.addListener((msg: BgRequest, sender, sendResponse: (r: BgResponse) => void) => {
  handle(msg, sender)
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e instanceof Error ? e.message : e) }));
  return true; // async response
});
