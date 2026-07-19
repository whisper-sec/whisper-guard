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
import { extractHostname } from "../shared/hostname";
import { registrableDomain } from "../shared/psl";
import type { BgRequest, BgResponse, CheckHostResult, EndpointDetail } from "../shared/messages";
import type { AssessVerdict, TabState } from "../shared/types";
import { computeEndpointHealth, isFlagged, reportTotals } from "../shared/report";
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
import { explainHost, identifyHost, reportHost } from "./cognition";
import { getSettings, setSettings } from "./settings";
import { allowForSession, recordRisk, sessionAllowed, sessionRisks } from "./session";
import { addBlockRule, injectGuard, redirectToWarning, removeBlockRule, shieldGranted } from "./shield";
import { isBlocking, protectHost, variantNeighborhood } from "./protect";
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
import { egressDisable, egressEnable, egressStatus, enrollBrowser, resumeEgress } from "./egress";
import { scanTabLinks } from "./link-scan";
import { rdapIpUrl, verifyIdentity } from "./rdap";

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

  // 3) Fold the tiers into one icon. The filled red plate is reserved for
  // the blocking gate (CRITICAL / HIGH / labelled malicious); a look-alike
  // hit or a MEDIUM band is an amber nudge.
  if (verdict && isBlocking(verdict)) {
    state.icon = "malicious";
  } else if ((verdict && verdict.band === "MEDIUM") || state.detector) {
    state.icon = "suspicious";
  } else if (verdict) {
    state.icon = bandToIcon(verdict.band);
  } else {
    state.icon = settings.cloudCheck ? "unknown" : "signedout";
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

  // 5) Active Shield (opt-in): full-page warning behind the blocking gate,
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
        band: verdict?.band ?? null,
        graphLabel: verdict?.label ?? null,
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
    case "verifyIdentity":
      return { ok: true, verification: await verifyIdentity(msg.ip) };
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
