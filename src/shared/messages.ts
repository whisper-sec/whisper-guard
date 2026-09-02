// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Typed runtime messages between the popup / options / pages and the
// background service worker. One discriminated union each way.

import type {
  ActivityRow,
  CandidateVerdict,
  DeviceFlowState,
  DetectorHit,
  EgressStatus,
  EndpointCounters,
  Enrollment,
  ExplainResult,
  FeedStatus,
  FleetEndpoint,
  IdentityVerification,
  LinkScanResult,
  ChainRungKind,
  GraphQuota,
  GraphScale,
  RungDetail,
  Protection,
  SessionRisk,
  SiteChain,
  Settings,
  TabState,
  WinsToday,
} from "./types";
import type { EndpointHealth, ReportHost, ReportTotals } from "./report";
import type { DevicePolicy, RevokeResult } from "./policy";
import type { PreemptDecision, PreemptDisposition } from "./preempt";

export type BgRequest =
  | { kind: "getTabState"; tabId: number }
  | { kind: "getSession" }
  | { kind: "getSettings" }
  | { kind: "setSettings"; patch: Partial<Settings> }
  | { kind: "signInStart" }
  | { kind: "signInStatus" }
  | { kind: "signInCancel" }
  | { kind: "signOut" }
  | { kind: "saveKey"; key: string }
  | { kind: "explain"; host: string }
  | { kind: "identify"; host: string }
  | { kind: "report"; host: string; note: string }
  | { kind: "confirmLookalikes"; host: string }
  | { kind: "checkHost"; host: string }
  | { kind: "allowHost"; host: string; session: boolean }
  | { kind: "dismissWarning"; host: string }
  | { kind: "updateCorpusNow" }
  | { kind: "getProtection"; host: string; withVariants?: boolean }
  | { kind: "getBrowserReport"; limit?: number }
  | { kind: "getFleetReport" }
  | { kind: "getEndpointDetail"; agent: string }
  | { kind: "getDevicePolicy"; agent: string }
  | { kind: "setDevicePolicy"; agent: string; policy: DevicePolicy }
  | { kind: "revokeEndpoint"; agent: string }
  | { kind: "getDestinationDrill"; host: string }
  | { kind: "openDashboard"; view?: string }
  | { kind: "egressStatus" }
  | { kind: "egressEnable" }
  | { kind: "egressDisable" }
  | { kind: "enroll" }
  | { kind: "scanLinks"; tabId: number }
  | { kind: "verifyIdentity"; ip: string }
  // Pre-emptive click/submit interruption: the content script asks
  // about a held action's TARGET (bare hostname only, ever), and reports
  // the user's honest one-click-through.
  | { kind: "preemptCheck"; host: string }
  | { kind: "preemptAllow"; host: string }
  // Resume of a held middle-/modifier-click: a synthetic click cannot
  // carry the user's modifiers, so the background opens the destination
  // with the NATIVE disposition (middle/Ctrl = background tab, +Shift =
  // foreground, Shift = window). The URL is consumed by tabs.create /
  // windows.create on this machine only; it never goes to the network.
  | { kind: "preemptOpen"; url: string; disposition: PreemptDisposition }
  // Popup-open arming: opening the popup is a real extension
  // invocation, so activeTab makes the CURRENT tab scriptable even
  // without the broad Active-Shield grant; the background arms the
  // pre-emptive guard there. Carries a tab id and nothing else.
  | { kind: "preemptArm"; tabId: number }
  // Cookie-consent auto-decline: the content module reports ONE
  // successful decline. The message carries a category and nothing else:
  // no host, no URL, nothing read from the page, so the wins record
  // (category + count) could not learn a site even if it wanted to.
  | { kind: "consentDeclined" }
  // The join path behind one hostname: the seven-rung walk from the name
  // to the buildings the network that announces its address is present in.
  // Built on the reader's ask rather than on every navigation, because the
  // public tier's hourly budget is a real number and browsing must not
  // spend it (see CHAIN_TTL_MS in shared/config.ts).
  | { kind: "getChain"; host: string }
  // What is behind ONE rung, fetched only when a reader expands it. Lazy on
  // purpose: a reader who never expands one must never spend a graph call
  // on it, and the public tier's hourly budget is a real number.
  | { kind: "getRungDetail"; host: string; rung: ChainRungKind }
  // The live size of the graph and the resolvers' pulse. Public, keyless,
  // carries nothing about the reader, and is never read from a constant.
  | { kind: "getScale" }
  // The caller's own tier and what is left of it: RULE 14's two-tier
  // boundary as a measurement rather than a pitch.
  | { kind: "getQuota" }
  // Today's quiet-wins tally: categories + counts only, ever.
  | { kind: "getWins" }
  // the hosts blocked for this session (the DNR rule ids are hashes, so
  // the popup asks the background for the mirrored ledger) - so a session block
  // is discoverably clearable, never a bare ERR_BLOCKED_BY_CLIENT.
  | { kind: "listBlocked" };

export interface CheckHostResult {
  host: string;
  detector: DetectorHit | null;
  verdict: { band: string; label: string | null; coverage: string | null } | null;
  signedIn: boolean;
  graphError: string | null;
}

/** The "This browser" report (keyless keystone). */
export interface BrowserReport {
  hosts: ReportHost[];
  totals: ReportTotals;
  generatedAt: number;
}

/** The keyed fleet report: same panels, every endpoint merged. */
export interface FleetReport {
  endpoints: FleetEndpoint[];
  hosts: ReportHost[];
  totals: ReportTotals;
  feed: ActivityRow[];
  feedStatus: FeedStatus;
  silent: string[];
  generatedAt: number;
}

/** One endpoint's full picture for the per-endpoint view. */
export interface EndpointDetail {
  endpoint: FleetEndpoint;
  counters: EndpointCounters | null;
  verification: IdentityVerification | null;
  health: EndpointHealth;
  activity: ActivityRow[];
  topHosts: ReportHost[];
  rdapUrl: string;
}

export interface DestinationDrill {
  host: string;
  ip: string | null;
  cohosted: number | null;
  prefix: string | null;
  threatNeighbors: number | null;
}

export type BgResponse =
  | { ok: true; tabState: TabState }
  | { ok: true; session: SessionRisk[] }
  | { ok: true; settings: Settings; signedIn: boolean; corpusVersion: number; corpusUpdated: string }
  | { ok: true; device: DeviceFlowState }
  | { ok: true; explain: ExplainResult }
  | { ok: true; candidates: CandidateVerdict[] }
  | { ok: true; check: CheckHostResult }
  | { ok: true; protection: Protection }
  | { ok: true; report: BrowserReport }
  | { ok: true; fleet: FleetReport }
  | { ok: true; endpoint: EndpointDetail }
  | { ok: true; policy: DevicePolicy }
  | { ok: true; revoked: RevokeResult }
  | { ok: true; drill: DestinationDrill }
  | { ok: true; egress: EgressStatus }
  | { ok: true; enrollment: Enrollment }
  | { ok: true; scan: LinkScanResult }
  | { ok: true; verification: IdentityVerification | null }
  | { ok: true; preempt: PreemptDecision }
  | { ok: true; chain: SiteChain }
  | { ok: true; detail: RungDetail }
  // null is a first-class answer: the endpoint could not be read, and the
  // surface says so instead of showing a remembered or invented figure.
  | { ok: true; scale: GraphScale | null }
  | { ok: true; quota: GraphQuota | null }
  | { ok: true; wins: WinsToday }
  | { ok: true; hosts: string[] } // the session block ledger (listBlocked)
  | { ok: true }
  | { ok: false; error: string; nokey?: boolean; nohost?: boolean };

export function send<T extends BgResponse = BgResponse>(msg: BgRequest): Promise<T> {
  return chrome.runtime.sendMessage(msg) as Promise<T>;
}
