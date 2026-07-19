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
  Protection,
  SessionRisk,
  Settings,
  TabState,
} from "./types";
import type { EndpointHealth, ReportHost, ReportTotals } from "./report";

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
  | { kind: "getDestinationDrill"; host: string }
  | { kind: "openDashboard"; view?: string }
  | { kind: "egressStatus" }
  | { kind: "egressEnable" }
  | { kind: "egressDisable" }
  | { kind: "enroll" }
  | { kind: "scanLinks"; tabId: number }
  | { kind: "verifyIdentity"; ip: string };

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
  | { ok: true; drill: DestinationDrill }
  | { ok: true; egress: EgressStatus }
  | { ok: true; enrollment: Enrollment }
  | { ok: true; scan: LinkScanResult }
  | { ok: true; verification: IdentityVerification | null }
  | { ok: true }
  | { ok: false; error: string; nokey?: boolean; nohost?: boolean };

export function send<T extends BgResponse = BgResponse>(msg: BgRequest): Promise<T> {
  return chrome.runtime.sendMessage(msg) as Promise<T>;
}
