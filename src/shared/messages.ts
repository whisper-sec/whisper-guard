// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Typed runtime messages between the popup / options / pages and the
// background service worker. One discriminated union each way.

import type {
  CandidateVerdict,
  DeviceFlowState,
  DetectorHit,
  ExplainResult,
  SessionRisk,
  Settings,
  TabState,
} from "./types";

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
  | { kind: "updateCorpusNow" };

export interface CheckHostResult {
  host: string;
  detector: DetectorHit | null;
  verdict: { band: string; label: string | null; coverage: string | null } | null;
  signedIn: boolean;
  graphError: string | null;
}

export type BgResponse =
  | { ok: true; tabState: TabState }
  | { ok: true; session: SessionRisk[] }
  | { ok: true; settings: Settings; signedIn: boolean; corpusVersion: number; corpusUpdated: string }
  | { ok: true; device: DeviceFlowState }
  | { ok: true; explain: ExplainResult }
  | { ok: true; candidates: CandidateVerdict[] }
  | { ok: true; check: CheckHostResult }
  | { ok: true }
  | { ok: false; error: string };

export function send<T extends BgResponse = BgResponse>(msg: BgRequest): Promise<T> {
  return chrome.runtime.sendMessage(msg) as Promise<T>;
}
