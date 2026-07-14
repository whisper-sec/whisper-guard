// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// The bands the graph emits, verbatim, plus the out-of-coverage sentinel.
// UNKNOWN is the honest common state and is never dressed up as green.
export type GraphBand =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFO"
  | "NONE"
  | "UNKNOWN";

// The four states the toolbar icon can express for an assessed host,
// plus transient/tier states.
export type IconState =
  | "benign"
  | "suspicious"
  | "malicious"
  | "unknown"
  | "checking"
  | "signedout"
  | "neutral";

export interface AssessVerdict {
  host: string;
  band: GraphBand;
  // Categorical coverage (known-clean / partial / no-data). NOT a percentage
  // and NOT a safety score; a CRITICAL host can be known-clean coverage.
  coverage: string | null;
  label: string | null;
  at: number;
}

export type DetectorKind = "confusable" | "tldswap" | "combosquat" | "brand-subdomain" | "nearmiss";

export interface DetectorHit {
  kind: DetectorKind;
  severity: "high" | "medium";
  brand: string;
  brandDomain: string;
  // The registrable domain that looked like the brand.
  matched: string;
  // One-tap destination: the real brand site.
  goTo: string;
}

export interface TabState {
  hostname: string | null;
  registrable: string | null;
  eligible: boolean;
  signedIn: boolean;
  icon: IconState;
  verdict: AssessVerdict | null;
  detector: DetectorHit | null;
  // Set when the graph could not be reached: we failed open, on-device
  // checks still ran, and the popup says so instead of faking a verdict.
  graphError: string | null;
  shieldOn: boolean;
}

export interface SessionRisk {
  host: string;
  reason: string;
  at: number;
}

export interface Settings {
  shield: boolean;
  amberBanner: boolean;
  fieldGuard: boolean;
  nearMiss: boolean;
  corpusAutoUpdate: boolean;
  allowlist: string[];
}

export const DEFAULT_SETTINGS: Settings = {
  shield: false,
  amberBanner: true,
  fieldGuard: true,
  nearMiss: false,
  corpusAutoUpdate: true,
  allowlist: [],
};

export interface CorpusBrand {
  name: string;
  domain: string;
  legit?: string[];
  // Suppress combosquat matching for brands whose token is a common word.
  noCombo?: boolean;
  // Allow combosquat matching for short but distinctive tokens (dhl, ups).
  comboOk?: boolean;
  // Brand owns countless TLD variants (google.*): suppress TLD-swap.
  anyTld?: boolean;
  // Extra curated combosquat tokens beyond the SLD (e.g. "steam").
  tokens?: string[];
}

export interface Corpus {
  version: number;
  generated: string;
  // Suffixes where global brands hold defensive registrations (apple.de,
  // paypal.co.uk): an exact-SLD TLD swap onto one of these is far more
  // likely the brand itself than an attack, so that axis is suppressed
  // there. Confusable and combosquat detection still apply everywhere.
  defensiveSuffixes: string[];
  allow: string[];
  brands: CorpusBrand[];
}

export interface DeviceFlowState {
  phase: "idle" | "waiting" | "approved" | "expired" | "error";
  userCode: string | null;
  verificationUri: string | null;
  message: string | null;
}

export interface ExplainResult {
  ok: boolean;
  // Best-effort fields: rendered when the graph supplies them, omitted when
  // absent, never invented.
  rows: Record<string, unknown>[];
  error: string | null;
}

export interface CandidateVerdict {
  host: string;
  band: GraphBand;
  label: string | null;
}
