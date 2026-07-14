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
  // The live graph check (hostname only, to one endpoint), on by default
  // and honest about itself; one switch turns it off and Guard falls back
  // to on-device checks alone.
  cloudCheck: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  shield: false,
  amberBanner: true,
  fieldGuard: true,
  nearMiss: false,
  corpusAutoUpdate: true,
  allowlist: [],
  cloudCheck: true,
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

// ------------------------------------------------------- composed protection

/** The one composed, reconciled site verdict (see background/protect.ts). */
export interface Protection {
  host: string;
  band: GraphBand;
  /** True when the gate says stop: CRITICAL / HIGH / labelled malicious. */
  blocking: boolean;
  label: string | null;
  coverage: string | null;
  /** Owner label via the inference chain, never a raw hash. */
  who: string | null;
  category: string | null;
  where: { city: string | null; country: string | null; ip: string | null } | null;
  /** Domain age in days from registration history, when known. */
  ageDays: number | null;
  /** Feed-cited reasons (threat feeds only; popularity lists are good). */
  why: string[];
  /** Registered look-alike variants of this name flagged in the graph. */
  variants: CandidateVerdict[];
  /** Set when parts of the picture could not be fetched (fail-open). */
  partial: boolean;
}

// ---------------------------------------------------------------- dashboard

/** One fleet roster entry (device or agent) from the control plane. */
export interface FleetEndpoint {
  agent: string;
  address: string;
  label: string;
  fqdn: string | null;
  device: boolean;
  created: number | null;
  state: string;
}

/** Live + warm counters for one endpoint (op:agent). */
export interface EndpointCounters {
  lastSeen: number | null;
  dnsQueries: number | null;
  dnsBlocked: number | null;
  dnsNxdomain: number | null;
  connectionsTotal: number | null;
  bytesUp: number | null;
  bytesDown: number | null;
}

/** One activity row from the endpoint log (dns or conn). */
export interface ActivityRow {
  ts: number;
  kind: string;
  agent: string;
  /** dns: qname; conn: peer host/addr. */
  target: string;
  qtype: string | null;
  decision: string | null;
  bytesUp: number | null;
  bytesDown: number | null;
}

/** Public endpoint-identity verification (rdap.whisper.online, keyless). */
export interface IdentityVerification {
  isWhisperAgent: boolean;
  fqdn: string | null;
  daneOk: boolean | null;
  jwsOk: boolean | null;
  posture: string | null;
  detail: string | null;
}

/** Feed liveness: how fresh the data on screen is, honestly. */
export interface FeedStatus {
  mode: "live" | "polling" | "offline";
  updatedAt: number | null;
}

// ------------------------------------------------------------------- egress

export interface EgressStatus {
  /** Whether the browser is currently routed through Whisper egress. */
  on: boolean;
  /** The browser's own registered device identity, once minted. */
  agent: string | null;
  address: string | null;
  label: string | null;
  /** Honest limit surfacing: who controls the proxy setting right now. */
  controlledByOther: boolean;
  /** WebRTC leak hardening state (Chromium only; null elsewhere). */
  webrtcHardened: boolean | null;
  /** Last error, human-readable, when a step failed. */
  error: string | null;
}
