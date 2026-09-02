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
  // Cookie-consent auto-decline: where Guard's on-page layer runs,
  // click a banner's REJECT / "necessary only" control automatically.
  // Entirely on-device, never an accept, and one switch turns it off.
  cookieDecline: boolean;
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
  cookieDecline: true,
  cloudCheck: true,
};

// ------------------------------------------------------------- daily wins

/**
 * The countable categories of quiet protection. POLICY EVENTS, NOT
 * BROWSING: a win is only ever a category name plus a count. No URL, no
 * domain, no hostname is ever attached to one.
 */
export const WIN_CATEGORIES = ["preemptBlock", "identityVerified", "cookieDecline"] as const;
export type WinCategory = (typeof WIN_CATEGORIES)[number];

/** Today's tally: date-keyed so it resets daily on its own. */
export interface WinsToday {
  /** Local calendar date the tally belongs to (YYYY-MM-DD). */
  date: string;
  total: number;
  counts: Record<WinCategory, number>;
}

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

/** One named, weighted factor behind a verdict (whisper.explain, shaped). */
export interface WhyFactor {
  /** The factor's name (a feed id, or a graph-computed line). */
  name: string;
  /** The graph's weight for the factor, when it carries one. */
  weight: number | null;
  /** threat = counts against the site; good = popularity/trust listing. */
  kind: "threat" | "good";
}

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
  /** The graph's threat score for this name, when explain returned one. */
  score: number | null;
  /** The named weighted factors behind the verdict, shown by default. */
  whyFactors: WhyFactor[];
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
  /** ENROLLED: the browser holds its own reserved identity (independent of
   *  routing; enrollment never needs the proxy permission). */
  enrolled: boolean;
  /** The browser's own registered device identity, once minted. */
  agent: string | null;
  address: string | null;
  label: string | null;
  /** The identity's reverse-DNS name, once known. */
  fqdn: string | null;
  /** The public RDAP provenance link for the identity's /128. */
  rdapUrl: string | null;
  /** Honest limit surfacing: who controls the proxy setting right now. */
  controlledByOther: boolean;
  /** WebRTC leak hardening state (Chromium only; null elsewhere). */
  webrtcHardened: boolean | null;
  /** Last error, human-readable, when a step failed. */
  error: string | null;
}

/** The result of enrolling this browser (identity only, no routing). */
export interface Enrollment {
  agent: string;
  address: string;
  label: string;
  fqdn: string | null;
  rdapUrl: string;
  /** Keyless RDAP verification of the fresh identity (null = unreachable). */
  verification: IdentityVerification | null;
}

// ---------------------------------------------------------------- link scan

/** One registrable destination found among the current page's links. */
export interface LinkVerdictRow {
  /** The registrable domain the links point at. */
  host: string;
  band: GraphBand;
  label: string | null;
  /** How many links on the page point at this destination. */
  links: number;
}

/** The pre-visit verdict sweep over the current page's outbound links. */
export interface LinkScanResult {
  /** Unique registrable destinations, riskiest first. */
  hosts: LinkVerdictRow[];
  /** Total <a href> links inspected on the page (locally). */
  totalLinks: number;
  flagged: number;
  suspicious: number;
  unknown: number;
  clean: number;
  /** True when the page held more unique destinations than the scan cap. */
  truncated: boolean;
}

// ------------------------------------------------------------------ the chain

/**
 * One rung of the join path behind a name. The rung is the unit of the
 * moat: any product can look a name up, and only a graph that joins the
 * layers can say which building the network that announces the prefix
 * that holds the address that the name resolves to is present in.
 */
export type ChainRungKind =
  | "name"
  | "vendor"
  | "address"
  | "prefix"
  | "network"
  | "operator"
  | "presence";

export interface ChainRung {
  kind: ChainRungKind;
  /** The eyebrow, e.g. "PREFIX". */
  label: string;
  /** The measured value, or the words for "the graph holds nothing here". */
  value: string | null;
  /** The right-hand fact: a count, a confidence, a country. */
  fact: string | null;
  /**
   * THREE outcomes, never conflated:
   *   live         the graph answered and holds a value
   *   empty        the graph answered and holds nothing about this rung
   *   unavailable  the call did not come back, so we do not know
   * An error that renders as an empty state is the defect this refuses.
   */
  state: "live" | "empty" | "unavailable";
  /** Set when the rung itself carries risk (a prefix full of listed hosts). */
  tone: "neutral" | "warn" | "hot";
  /**
   * What the walk already knows about this rung beyond the one line: the
   * other addresses, the roles, the rest of the buildings. Free, because it
   * came back with the walk, so it costs a click and no request.
   */
  detail: string[];
  /**
   * True when MORE is fetchable on demand (the network's threat density,
   * the names sharing this address). Deliberately lazy: the public tier
   * allows a hundred calls an hour, and a reader who never expands a rung
   * should not spend one.
   */
  drillable: boolean;
}

/** The answer to expanding one rung. */
export interface RungDetail {
  kind: ChainRungKind;
  lines: string[];
  /** A measured ratio worth drawing as a bar: listed of announced. */
  ratio: { label: string; part: number; whole: number } | null;
  /** Set when the read did not come back, so "nothing" is never silent. */
  error: string | null;
}

export interface SiteChain {
  host: string;
  rungs: ChainRung[];
  /** How many rungs the graph could actually answer. */
  live: number;
  /** How many rungs could not be read at all. */
  unavailable: number;
  /** The graph's own words for how it attributed the vendor. */
  evidence: string[];
  facilities: string[];
  exchanges: string[];

  // The same facts in structured form, so the composed verdict
  // (background/protect.ts) can read them off this ONE walk instead of
  // asking the graph the same questions again. Cheaper, and it makes it
  // impossible for the panel to show an owner that disagrees with its own
  // OPERATOR rung.
  owner: string | null;
  country: string | null;
  /** The city the representative address sits in, when the graph has one. */
  city: string | null;
  asn: string | null;
  /** False when the enrich call did not come back, so a null owner above
   *  means "not read" rather than "not known". */
  asnOk: boolean;
  ip: string | null;
  vendor: string | null;
  /** The graph's host class (multi_tenant_user_content, cdn, ...). */
  vendorCategory: string | null;
  /** The graph's own category for the vendor (saas, cdn, ...). */
  identifyCategory: string | null;
  roles: string[];
  ageDays: number | null;
  prefix: string | null;
  threatNeighbors: number | null;

  at: number;
}

// ----------------------------------------------------------- the graph scale

/**
 * The live size of the graph the verdicts come from, read from the public
 * stats endpoint every time and never from a constant in this repo. A
 * hardcoded figure is stale the day after it is written, and a security
 * product quoting a stale figure about its own coverage is worse than one
 * quoting none.
 */
export interface GraphScale {
  nodes: number;
  edges: number;
  objects: number;
  /** Identities live on the Whisper network right now. */
  identities: number;
  /** DNS questions the resolvers answered in the trailing window. */
  queries: number;
  /** The trailing window those queries were counted over. */
  windowHours: number;
  /** Resolver answer latency, microseconds. */
  p50Us: number | null;
  p99Us: number | null;
  /** 5-minute query buckets, oldest first: the pulse the header draws. */
  pulse: number[];
  /** When the endpoint says it computed this. */
  updated: number;
  /** True when the endpoint itself declares degraded input. */
  degraded: boolean;
}

// ------------------------------------------------------------------- quota

/**
 * The keyless budget, read from the graph rather than guessed. This is the
 * two-tier boundary made visible: a signed-out reader gets a real number
 * and a real reset time instead of a pitch, and can see exactly what an
 * account changes.
 */
export interface GraphQuota {
  plan: string;
  anonymous: boolean;
  hourlyLimit: number | null;
  hourlyRemaining: number | null;
  dailyLimit: number | null;
  dailyRemaining: number | null;
  /** The join depth this tier allows. The whole reason the chain is built
   *  in two rounds rather than one query. */
  maxDepth: number | null;
}
