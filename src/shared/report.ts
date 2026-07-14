// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The pure report layer: owner/category inference, tallies, totals,
// concentration, verdict helpers, endpoint health. Framework-free and
// side-effect-free so the background, the popup and the dashboard share
// the exact same shaping, and it is unit-testable in isolation.
//
// The inference chain exists because raw whisper.identify is sparse (hash
// canonical names, null categories): a destination is never rendered raw.
// The category palette is disjoint from the verdict scale by construction,
// and "unresolved" is honest grey, never a class faked from nothing.

export type ReportCategory =
  | "search"
  | "ads"
  | "media"
  | "social"
  | "work"
  | "platform"
  | "cloud"
  | "cdn"
  | "infrastructure"
  | "unresolved";

export const CATEGORY_LABEL: Record<ReportCategory, string> = {
  search: "Search",
  ads: "Advertising & tracking",
  media: "Media & entertainment",
  social: "Social",
  work: "Work & productivity",
  platform: "Platform & devices",
  cloud: "Cloud",
  cdn: "CDN & edge",
  infrastructure: "Infrastructure",
  unresolved: "Not yet classified",
};

/** One hue per category (dark surface), disjoint from the verdict scale. */
export const CATEGORY_HEX: Record<ReportCategory, string> = {
  search: "#2263bd",
  ads: "#c026d3",
  media: "#9061e8",
  social: "#e0448c",
  work: "#1a7fa8",
  platform: "#9085e9",
  cloud: "#1aa0d6",
  cdn: "#4f97dc",
  infrastructure: "#a1751f",
  unresolved: "#9098a8",
};

/** One destination, fully resolved through the graph. */
export interface ReportHost {
  host: string;
  ip?: string;
  city?: string;
  /** ISO2 network jurisdiction (anycast-fuzzy; labelled so in the UI). */
  country?: string;
  asn?: string;
  asnName?: string;
  /** Announcing prefix (the keyless network signal when no ASN is visible). */
  prefix?: string;
  /** Owner label, always set: inference chain, falling back to the domain. */
  owner: string;
  category: ReportCategory;
  /** Reconciled verdict band (UNKNOWN / NONE / LOW / MEDIUM / HIGH / CRITICAL). */
  verdict: string;
  /** Lookups / sightings in the window. */
  q: number;
  /** Last sighting, epoch ms (0 when unknown). */
  lastAt: number;
}

// ---------------------------------------------------- owner-label inference

/** A 32-hex string is an internal hash, never a real org name. */
export function isHashLabel(s: string): boolean {
  return /^[0-9a-f]{32}$/i.test(s.trim());
}

/** A RIR maintainer/handle marker, not a company name. */
export function looksLikeMaintainer(s: string): boolean {
  const t = s.trim();
  return /-(MNT|RIPE|ARIN|APNIC|LACNIC|AFRINIC)\b/i.test(t) || /\bMNT-/i.test(t);
}

/** "GITHUB - GitHub, Inc." -> "GitHub, Inc." */
export function asnCompany(asnName: string | undefined): string | undefined {
  if (!asnName) return undefined;
  const dash = asnName.indexOf(" - ");
  const company = dash >= 0 ? asnName.slice(dash + 3).trim() : asnName.trim();
  return company || undefined;
}

/** The registrable domain: the PSL apex when known, else a 2-label guess. */
export function fallbackRegistrable(host: string, apex?: string): string {
  if (apex && apex.trim()) return apex.trim();
  const clean = host.replace(/\.$/, "");
  const parts = clean.split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : clean;
}

/**
 * Resolve the owner LABEL: prefer the ASN's registered organization (tidied);
 * if it is missing / a hash / a maintainer handle, fall back to identify's
 * canonical name; else the registrable domain. Never renders a raw hash.
 */
export function resolveOwnerLabel(
  org: string | undefined,
  canonical: string | undefined,
  host: string,
  apex?: string,
): string {
  const cleanOrg = org ? (asnCompany(org) ?? org).trim() : undefined;
  if (cleanOrg && !isHashLabel(cleanOrg) && !looksLikeMaintainer(cleanOrg)) return cleanOrg;
  const c = canonical?.trim();
  if (c && !isHashLabel(c)) return c;
  return fallbackRegistrable(host, apex);
}

// ------------------------------------------------------ category inference

const ROLE_CATEGORY: [RegExp, ReportCategory][] = [
  // ads BEFORE search: "search & advertising" roles land on the tracker side.
  [/ads?\b|advertis|ad.?tech|ad.?exchange|analytic|tracker|tracking|tag.?manager|beacon|telemetry|attribution|audience|retarget/i, "ads"],
  [/cdn|content.?deliver|edge/i, "cdn"],
  [/search/i, "search"],
  [/social|messaging|forum|community|dating/i, "social"],
  [/media|stream|video|music|podcast|radio|news|entertain|gam(?:e|ing)|sport|tv\b|broadcast/i, "media"],
  [/telecom|\bisp\b|carrier|broadband|mobile.?network|host|colo|data.?cent|registrar|certificate|\bpki\b|\bntp\b|\bvpn\b/i, "infrastructure"],
  [/platform|operating.?system|vendor|device|os\b|app.?store/i, "platform"],
  [/cloud|iaas|paas|compute|storage/i, "cloud"],
  [/saas|productivity|collaborat|dev.?tools?|code|git|e-?commerce|shop|retail|financ|bank|payment|mail|educat|universit|\bhr\b|crm|erp|design|meeting|conferenc/i, "work"],
];

export function normalizeCategory(
  category: string | undefined,
  roles: string[] | undefined,
): ReportCategory | undefined {
  const hay = [category ?? "", ...(roles ?? [])].join(" ").trim();
  if (!hay) return undefined;
  for (const [re, cat] of ROLE_CATEGORY) if (re.test(hay)) return cat;
  return undefined;
}

/** Category from a recognized owner brand; ad-tech is checked FIRST. */
export function categoryFromOwner(owner: string): ReportCategory | undefined {
  const o = owner.toLowerCase();
  if (/doubleclick|adnxs|app.?nexus|criteo|taboola|outbrain|trade ?desk|pubmatic|magnite|rubicon|scorecard|comscore|moat|quantcast|branch metrics|adjust|appsflyer|amplitude|mixpanel|segment\.io|hotjar|chartbeat/.test(o))
    return "ads";
  if (/cloudflare|fastly|akamai|edgecast|limelight|cdn77|bunny\s?(net|way)|jsdelivr|unpkg/.test(o)) return "cdn";
  if (/netflix|spotify|disney|hulu|hbo|warner|paramount|twitch|vimeo|soundcloud|pandora|crunchyroll|\bbbc\b|nytimes|guardian|cnn\b|reuters|bloomberg|nintendo|playstation|\bxbox\b|steam|valve|epic games|riot games|electronic arts|activision|ubisoft/.test(o))
    return "media";
  if (/google|alphabet|youtube/.test(o)) return "search";
  if (/amazon|\baws\b|oracle|alibaba|tencent cloud/.test(o)) return "cloud";
  if (/apple|microsoft|samsung electronics|huawei|xiaomi|canonical|red hat|mozilla/.test(o)) return "platform";
  if (/facebook|meta platforms|instagram|whatsapp|tiktok|bytedance|snap inc|twitter|x corp|linkedin|pinterest|reddit|discord|telegram|signal messenger|mastodon|bluesky/.test(o))
    return "social";
  if (/github|gitlab|atlassian|slack|salesforce|adobe|zoom|dropbox|notion|shopify|stripe|openai|figma|miro|asana|monday\.com|docusign|intuit|sap\b|workday|servicenow|zendesk|hubspot|mailchimp|paypal|klarna|wise\b|revolut/.test(o))
    return "work";
  if (/comcast|verizon|vodafone|telefonica|deutsche telekom|t-mobile|at&t|orange s\.?a|liberty global|telia|\bkpn\b|ziggo|bt group|swisscom|telstra|\btelecom\b|\btelekom\b|digitalocean|hetzner|\bovh\b|linode|vultr|leaseweb|godaddy|namecheap|ionos|hostinger|contabo|digicert|let'?s encrypt|sectigo|globalsign|verisign|internet systems consortium|\bripe\b|\barin\b|icann|nlnet/.test(o))
    return "infrastructure";
  return undefined;
}

const CLOUD_PROVIDERS: { name: string; match: RegExp; cat: ReportCategory }[] = [
  { name: "AWS", match: /amazon|aws|amazon-02|amazon-aes/i, cat: "cloud" },
  { name: "Google Cloud", match: /google|gcp/i, cat: "cloud" },
  { name: "Cloudflare", match: /cloudflare/i, cat: "cdn" },
  { name: "Microsoft Azure", match: /microsoft|azure|msft/i, cat: "cloud" },
  { name: "Akamai", match: /akamai/i, cat: "cdn" },
  { name: "Fastly", match: /fastly/i, cat: "cdn" },
  { name: "Meta", match: /facebook|meta platforms/i, cat: "social" },
  { name: "Oracle Cloud", match: /oracle/i, cat: "cloud" },
  { name: "DigitalOcean", match: /digitalocean/i, cat: "infrastructure" },
  { name: "Hetzner", match: /hetzner/i, cat: "infrastructure" },
  { name: "OVH", match: /ovh/i, cat: "infrastructure" },
  { name: "Linode", match: /linode|akamai connected cloud/i, cat: "infrastructure" },
  { name: "Apple", match: /\bapple\b/i, cat: "platform" },
];

/** Recognized cloud/CDN/hosting operator behind a network, or undefined. */
export function classifyCloud(asnName?: string, org?: string): string | undefined {
  const hay = `${asnName ?? ""} ${org ?? ""}`;
  for (const p of CLOUD_PROVIDERS) if (p.match.test(hay)) return p.name;
  return undefined;
}

function cloudCategory(asnName?: string, org?: string): ReportCategory | undefined {
  const hay = `${asnName ?? ""} ${org ?? ""}`;
  for (const p of CLOUD_PROVIDERS) if (p.match.test(hay)) return p.cat;
  return undefined;
}

/** Classify the announcing network itself (the ASN-org net). */
export function classifyAsnType(asnName?: string, org?: string): ReportCategory | undefined {
  const hay = `${asnName ?? ""} ${org ?? ""}`.toLowerCase();
  if (!hay.trim()) return undefined;
  if (/telecom|telekom|telefonica|vodafone|comcast|verizon|at&t|t-mobile|\bmobile\b|broadband|communicat|\bcable\b|wireless|\bisp\b|internet service|host|colo|data.?cent|\bvps\b|dedicated|server|registr|\bdns\b|\bnic\b/.test(hay))
    return "infrastructure";
  if (/cdn|content deliver|\bedge\b/.test(hay)) return "cdn";
  if (/cloud|compute|iaas/.test(hay)) return "cloud";
  if (/media|broadcast|television|publish|entertainment|gaming/.test(hay)) return "media";
  if (/universit|college|research|academ|educat|school|financ|\bbank\b|insurance|government|ministry/.test(hay))
    return "work";
  return undefined;
}

/** Structural keywords the hostname itself wears (ads., cdn., ocsp., ...). */
export function classifyHostname(host: string): ReportCategory | undefined {
  const h = host.toLowerCase().replace(/\.$/, "");
  const B = "(^|[.-])";
  const E = "([.-]|$)";
  const test = (words: string) => new RegExp(`${B}(${words})${E}`).test(h);
  if (test("ads?|adserver|adservice|advert(ising)?|track(ing|er)?|analytics|beacons?|telemetry|metrics|pixel|doubleclick|banners?|sponsor(ed)?|affiliates?|retarget(ing)?"))
    return "ads";
  if (test("cdn\\d*|static|assets?|img|images|edge|cache|media\\d+")) return "cdn";
  if (test("mail|smtp|imap|webmail|calendar|docs|drive|meet|office|shop|store|checkout|pay(ments)?")) return "work";
  if (test("ocsp|crl|pki|certs?|ntp|time|dns|doh|resolver|whois|rdap|updates?|download(s)?|mirrors?|firmware|api|apis|gateway|auth|login|sso|oauth|status|stun|turn|vpn"))
    return "infrastructure";
  if (test("videos?|stream(ing)?|music|radio|podcasts?|news|tv")) return "media";
  return undefined;
}

export interface CategorySignals {
  host?: string;
  identifyCategory?: string;
  identifyRoles?: string[];
  owner?: string;
  asnName?: string;
  org?: string;
}

/**
 * Categorize from every signal we hold, first match wins, no disguised
 * catch-all: identify -> the name's own ad keywords -> owner brand ->
 * cloud/CDN provider -> the network's own kind -> the name's structural
 * keywords -> honest "unresolved".
 */
export function inferCategory(s: CategorySignals): ReportCategory {
  const fromIdentify = normalizeCategory(s.identifyCategory, s.identifyRoles);
  if (fromIdentify) return fromIdentify;
  if (s.host && classifyHostname(s.host) === "ads") return "ads";
  if (s.owner) {
    const fromOwner = categoryFromOwner(s.owner);
    if (fromOwner) return fromOwner;
  }
  const fromProvider = cloudCategory(s.asnName, s.org);
  if (fromProvider) return fromProvider;
  const fromAsn = classifyAsnType(s.asnName, s.org);
  if (fromAsn) return fromAsn;
  if (s.host) {
    const fromHost = classifyHostname(s.host);
    if (fromHost) return fromHost;
  }
  return "unresolved";
}

// ------------------------------------------------------------- verdicts

export type VerdictClass = "clean" | "low" | "med" | "bad" | "unknown";

export function verdictClass(v: string | undefined): VerdictClass {
  const u = (v ?? "NONE").toUpperCase();
  if (u === "HIGH" || u === "CRITICAL") return "bad";
  if (u === "MEDIUM") return "med";
  if (u === "LOW") return "low";
  if (u === "UNKNOWN") return "unknown";
  return "clean";
}

/** "flagged" = a genuinely known-bad reconciled verdict, never popularity. */
export function isFlagged(v: string | undefined): boolean {
  const u = (v ?? "").toUpperCase();
  return u === "HIGH" || u === "CRITICAL";
}

/** A feed that ranks popularity/trust: being listed there is GOOD. */
export function isPopularityFeed(feedId: string): boolean {
  return /tranco|cloudflare[-\s_]?radar|umbrella|majestic|alexa|top[-\s_]?1m|popularity/i.test(feedId);
}

// ------------------------------------------------------------- tallies

/** Short company name for tallies + callouts. */
export function shortOwner(owner: string): string {
  return owner.replace(/,.*$/, "").trim();
}

export interface OwnerRow {
  owner: string;
  count: number;
  category: ReportCategory;
}

export function tallyOwners(hosts: ReportHost[]): OwnerRow[] {
  const by = new Map<string, { count: number; cats: Map<ReportCategory, number> }>();
  for (const h of hosts) {
    const key = shortOwner(h.owner);
    const cur = by.get(key) ?? { count: 0, cats: new Map<ReportCategory, number>() };
    cur.count += 1;
    cur.cats.set(h.category, (cur.cats.get(h.category) ?? 0) + 1);
    by.set(key, cur);
  }
  return [...by.entries()]
    .map(([owner, v]) => {
      const category = [...v.cats.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "unresolved";
      return { owner, count: v.count, category };
    })
    .sort((a, b) => b.count - a.count);
}

export function tallyCategory(hosts: ReportHost[]): [ReportCategory, number][] {
  const by = new Map<ReportCategory, number>();
  for (const h of hosts) by.set(h.category, (by.get(h.category) ?? 0) + 1);
  return [...by.entries()].sort((a, b) => b[1] - a[1]);
}

export function tallyCountry(hosts: ReportHost[]): [string, number][] {
  const by = new Map<string, number>();
  for (const h of hosts) {
    if (!h.country) continue;
    by.set(h.country, (by.get(h.country) ?? 0) + 1);
  }
  return [...by.entries()].sort((a, b) => b[1] - a[1]);
}

export interface NetworkRow {
  net: string;
  owner: string;
  count: number;
}

/** Tally by network: ASN when visible (keyed), else announcing prefix. */
export function tallyNetwork(hosts: ReportHost[]): NetworkRow[] {
  const by = new Map<string, { owner: string; count: number }>();
  for (const h of hosts) {
    const net = h.asn ?? h.prefix;
    if (!net) continue;
    const cur = by.get(net) ?? { owner: h.owner, count: 0 };
    cur.count += 1;
    by.set(net, cur);
  }
  return [...by.entries()]
    .map(([net, v]) => ({ net, owner: v.owner, count: v.count }))
    .sort((a, b) => b.count - a.count);
}

/** Top-3 owner concentration: "61% of this is 3 companies". */
export function concentration(hosts: ReportHost[]): { pct: number; top: string[] } {
  if (hosts.length === 0) return { pct: 0, top: [] };
  const owners = tallyOwners(hosts);
  const top3 = owners.slice(0, 3);
  const sum = top3.reduce((s, o) => s + o.count, 0);
  return { pct: Math.round((sum / hosts.length) * 100), top: top3.map((o) => o.owner) };
}

export interface ReportTotals {
  destinations: number;
  companies: number;
  countries: number;
  networks: number;
  lookups: number;
  flagged: number;
}

export function reportTotals(hosts: ReportHost[]): ReportTotals {
  const companies = new Set(hosts.map((h) => shortOwner(h.owner)));
  const countries = new Set(hosts.map((h) => h.country).filter(Boolean));
  const networks = new Set(hosts.map((h) => h.asn ?? h.prefix).filter(Boolean));
  return {
    destinations: hosts.length,
    companies: companies.size,
    countries: countries.size,
    networks: networks.size,
    lookups: hosts.reduce((s, h) => s + h.q, 0),
    flagged: hosts.filter((h) => isFlagged(h.verdict)).length,
  };
}

// ---------------------------------------------------------------- geo

/** ISO 3166-1 alpha-2 -> flag emoji ('' if not a valid code). */
export function flagEmoji(iso2: string | undefined): string {
  if (!iso2) return "";
  const cc = iso2.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return "";
  const A = 0x1f1e6;
  return String.fromCodePoint(A + (cc.charCodeAt(0) - 65), A + (cc.charCodeAt(1) - 65));
}

/** Best-effort ISO2 from a place string ("Frankfurt am Main, DE" -> "DE"). */
export function isoFromPlace(place: string | undefined): string | undefined {
  if (!place) return undefined;
  const comma = place.lastIndexOf(",");
  const tail = (comma >= 0 ? place.slice(comma + 1) : place).trim().toUpperCase();
  return /^[A-Z]{2}$/.test(tail) ? tail : undefined;
}

// ------------------------------------------------------------- health

export type FactorState = "met" | "unmet" | "unknown";

export interface HealthFactor {
  key: "verified" | "signed" | "dane" | "rpki" | "clean";
  label: string;
  weight: number;
  state: FactorState;
  detail: string;
}

export interface EndpointHealth {
  score: number;
  level: "strong" | "partial" | "weak";
  factors: HealthFactor[];
  threatNote?: string;
  revoked: boolean;
}

export interface HealthInputs {
  isWhisperAgent?: boolean;
  daneOk?: boolean;
  jwsOk?: boolean;
  /** RPKI ROA check: true valid, false invalid, null unknown. */
  rpki: boolean | null;
  flaggedDestinations: number;
  threatLoaded: boolean;
  state?: string;
}

const HEALTH_WEIGHTS = { verified: 30, signed: 18, dane: 17, rpki: 15, clean: 20 } as const;

function boolState(v: boolean | undefined): FactorState {
  if (v === true) return "met";
  if (v === false) return "unmet";
  return "unknown";
}

/**
 * The explainable 0-100 endpoint trust score: the sum of named, weighted
 * factors, each shown met / unmet / unknown, never a black box. A revoked
 * endpoint is hard-capped regardless of its proofs.
 */
export function computeEndpointHealth(input: HealthInputs): EndpointHealth {
  const cleanState: FactorState = !input.threatLoaded
    ? "unknown"
    : input.flaggedDestinations > 0
      ? "unmet"
      : "met";

  const factors: HealthFactor[] = [
    { key: "verified", label: "Verified identity", weight: HEALTH_WEIGHTS.verified, state: boolState(input.isWhisperAgent), detail: "Resolves as a Whisper endpoint via verify-identity." },
    { key: "signed", label: "Signed identity", weight: HEALTH_WEIGHTS.signed, state: boolState(input.jwsOk), detail: "Identity document carries a valid JWS signature." },
    { key: "dane", label: "DANE-TLSA", weight: HEALTH_WEIGHTS.dane, state: boolState(input.daneOk), detail: "TLS key pinned in DNS via a DANE-TLSA record." },
    { key: "rpki", label: "RPKI routing", weight: HEALTH_WEIGHTS.rpki, state: input.rpki === null ? "unknown" : input.rpki ? "met" : "unmet", detail: "Announced prefix authorised by a valid ROA." },
    { key: "clean", label: "Threat-clean (24h)", weight: HEALTH_WEIGHTS.clean, state: cleanState, detail: "No connections to threat-listed destinations recently." },
  ];

  let score = factors.reduce((sum, f) => (f.state === "met" ? sum + f.weight : sum), 0);

  let threatNote: string | undefined;
  if (input.threatLoaded && input.flaggedDestinations > 0) {
    const penalty = Math.min(25, 10 + 5 * (input.flaggedDestinations - 1));
    score = Math.max(0, score - penalty);
    threatNote = `Reached ${input.flaggedDestinations} threat-listed destination${input.flaggedDestinations === 1 ? "" : "s"} in the last 24h.`;
  }

  const revoked = (input.state ?? "").toLowerCase() === "revoked";
  if (revoked) score = Math.min(score, 15);
  score = Math.round(Math.max(0, Math.min(100, score)));

  let level: EndpointHealth["level"] = score >= 75 ? "strong" : score >= 45 ? "partial" : "weak";
  if (revoked) level = "weak";
  return { score, level, factors, threatNote, revoked };
}

export function healthHeadline(health: EndpointHealth): string {
  if (health.revoked) return "Revoked";
  switch (health.level) {
    case "strong":
      return "Strongly trusted";
    case "partial":
      return "Partially verified";
    default:
      return "Unverified";
  }
}
