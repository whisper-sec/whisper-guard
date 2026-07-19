// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// All endpoints and tunables in one place. Four Whisper endpoints exist,
// each with one narrow purpose; browsing hostnames go to exactly ONE of them:
//
//   graph.whisper.security    the safety check + enrichment (hostname only, keyed or not)
//   console.whisper.security  sign-in only (RFC 8628 device flow, no browsing data)
//   get.whisper.online        detector corpus updates only (no browsing data)
//   rdap.whisper.online       public endpoint-identity verification (IP literals only)

export const GRAPH_QUERY_URL = "https://graph.whisper.security/api/query";
export const CONSOLE_URL = "https://console.whisper.security";
export const CORPUS_URL = "https://get.whisper.online/guard/corpus.v1.json";
export const CONSOLE_KEYS_URL = "https://console.whisper.security/settings";
export const RDAP_BASE = "https://rdap.whisper.online";

// The public assess contract, the same one the Whisper platform exposes.
export const ASSESS_QUERY =
  "CALL whisper.assess($hs) YIELD host,label,band,coverage RETURN host,label,band,coverage";

// Batched identify: the raw rows are sparse (hash canonical names, null
// categories) and are ALWAYS shaped through the inference chain in
// shared/report.ts, never rendered raw.
export const IDENTIFY_BATCH_QUERY =
  "CALL whisper.identify($hs) YIELD host, canonical_name, category, roles " +
  "RETURN host, canonical_name, category, roles";

// Registered look-alike variants of a name, generated server-side by the
// graph (exists-only). The impersonation engine behind "who is wearing a
// name like this one".
export const VARIANTS_QUERY = "CALL whisper.variants($h, true)";

// WHOIS snapshots for domain age. Many snapshots return; the freshest by
// updateDate wins, createDate carries the age.
export const HISTORY_QUERY = "CALL whisper.history($h)";

// KEYED enrichment: the full resolution chain (IP, city+country, ASN,
// registered organization, ASN name, reconciled verdict), one row per host.
export const ENRICH_KEYED_QUERY =
  "UNWIND $hosts AS host MATCH (n:HOSTNAME {name:host}) " +
  "OPTIONAL MATCH (n)-[:RESOLVES_TO]->(ip:IPV4) " +
  "OPTIONAL MATCH (ip)-[:LOCATED_IN]->(city:CITY)-[:HAS_COUNTRY]->(cc:COUNTRY) " +
  "OPTIONAL MATCH (ip)-[:ANNOUNCED_BY]->(:ANNOUNCED_PREFIX)-[:ROUTES]->(a:ASN) " +
  "OPTIONAL MATCH (a)-[:REGISTERED_BY]->(org:ORGANIZATION) " +
  "OPTIONAL MATCH (a)-[:HAS_NAME]->(an:ASN_NAME) " +
  "WITH host, head(collect(DISTINCT ip.name)) AS ip, head(collect(DISTINCT city.name)) AS city, " +
  "head(collect(DISTINCT cc.name)) AS country, head(collect(DISTINCT a.name)) AS asn, " +
  "head(collect(DISTINCT org.name)) AS owner, head(collect(DISTINCT an.name)) AS asnName, " +
  "head(collect(DISTINCT ip.verdictLevel)) AS verdict " +
  "RETURN host, ip, city, country, asn, owner, asnName, verdict";

// KEYLESS enrichment: the public tier caps raw traversals at 2 hops total,
// so geo and network ride two parallel 2-hop queries (the named procs above
// do their deep traversal server-side and stay fully keyless).
export const ENRICH_GEO_QUERY =
  "UNWIND $hosts AS host MATCH (n:HOSTNAME {name:host}) " +
  "OPTIONAL MATCH (n)-[:RESOLVES_TO]->(ip:IPV4)-[:LOCATED_IN]->(city:CITY) " +
  "WITH host, head(collect(DISTINCT ip.name)) AS ip, head(collect(DISTINCT city.name)) AS city, " +
  "head(collect(DISTINCT ip.verdictLevel)) AS verdict " +
  "RETURN host, ip, city, verdict";

export const ENRICH_NET_QUERY =
  "UNWIND $hosts AS host MATCH (n:HOSTNAME {name:host}) " +
  "OPTIONAL MATCH (n)-[:RESOLVES_TO]->(:IPV4)-[:ANNOUNCED_BY]->(p:ANNOUNCED_PREFIX) " +
  "WITH host, head(collect(DISTINCT p.name)) AS prefix, " +
  "head(collect(DISTINCT p.threatNeighborCount)) AS threatNeighbors " +
  "RETURN host, prefix, threatNeighbors";

// KEYED destination drill: co-hosting fan-in (how many other names sit on
// the same address) + the announcing prefix's threat-neighbor count.
export const COHOST_QUERY =
  "MATCH (h:HOSTNAME {name:$h})-[:RESOLVES_TO]->(ip:IPV4) " +
  "OPTIONAL MATCH (ip)<-[:RESOLVES_TO]-(other:HOSTNAME) WHERE other.name <> $h " +
  "OPTIONAL MATCH (ip)-[:ANNOUNCED_BY]->(p:ANNOUNCED_PREFIX) " +
  "RETURN ip.name AS ip, count(DISTINCT other) AS cohosted, " +
  "head(collect(DISTINCT p.name)) AS prefix, " +
  "head(collect(DISTINCT p.threatNeighborCount)) AS threatNeighbors LIMIT 1";

// Graph call budget. If the graph is slower than this we fail open.
export const GRAPH_TIMEOUT_MS = 4000;
// Control-plane ops traverse warm storage and can be slower; still bounded.
export const CONTROL_TIMEOUT_MS = 8000;
// Provisioning ops (register a device + allocate its /128, connect + set up
// egress) do real work on the control plane and legitimately take several
// seconds; give them a generous budget so a real round-trip is never mistaken
// for a failure. Still bounded, so a genuinely stuck call cannot hang forever.
export const CONTROL_PROVISION_TIMEOUT_MS = 30_000;
export const GRAPH_MAX_RESPONSE_BYTES = 1_048_576;

// "Protect this browser" (egress) permission sets, one source of truth for
// the background and the dashboard. On Chromium `proxy` is a REQUIRED
// permission (Chrome forbids it in optional_permissions), so it is NOT in the
// runtime-requested set there; the rest are requested on the user's click.
// Firefox DOES allow `proxy` as optional, so it is requested at runtime there.
export const EGRESS_REQUEST = {
  chromium: {
    permissions: ["webRequest", "webRequestAuthProvider", "privacy"],
    origins: ["<all_urls>"],
  },
  firefox: { permissions: ["proxy"], origins: ["<all_urls>"] },
} as const;

// Per-tab navigation debounce (SPA route bursts, redirect chains).
export const NAV_DEBOUNCE_MS = 150;

// Verdict cache TTLs by band, in milliseconds.
export const TTL_BENIGN_MS = 6 * 3600_000;
export const TTL_SUSPICIOUS_MS = 2 * 3600_000;
export const TTL_MALICIOUS_MS = 24 * 3600_000;
export const TTL_UNKNOWN_MS = 3600_000;
export const CACHE_MAX_ENTRIES = 512;

// Device flow defaults (RFC 8628): poll every 5s, give up after 10 minutes,
// unless the console says otherwise.
export const DEVICE_POLL_DEFAULT_MS = 5000;
export const DEVICE_LIFETIME_DEFAULT_MS = 10 * 60_000;

// Corpus auto-update cadence.
export const CORPUS_UPDATE_MINUTES = 24 * 60;

// Ed25519 public key (JWK, base64url "x") that signs the remote corpus.
// Empty until the signed corpus channel ships its key; while empty, remote
// corpus updates are skipped entirely and the bundled corpus is used.
// The detector never trusts an unsigned remote corpus.
export const CORPUS_SIGNING_KEY_B64U = "";

// Cap on generated look-alike candidates confirmed via one batched assess.
export const CANDIDATE_CAP = 48;

// Page-link pre-verdicts: unique registrable destinations per scan, and the
// per-call batch for the assess sweep. activeTab + scripting only; the page
// reduces its own links to bare hostnames before anything leaves it.
export const LINK_SCAN_HOST_CAP = 160;
export const LINK_SCAN_BATCH = 60;

// ---------------------------------------------------------------- dashboard

// The on-device destination log: last 24h, busiest-first cap.
export const NAVLOG_WINDOW_MS = 24 * 3600_000;
export const NAVLOG_MAX_HOSTS = 600;

// Enrichment batching: per-call host cap and per-host cache TTL
// (resolution/owner/geo are near-static; 1h keeps calls minimal).
export const ENRICH_BATCH = 60;
export const ENRICH_TTL_MS = 3600_000;

// Fleet: per-device activity pull and the merged busiest-host cap.
export const FLEET_LOGS_LIMIT = 400;
export const FLEET_HOST_CAP = 800;
export const FLEET_DEVICE_CAP = 24;

// Realtime feed: the browser floors alarms at 30s; the tighter interval
// runs only while a dashboard tab holds its port open. Ring + cursor are
// persisted so a worker eviction never loses the feed.
export const POLL_ALARM_MINUTES = 0.5;
export const POLL_OPEN_MS = 12_000;
export const FEED_RING_MAX = 500;
