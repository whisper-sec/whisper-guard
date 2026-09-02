// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// All endpoints and tunables in one place. Six Whisper hosts exist, each
// with one narrow purpose; browsing hostnames go to exactly ONE of them:
//
//   graph.whisper.online      the graph front door. Two arms on one host: the
//                             safety check + enrichment (hostname only, keyed
//                             or not), which is the ONLY thing a browsing
//                             hostname ever reaches, and the keyed control
//                             plane (whisper.agents) for the fleet roster,
//                             enrollment and egress, which is never called
//                             without a key and never carries a hostname
//   console.whisper.online    the Whisper console. The ONE place this
//                             extension ever SENDS a reader. Nothing is
//                             fetched from it
//   console.whisper.security  the sign-in origin, and nothing else. Two
//                             unauthenticated device-flow endpoints are
//                             fetched from it; no browsing data is sent and
//                             no reader is ever navigated there by us
//   get.whisper.online        detector corpus updates only (no browsing data)
//   nic.whisper.online        the public network statistics document: the live
//                             size of the graph and the resolvers' own pulse. A
//                             plain GET of a public file with no query string,
//                             no header and no body, so nothing about the
//                             reader can ride on it
//   rdap.whisper.online       public endpoint-identity verification (IP literals only)
//
// One graph host, two arms. graph.whisper.online answers both the keyless
// read arm and the keyed control arm, so Guard needs one host permission,
// one privacy sentence and one endpoint to explain to a user.
//
// The two constants below therefore name the same host, and that is
// deliberate rather than redundant: the RULES differ even where the host
// does not. A read is keyless-capable and carries a bare hostname; a control
// call is always keyed and carries no browsing datum. Those are properties
// of the REQUEST, not of the hostname, which is why they are worth naming
// separately and why graphQuery defaults to the READ endpoint, so a browsing
// hostname cannot reach the control path by omission.
//
// Both invariants are pinned from the outside in e2e/graph-endpoints.spec.ts,
// together with the one that matters most to a signed-out user: when the
// graph cannot answer a keyless read, the verdict degrades to UNKNOWN and
// never to a false clean.

/** Graph READS: assess, identify, explain, variants, history, submit, enrichment. */
export const GRAPH_QUERY_URL = "https://graph.whisper.online/api/query";
/** The keyed CONTROL plane (whisper.agents). Never carries a browsing hostname. */
export const CONTROL_QUERY_URL = "https://graph.whisper.online/api/query";
/**
 * The bare graph hostname, for the privacy sentences the UI shows. Derived
 * from the URL above rather than written twice, because a promise about where
 * a hostname went is only worth anything if it cannot drift from where it
 * actually goes.
 */
export const GRAPH_HOST = new URL(GRAPH_QUERY_URL).hostname;

/**
 * The console, and the ONE address this extension ever sends a reader to.
 * Every "open the console" affordance in the product resolves here.
 *
 * It is deliberately NOT the host the sign-in flow talks to, and the split
 * is not cosmetic: measured against both hosts on 2026-09-01, the sign-in
 * origin answers a signed-out visitor with HTTP 404 on every page, while
 * this one answers 307 to the sign-in and returns the reader afterwards.
 * Sending someone to the former is sending them to a dead end, so we do
 * not.
 */
export const CONSOLE_URL = "https://console.whisper.online";

/**
 * The sign-in ORIGIN: where the RFC 8628 device-authorization endpoints
 * actually live, and the only thing this constant is for. It is auth
 * machinery, never a destination: nothing in the extension navigates here.
 *
 * They are not on CONSOLE_URL and cannot be moved there by us: CONSOLE_URL
 * gates its whole /api surface behind a session, which a browserless device
 * flow by definition does not have, and it answers 401 UNAUTHENTICATED
 * accordingly (probed live, 2026-09-01). The device-flow endpoints exist
 * only on this origin. Repointing this at CONSOLE_URL would silently break
 * sign-in for everyone, so it stays, named for what it is.
 */
export const DEVICE_FLOW_ORIGIN = "https://console.whisper.security";

/**
 * The public keyless network statistics document: the live size of the
 * graph the verdicts come from, and the live pulse of the resolvers that
 * answer from it.
 *
 * It is a plain GET of a public JSON file. No query string, no header, no
 * body, no cookie: nothing about the reader can ride on it, which is why
 * it is safe to poll while a surface is open. The figures are read every
 * time and NEVER written into this repository as constants - a hardcoded
 * graph total is stale the day after it ships, and a security product
 * quoting a stale figure about its own coverage is worse than one quoting
 * none. When the endpoint cannot be reached the surface says so.
 */
export const STATS_URL = "https://nic.whisper.online/stats/data.json";
export const SCALE_TIMEOUT_MS = 4000;
export const SCALE_MAX_BYTES = 512_000;
/** How long a read of the scale stays fresh. The document itself carries
 *  Cache-Control max-age=30, so this matches its own cadence. */
export const SCALE_TTL_MS = 30_000;

export const CORPUS_URL = "https://get.whisper.online/guard/corpus.v1.json";
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

// KEYLESS enrichment, the geo half. The public tier caps a raw query at two
// patterns, which is not enough to reach the operator three joins out, so
// the OPERATOR half is served by CALL whisper.enrich - a named procedure
// that does the deep walk server-side and answers keyless in one request
// for a whole batch. This query survives for the one fact the procedure
// does not carry: the city the address sits in, which is the fact a person
// recognises.
export const ENRICH_GEO_QUERY =
  "UNWIND $hosts AS host MATCH (n:HOSTNAME {name:host}) " +
  "OPTIONAL MATCH (n)-[:RESOLVES_TO]->(ip:IPV4)-[:LOCATED_IN]->(city:CITY) " +
  "WITH host, head(collect(DISTINCT ip.name)) AS ip, head(collect(DISTINCT city.name)) AS city, " +
  "head(collect(DISTINCT ip.verdictLevel)) AS verdict " +
  "RETURN host, ip, city, verdict";

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
// Control-plane ops do more work than a read and can be slower; still bounded.
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

// Pre-emptive click/form-submit interruption. A held click must
// resolve fast, so the background's keyless assess gets a tighter budget
// than the nav pipeline's; the content script adds a belt-and-braces cap
// after which the original action proceeds untouched (fail open: a slow or
// dead graph never blocks the user).
export const PREEMPT_ASSESS_TIMEOUT_MS = 2000;
export const PREEMPT_DECIDE_TIMEOUT_MS = 2600;

// Cookie-consent auto-decline. Most CMPs mount their banner within
// a few seconds of load; the MutationObserver watching for a late banner
// disconnects after this window (or on the first successful decline), so
// the module never lingers on long-lived pages. Rescans after a DOM burst
// are debounced so a busy page costs one bounded scan, not one per node.
export const CONSENT_SCAN_WINDOW_MS = 15_000;
export const CONSENT_RESCAN_DEBOUNCE_MS = 250;

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

// ------------------------------------------------------------------ the chain

// The chain (background/chain.ts) is built on the popup's ask, never on
// every navigation. The public tier allows 100 graph calls an hour from one
// address and the chain costs seven of them, so building it on every page
// load would exhaust a reader's budget inside twenty minutes of ordinary
// browsing and leave nothing for the verdict that actually protects them.
// A composed chain is memoised for this long.
export const CHAIN_TTL_MS = 10 * 60_000;
