// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// All endpoints and tunables in one place. Three Whisper endpoints exist,
// each with one narrow purpose; browsing hostnames go to exactly ONE of them:
//
//   graph.whisper.security    the safety check itself (hostname only, keyed or not)
//   console.whisper.security  sign-in only (RFC 8628 device flow, no browsing data)
//   get.whisper.online        detector corpus updates only (no browsing data)

export const GRAPH_QUERY_URL = "https://graph.whisper.security/api/query";
export const CONSOLE_URL = "https://console.whisper.security";
export const CORPUS_URL = "https://get.whisper.online/guard/corpus.v1.json";
export const CONSOLE_KEYS_URL = "https://console.whisper.security/settings";

// The public assess contract, the same one the Whisper platform exposes.
export const ASSESS_QUERY =
  "CALL whisper.assess($hs) YIELD host,label,band,coverage RETURN host,label,band,coverage";

// Graph call budget. If the graph is slower than this we fail open to UNKNOWN.
export const GRAPH_TIMEOUT_MS = 4000;
export const GRAPH_MAX_RESPONSE_BYTES = 262144;

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
