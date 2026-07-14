// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE privacy chokepoint. Everything that could ever reach the network goes
// through extractHostname(): the full URL comes in, ONLY the hostname comes
// out, and path/query/fragment/userinfo are discarded at parse time. There
// is no other route from a URL to the wire.

const PRIVATE_SUFFIXES = [".local", ".internal", ".localhost", ".home.arpa", ".test", ".invalid"];

/** True for hosts that must never be assessed or sent anywhere. */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.replace(/\.$/, "").toLowerCase();
  if (h === "" || h === "localhost") return true;
  if (!h.includes(".")) return true; // bare intranet names
  for (const s of PRIVATE_SUFFIXES) if (h.endsWith(s)) return true;
  // IPv6 literal (URL.hostname keeps the brackets).
  if (h.startsWith("[")) return true;
  // IPv4 literal, incl. RFC1918 by construction: all IP literals are skipped.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  return false;
}

/**
 * Extract the assessable hostname from a URL, or null when the page is out
 * of scope (non-http(s), internal, local, an IP literal). This is the only
 * function that ever touches the full URL.
 */
export function extractHostname(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  const host = u.hostname.replace(/\.$/, "").toLowerCase();
  if (isPrivateHost(host)) return null;
  return host;
}
