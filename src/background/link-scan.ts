// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Page-link pre-verdicts: one click reads every link on the CURRENT page and
// verdicts each destination BEFORE the user visits any of them. No new
// permissions: the click that opens the popup grants activeTab, and the
// injection rides the existing "scripting" permission.
//
// THE PRIVACY INVARIANT, held twice over:
//   1) the injected collector reduces links to bare HOSTNAMES inside the
//      page itself, so paths / queries / fragments / text never even reach
//      the extension, let alone the wire;
//   2) the background then dedups to registrable domains and assesses those
//      through the same single chokepoint every other check uses. Only a
//      site's name is ever checked. Never the page, never your history.
//
// Keyless-friendly: the sweep rides the public assess tier, cache first.

import { LINK_SCAN_BATCH, LINK_SCAN_HOST_CAP } from "../shared/config";
import { isPrivateHost } from "../shared/hostname";
import { registrableDomain } from "../shared/psl";
import type { GraphBand, LinkScanResult, LinkVerdictRow } from "../shared/types";
import { assessHosts } from "./assess";
import { cacheGet, cachePut } from "./cache";

/**
 * Runs INSIDE the page (serialized by chrome.scripting): collect the
 * hostnames of all http(s) <a href> links. Hostnames only, by construction;
 * everything else about the link dies here, inside the page.
 */
function collectLinkHostnames(): string[] {
  const out: string[] = [];
  const anchors = document.querySelectorAll<HTMLAnchorElement>("a[href]");
  for (const a of anchors) {
    if (out.length >= 5000) break;
    try {
      const u = new URL(a.href, document.baseURI);
      if (u.protocol === "http:" || u.protocol === "https:") {
        out.push(u.hostname.replace(/\.$/, "").toLowerCase());
      }
    } catch {
      // unparsable href: skip
    }
  }
  return out;
}

const RANK: Record<GraphBand, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  UNKNOWN: 3,
  LOW: 4,
  INFO: 5,
  NONE: 6,
};

/**
 * Scan the tab's links and verdict every unique registrable destination,
 * cache-first, then ONE batched assess per LINK_SCAN_BATCH of misses.
 */
export async function scanTabLinks(tabId: number): Promise<LinkScanResult> {
  let hostnames: string[];
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: collectLinkHostnames,
    });
    hostnames = Array.isArray(results[0]?.result)
      ? (results[0].result as unknown[]).filter((h): h is string => typeof h === "string")
      : [];
  } catch (e) {
    throw new Error(
      `could not read the page's links: ${String(e instanceof Error ? e.message : e)}`,
    );
  }

  // Reduce to unique registrable destinations, counting links per each.
  const counts = new Map<string, number>();
  let totalLinks = 0;
  for (const h of hostnames) {
    if (isPrivateHost(h)) continue;
    const reg = registrableDomain(h) ?? h;
    totalLinks++;
    counts.set(reg, (counts.get(reg) ?? 0) + 1);
  }
  const unique = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const truncated = unique.length > LINK_SCAN_HOST_CAP;
  const wanted = unique.slice(0, LINK_SCAN_HOST_CAP).map(([host]) => host);

  // Cache first; one batched assess per chunk of misses.
  const verdicts = new Map<string, { band: GraphBand; label: string | null }>();
  const misses: string[] = [];
  for (const host of wanted) {
    const cached = await cacheGet(host);
    if (cached) verdicts.set(host, { band: cached.band, label: cached.label });
    else misses.push(host);
  }
  for (let i = 0; i < misses.length; i += LINK_SCAN_BATCH) {
    const batch = misses.slice(i, i + LINK_SCAN_BATCH);
    const got = await assessHosts(batch);
    for (const host of batch) {
      const v = got.get(host);
      if (v) {
        await cachePut(v);
        verdicts.set(host, { band: v.band, label: v.label });
      } else {
        // No row for a host we asked about: honest UNKNOWN, never invented.
        verdicts.set(host, { band: "UNKNOWN", label: null });
      }
    }
  }

  const rows: LinkVerdictRow[] = wanted.map((host) => {
    const v = verdicts.get(host) ?? { band: "UNKNOWN" as GraphBand, label: null };
    return { host, band: v.band, label: v.label, links: counts.get(host) ?? 0 };
  });
  rows.sort((a, b) => RANK[a.band] - RANK[b.band] || b.links - a.links || a.host.localeCompare(b.host));

  let flagged = 0;
  let suspicious = 0;
  let unknown = 0;
  let clean = 0;
  for (const r of rows) {
    if (r.band === "CRITICAL" || r.band === "HIGH") flagged++;
    else if (r.band === "MEDIUM") suspicious++;
    else if (r.band === "UNKNOWN") unknown++;
    else clean++;
  }

  return { hosts: rows, totalLinks, flagged, suspicious, unknown, clean, truncated };
}
