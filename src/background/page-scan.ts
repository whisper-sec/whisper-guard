// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Page indicator scan: one click reads the CURRENT page's text, lifts every
// indicator out of it, and verdicts the ones the graph can speak to.
//
// WHY THIS EXISTS. An analyst reading an advisory, a ticket or a mail wants the
// indicators on that page enriched, without copying them somewhere. The
// competing extension in this category does exactly that, and does it with a
// STATIC content script matching <all_urls> carrying a 12,059,990-byte bundle
// that is parsed on every page the user ever opens, whether or not they ever
// scan anything, behind a REQUIRED <all_urls> grant and a paid API credential.
//
// We do the same job the other way round, and the difference is the product:
//   - nothing is injected until the reader asks. There is no content_scripts
//     entry, so an ordinary page load costs zero;
//   - page access is the CURRENT TAB, on the click gesture, under the existing
//     optional-permission model. If you never scan, we never needed the page;
//   - extraction happens INSIDE the page. Only the extracted indicators come
//     back, never the document. The same invariant the link scan holds;
//   - it works with NO ACCOUNT, on the public keyless tier, cache-first.
//
// See extractIocs for why defanged forms are the point rather than a nicety.

import { LINK_SCAN_BATCH, LINK_SCAN_HOST_CAP } from "../shared/config";
import { isPrivateHost } from "../shared/hostname";
import { applyIgnoreList, extractIocs, type Ioc } from "../shared/ioc";
import type { GraphBand } from "../shared/types";
import { assessHosts } from "./assess";
import { cacheGet, cachePut } from "./cache";

/** One extracted indicator plus whatever the graph could say about it. */
export interface IocRow {
  kind: Ioc["kind"];
  value: string;
  host: string | null;
  /** UNKNOWN when the graph holds nothing; null when we did not ask (hash/CVE). */
  band: GraphBand | null;
  label: string | null;
}

export interface PageScanResult {
  rows: IocRow[];
  /** Distinct indicators found before the ignore list and the cap. */
  found: number;
  /** Silenced by the reader's ignore list. */
  ignored: number;
  /** True when the cap trimmed the result, so the UI can say so honestly. */
  truncated: boolean;
  /** Hosts we asked the graph about. Zero is a legitimate answer. */
  assessed: number;
}

/**
 * Runs INSIDE the page (serialized by chrome.scripting). Returns the page's
 * visible text, bounded. It deliberately reads textContent rather than innerHTML:
 * markup carries urls the reader cannot see, and reporting an indicator nobody
 * can point at on screen is how a scanner loses trust.
 */
function collectPageText(): string {
  const MAX = 400_000;
  const body = document.body;
  if (!body) return "";
  const text = body.innerText || body.textContent || "";
  return text.length > MAX ? text.slice(0, MAX) : text;
}

/**
 * Scan the tab and verdict every indicator the graph can speak to.
 *
 * Hashes and CVEs come back with `band: null` rather than UNKNOWN: we did not
 * ask, and "we asked and found nothing" is a different statement from "we never
 * asked". Conflating them is the failure this codebase keeps writing tests
 * against.
 */
export async function scanTabIocs(
  tabId: number,
  ignore: readonly string[] = [],
): Promise<PageScanResult> {
  let text: string;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: collectPageText,
    });
    text = typeof results[0]?.result === "string" ? results[0].result : "";
  } catch (e) {
    throw new Error(
      `could not read the page's text: ${String(e instanceof Error ? e.message : e)}`,
    );
  }

  const all = extractIocs(text, LINK_SCAN_HOST_CAP * 4);
  const kept = applyIgnoreList(all, ignore);
  const truncated = kept.length > LINK_SCAN_HOST_CAP;
  const rows0 = kept.slice(0, LINK_SCAN_HOST_CAP);

  // Only network indicators have a host the graph can assess. A private or
  // reserved host is skipped rather than asked about: it identifies the
  // reader's own network and is not the graph's business.
  const hosts = [
    ...new Set(
      rows0
        .map((i) => i.host)
        .filter((h): h is string => typeof h === "string" && h.length > 0 && !isPrivateHost(h)),
    ),
  ];

  const verdicts = new Map<string, { band: GraphBand; label: string | null }>();
  const misses: string[] = [];
  for (const host of hosts) {
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
      }
    }
  }

  const rows: IocRow[] = rows0.map((i) => {
    if (!i.host || isPrivateHost(i.host)) {
      return { kind: i.kind, value: i.value, host: i.host, band: null, label: null };
    }
    const v = verdicts.get(i.host);
    return {
      kind: i.kind,
      value: i.value,
      host: i.host,
      band: v ? v.band : "UNKNOWN",
      label: v ? v.label : null,
    };
  });

  return {
    rows,
    found: all.length,
    ignored: all.length - kept.length,
    truncated,
    assessed: hosts.length,
  };
}
