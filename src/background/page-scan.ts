// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Page indicator scan: one click reads the CURRENT page's text, lifts every
// indicator out of it, and verdicts the ones the graph can speak to.
//
// WHY THIS EXISTS. An analyst reading an advisory, a ticket or a mail wants the
// indicators on that page enriched, without copying them somewhere. The
// usual shape in this category is a STATIC content script matching <all_urls>,
// parsed on every page the user ever opens whether or not they scan anything,
// behind a required host grant.
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

import { HISTORY_QUERY_ONE, LINK_SCAN_BATCH, LINK_SCAN_HOST_CAP, TOR_RELAY_QUERY } from "../shared/config";
import { isPrivateHost } from "../shared/hostname";
import {applyIgnoreList, type Ioc} from "../shared/ioc";
import type { GraphBand } from "../shared/types";
import { assessHosts } from "./assess";
import { graphQuery } from "./graph-client";
import { cacheGet, cachePut } from "./cache";

/**
 * The facts only a graph holds, attached to one indicator. Both of these are
 * things nothing else in a browser says, and both are keyless.
 */
export interface IocContext {
  /** The address is a Tor exit relay. Absent means we asked and it is not. */
  torExit?: boolean;
  /** When the name was first registered, and by whom - the phishing signal. */
  created?: string;
  registrar?: string;
  registrant?: string;
}

/** One extracted indicator plus whatever the graph could say about it. */
export interface IocRow {
  kind: Ioc["kind"];
  value: string;
  host: string | null;
  /** `null` means the scan did not assess this indicator (no host, or a host
   *  `isPrivateHost` keeps off the network: IP literals, file hashes, bare
   *  names). UNKNOWN means the graph was asked and holds nothing. */
  band: GraphBand | null;
  label: string | null;
  /** Registration age for a name, Tor-exit status for an address. */
  context?: IocContext;
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
function readStashedIocs(): unknown {
  const w = window as unknown as { __whisperIocs?: unknown };
  const out = w.__whisperIocs;
  // Do not leave the page's indicators sitting on the window for other scripts.
  try { delete w.__whisperIocs; } catch { /* non-configurable: ignore */ }
  return out ?? [];
}

/**
 * Scan the tab and verdict every indicator the graph can speak to.
 *
 * An indicator with no host (a CVE id, a file hash) or with a host
 * `isPrivateHost` keeps off the network (an IP literal) is never sent anywhere
 * and comes back with `band: null`: UNKNOWN would claim the graph was asked and
 * holds nothing, which is a different statement. Only public hostnames are put
 * to whisper.assess.
 */
export async function scanTabIocs(
  tabId: number,
  ignore: readonly string[] = [],
): Promise<PageScanResult> {
  let all: Ioc[];
  try {
    // The document is read and reduced to indicators INSIDE the page, by the bundled
    // ioc-collect.js. Only the Ioc[] crosses back. The page's text never does.
    await chrome.scripting.executeScript({ target: { tabId }, files: ["ioc-collect.js"] });
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: readStashedIocs,
    });
    all = Array.isArray(results[0]?.result) ? (results[0].result as Ioc[]) : [];
  } catch (e) {
    throw new Error(
      `could not scan the page: ${String(e instanceof Error ? e.message : e)}`,
    );
  }

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

  // The two facts a browser has never been able to state, both keyless.
  //
  // An IP that is a Tor exit relay is a different thing from an IP that merely
  // has no listings, and no other extension in this category will tell you.
  // A name's registration date and registrar turn "unknown domain" into
  // "registered eleven days ago through a registrar with no abuse contact",
  // which is the signal that actually separates phishing from an obscure site.
  //
  // Both are bounded to the same cap, both are best-effort, and neither can
  // fail the scan. Absent means we asked and got nothing, which the UI must
  // render differently from "we never asked".
  const context = new Map<string, IocContext>();
  for (const i of rows0.slice(0, LINK_SCAN_BATCH)) {
    const subject = i.host;
    if (!subject || context.has(subject) || isPrivateHost(subject)) continue;
    try {
      if (i.kind === "ipv4" || i.kind === "ipv6") {
        const r = await graphQuery(TOR_RELAY_QUERY, { h: subject }, undefined, { keyless: true });
        if (r[0]?.["found"] === true) context.set(subject, { torExit: true });
      } else if (i.kind === "domain" || i.kind === "url") {
        const r = await graphQuery(HISTORY_QUERY_ONE, { h: subject }, undefined, { keyless: true });
        const row = r[0];
        if (row) {
          const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
          const c: IocContext = {
            created: str(row["createDate"]),
            registrar: str(row["registrar"]),
            registrant: str(row["registrant"]),
          };
          if (c.created || c.registrar || c.registrant) context.set(subject, c);
        }
      }
    } catch {
      // Enrichment. Never fails the scan.
    }
  }

  const rows: IocRow[] = rows0.map((i) => {
    if (!i.host || isPrivateHost(i.host)) {
      return {
        kind: i.kind,
        value: i.value,
        host: i.host,
        band: null,
        label: null,
      };
    }
    const v = verdicts.get(i.host);
    const c = context.get(i.host);
    return {
      kind: i.kind,
      value: i.value,
      host: i.host,
      band: v ? v.band : "UNKNOWN",
      label: v ? v.label : null,
      ...(c ? { context: c } : {}),
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
