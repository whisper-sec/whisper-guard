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

import { HISTORY_QUERY_ONE, LINK_SCAN_BATCH, LINK_SCAN_HOST_CAP, TOR_RELAY_QUERY } from "../shared/config";
import { isPrivateHost } from "../shared/hostname";
import { applyIgnoreList, extractIocs, type Ioc } from "../shared/ioc";
import type { GraphBand } from "../shared/types";
import { assessHosts } from "./assess";
import { explainHost } from "./cognition";
import { graphQuery } from "./graph-client";
import { cacheGet, cachePut } from "./cache";

/**
 * The graph's own account of ONE indicator, from whisper.explain. This is the
 * answer the competing tool cannot give: not a score, a sentence plus the named
 * factors and the named feeds behind it.
 *
 * explain auto-detects the indicator TYPE, so a hash, a CVE, an ip and a domain
 * all go through one call and come back labelled. That single fact is why this
 * replaced a hand-rolled assess-plus-vulnPosture pair: fewer calls, more answer,
 * and no type dispatch of our own to get wrong.
 */
export interface IocExplain {
  /** What the graph decided this indicator IS: hash / cve / ip / domain / url. */
  type: string | null;
  level: string | null;
  /** A human sentence, e.g. "... is a CISA known-exploited vulnerability (KEV)". */
  explanation: string | null;
  /** Named, weighted reasons. Not a score - the reasons behind one. */
  factors: string[];
  /** The feeds that said so, by name. */
  sources: string[];
}

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
  /** UNKNOWN when the graph holds nothing; null when we did not ask (hash/CVE). */
  band: GraphBand | null;
  label: string | null;
  /** Present when the graph had an account of this indicator to give. */
  why?: IocExplain;
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

  // #1205 items 2 and 5, and the reason this is one block rather than two.
  //
  // whisper.explain takes ANY indicator and tells you what it decided the thing
  // IS, plus a human sentence, the named factors and the named feeds. A hash
  // comes back type "hash" and joins the known-bad corpus and the NSRL
  // known-good set - the same join the sensor's exec-hash bridge uses. A CVE id
  // comes back type "cve": CVE-2021-44228 answers CRITICAL, score 10.0, "a CISA
  // known-exploited vulnerability (KEV), with known ransomware-campaign use",
  // over seven named sources. Keyless, so it rides the public tier.
  //
  // I built an assess-plus-vulnPosture pair first, having concluded from two
  // probes that no hash surface existed. It did; I had not read the sensor,
  // which calls exactly this. Recorded because the lesson is the method, not
  // the fact: absence from a narrow probe is not absence.
  //
  // Bounded to the cap and taken in appearance order, so a long page costs a
  // predictable number of calls. Any failure is an absent account, never a
  // failed scan.
  const why = new Map<string, IocExplain>();
  const strArr = (v: unknown): string[] =>
    Array.isArray(v)
      ? v
          .map((x) =>
            typeof x === "string"
              ? x
              : x && typeof x === "object" && typeof (x as { source?: unknown }).source === "string"
                ? ((x as { source: string }).source)
                : null,
          )
          .filter((x): x is string => !!x)
      : [];
  for (const i of rows0.slice(0, LINK_SCAN_BATCH)) {
    const subject = i.host ?? i.value;
    if (!subject || why.has(subject)) continue;
    const r = await explainHost(subject);
    if (!r.ok || !r.rows.length) continue;
    const row = r.rows[0] as Record<string, unknown>;
    if (row["found"] !== true) continue; // "not found" is not an account
    why.set(subject, {
      type: typeof row["type"] === "string" ? row["type"] : null,
      level: typeof row["level"] === "string" ? row["level"] : null,
      explanation: typeof row["explanation"] === "string" ? row["explanation"] : null,
      factors: strArr(row["factors"]),
      sources: strArr(row["sources"]),
    });
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
      const w0 = why.get(i.host ?? i.value);
      return {
        kind: i.kind,
        value: i.value,
        host: i.host,
        band: null,
        label: null,
        ...(w0 ? { why: w0 } : {}),
      };
    }
    const v = verdicts.get(i.host);
    const w = why.get(i.host);
    const c = context.get(i.host);
    return {
      kind: i.kind,
      value: i.value,
      host: i.host,
      band: v ? v.band : "UNKNOWN",
      label: v ? v.label : null,
      ...(w ? { why: w } : {}),
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
