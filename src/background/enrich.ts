// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Batched destination enrichment for the dashboard: hostname -> owner /
// category / geo / network / verdict, through the graph, shaped by the
// pure inference chain in shared/report.ts.
//
// Two tiers, same shape:
//   keyed    one deep query (IP, city+country, ASN, organization, verdict)
//   keyless  two parallel 2-hop queries (geo, announcing prefix) + identify
// Per-host 1h cache (resolution/owner data is near-static), fully fail-open:
// a failed batch leaves hosts with their name-derived signals, never an error.

import {
  ENRICH_BATCH,
  ENRICH_GEO_QUERY,
  ENRICH_KEYED_QUERY,
  ENRICH_NET_QUERY,
  ENRICH_TTL_MS,
  IDENTIFY_BATCH_QUERY,
} from "../shared/config";
import {
  classifyHostname,
  fallbackRegistrable,
  inferCategory,
  isoFromPlace,
  resolveOwnerLabel,
  type ReportHost,
} from "../shared/report";
import { registrableDomain } from "../shared/psl";
import { cacheGet } from "./cache";
import { graphQuery, hasKey } from "./graph-client";
import type { NavEntry } from "./navlog";

type CachedRow = Omit<ReportHost, "q" | "lastAt">;

const cache = new Map<string, { row: CachedRow; at: number }>();

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

interface MainRow {
  ip?: string;
  city?: string;
  country?: string;
  asn?: string;
  org?: string;
  asnName?: string;
  prefix?: string;
  verdict?: string;
}
interface IdentifyRow {
  canonical?: string;
  category?: string;
  roles?: string[];
}

async function runKeyed(hosts: string[]): Promise<Map<string, MainRow>> {
  const out = new Map<string, MainRow>();
  if (hosts.length === 0) return out;
  const rows = await graphQuery(ENRICH_KEYED_QUERY, { hosts }).catch(() => []);
  for (const r of rows) {
    const host = str(r["host"]);
    if (!host) continue;
    out.set(host, {
      ip: str(r["ip"]),
      city: str(r["city"]),
      country: str(r["country"])?.toUpperCase(),
      asn: str(r["asn"]),
      org: str(r["owner"]),
      asnName: str(r["asnName"]),
      verdict: str(r["verdict"]),
    });
  }
  return out;
}

async function runKeyless(hosts: string[]): Promise<Map<string, MainRow>> {
  const out = new Map<string, MainRow>();
  if (hosts.length === 0) return out;
  const [geoRows, netRows] = await Promise.all([
    graphQuery(ENRICH_GEO_QUERY, { hosts }).catch(() => []),
    graphQuery(ENRICH_NET_QUERY, { hosts }).catch(() => []),
  ]);
  for (const r of geoRows) {
    const host = str(r["host"]);
    if (!host) continue;
    const city = str(r["city"]);
    out.set(host, {
      ip: str(r["ip"]),
      city,
      country: isoFromPlace(city),
      verdict: str(r["verdict"]),
    });
  }
  for (const r of netRows) {
    const host = str(r["host"]);
    if (!host) continue;
    const cur = out.get(host) ?? {};
    cur.prefix = str(r["prefix"]);
    out.set(host, cur);
  }
  return out;
}

async function runIdentify(hosts: string[]): Promise<Map<string, IdentifyRow>> {
  const out = new Map<string, IdentifyRow>();
  if (hosts.length === 0) return out;
  const rows = await graphQuery(IDENTIFY_BATCH_QUERY, { hs: hosts }).catch(() => []);
  for (const r of rows) {
    const host = str(r["host"]);
    if (!host) continue;
    out.set(host, {
      canonical: str(r["canonical_name"]),
      category: str(r["category"]),
      roles: strList(r["roles"]),
    });
  }
  return out;
}

function shapeRow(host: string, main: MainRow | undefined, identify: IdentifyRow | undefined): CachedRow {
  const apex = registrableDomain(host) ?? undefined;
  const owner = resolveOwnerLabel(main?.org, identify?.canonical, host, apex);
  const category = inferCategory({
    host,
    identifyCategory: identify?.category,
    identifyRoles: identify?.roles,
    owner,
    asnName: main?.asnName,
    org: main?.org,
  });
  return {
    host,
    ip: main?.ip,
    city: main?.city,
    country: main?.country,
    asn: main?.asn,
    asnName: main?.asnName,
    prefix: main?.prefix,
    owner,
    category,
    verdict: (main?.verdict ?? "UNKNOWN").toUpperCase(),
  };
}

/**
 * Enrich a destination list (busiest-first, already capped by the caller's
 * view) into full ReportHost rows. The reconciled assess band, when the
 * verdict cache holds one for a host, outranks the raw stored level.
 */
export async function enrichDestinations(entries: NavEntry[]): Promise<ReportHost[]> {
  const now = Date.now();
  const wanted = entries.map((e) => ({ ...e, host: e.host.replace(/\.$/, "").toLowerCase() }));
  const misses = [...new Set(wanted.map((w) => w.host))].filter((h) => {
    const hit = cache.get(h);
    return !(hit && now - hit.at < ENRICH_TTL_MS);
  });

  if (misses.length > 0) {
    const keyed = await hasKey();
    for (let i = 0; i < misses.length; i += ENRICH_BATCH) {
      const batch = misses.slice(i, i + ENRICH_BATCH);
      const [main, identify] = await Promise.all([
        keyed ? runKeyed(batch) : runKeyless(batch),
        runIdentify(batch),
      ]);
      for (const host of batch) {
        cache.set(host, { row: shapeRow(host, main.get(host), identify.get(host)), at: now });
      }
    }
  }

  const out: ReportHost[] = [];
  for (const w of wanted) {
    const cached = cache.get(w.host)?.row;
    const row: CachedRow = cached ?? {
      host: w.host,
      owner: fallbackRegistrable(w.host),
      category: classifyHostname(w.host) ?? "unresolved",
      verdict: "UNKNOWN",
    };
    // The reconciled band from the shared verdict cache wins over the raw
    // stored level: reconciliation already discounts popularity listings.
    const assessed = await cacheGet(w.host);
    const verdict = assessed ? assessed.band : row.verdict;
    out.push({ ...row, verdict, q: w.q, lastAt: w.lastAt });
  }
  return out;
}
