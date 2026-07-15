// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The composed site verdict: ONE reconciled picture per hostname, reused by
// the icon, the popup site card, the on-page banner and the warning page.
//
//   band/gate   whisper.assess (the reconciled engine verdict; the ONLY
//               thing that blocks; popularity listings can never flag)
//   who         whisper.identify shaped through the owner inference chain
//               (raw identify returns hashes and nulls, never rendered raw)
//   why         whisper.explain, feed-cited, popularity feeds excluded
//   age         whisper.history registration date (freshest snapshot wins)
//   where       resolved geo (2-hop public tier; the keyed tier adds the
//               announcing network + registered organization)
//   variants    whisper.variants (exists-only): registered look-alikes of
//               this name, confirmed against assess before they are shown
//
// Every part fails open independently: a slow graph never blocks browsing
// and a missing part renders as absent, never invented.

import {
  ENRICH_GEO_QUERY,
  ENRICH_KEYED_QUERY,
  HISTORY_QUERY,
  VARIANTS_QUERY,
} from "../shared/config";
import type { AssessVerdict, CandidateVerdict, GraphBand, Protection, WhyFactor } from "../shared/types";
import {
  inferCategory,
  isoFromPlace,
  isPopularityFeed,
  resolveOwnerLabel,
} from "../shared/report";
import { assessHost, assessHosts } from "./assess";
import { cacheGet, cachePut } from "./cache";
import { graphQuery, hasKey } from "./graph-client";

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

/** The block/warn gate: CRITICAL / HIGH bands or an explicit malicious label. */
export function isBlocking(verdict: AssessVerdict | null): boolean {
  if (!verdict) return false;
  if (verdict.band === "CRITICAL" || verdict.band === "HIGH") return true;
  return (verdict.label ?? "").toLowerCase() === "malicious";
}

/** Assess with the shared cache (the same rows the nav pipeline painted). */
async function assessCached(host: string): Promise<AssessVerdict> {
  const cached = await cacheGet(host);
  if (cached) return cached;
  const v = await assessHost(host);
  await cachePut(v);
  return v;
}

async function fetchWho(host: string): Promise<{
  who: string | null;
  category: string | null;
  where: Protection["where"];
}> {
  const keyed = await hasKey();
  const [identifyRows, geoRows] = await Promise.all([
    graphQuery(
      "CALL whisper.identify($h) YIELD host, canonical_name, category, roles " +
        "RETURN host, canonical_name, category, roles",
      { h: host },
    ).catch(() => [] as Record<string, unknown>[]),
    graphQuery(keyed ? ENRICH_KEYED_QUERY : ENRICH_GEO_QUERY, { hosts: [host] }).catch(
      () => [] as Record<string, unknown>[],
    ),
  ]);

  const idRow = identifyRows.find((r) => str(r["host"])?.toLowerCase() === host.toLowerCase());
  const canonical = str(idRow?.["canonical_name"]) ?? undefined;
  const roles = Array.isArray(idRow?.["roles"])
    ? (idRow["roles"] as unknown[]).filter((x): x is string => typeof x === "string")
    : undefined;

  const geo = geoRows.find((r) => str(r["host"])?.toLowerCase() === host.toLowerCase());
  const city = str(geo?.["city"]);
  const org = str(geo?.["owner"]) ?? undefined;
  const asnName = str(geo?.["asnName"]) ?? undefined;
  const country = str(geo?.["country"]) ?? isoFromPlace(city ?? undefined) ?? null;

  const who = resolveOwnerLabel(org, canonical, host);
  const category = inferCategory({
    host,
    identifyCategory: str(idRow?.["category"]) ?? undefined,
    identifyRoles: roles,
    owner: who,
    asnName,
    org,
  });
  const where =
    city || country || str(geo?.["ip"])
      ? { city, country, ip: str(geo?.["ip"]) }
      : null;
  return { who, category, where };
}

interface WhyPicture {
  why: string[];
  score: number | null;
  factors: WhyFactor[];
}

/**
 * The WHY behind the verdict, shaped from whisper.explain: the graph's
 * score plus every listing as a NAMED, WEIGHTED factor. Popularity feeds
 * (Tranco and friends) are shown as good standing, never as a threat.
 */
async function fetchWhy(host: string): Promise<WhyPicture> {
  const rows = await graphQuery("CALL whisper.explain($h)", { h: host }).catch(
    () => [] as Record<string, unknown>[],
  );
  const row = rows[0];
  if (!row) return { why: [], score: null, factors: [] };
  const why: string[] = [];
  const found = row["found"] === true;
  const explanation = str(row["explanation"]);
  const rawScore = row["score"];
  const score =
    typeof rawScore === "number" && Number.isFinite(rawScore)
      ? Math.round(rawScore * 10) / 10
      : null;
  const sources = Array.isArray(row["sources"]) ? (row["sources"] as Record<string, unknown>[]) : [];

  const factors: WhyFactor[] = [];
  const threatFeeds: string[] = [];
  for (const s of sources) {
    const id = str(s["feedId"]);
    if (!id) continue;
    const w = s["weight"];
    const weight = typeof w === "number" && Number.isFinite(w) ? w : null;
    const good = isPopularityFeed(id);
    factors.push({ name: id, weight, kind: good ? "good" : "threat" });
    if (!good) threatFeeds.push(id);
  }
  // Threat factors first, heaviest first; good standing after.
  factors.sort(
    (a, b) =>
      (a.kind === "threat" ? 0 : 1) - (b.kind === "threat" ? 0 : 1) ||
      (b.weight ?? 0) - (a.weight ?? 0) ||
      a.name.localeCompare(b.name),
  );

  if (found && threatFeeds.length > 0) {
    why.push(`Listed in ${threatFeeds.length} threat feed${threatFeeds.length === 1 ? "" : "s"}: ${threatFeeds.join(", ")}`);
    if (explanation) why.push(explanation);
  }
  return { why, score, factors };
}

async function fetchAgeDays(host: string): Promise<number | null> {
  const rows = await graphQuery(HISTORY_QUERY, { h: host }).catch(
    () => [] as Record<string, unknown>[],
  );
  // Many WHOIS snapshots return; the freshest by updateDate/queryTime wins.
  let best: Record<string, unknown> | null = null;
  let bestKey = "";
  for (const r of rows) {
    const key = `${str(r["updateDate"]) ?? ""}|${str(r["queryTime"]) ?? ""}`;
    if (key > bestKey) {
      bestKey = key;
      best = r;
    }
  }
  const created = str(best?.["createDate"]);
  if (!created) return null;
  const t = Date.parse(created);
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 86_400_000));
}

const VARIANT_CAP = 24;

/**
 * Registered look-alike variants of this name, confirmed against assess.
 * Existence alone is not evidence: only flagged variants are returned as
 * flagged; the total registered count rides along for context.
 */
export async function variantNeighborhood(
  host: string,
): Promise<{ registered: number; flagged: CandidateVerdict[] }> {
  const rows = await graphQuery(VARIANTS_QUERY, { h: host }).catch(
    () => [] as Record<string, unknown>[],
  );
  const names: string[] = [];
  for (const r of rows) {
    if (r["exists"] !== true) continue;
    const v = str(r["variant"]);
    if (v && v.toLowerCase() !== host.toLowerCase()) names.push(v.toLowerCase());
  }
  const unique = [...new Set(names)];
  const toConfirm = unique.slice(0, VARIANT_CAP);
  const flagged: CandidateVerdict[] = [];
  if (toConfirm.length > 0) {
    const verdicts = await assessHosts(toConfirm).catch(() => new Map<string, AssessVerdict>());
    for (const [h, v] of verdicts) {
      if (v.band === "CRITICAL" || v.band === "HIGH" || v.band === "MEDIUM") {
        flagged.push({ host: h, band: v.band, label: v.label });
      }
    }
  }
  flagged.sort((a, b) => a.host.localeCompare(b.host));
  return { registered: unique.length, flagged };
}

const composed = new Map<string, { p: Protection; at: number }>();
const COMPOSED_TTL_MS = 10 * 60_000;

/**
 * The full composed picture for one hostname. Cached briefly so reopening
 * the popup is instant. `withVariants` adds the (heavier) look-alike
 * neighborhood; everything else always rides along.
 */
export async function protectHost(host: string, withVariants = false): Promise<Protection> {
  const h = host.toLowerCase();
  const key = `${h}|${withVariants ? 1 : 0}`;
  const hit = composed.get(key);
  if (hit && Date.now() - hit.at < COMPOSED_TTL_MS) return hit.p;

  let partial = false;
  const verdict = await assessCached(h).catch((): AssessVerdict => {
    partial = true;
    return { host: h, band: "UNKNOWN" as GraphBand, coverage: null, label: null, at: Date.now() };
  });

  const [who, why, ageDays, variants] = await Promise.all([
    fetchWho(h).catch(() => {
      partial = true;
      return { who: null, category: null, where: null };
    }),
    fetchWhy(h).catch((): WhyPicture => {
      partial = true;
      return { why: [], score: null, factors: [] };
    }),
    fetchAgeDays(h).catch(() => {
      partial = true;
      return null;
    }),
    withVariants
      ? variantNeighborhood(h).then(
          (v) => v.flagged,
          () => {
            partial = true;
            return [] as CandidateVerdict[];
          },
        )
      : Promise.resolve([] as CandidateVerdict[]),
  ]);

  const p: Protection = {
    host: h,
    band: verdict.band,
    blocking: isBlocking(verdict),
    label: verdict.label,
    coverage: verdict.coverage,
    who: who.who,
    category: who.category,
    where: who.where,
    ageDays,
    why: why.why,
    score: why.score,
    whyFactors: why.factors,
    variants,
    partial,
  };
  composed.set(key, { p, at: Date.now() });
  // A composed miss for the light form also satisfies later light asks.
  if (withVariants) composed.set(`${h}|0`, { p, at: Date.now() });
  return p;
}
