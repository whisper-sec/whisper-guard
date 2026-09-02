// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The composed site verdict: ONE reconciled picture per hostname, reused by
// the icon, the popup site card, the on-page banner and the warning page.
//
//   band/gate   whisper.assess (the reconciled engine verdict; the ONLY
//               thing that blocks; popularity listings can never flag)
//   who/where/  read straight off THE CHAIN (background/chain.ts), the one
//   age/cat     walk that already joined the name to its vendor, its
//               address, its prefix, its network, its operator and its
//               registration date. Asking the graph those questions a
//               second time cost calls out of a budget that is a real
//               number, and let the panel's "Who" row disagree with its
//               own OPERATOR rung. It now cannot: there is one walk.
//   why         whisper.explain, feed-cited, popularity feeds excluded
//   variants    whisper.variants (exists-only): registered look-alikes of
//               this name, confirmed against assess before they are shown
//
// Every part fails open independently: a slow graph never blocks browsing
// and a missing part renders as absent, never invented.

import { decide } from "../shared/escalation";
import { VARIANTS_QUERY } from "../shared/config";
import type { AssessVerdict, CandidateVerdict, GraphBand, Protection, WhyFactor } from "../shared/types";
import { inferCategory, isPopularityFeed, resolveOwnerLabel } from "../shared/report";
import { assessHost, assessHosts } from "./assess";
import { chainFor } from "./chain-cache";
import { cacheGet, cachePut } from "./cache";
import { graphQuery } from "./graph-client";

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

/** The block/warn gate: the calm ladder's blocking rung: CRITICAL /
 *  HIGH bands or an explicit malicious label, decided in ONE place. */
export function isBlocking(verdict: AssessVerdict | null): boolean {
  if (!verdict) return false;
  return decide({ band: verdict.band, label: verdict.label }, "page") === "blocking";
}

/** Assess with the shared cache (the same rows the nav pipeline painted). */
async function assessCached(host: string): Promise<AssessVerdict> {
  const cached = await cacheGet(host);
  if (cached) return cached;
  const v = await assessHost(host);
  await cachePut(v);
  return v;
}

/**
 * Who runs it, what kind of thing it is, and where its network is
 * registered - read off the ONE chain walk rather than re-asked. The
 * fields the chain could not read stay null, and the caller marks the
 * picture partial, so "we did not read it" never renders as "there is
 * none".
 */
async function fetchWho(host: string): Promise<{
  who: string | null;
  category: string | null;
  where: Protection["where"];
  ageDays: number | null;
  ok: boolean;
}> {
  const chain = await chainFor(host);
  const who = resolveOwnerLabel(chain.owner ?? undefined, chain.vendor ?? undefined, host);
  const category = inferCategory({
    host,
    identifyCategory: chain.identifyCategory ?? undefined,
    identifyRoles: chain.roles,
    owner: who,
    org: chain.owner ?? undefined,
  });
  const where =
    chain.city || chain.country || chain.ip
      ? { city: chain.city, country: chain.country, ip: chain.ip }
      : null;
  return { who, category, where, ageDays: chain.ageDays, ok: chain.unavailable === 0 };
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

  const [who, why, variants] = await Promise.all([
    fetchWho(h).catch(() => {
      partial = true;
      return { who: null, category: null, where: null, ageDays: null, ok: false };
    }),
    fetchWhy(h).catch((): WhyPicture => {
      partial = true;
      return { why: [], score: null, factors: [] };
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

  if (!who.ok) partial = true;

  const p: Protection = {
    host: h,
    band: verdict.band,
    blocking: isBlocking(verdict),
    label: verdict.label,
    coverage: verdict.coverage,
    who: who.who,
    category: who.category,
    where: who.where,
    ageDays: who.ageDays,
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
