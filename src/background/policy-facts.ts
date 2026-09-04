// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The read behind the policy preview: for a page of destinations, the ONE
// fact each named protection keys on, in a single keyed graph call.
//
// The contract this file exists to keep is the one the last round found
// broken elsewhere in this product: A FAILED READ MUST NOT LOOK LIKE A CLEAN
// ANSWER. Every path here reports which hosts were actually answered for.
// A transport fault sets `error` and leaves `byHost` empty, so the preview
// counts every destination as unknown; a clean answer that simply had no row
// for a name puts that name in `unread`, which the preview also counts as
// unknown. Nothing in this module can turn "we did not find out" into "there
// is nothing there".

import {
  POLICY_BULLETPROOF_QUERY,
  POLICY_FACTS_BATCH,
  POLICY_FACTS_QUERY,
  POLICY_FACTS_TTL_MS,
} from "../shared/config";
import type { HostPolicyFacts, PolicyFactSet } from "../shared/policy-preview";
import { graphQuery, hasKey } from "./graph-client";

/**
 * `facts: null` is a REAL answer, not a miss: the graph was asked and holds
 * no record of that name at all. It is cached so a page of never-seen
 * destinations does not re-ask on every render, and it is kept distinct from
 * a row of all-false facts, because "the graph has never heard of this name"
 * and "the graph knows this name and nothing is wrong with it" are different
 * facts and only the second one is evidence of anything.
 */
interface Cached {
  facts: HostPolicyFacts | null;
  at: number;
}

const cache = new Map<string, Cached>();

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);
const bool = (v: unknown): boolean => v === true || v === "true";
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : [];

function shape(host: string, row: Record<string, unknown>): HostPolicyFacts {
  return {
    host,
    band: str(row["band"]),
    sanctioned: bool(row["sanctioned"]),
    tor: bool(row["tor"]),
    rpkiReason: str(row["rpkiReason"]),
    bulletproofMarker: null, // filled from the assess leg below
    countries: strList(row["countries"]).map((c) => c.trim().toUpperCase()).filter(Boolean),
  };
}

/**
 * The bulletproof marker, decided exactly as the resolver decides it: the
 * word "bulletproof", case-insensitively, in the assess verdict's band,
 * label or sub_labels. Returns the matching string so the surface can quote
 * the graph's own word rather than paraphrasing it.
 */
function bulletproofMarker(row: Record<string, unknown>): string | null {
  const candidates = [str(row["band"]), str(row["label"]), ...strList(row["sub_labels"])];
  for (const c of candidates) {
    if (c && c.toLowerCase().includes("bulletproof")) return c;
  }
  return null;
}

/**
 * Read the protection facts for a destination list.
 *
 * Keyed only, and it says so rather than half-answering: the walk is three
 * hops (name -> address -> announcing prefix -> network) and the public tier
 * caps a raw query at two, so a keyless attempt would come back empty and be
 * indistinguishable from "none of these destinations match anything".
 */
export async function policyFacts(hosts: string[]): Promise<PolicyFactSet> {
  const wanted = [...new Set(hosts.map((h) => h.replace(/\.$/, "").toLowerCase()).filter(Boolean))];
  if (wanted.length === 0) return { byHost: {}, unread: [], error: null };

  if (!(await hasKey())) {
    return {
      byHost: {},
      unread: wanted,
      error: "these checks need an account: the walk behind them is deeper than the public tier allows",
    };
  }

  const now = Date.now();
  const byHost: Record<string, HostPolicyFacts> = {};
  const misses: string[] = [];
  for (const h of wanted) {
    const hit = cache.get(h);
    if (!hit || now - hit.at >= POLICY_FACTS_TTL_MS) misses.push(h);
    else if (hit.facts) byHost[h] = hit.facts;
    // hit.facts === null: answered, no record. Left out of byHost on
    // purpose, so it lands in `unread` and is counted as unknown exactly
    // as it was on the request that first discovered it.
  }

  // Every batch is attempted; a batch that faults marks ONLY its own hosts
  // unknown, so one bad slice never erases the answers the others returned.
  let error: string | null = null;
  for (let i = 0; i < misses.length; i += POLICY_FACTS_BATCH) {
    const batch = misses.slice(i, i + POLICY_FACTS_BATCH);
    let rows: Record<string, unknown>[];
    let assessRows: Record<string, unknown>[];
    try {
      // Two legs, one round trip's worth of latency. The property read
      // answers four protections; the assess call answers bulletproof,
      // because that is the procedure the resolver itself asks and a
      // different signal here would be a second opinion wearing the
      // clothes of the first.
      [rows, assessRows] = await Promise.all([
        graphQuery(POLICY_FACTS_QUERY, { hosts: batch }),
        graphQuery(POLICY_BULLETPROOF_QUERY, { hs: batch }),
      ]);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      continue;
    }
    const markers = new Map<string, string>();
    for (const row of assessRows) {
      const host = str(row["host"])?.toLowerCase();
      const marker = bulletproofMarker(row);
      if (host && marker) markers.set(host, marker);
    }
    const seen = new Set<string>();
    for (const row of rows) {
      const host = str(row["host"])?.toLowerCase();
      if (!host) continue;
      const facts = { ...shape(host, row), bulletproofMarker: markers.get(host) ?? null };
      cache.set(host, { facts, at: now });
      byHost[host] = facts;
      seen.add(host);
    }
    // This batch came back cleanly, so every name in it WAS asked about.
    // The ones with no row are recorded as "no record" - cached so a page of
    // never-seen destinations stops re-asking, and still reported as unknown
    // rather than as clean.
    for (const h of batch) {
      if (!seen.has(h)) cache.set(h, { facts: null, at: now });
    }
  }

  const unread = wanted.filter((h) => !(h in byHost));
  return { byHost, unread, error };
}

/** Drop everything (sign-out): protection facts are account-scoped reads. */
export function clearPolicyFacts(): void {
  cache.clear();
}
