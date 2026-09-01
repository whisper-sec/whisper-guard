// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// whisper.assess over the graph client: the same public contract the
// Whisper platform exposes. One host or a batch of hosts; a present,
// host-matched row with a blank band is a no-data row and normalizes to
// UNKNOWN (a success, not an error). We never act on a verdict for a host
// we did not ask about.

import { ASSESS_QUERY } from "../shared/config";
import type { AssessVerdict, GraphBand } from "../shared/types";
import { graphQuery } from "./graph-client";

const BANDS: ReadonlySet<string> = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
  "NONE",
  "UNKNOWN",
]);

export function normalizeBand(raw: unknown): GraphBand {
  if (typeof raw !== "string") return "UNKNOWN";
  const b = raw.trim().toUpperCase();
  return (BANDS.has(b) ? b : "UNKNOWN") as GraphBand;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

/** Assess a batch of hostnames in one graph call. */
export async function assessHosts(
  hosts: string[],
  opts: { keyless?: boolean; timeoutMs?: number } = {},
): Promise<Map<string, AssessVerdict>> {
  const out = new Map<string, AssessVerdict>();
  if (hosts.length === 0) return out;
  const rows = await graphQuery(ASSESS_QUERY, { hs: hosts }, opts.timeoutMs, {
    keyless: opts.keyless ?? false,
  });
  const asked = new Set(hosts.map((h) => h.toLowerCase()));
  const now = Date.now();
  for (const row of rows) {
    const host = str(row["host"])?.toLowerCase();
    if (!host || !asked.has(host)) continue;
    out.set(host, {
      host,
      band: normalizeBand(row["band"]),
      coverage: str(row["coverage"]),
      label: str(row["label"]),
      at: now,
    });
  }
  return out;
}

/** Assess one hostname. A missing row degrades to UNKNOWN (fail open). */
export async function assessHost(host: string): Promise<AssessVerdict> {
  const map = await assessHosts([host]);
  return (
    map.get(host.toLowerCase()) ?? {
      host: host.toLowerCase(),
      band: "UNKNOWN",
      coverage: "no-data",
      label: null,
      at: Date.now(),
    }
  );
}

/**
 * Assess one hostname KEYLESS on a tight budget: the pre-emptive click
 * check. Public tier only, so nothing account-bound ever rides
 * along with a click's target hostname; a missing row is UNKNOWN.
 */
export async function assessHostKeyless(host: string, timeoutMs: number): Promise<AssessVerdict> {
  const map = await assessHosts([host], { keyless: true, timeoutMs });
  return (
    map.get(host.toLowerCase()) ?? {
      host: host.toLowerCase(),
      band: "UNKNOWN",
      coverage: "no-data",
      label: null,
      at: Date.now(),
    }
  );
}
