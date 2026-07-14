// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Lazy keyed deep-dives, fired only on popup interaction, never on
// navigation: whisper.explain (the "why"), whisper.identify (who runs it),
// whisper.submit (report), and assess-on-candidates (the only thing that
// upgrades an on-device look-alike nudge to an evidenced verdict; candidate
// generation alone proves nothing).
//
// Explain fields are best-effort by contract: rendered when the graph
// supplies them, omitted when absent, never invented.

import { CANDIDATE_CAP } from "../shared/config";
import type { CandidateVerdict, ExplainResult } from "../shared/types";
import { registrableDomain } from "../shared/psl";
import { generateCandidates } from "../detector/variants";
import { assessHosts } from "./assess";
import { GraphError, graphQuery } from "./graph-client";

function errMessage(e: unknown): string {
  if (e instanceof GraphError) {
    if (e.reason === "nokey") return "sign in to see this";
    if (e.reason === "auth") return "the graph rejected the key; sign in again";
    return "could not reach Whisper; showing on-device checks only";
  }
  return "could not reach Whisper; showing on-device checks only";
}

export async function explainHost(host: string): Promise<ExplainResult> {
  try {
    const rows = await graphQuery("CALL whisper.explain($h)", { h: host });
    return { ok: true, rows, error: null };
  } catch (e) {
    return { ok: false, rows: [], error: errMessage(e) };
  }
}

export async function identifyHost(host: string): Promise<ExplainResult> {
  try {
    const rows = await graphQuery(
      "CALL whisper.identify($h) YIELD host, vendor_id, canonical_name, is_canonical, confidence, category, roles " +
        "RETURN host, vendor_id, canonical_name, is_canonical, confidence, category, roles",
      { h: host },
    );
    return { ok: true, rows, error: null };
  } catch (e) {
    return { ok: false, rows: [], error: errMessage(e) };
  }
}

export async function reportHost(host: string, note: string): Promise<ExplainResult> {
  try {
    const rows = await graphQuery("CALL whisper.submit($a)", {
      a: {
        indicator: host,
        kind: "hostname",
        claim: "phishing-suspect",
        source: "whisper-guard",
        note: note.slice(0, 500),
      },
    });
    return { ok: true, rows, error: null };
  } catch (e) {
    return { ok: false, rows: [], error: errMessage(e) };
  }
}

/**
 * Evidenced look-alike confirmation: generate candidates on-device, assess
 * them in ONE batched graph call, return only the registered candidates the
 * graph actually flags. UNKNOWN candidates are not evidence and are
 * filtered out, not dressed up.
 */
export async function confirmLookalikes(host: string): Promise<CandidateVerdict[]> {
  const reg = registrableDomain(host.toLowerCase());
  if (!reg) return [];
  const candidates = generateCandidates(reg, CANDIDATE_CAP);
  if (candidates.length === 0) return [];
  const verdicts = await assessHosts(candidates);
  const out: CandidateVerdict[] = [];
  for (const [h, v] of verdicts) {
    if (v.band === "CRITICAL" || v.band === "HIGH" || v.band === "MEDIUM") {
      out.push({ host: h, band: v.band, label: v.label });
    }
  }
  out.sort((a, b) => a.host.localeCompare(b.host));
  return out;
}
