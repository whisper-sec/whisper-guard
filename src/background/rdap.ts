// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The keyless public identity checks: rdap.whisper.online. IP literals of
// endpoints the user already sees (their own fleet, their own egress
// identity) are the ONLY thing ever sent here; browsing hostnames never
// touch this endpoint.

import { RDAP_BASE } from "../shared/config";
import type { IdentityVerification } from "../shared/types";

const TIMEOUT_MS = 5000;

async function getJson(url: string): Promise<Record<string, unknown> | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { accept: "application/json" } });
    const parsed: unknown = await res.json();
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const boolOrNull = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

/**
 * Verify whether an address is a Whisper endpoint identity (keyless).
 * Honest at both poles: is_whisper_agent false is a real answer, and a
 * network fault returns null so callers render "could not verify", never
 * a fake negative.
 */
export async function verifyIdentity(ip: string): Promise<IdentityVerification | null> {
  const body = await getJson(`${RDAP_BASE}/verify-identity?ip=${encodeURIComponent(ip)}`);
  if (!body) return null;
  const evidence =
    body["evidence"] && typeof body["evidence"] === "object"
      ? (body["evidence"] as Record<string, unknown>)
      : {};
  return {
    isWhisperAgent: body["is_whisper_agent"] === true,
    fqdn: str(body["fqdn"]),
    daneOk: boolOrNull(body["dane_ok"]),
    jwsOk: boolOrNull(body["jws_ok"]),
    posture: str(evidence["posture"]),
    detail: str(body["detail"]),
  };
}

/** The public RDAP registration URL for a /128 (the provenance link). */
export function rdapIpUrl(ip: string): string {
  return `${RDAP_BASE}/ip/${ip}`;
}
