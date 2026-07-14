// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The keyed fleet layer: roster (op:list), per-endpoint counters
// (op:agent) and activity (op:logs), merged per-device with individual
// fail-open so one silent endpoint never darkens the fleet view.

import { FLEET_DEVICE_CAP, FLEET_HOST_CAP, FLEET_LOGS_LIMIT } from "../shared/config";
import type { ActivityRow, EndpointCounters, FleetEndpoint } from "../shared/types";
import { controlCall } from "./control";
import type { NavEntry } from "./navlog";

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The caller's registered endpoints (devices and agents alike). */
export async function listEndpoints(): Promise<FleetEndpoint[]> {
  const res = await controlCall("list", { kind: "agents" });
  const out: FleetEndpoint[] = [];
  for (const row of res.rows) {
    const item = row["item"];
    if (!isObject(item)) continue;
    const agent = str(item["agent"]);
    const address = str(item["address"]);
    if (!agent || !address) continue;
    out.push({
      agent,
      address,
      label: str(item["label"]) ?? agent,
      fqdn: str(item["fqdn"]),
      device: item["device"] === true || item["device"] === "true",
      created: num(item["created"]),
      state: str(item["state"]) ?? "unknown",
    });
  }
  // Newest first; devices surface naturally with their labels.
  out.sort((a, b) => (b.created ?? 0) - (a.created ?? 0));
  return out;
}

/** Live + warm counters for one endpoint. */
export async function endpointCounters(agent: string): Promise<EndpointCounters> {
  const res = await controlCall("agent", { agent });
  const row = res.rows[0] ?? {};
  return {
    lastSeen: num(row["last_seen"]),
    dnsQueries: num(row["dns_queries"]),
    dnsBlocked: num(row["dns_blocked"]),
    dnsNxdomain: num(row["dns_nxdomain"]),
    connectionsTotal: num(row["connections_total"]),
    bytesUp: num(row["bytes_up"]),
    bytesDown: num(row["bytes_down"]),
  };
}

function toActivityRow(row: Record<string, unknown>): ActivityRow | null {
  const ts = num(row["ts"]);
  const kind = str(row["kind"]);
  if (ts === null || !kind) return null;
  const qname = str(row["qname"]);
  const peer = str(row["peer"]);
  const target = (kind === "dns" ? qname : (peer ?? qname)) ?? "";
  if (target === "") return null;
  return {
    ts,
    kind,
    agent: str(row["agent"]) ?? "",
    target: target.replace(/\.$/, "").toLowerCase(),
    qtype: str(row["qtype"]),
    decision: str(row["decision"]),
    bytesUp: num(row["bytes_up"]),
    bytesDown: num(row["bytes_down"]),
  };
}

/** Recent activity for one endpoint (dns + conn), newest first. */
export async function endpointLogs(
  agent: string,
  since = "-24h",
  limit = FLEET_LOGS_LIMIT,
): Promise<ActivityRow[]> {
  const res = await controlCall("logs", { agent, since, limit });
  const out: ActivityRow[] = [];
  for (const row of res.rows) {
    const a = toActivityRow(row);
    if (a) out.push(a);
  }
  out.sort((a, b) => b.ts - a.ts);
  return out;
}

export interface FleetActivity {
  endpoints: FleetEndpoint[];
  /** Merged busiest destinations across the fleet (window = 24h). */
  destinations: NavEntry[];
  /** Newest merged activity rows (for the ledger). */
  recent: ActivityRow[];
  /** Endpoints whose log pull failed (shown honestly, not hidden). */
  silent: string[];
}

/**
 * The whole fleet's last-24h picture: roster, then per-device logs in
 * parallel (each fail-open), merged into busiest destinations capped to
 * the view's budget.
 */
export async function fleetActivity(): Promise<FleetActivity> {
  const endpoints = await listEndpoints();
  const polled = endpoints.slice(0, FLEET_DEVICE_CAP);
  const silent: string[] = [];
  const results = await Promise.all(
    polled.map((e) =>
      endpointLogs(e.agent).catch(() => {
        silent.push(e.agent);
        return [] as ActivityRow[];
      }),
    ),
  );

  const byHost = new Map<string, { q: number; lastAt: number }>();
  const recent: ActivityRow[] = [];
  for (const rows of results) {
    for (const r of rows) {
      recent.push(r);
      const cur = byHost.get(r.target) ?? { q: 0, lastAt: 0 };
      cur.q += 1;
      if (r.ts > cur.lastAt) cur.lastAt = r.ts;
      byHost.set(r.target, cur);
    }
  }
  recent.sort((a, b) => b.ts - a.ts);
  const destinations = [...byHost.entries()]
    .map(([host, v]) => ({ host, q: v.q, lastAt: v.lastAt }))
    .sort((a, b) => b.q - a.q || b.lastAt - a.lastAt)
    .slice(0, FLEET_HOST_CAP);

  return { endpoints, destinations, recent: recent.slice(0, 300), silent };
}
