// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The single network client for the Whisper graph. Every request is a
// POST { query, parameters } to graph.whisper.security/api/query, with the
// user's key as X-API-Key when one exists. The public tier (assess,
// identify, explain, variants, history, shallow enrichment) answers
// keyless; the key unlocks the control plane and deep traversals. The ONLY
// caller-controlled value on the wire is a bound Cypher parameter, never
// string-concatenated; the only browsing datum that ever appears in a
// parameter is a hostname.
//
// Response parsing is liberal (rows as objects keyed by column), errors are
// typed and helpful, and the body read is size-capped.

import { GRAPH_MAX_RESPONSE_BYTES, GRAPH_QUERY_URL, GRAPH_TIMEOUT_MS } from "../shared/config";

export class GraphError extends Error {
  constructor(
    public readonly reason: "auth" | "timeout" | "connect" | "server" | "parse" | "nokey",
    message: string,
  ) {
    super(message);
    this.name = "GraphError";
  }
}

export async function getKey(): Promise<string | null> {
  const stored = await chrome.storage.local.get("apiKey");
  const key = stored["apiKey"];
  return typeof key === "string" && key.trim() !== "" ? key.trim() : null;
}

export async function hasKey(): Promise<boolean> {
  return (await getKey()) !== null;
}

/**
 * Run one graph query, keyless or keyed (the key rides along when the user
 * has one). Returns the rows (array of column-keyed objects). Throws a
 * typed GraphError on any fault so callers can fail open.
 */
export async function graphQuery(
  query: string,
  parameters: Record<string, unknown>,
  timeoutMs = GRAPH_TIMEOUT_MS,
): Promise<Record<string, unknown>[]> {
  const key = await getKey();

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(GRAPH_QUERY_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        ...(key ? { "X-API-Key": key } : {}),
      },
      body: JSON.stringify({ query, parameters, timeout: timeoutMs }),
      signal: ctl.signal,
    });
  } catch (e) {
    throw new GraphError(
      ctl.signal.aborted ? "timeout" : "connect",
      ctl.signal.aborted ? "the graph took too long to answer" : `could not reach the graph: ${String(e)}`,
    );
  } finally {
    clearTimeout(timer);
  }

  if (res.status === 401 || res.status === 403) {
    throw new GraphError("auth", "the graph rejected the key; sign in again");
  }
  if (res.status >= 500) throw new GraphError("server", `graph server error: ${res.status}`);
  if (!res.ok) throw new GraphError("server", `graph unexpected status: ${res.status}`);

  const text = await res.text();
  if (text.length > GRAPH_MAX_RESPONSE_BYTES) {
    throw new GraphError("parse", "graph response too large");
  }
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    throw new GraphError("parse", "graph response was not JSON");
  }

  // Liberal-accept the row shape: { rows: [...] } is the production form;
  // a bare array or { data: [...] } are tolerated.
  const rows =
    root && typeof root === "object" && Array.isArray((root as Record<string, unknown>)["rows"])
      ? ((root as Record<string, unknown>)["rows"] as unknown[])
      : Array.isArray(root)
        ? root
        : root && typeof root === "object" && Array.isArray((root as Record<string, unknown>)["data"])
          ? ((root as Record<string, unknown>)["data"] as unknown[])
          : null;
  if (rows === null) throw new GraphError("parse", "graph response had no rows");
  return rows.filter((r): r is Record<string, unknown> => r !== null && typeof r === "object");
}
