// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The pieces of the live gate that can be proved without a browser or a key:
// where its subject comes from, what happens when none can be had, and a
// teardown that is safe whatever setup managed to do.
//
// The gate used to draw its subject from a third-party download, and when
// that download was retired the suite reported "skipped" for every test. A
// release gate that skips is a gate that passed nothing and looked like it
// passed. So the rule here is the one a gate needs: find a subject from a
// source we can reason about, or fail with a message saying exactly what was
// searched. Never skip.

/** Runs one parameterised Cypher read against the graph and returns its rows. */
export type GraphRead = (query: string, parameters: Record<string, unknown>) => Promise<Record<string, unknown>[]>;

/**
 * The feed sources the subject is drawn from, in order. These are the
 * graph's own FEED_SOURCE nodes, not hostnames: the repository names WHERE to
 * look, never WHAT is bad. A listing is only asserted by the graph at the
 * moment of the run.
 */
export const SUBJECT_FEEDS: readonly string[] = [
  "abuse-ch-threatfox-domain",
  "abuse-ch-urlhaus",
  "hagezi-tif-full",
];

export const PAGE_SIZE = 200;
export const MAX_PAGES_PER_FEED = 5;

/**
 * One page of a feed's listed hostnames, in a stable order, assessed in the
 * same query and narrowed to the CRITICAL band. Ordering by name makes the
 * walk deterministic for a given graph generation: the same graph yields the
 * same subject.
 */
export const SUBJECT_QUERY =
  "MATCH (f:FEED_SOURCE {name: $feed})<-[:LISTED_IN]-(h:HOSTNAME) " +
  "WITH h.name AS n ORDER BY n SKIP $skip LIMIT $limit " +
  "WITH collect(n) AS hs " +
  "CALL whisper.assess(hs) YIELD host, label, band, coverage " +
  "WHERE band = 'CRITICAL' " +
  "RETURN host, label, band, coverage ORDER BY host";

/**
 * A hostname the browser can be pointed at and pinned with
 * --host-resolver-rules: lower-case LDH labels, at least one dot, not an
 * address literal. Anything else in a feed (URLs, IPs, wildcards) is passed
 * over rather than guessed at.
 */
export function isUsableHost(h: string): boolean {
  if (h.length === 0 || h.length > 253) return false;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(h)) return false;
  return !/^[0-9.]+$/.test(h);
}

export interface LiveSubject {
  host: string;
  row: Record<string, unknown>;
  feed: string;
}

export class NoLiveSubjectError extends Error {
  constructor(public readonly searched: string[]) {
    super(
      "the live gate found no CRITICAL subject in the graph, so it cannot prove the red plate. " +
        `Searched: ${searched.join("; ")}. This is a FAILURE, not a skip: either the graph ` +
        "stopped rating its own listings CRITICAL (a product question) or the feed names " +
        "in e2e/helpers/live-gate.ts no longer exist (update SUBJECT_FEEDS).",
    );
    this.name = "NoLiveSubjectError";
  }
}

/**
 * Walk the feeds page by page until the graph rates one of its own listed
 * hostnames CRITICAL. A graph error propagates as-is: an unreachable graph is
 * a failed gate, never a reason to stop looking quietly.
 */
export async function pickCriticalSubject(
  read: GraphRead,
  opts: { feeds?: readonly string[]; pageSize?: number; maxPages?: number } = {},
): Promise<LiveSubject> {
  const feeds = opts.feeds ?? SUBJECT_FEEDS;
  const pageSize = opts.pageSize ?? PAGE_SIZE;
  const maxPages = opts.maxPages ?? MAX_PAGES_PER_FEED;
  const searched: string[] = [];
  for (const feed of feeds) {
    let rated = 0;
    let pages = 0;
    for (; pages < maxPages; pages++) {
      const rows = await read(SUBJECT_QUERY, { feed, skip: pages * pageSize, limit: pageSize });
      const usable = rows
        .filter((r) => r["band"] === "CRITICAL" && isUsableHost(String(r["host"] ?? "")))
        .sort((a, b) => String(a["host"]).localeCompare(String(b["host"])));
      rated += rows.length;
      const first = usable[0];
      if (first) return { host: String(first["host"]), row: first, feed };
    }
    searched.push(`${feed} (${pages} page(s) of ${pageSize}, ${rated} CRITICAL row(s), none usable)`);
  }
  throw new NoLiveSubjectError(searched);
}

/**
 * The graph read the live suite uses. Non-2xx and an error body both throw,
 * with the status, so a key or endpoint problem reads as what it is.
 */
export function graphReader(endpoint: string, key: string, fetchImpl: typeof fetch = fetch): GraphRead {
  return async (query, parameters) => {
    const res = await fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", "X-API-Key": key },
      body: JSON.stringify({ query, parameters }),
    });
    if (!res.ok) throw new Error(`the graph answered HTTP ${res.status} to the live gate's subject query`);
    const parsed = (await res.json()) as { rows?: Record<string, unknown>[]; error?: unknown; message?: unknown };
    if (!Array.isArray(parsed.rows)) {
      throw new Error(`the graph returned no rows array: ${String(parsed.error ?? parsed.message ?? "unknown error")}`);
    }
    return parsed.rows;
  };
}

/** Anything with a callback-style close, such as node:http's Server. */
export interface Closable {
  close(cb?: (err?: Error) => void): unknown;
  listening?: boolean;
}

/**
 * Close a server that setup may or may not have created. `server?.close(r)`
 * looks safe and is not: when the server is undefined the optional call is
 * skipped, `r` is never called, and the awaiting promise never settles, so a
 * teardown after a failed setup hangs the run until the global timeout. A
 * server that was created but never listened also never calls back on some
 * runtimes; it is resolved straight away too.
 */
export function closeQuietly(server: Closable | undefined | null): Promise<void> {
  if (!server || server.listening === false) return Promise.resolve();
  return new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
}

/**
 * Whether this process is the release gate itself (`npm run e2e:live`).
 * The gate must fail when it cannot run; an incidental run of every spec
 * from a developer's checkout may skip the key-only suite, and says so.
 */
export function isLiveGate(env: NodeJS.ProcessEnv = process.env): boolean {
  return env["npm_lifecycle_event"] === "e2e:live" || env["WHISPER_GUARD_LIVE_GATE"] === "1";
}
