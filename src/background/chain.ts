// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE CHAIN: the join path behind a name, rung by rung.
//
// One hop is a lookup and every product has one. What no other browser
// extension can draw is the path: a name, to the vendor that runs it, to
// the address it resolves to, to the prefix that address sits in, to the
// network that announces that prefix, to the operator that holds the
// network, to the buildings and exchanges that operator is physically
// present in. Seven rungs, and the reader gets every one of them without
// an account.
//
// Two rounds, because the graph's public tier caps a query at two
// patterns and rungs 4-7 need a value the first round produces:
//
//   round 1  whisper.enrich    owner, country, ASN, prevalence   (deep, server-side)
//            whisper.resolve   the A and AAAA records
//            whisper.identify  the vendor atlas and the roles
//            whisper.history   when the name was first registered
//   round 2  IP  -> ANNOUNCED_PREFIX -> ASN     (two hops, one pattern)
//            IP  -> CITY -> COUNTRY              (two hops, one pattern)
//            ASN -> FACILITY | INTERNET_EXCHANGE (one hop, one pattern)
//
// Seven calls, and they are the ONLY seven the panel spends on infrastructure:
// the composed verdict (background/protect.ts) reads its owner, category,
// location and age straight off this walk rather than asking again. That is
// not only cheaper, it is the reason the panel cannot show a "Who" row that
// disagrees with its own OPERATOR rung.
//
// Every rung distinguishes THREE outcomes and never conflates them: it
// has a value, or the graph answered and holds nothing about it, or the
// call did not come back. An error that renders as an empty state is the
// defect this module is built to refuse, so "unavailable" is a state a
// rung can be in and it says so on screen.

import { graphQuery } from "./graph-client";
import { HISTORY_QUERY } from "../shared/config";
import type { ChainRung, ChainRungKind, RungDetail, SiteChain } from "../shared/types";

const str = (v: unknown): string | null => {
  if (typeof v !== "string") return null;
  const t = v.trim();
  return t === "" ? null : t;
};
const num = (v: unknown): number | null =>
  typeof v === "number" && Number.isFinite(v) ? v : null;

const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.map(str).filter((s): s is string => s !== null) : [];

/** The rung order, top to bottom. Exported so the UI cannot invent one. */
export const RUNG_ORDER: ChainRungKind[] = [
  "name",
  "vendor",
  "address",
  "prefix",
  "network",
  "operator",
  "presence",
];

const RUNG_LABEL: Record<ChainRungKind, string> = {
  name: "NAME",
  vendor: "RUNS ON",
  address: "ADDRESS",
  prefix: "PREFIX",
  network: "NETWORK",
  operator: "OPERATOR",
  presence: "PRESENT AT",
};

/** What the reader is told when the graph answered and held nothing. */
const RUNG_EMPTY: Record<ChainRungKind, string> = {
  name: "no name",
  vendor: "no vendor match",
  address: "no address on record",
  prefix: "not in a routed prefix",
  network: "no announcing network",
  operator: "no registered operator",
  presence: "no recorded presence",
};

function rung(
  kind: ChainRungKind,
  value: string | null,
  fact: string | null,
  state: ChainRung["state"],
  tone: ChainRung["tone"] = "neutral",
  detail: string[] = [],
  drillable = false,
): ChainRung {
  return {
    kind,
    label: RUNG_LABEL[kind],
    value: value ?? (state === "empty" ? RUNG_EMPTY[kind] : null),
    fact,
    state,
    tone,
    detail,
    // Only a rung with a value is worth expanding: there is nothing behind
    // a rung the graph could not answer.
    drillable: drillable && state === "live",
  };
}

/** A rung whose own call did not come back. Never silently blank. */
const lost = (kind: ChainRungKind): ChainRung =>
  rung(kind, "could not be read", null, "unavailable");

// --------------------------------------------------------------- round 1

interface EnrichRow {
  owner: string | null;
  country: string | null;
  asn: string | null;
  prevalence: number | null;
  coverage: string | null;
  ok: boolean;
}

async function fetchEnrich(host: string): Promise<EnrichRow> {
  try {
    const rows = await graphQuery("CALL whisper.enrich($h)", { h: host });
    const r = rows[0];
    if (!r) return { owner: null, country: null, asn: null, prevalence: null, coverage: null, ok: true };
    return {
      owner: str(r["owner"]),
      country: str(r["country"]),
      asn: str(r["asn"]),
      prevalence: num(r["prevalence"]),
      coverage: str(r["coverage"]),
      ok: true,
    };
  } catch {
    return { owner: null, country: null, asn: null, prevalence: null, coverage: null, ok: false };
  }
}

interface ResolveRow {
  a: string[];
  aaaa: string[];
  ok: boolean;
}

async function fetchResolve(host: string): Promise<ResolveRow> {
  try {
    const rows = await graphQuery("CALL whisper.resolve($h)", { h: host });
    const r = rows[0];
    return { a: strList(r?.["a"]), aaaa: strList(r?.["aaaa"]), ok: true };
  } catch {
    return { a: [], aaaa: [], ok: false };
  }
}

interface VendorRow {
  vendor: string | null;
  hostClass: string | null;
  category: string | null;
  roles: string[];
  /** The graph's own join path for the attribution, e.g.
   *  RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:github. */
  evidence: string[];
  confidence: number | null;
  ok: boolean;
}

async function fetchVendor(host: string): Promise<VendorRow> {
  try {
    const rows = await graphQuery("CALL whisper.identify($h)", { h: host });
    const r = rows[0];
    if (!r) return { vendor: null, hostClass: null, category: null, roles: [], evidence: [], confidence: null, ok: true };
    return {
      vendor: str(r["canonical_name"]),
      hostClass: str(r["host_class"]),
      category: str(r["category"]),
      roles: strList(r["roles"]),
      evidence: strList(r["evidence"]),
      confidence: num(r["confidence"]),
      ok: true,
    };
  } catch {
    return { vendor: null, hostClass: null, category: null, roles: [], evidence: [], confidence: null, ok: false };
  }
}

/**
 * When the name was first registered, in days. Many WHOIS snapshots come
 * back; the freshest by update date wins. A name registered days ago is one
 * of the strongest ordinary signals there is, and it belongs on the NAME
 * rung because it is a fact about the name rather than about the verdict.
 */
async function fetchAge(host: string): Promise<{ days: number | null; ok: boolean }> {
  let rows: Record<string, unknown>[];
  try {
    rows = await graphQuery(HISTORY_QUERY, { h: host });
  } catch {
    return { days: null, ok: false };
  }
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
  if (!created) return { days: null, ok: true };
  const t = Date.parse(created);
  if (!Number.isFinite(t)) return { days: null, ok: true };
  return { days: Math.max(0, Math.floor((Date.now() - t) / 86_400_000)), ok: true };
}

/** The age of a name, in the words a reader thinks in. Under a month is
 *  called out, because that is the window where it matters. */
function ageFact(days: number | null): string | null {
  if (days === null) return null;
  if (days < 32) return `registered ${days} day${days === 1 ? "" : "s"} ago`;
  if (days < 366) return `registered ${Math.round(days / 30.4)} months ago`;
  const y = Math.floor(days / 365.25);
  return `registered ${y} year${y === 1 ? "" : "s"} ago`;
}

// --------------------------------------------------------------- round 2

interface RouteRow {
  prefix: string | null;
  threatNeighbors: number | null;
  asn: string | null;
  ok: boolean;
}

/** IP -> ANNOUNCED_PREFIX -> ASN. Two hops, ONE pattern: exactly the
 *  public tier's depth budget, with nothing left over for a second. */
const ROUTE_QUERY =
  "MATCH (ip:IPV4 {name:$ip})-[:ANNOUNCED_BY]->(p:ANNOUNCED_PREFIX)-[:ROUTES]->(a:ASN) " +
  "RETURN p.name AS prefix, p.threatNeighborCount AS threatNeighbors, a.name AS asn LIMIT 1";

async function fetchRoute(ip: string): Promise<RouteRow> {
  try {
    const rows = await graphQuery(ROUTE_QUERY, { ip });
    const r = rows[0];
    if (!r) return { prefix: null, threatNeighbors: null, asn: null, ok: true };
    return {
      prefix: str(r["prefix"]),
      threatNeighbors: num(r["threatNeighbors"]),
      asn: str(r["asn"]),
      ok: true,
    };
  } catch {
    return { prefix: null, threatNeighbors: null, asn: null, ok: false };
  }
}

/** Where the address physically sits. The city is the fact a reader
 *  recognises: "Montreal" means something to a person in a way that
 *  "AS64550" does not, and the two together are the join. */
const PLACE_QUERY =
  "MATCH (ip:IPV4 {name:$ip})-[:LOCATED_IN]->(c:CITY) " +
  "OPTIONAL MATCH (c)-[:HAS_COUNTRY]->(cc:COUNTRY) " +
  "RETURN c.name AS city, cc.name AS country LIMIT 1";

async function fetchPlace(ip: string): Promise<{ city: string | null; country: string | null; ok: boolean }> {
  try {
    const rows = await graphQuery(PLACE_QUERY, { ip });
    const r = rows[0];
    return { city: str(r?.["city"]), country: str(r?.["country"]), ok: true };
  } catch {
    return { city: null, country: null, ok: false };
  }
}

interface PresenceRow {
  facilities: number;
  ixps: number;
  facilitySample: string[];
  ixSample: string[];
  ok: boolean;
}

/** ASN -> FACILITY and ASN -> INTERNET_EXCHANGE in ONE pattern, via a
 *  relationship-type union. Two separate OPTIONAL MATCHes would be two
 *  patterns on top of the anchor and the public tier refuses that. */
const PRESENCE_QUERY =
  "MATCH (a:ASN {name:$a})-[r:AS_PRESENT_AT|IX_MEMBER]->(x) " +
  "WITH type(r) AS t, x.name AS nm " +
  "RETURN t, count(*) AS n, collect(nm)[0..3] AS sample";

async function fetchPresence(asn: string): Promise<PresenceRow> {
  try {
    const rows = await graphQuery(PRESENCE_QUERY, { a: asn });
    const out: PresenceRow = { facilities: 0, ixps: 0, facilitySample: [], ixSample: [], ok: true };
    for (const r of rows) {
      const t = str(r["t"]);
      const n = num(r["n"]) ?? 0;
      const sample = strList(r["sample"]);
      if (t === "AS_PRESENT_AT") {
        out.facilities = n;
        out.facilitySample = sample;
      } else if (t === "IX_MEMBER") {
        out.ixps = n;
        out.ixSample = sample;
      }
    }
    return out;
  } catch {
    return { facilities: 0, ixps: 0, facilitySample: [], ixSample: [], ok: false };
  }
}

// ------------------------------------------------------------- composition

const plural = (n: number, one: string, many = `${one}s`): string =>
  `${n} ${n === 1 ? one : many}`;

/** Popularity rank, spoken the way a reader thinks about it. LOWER is more
 *  prevalent (it is a rank, not a score), which is exactly the trap, so the
 *  word "rank" is always attached. */
function prevalenceFact(prevalence: number | null): string | null {
  if (prevalence === null) return null;
  if (prevalence <= 0) return null;
  if (prevalence <= 1000) return `top-1k rank ${prevalence}`;
  if (prevalence <= 100_000) return `rank ${prevalence.toLocaleString("en")}`;
  return "ranked, outside the top 100k";
}

/**
 * Build the chain for one hostname. Never throws: a rung whose call fails
 * comes back as "unavailable" and the rest of the spine still renders.
 */
export async function buildChain(host: string): Promise<SiteChain> {
  const h = host.toLowerCase();

  const [enrich, resolved, vendor, age] = await Promise.all([
    fetchEnrich(h),
    fetchResolve(h),
    fetchVendor(h),
    fetchAge(h),
  ]);

  const primaryIp = resolved.a[0] ?? resolved.aaaa[0] ?? null;

  // Round 2 needs round 1's outputs. The ASN can come from enrich (which
  // walks it server-side) and is confirmed by the route read; either alone
  // is enough to draw the network rung.
  const noRoute: RouteRow = { prefix: null, threatNeighbors: null, asn: null, ok: true };
  const noPresence: PresenceRow = { facilities: 0, ixps: 0, facilitySample: [], ixSample: [], ok: true };
  const noPlace = { city: null, country: null, ok: true };
  const routable = primaryIp !== null && resolved.a.length > 0;
  const [route, place, presence] = await Promise.all([
    routable ? fetchRoute(primaryIp) : Promise.resolve(noRoute),
    routable ? fetchPlace(primaryIp) : Promise.resolve(noPlace),
    enrich.asn ? fetchPresence(enrich.asn) : Promise.resolve(noPresence),
  ]);

  const rungs: ChainRung[] = [];

  // 1. NAME. Always known: it is the name in the address bar. What is not
  //    always known is how long it has existed, and a name registered days
  //    ago deserves suspicion no feed has caught up with yet.
  rungs.push(
    rung(
      "name",
      h,
      ageFact(age.days),
      "live",
      age.days !== null && age.days < 32 ? "warn" : "neutral",
    ),
  );

  // 2. RUNS ON. The vendor atlas match, with the roles the graph observed.
  if (!vendor.ok) {
    rungs.push(lost("vendor"));
  } else if (vendor.vendor) {
    // What KIND of thing it is, then how sure the graph is. The kind is the
    // fact a reader uses; the confidence is the fact that keeps the kind
    // honest, and both fit where two separate rows did not.
    const bits: string[] = [];
    // "unresolved" is the graph's word for "not classified", and printing it
    // as the KIND of thing a site is turns an absence into a label. The rung
    // says nothing rather than saying nothing loudly.
    if (vendor.category && vendor.category !== "unresolved" && vendor.category !== "unknown") {
      bits.push(vendor.category.replace(/_/g, " "));
    }
    if (vendor.confidence !== null) bits.push(`${Math.round(vendor.confidence * 100)}% sure`);
    // The roles the graph observed this name playing, and its own words for
    // how it made the match. Both came back with the walk.
    const vd: string[] = [];
    if (vendor.roles.length > 0) {
      vd.push(`observed as ${vendor.roles.map((r) => r.toLowerCase().replace(/_/g, " ")).join(", ")}`);
    }
    if (vendor.hostClass) vd.push(`host class ${vendor.hostClass.replace(/_/g, " ")}`);
    for (const e of vendor.evidence.filter((x) => x.includes("->")).slice(0, 2)) vd.push(e);
    rungs.push(rung("vendor", vendor.vendor, bits.join(" · ") || null, "live", "neutral", vd));
  } else {
    const raw = vendor.category === "unresolved" || vendor.category === "unknown" ? null : vendor.category;
    const kind = raw ?? vendor.hostClass;
    rungs.push(rung("vendor", null, kind ? kind.replace(/_/g, " ") : null, "empty"));
  }

  // 3. ADDRESS. What it actually resolves to, and how many.
  if (!resolved.ok) {
    rungs.push(lost("address"));
  } else if (primaryIp) {
    // The city is what a person recognises. The record counts are what an
    // engineer wants. The rung carries the recognisable one and keeps the
    // counts for the title, because 400 pixels is 400 pixels.
    const counts: string[] = [];
    if (resolved.a.length > 0) counts.push(plural(resolved.a.length, "A record"));
    if (resolved.aaaa.length > 0) counts.push(plural(resolved.aaaa.length, "AAAA"));
    const fact = place.city ?? (counts.join(" · ") || null);
    // Every address the name answers on, not only the representative one.
    const ad: string[] = [];
    if (counts.length > 0) ad.push(counts.join(" · "));
    for (const a of resolved.a.slice(0, 6)) ad.push(a);
    for (const a of resolved.aaaa.slice(0, 4)) ad.push(a);
    if (place.city && place.country) ad.push(`${place.city} (${place.country})`);
    rungs.push(rung("address", primaryIp, fact, "live", "neutral", ad, true));
  } else {
    rungs.push(rung("address", null, null, "empty"));
  }

  // 4. PREFIX. The routed block, and how many flagged neighbours share it.
  //    A prefix full of listed addresses is a real signal about a name that
  //    is otherwise unremarkable, and it is only visible by joining.
  if (!route.ok) {
    rungs.push(lost("prefix"));
  } else if (route.prefix) {
    const tn = route.threatNeighbors;
    const fact =
      tn === null ? null : tn === 0 ? "no flagged neighbours" : plural(tn, "flagged neighbour");
    const tone: ChainRung["tone"] = tn === null || tn === 0 ? "neutral" : tn >= 8 ? "hot" : "warn";
    rungs.push(rung("prefix", route.prefix, fact, "live", tone, [], true));
  } else {
    rungs.push(rung("prefix", null, null, "empty"));
  }

  // 5. NETWORK. The autonomous system that announces it.
  const asn = enrich.asn ?? route.asn;
  if (!enrich.ok && !route.ok) {
    rungs.push(lost("network"));
  } else if (asn) {
    rungs.push(rung("network", asn, prevalenceFact(enrich.prevalence), "live", "neutral", [], true));
  } else {
    rungs.push(rung("network", null, null, "empty"));
  }

  // 6. OPERATOR. Who holds that network, and where it is registered. A
  //    network attribution, never a threat attribution, and the copy says so.
  if (!enrich.ok) {
    rungs.push(lost("operator"));
  } else if (enrich.owner) {
    rungs.push(rung("operator", enrich.owner, enrich.country ?? place.country, "live"));
  } else {
    rungs.push(rung("operator", null, enrich.country ?? place.country, "empty"));
  }

  // 7. PRESENT AT. The physical layer: the buildings and the exchanges.
  //    This is the rung that ends the argument about who else can do this.
  if (!presence.ok) {
    rungs.push(lost("presence"));
  } else if (presence.facilities > 0 || presence.ixps > 0) {
    const lead = presence.facilitySample[0] ?? presence.ixSample[0] ?? null;
    const bits: string[] = [];
    if (presence.facilities > 0) bits.push(plural(presence.facilities, "facility", "facilities"));
    if (presence.ixps > 0) bits.push(plural(presence.ixps, "exchange"));
    // The buildings and the exchanges by name. This is the rung that ends
    // the argument about who else can draw this, so it is worth expanding.
    const pd: string[] = [];
    for (const f of presence.facilitySample) pd.push(f);
    for (const x of presence.ixSample) pd.push(`${x} (exchange)`);
    rungs.push(rung("presence", lead, bits.join(" · ") || null, "live", "neutral", pd));
  } else {
    rungs.push(rung("presence", null, null, "empty"));
  }

  const live = rungs.filter((r) => r.state === "live").length;
  const unavailable = rungs.filter((r) => r.state === "unavailable").length;

  return {
    host: h,
    rungs,
    live,
    unavailable,
    // The graph's own words for how it made the vendor attribution.
    evidence: vendor.evidence,
    facilities: presence.facilitySample,
    exchanges: presence.ixSample,
    // The same facts in structured form. The composed verdict reads these
    // rather than asking the graph again, which is both cheaper and the
    // reason a "Who" row can never disagree with the OPERATOR rung.
    owner: enrich.owner,
    country: enrich.country ?? place.country,
    city: place.city,
    asn,
    asnOk: enrich.ok,
    ip: primaryIp,
    vendor: vendor.vendor,
    vendorCategory: vendor.hostClass,
    identifyCategory: vendor.category,
    roles: vendor.roles,
    ageDays: age.days,
    prefix: route.prefix,
    threatNeighbors: route.threatNeighbors,
    at: Date.now(),
  };
}

// ------------------------------------------------------------ the drill
//
// What is behind ONE rung, fetched only when a reader expands it.
//
// Deliberately lazy. The public tier allows a hundred graph calls an hour
// from one address and the walk already spends seven of them, so a reader
// who never expands a rung must never pay for one. The two rungs that can
// say more are the ones where the extra call buys a fact nothing else on
// the panel carries.

/** How much of a network's announced space is actually listed. A ratio,
 *  not a verdict: a huge clean network and a tiny dirty one look nothing
 *  alike, and only this call can tell them apart. */
const DENSITY_QUERY = "CALL whisper.asnThreatDensity($a)";

/** How many other names answer on this address. One pattern, one hop:
 *  exactly what the public tier allows, and the single strongest thing you
 *  can say about a name on shared hosting. */
const COHOST_KEYLESS_QUERY =
  "MATCH (ip:IPV4 {name:$ip})<-[:RESOLVES_TO]-(other:HOSTNAME) " +
  "RETURN count(DISTINCT other) AS cohosted";

export async function rungDetail(host: string, kind: ChainRungKind): Promise<RungDetail> {
  const chain = await buildChain(host);
  const empty: RungDetail = { kind, lines: [], ratio: null, error: null };

  if (kind === "network") {
    if (!chain.asn) return { ...empty, error: "no announcing network to look up" };
    let rows: Record<string, unknown>[];
    try {
      rows = await graphQuery(DENSITY_QUERY, { a: chain.asn });
    } catch {
      return { ...empty, error: "the network read did not come back" };
    }
    const r = rows[0];
    if (!r) {
      // The procedure answered and holds nothing for this ASN. Different
      // from the call failing, and said differently.
      return { ...empty, lines: [`The graph holds no measured density for ${chain.asn}.`] };
    }
    const listed = num(r["listedIps"]);
    const announced = num(r["announcedIpv4"]);
    const prefixes = num(r["routedPrefixes"]);
    const lines: string[] = [];
    if (prefixes !== null) lines.push(`${plural(prefixes, "prefix", "prefixes")} routed`);
    if (listed !== null && announced !== null && announced > 0) {
      const pct = (listed / announced) * 100;
      lines.push(
        `${listed.toLocaleString("en")} listed of ${announced.toLocaleString("en")} announced addresses ` +
          `(${pct < 0.01 ? "under 0.01" : pct.toFixed(2)}%)`,
      );
    }
    return {
      kind,
      lines,
      ratio:
        listed !== null && announced !== null && announced > 0
          ? { label: "listed addresses in this network", part: listed, whole: announced }
          : null,
      error: null,
    };
  }

  if (kind === "prefix" || kind === "address") {
    if (!chain.ip) return { ...empty, error: "no address to look up" };
    let rows: Record<string, unknown>[];
    try {
      rows = await graphQuery(COHOST_KEYLESS_QUERY, { ip: chain.ip });
    } catch {
      return { ...empty, error: "the co-hosting read did not come back" };
    }
    const cohosted = num(rows[0]?.["cohosted"]) ?? 0;
    const lines = [
      cohosted === 0
        ? `No other name in the graph answers on ${chain.ip}.`
        : `${cohosted.toLocaleString("en")} other name${cohosted === 1 ? "" : "s"} answer on ${chain.ip}.`,
    ];
    if (chain.threatNeighbors !== null && chain.prefix) {
      lines.push(
        chain.threatNeighbors === 0
          ? `Nothing in ${chain.prefix} is listed.`
          : `${plural(chain.threatNeighbors, "address")} in ${chain.prefix} ${chain.threatNeighbors === 1 ? "is" : "are"} listed as a threat.`,
      );
    }
    return { kind, lines, ratio: null, error: null };
  }

  // Every other rung's detail came back with the walk itself.
  const r = chain.rungs.find((x) => x.kind === kind);
  return { kind, lines: r?.detail ?? [], ratio: null, error: null };
}
