// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The full-tab dashboard: three views over one component set.
//
//   This browser  keyless keystone. On-device destinations, graph-enriched;
//                 genuinely realtime (a background port nudges us per
//                 committed navigation).
//   Fleet         keyed. Roster + merged last-24h activity of every
//                 endpoint, same panels; the feed is honest POLLING and
//                 says so ("updated Ns ago").
//   Endpoint      keyed. Counters, explainable identity health, the
//                 connection constellation, destination receipts, activity.
//
// Everything renders DOM-built (no HTML strings), fails open to honest
// empty states, and never shows a number it cannot back.

import { send, type BrowserReport, type DestinationDrill, type EndpointDetail, type FleetReport } from "../shared/messages";
import { addressNode, mountProtectControl, type ProtectControl } from "../shared/protect-control";
import { CANVAS_MONO, categoryColor, chartInk, onThemeChange } from "../shared/theme";
import type { ActivityRow, EgressStatus, FleetEndpoint, GraphScale, SiteChain } from "../shared/types";
import { renderChain, renderChainPending } from "../shared/chain-view";
import { compact, countUp, sparkline } from "../shared/spark";
import { arcGauge, donut as donutSvg, flowJoin, pulseTrack, ratioBar, stackShare, timeStrip, type FlowColumn, type FlowLink, type FlowNode, type PulseHandle, type Slice, type TimeEvent } from "../shared/viz";
import { mountTierMeter } from "../shared/tier";
import {
  CATEGORY_HEX,
  CATEGORY_LABEL,
  concentration,
  flagEmoji,
  isFlagged,
  shortOwner,
  tallyCategory,
  tallyCountry,
  tallyOwners,
  verdictClass,
  type ReportHost,
  type ReportTotals,
} from "../shared/report";
import {
  BUNDLE_INFO,
  bundlesForPreset,
  countryName,
  countryOptions,
  MAX_GEO_CODES,
  MAX_POLICY_ENTRIES,
  normalizeDomain,
  PRESETS,
  presetOf,
  resolveCountry,
  type DevicePolicy,
  type RevokeResult,
} from "../shared/policy";
import {
  GEO_PREVIEW_ID,
  presetSentence,
  previewBundles,
  previewPreset,
  type BundlePreview,
  type PolicyFactSet,
} from "../shared/policy-preview";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

function el(tag: string, cls?: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function agoLabel(ts: number | null): string {
  if (!ts) return "";
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function fmtBytes(n: number | null): string {
  if (n === null) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

function verdictChip(verdict: string): HTMLElement {
  const cls = verdictClass(verdict);
  const map: Record<string, { c: string; t: string }> = {
    bad: { c: verdict.toUpperCase() === "CRITICAL" ? "crit" : "high", t: verdict.toUpperCase() },
    med: { c: "med", t: "MEDIUM" },
    low: { c: "low", t: "LOW" },
    unknown: { c: "unknown", t: "UNKNOWN" },
    clean: { c: "ok", t: "CLEAR" },
  };
  const m = map[cls] ?? { c: "unknown", t: "UNKNOWN" };
  return el("span", `w-chip ${m.c} cell-verdict`, m.t);
}

// ------------------------------------------------------------ tiles

interface TileSpec {
  label: string;
  value: string;
  hot?: boolean;
  /**
   * The count placed against the whole it came out of, so the tile carries
   * a proportion and not only an integer.
   *
   * Six bare integers in a row is the densest narration on the dashboard:
   * "3 companies" and "2 networks" mean nothing until a reader knows they
   * came from three destinations, and once they do, the pair IS the
   * finding. The mark says how far the traffic narrows at that step.
   */
  of?: { part: number; whole: number; caption: string };
}

function renderTiles(container: HTMLElement, tiles: TileSpec[]): void {
  container.replaceChildren(
    ...tiles.map((t) => {
      const tile = el("div", `w-tile${t.hot ? " flagged-hot" : ""}`);
      tile.append(el("div", "w-label", t.label), el("div", "w-stat", t.value));
      if (t.of && t.of.whole > 0) {
        // No accessible name: the caption underneath IS the name, and
        // giving the mark the same string made every tile announce and
        // read back its own proportion twice.
        const bar = ratioBar(t.of.part, t.of.whole, {
          width: 110,
          height: 4,
          tone: t.hot ? "hot" : "accent",
        });
        if (bar) {
          const mark = el("div", "tile-mark");
          mark.appendChild(bar);
          tile.appendChild(mark);
          tile.append(el("div", "tile-cap", t.of.caption));
        }
      }
      return tile;
    }),
  );
}

function totalsTiles(totals: ReportTotals): TileSpec[] {
  const d = totals.destinations;
  // Every count except the destination count and the raw lookup count is a
  // NARROWING of the destination count, so each is drawn against it. The
  // destination tile has nothing to be a fraction of, and lookups are a
  // different unit entirely (sightings, not places), so neither gets a
  // mark rather than getting a meaningless one.
  const per = (n: number, noun: string): TileSpec["of"] =>
    d > 0 ? { part: n, whole: d, caption: `${n} of ${d} ${noun}` } : undefined;
  return [
    { label: "Destinations", value: String(d) },
    { label: "Companies", value: String(totals.companies), of: per(totals.companies, "destinations") },
    { label: "Countries", value: String(totals.countries), of: per(totals.countries, "destinations") },
    { label: "Networks", value: String(totals.networks), of: per(totals.networks, "destinations") },
    { label: "Lookups", value: String(totals.lookups) },
    {
      label: "Flagged",
      value: String(totals.flagged),
      hot: totals.flagged > 0,
      of: per(totals.flagged, "destinations"),
    },
  ];
}

// ------------------------------------------------------------ donut

/**
 * Where it goes, by kind. Moved off canvas onto the shared SVG primitive:
 * canvas is a bitmap, so it was the one mark on the dashboard that went
 * soft on a HiDPI screen and had to be redrawn by hand on every theme
 * change. The SVG donut inherits the theme like the rest of the page and
 * carries a per-slice title, so a hover says which kind and how many.
 */
function renderDonut(mount: HTMLElement, legendEl: HTMLElement, hosts: ReportHost[]): void {
  const cats = tallyCategory(hosts);
  const total = cats.reduce((s, [, n]) => s + n, 0);
  const slices: Slice[] = cats.map(([cat, n]) => ({
    label: CATEGORY_LABEL[cat],
    value: n,
    color: categoryColor(cat),
  }));
  const svg = donutSvg(slices, {
    size: 168,
    center: String(total),
    caption: "DESTINATIONS",
  });
  // No destinations is not a donut of zero: the primitive refuses, and the
  // card says the true thing instead of drawing an empty ring.
  mount.replaceChildren(svg ?? el("div", "w-note", "No destinations in the window yet."));

  legendEl.replaceChildren(
    ...cats.slice(0, 8).map(([cat, n]) => {
      const row = el("div", "legend-row");
      const dot = el("span", "w-dot");
      dot.style.background = categoryColor(cat);
      row.append(dot, el("span", "name", CATEGORY_LABEL[cat]), el("span", "n", String(n)));
      return row;
    }),
  );
}

/**
 * Draw the analytic furniture only when there is something to put in it.
 *
 * An empty page that still draws six stat tiles, a join card, a donut card
 * and a time-strip card is a page asserting it measured a fleet and found
 * nothing. What actually happened is that nothing has been seen yet. The
 * cheapest way to stop making that claim is to not draw the frames, and to
 * say in one sentence what will fill them.
 */
function setAnalyticsShown(prefix: "b" | "f", shown: boolean, emptyReason: string): void {
  for (const id of [`${prefix}-tiles`, `${prefix}-join-card`, `${prefix}-breakdowns`]) {
    const node = document.getElementById(id);
    if (node) (node as HTMLElement).hidden = !shown;
  }
  const nodata = $(`${prefix}-nodata`);
  nodata.hidden = shown;
  if (!shown) $(`${prefix}-nodata-body`).textContent = emptyReason;
}

// ============================================================ the join flow

/** How many destinations the flow draws before it stops being readable.
 *  Past a dozen rungs the labels collide and the ribbons stop being
 *  followable, and a picture nobody can trace is worse than a list. */
const JOIN_MAX_DESTINATIONS = 10;

/** Rows whose band means the graph is warning about them. */
function hostTone(h: ReportHost): "hot" | "warn" | "neutral" {
  if (h.verdict === "CRITICAL" || h.verdict === "HIGH") return "hot";
  if (h.verdict === "MEDIUM" || h.verdict === "LOW") return "warn";
  return "neutral";
}

/**
 * THE JOIN, drawn.
 *
 * Four columns: the destinations this browser reached, the networks that
 * announce them, the operators holding those networks, and the
 * jurisdictions those operators sit in. Ribbons carry the traffic.
 *
 * This replaces three cards that were the same bar-list over the same rows
 * grouped three different ways. Those cards could tell a reader that they
 * visited six companies and four networks. They could not tell them that
 * four of the six resolve into one network, which is the observation that
 * needs a graph and the only one here a competitor cannot buy from a feed.
 *
 * The narrowing left to right IS the finding, so the columns are ordered by
 * how much they narrow and every count on a node is real.
 */
function renderJoinFlow(
  mount: HTMLElement,
  noteEl: HTMLElement,
  emptyEl: HTMLElement,
  hosts: ReportHost[],
  subject: string,
): void {
  // Visibility is NOT this function's business: setAnalyticsShown owns it.
  // Un-hiding the card here as well meant the empty state hid the card and
  // this reopened it a line later, so a browser that had seen nothing still
  // drew a join card containing one sentence about having nothing to draw.
  const enriched = hosts.filter((h) => h.asn || h.owner);
  if (enriched.length === 0) {
    mount.replaceChildren();
    noteEl.textContent = "";
    emptyEl.hidden = false;
    // Two different facts, and they must not share a sentence: no traffic
    // at all, versus traffic the graph has not been able to place yet.
    emptyEl.textContent =
      hosts.length === 0
        ? `No destinations yet. Browse a little and the join builds itself.`
        : `${hosts.length} destination${hosts.length === 1 ? "" : "s"} so far, none of them placed on a network yet. The join appears once the graph resolves one.`;
    return;
  }
  emptyEl.hidden = true;

  const top = [...enriched].sort((a, b) => b.q - a.q).slice(0, JOIN_MAX_DESTINATIONS);

  const dest: FlowNode[] = top.map((h) => ({
    id: `d:${h.host}`,
    label: h.host,
    weight: Math.max(1, h.q),
    tone: hostTone(h),
  }));

  const agg = (
    key: (h: ReportHost) => string | null,
    label: (h: ReportHost) => string,
    prefix: string,
  ): { nodes: FlowNode[]; idOf: Map<string, string> } => {
    const tally = new Map<string, { weight: number; label: string; hot: boolean }>();
    const idOf = new Map<string, string>();
    for (const h of top) {
      const k = key(h);
      if (!k) continue;
      const id = `${prefix}:${k}`;
      idOf.set(h.host, id);
      const cur = tally.get(id) ?? { weight: 0, label: label(h), hot: false };
      cur.weight += Math.max(1, h.q);
      if (hostTone(h) === "hot") cur.hot = true;
      tally.set(id, cur);
    }
    return {
      nodes: [...tally.entries()]
        .sort((a, b) => b[1].weight - a[1].weight)
        .map(([id, v]) => ({ id, label: v.label, weight: v.weight, tone: v.hot ? ("hot" as const) : ("neutral" as const) })),
      idOf,
    };
  };

  const nets = agg((h) => h.asn ?? null, (h) => h.asn ?? "", "n");
  const owners = agg((h) => h.owner || null, (h) => shortOwner(h.owner), "o");
  const countries = agg(
    (h) => h.country ?? null,
    (h) => `${flagEmoji(h.country ?? "") } ${h.country ?? ""}`.trim(),
    "c",
  );

  const columns: FlowColumn[] = [
    { label: "destinations", nodes: dest },
    { label: "networks", nodes: nets.nodes },
    { label: "operators", nodes: owners.nodes },
    { label: "countries", nodes: countries.nodes },
  ];

  const links: FlowLink[] = [];
  for (const h of top) {
    const w = Math.max(1, h.q);
    const tone = hostTone(h) === "hot" ? ("hot" as const) : ("accent" as const);
    const d = `d:${h.host}`;
    const n = nets.idOf.get(h.host);
    const o = owners.idOf.get(h.host);
    const c = countries.idOf.get(h.host);
    // Each hop is drawn only when BOTH of its ends were resolved, so a
    // destination the graph could place on a network but not on an operator
    // shows a ribbon that stops there rather than one invented to continue.
    if (n) links.push({ from: d, to: n, weight: w, tone });
    if (n && o) links.push({ from: n, to: o, weight: w, tone });
    if (o && c) links.push({ from: o, to: c, weight: w, tone });
  }

  // The readout beside the card heading counts the same columns in words,
  // and each node carries its own hover title, so the figure itself needs
  // no name repeating what is already written next to it.
  const svg = flowJoin(columns, links, { width: 1100, rowHeight: 24 });
  if (svg) {
    mount.replaceChildren(svg);
  } else {
    mount.replaceChildren();
    emptyEl.hidden = false;
    emptyEl.textContent = "Not enough resolved hops yet to draw the join.";
  }

  // The readout says plainly that the picture is a TOP-N, and carries the
  // full jurisdiction tally beside the drawn one. Dropping the by-country
  // card removed a fact about every destination, and replacing it with a
  // column that only covers the ten busiest would have quietly shrunk it.
  const allCountries = tallyCountry(hosts).length;
  const drawnCountries = countries.nodes.length;
  const shown = top.length < enriched.length ? `top ${top.length} of ${enriched.length}` : `${top.length}`;
  noteEl.textContent =
    `${shown} destination${top.length === 1 ? "" : "s"} · ` +
    `${nets.nodes.length} network${nets.nodes.length === 1 ? "" : "s"} · ` +
    `${owners.nodes.length} operator${owners.nodes.length === 1 ? "" : "s"} · ` +
    (allCountries > drawnCountries
      ? `${drawnCountries} of ${allCountries} jurisdictions`
      : `${drawnCountries} ${drawnCountries === 1 ? "jurisdiction" : "jurisdictions"}`) +
    `, ${subject}`;
}

/**
 * Concentration as a bar rather than a sentence.
 *
 * "62% of where this browser goes is A, B, C" is a true sentence a reader
 * has to assemble in their head. The same fact as one full-width stacked
 * bar is a shape: how much of the width three names take is the whole
 * point, and the tail being visible as a tail is half of it.
 */
function renderConcentration(
  wrap: HTMLElement,
  barMount: HTMLElement,
  capEl: HTMLElement,
  hosts: ReportHost[],
): void {
  const owners = tallyOwners(hosts);
  // Concentration is a claim about how FEW hands hold the traffic, so it
  // needs a meaningful number of hands to be a claim at all. With three
  // destinations under three operators the honest reading is "100% of these
  // three are held by three operators", which is arithmetic wearing the
  // clothes of a finding. Below five holders the card stays shut.
  const MIN_HOLDERS = 5;
  if (owners.length < MIN_HOLDERS) {
    wrap.hidden = true;
    return;
  }
  const slices: Slice[] = owners.slice(0, 8).map((o) => ({
    label: o.owner,
    value: o.count,
    color: CATEGORY_HEX[o.category] ?? categoryColor(o.category),
  }));
  const restCount = owners.slice(8).reduce((a, o) => a + o.count, 0);
  if (restCount > 0) {
    slices.push({ label: `${owners.length - 8} others`, value: restCount, color: "var(--w-line-strong)" });
  }
  const bar = stackShare(slices, { width: 1100, height: 14, title: "share of destinations by operator" });
  if (!bar) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  barMount.replaceChildren(bar);
  const conc = concentration(hosts);
  capEl.textContent =
    `${conc.pct}% of these destinations sit with just ${conc.top.length} of ${owners.length} operators: ` +
    `${conc.top.join(", ")}.`;
}

/**
 * When it went there: a real time axis over the trailing day.
 *
 * The ledger below is sorted busiest-first and the fleet feed newest-first,
 * and neither can show that eleven of twelve sightings happened inside four
 * minutes. That clustering is often the only visible difference between a
 * person browsing and something running on its own, so it gets an axis.
 */
function renderWhenStrip(
  mount: HTMLElement,
  noteEl: HTMLElement,
  emptyEl: HTMLElement,
  hosts: ReportHost[],
): void {
  const events: TimeEvent[] = hosts
    .filter((h) => h.lastAt > 0)
    .map((h) => ({
      at: h.lastAt,
      tone: hostTone(h) === "hot" ? ("hot" as const) : hostTone(h) === "warn" ? ("warn" as const) : ("accent" as const),
      label: h.host,
    }));
  const svg = timeStrip(events, { width: 520, height: 64, hours: 24 });
  if (!svg) {
    mount.replaceChildren();
    emptyEl.hidden = false;
    noteEl.textContent = "";
    return;
  }
  emptyEl.hidden = true;
  mount.replaceChildren(svg);
  const flagged = events.filter((e) => e.tone === "hot").length;
  noteEl.textContent = flagged > 0 ? `${events.length} sightings, ${flagged} flagged` : `${events.length} sightings`;
}

// ------------------------------------------------------------ ledger

// -------------------------------------------------------- the scale band
//
// Read live on every load, never written into the build. When the endpoint
// cannot be read the band stays hidden: a page that shows a remembered
// figure about its own coverage is worse than one that shows none, because
// the reader cannot tell which it is looking at.

async function loadScaleBand(): Promise<void> {
  const res = await send<{ ok: true; scale: GraphScale | null }>({ kind: "getScale" });
  if (!res.ok || !res.scale) return;
  const sc = res.scale;
  $("scale-band").hidden = false;
  countUp($("sb-nodes"), sc.nodes, compact);
  countUp($("sb-edges"), sc.edges, compact);
  countUp($("sb-identities"), sc.identities, (n) => Math.round(n).toLocaleString("en"));

  const buckets = sc.pulse.length;
  const note = $("sb-pulse-note");
  const chart = $("sb-pulse-chart");
  const spark = sparkline(sc.pulse, {
    width: 640,
    height: 52,
    fill: 0.14,
    head: true,
    title: `DNS questions answered per 5 minutes over the last ${sc.windowHours} hours`,
  });
  if (spark) {
    // Let the SVG stretch to the card; the stroke is non-scaling so it stays
    // one pixel wide however wide the card gets.
    spark.removeAttribute("width");
    spark.removeAttribute("height");
    chart.replaceChildren(spark);
    const lat = sc.p50Us !== null ? ` · p50 ${Math.round(sc.p50Us)}us` : "";
    note.textContent =
      `${sc.queries.toLocaleString("en")} questions answered in ${sc.windowHours}h${lat}` +
      `${sc.degraded ? " · the endpoint reports degraded input" : ""}`;
  } else {
    // The endpoint answered but carried no series worth drawing. Say that,
    // rather than drawing a flat line that implies a measured steady state.
    chart.replaceChildren();
    note.textContent =
      buckets === 0
        ? "no per-bucket series published right now"
        : "not enough variation in the window to plot";
  }
}

// ---------------------------------------------------- the chain, in a row
//
// A destination row opens the join path behind it, in place. The same
// module the panel mounts, so there is one chain and it reads the same
// everywhere. Keyless, so this works signed out.

const openChains = new Map<string, HTMLElement>();

async function toggleChain(row: HTMLElement, host: string): Promise<void> {
  const existing = openChains.get(host);
  if (existing) {
    existing.remove();
    openChains.delete(host);
    row.classList.remove("open");
    return;
  }
  const panel = el("div", "ledger-chain");
  renderChainPending(panel, 7, `THE CHAIN BEHIND ${host.toUpperCase()}`);
  row.after(panel);
  openChains.set(host, panel);
  row.classList.add("open");

  const res = await send<{ ok: true; chain: SiteChain }>({ kind: "getChain", host });
  // The row may have been closed, or the ledger re-rendered under us, while
  // the walk was in flight.
  if (!openChains.has(host) || !panel.isConnected) return;
  if (!res.ok) {
    panel.replaceChildren(el("div", "w-note", "The graph could not be reached for this walk. Nothing here is a verdict."));
    return;
  }
  renderChain(panel, res.chain, { heading: `THE CHAIN BEHIND ${host.toUpperCase()}` });
}

function hostRow(
  h: ReportHost,
  fresh: Set<string>,
  onClick?: (h: ReportHost) => void,
  onExpand?: (row: HTMLElement, h: ReportHost) => void,
  busiest = 0,
): HTMLElement {
  const row = el("div", `w-ledger-row${fresh.has(h.host) ? " fresh" : ""}`);
  const catDot = el("span", "w-dot");
  catDot.style.background = CATEGORY_HEX[h.category];
  const cat = el("span", "cell-cat");
  cat.append(catDot, document.createTextNode(CATEGORY_LABEL[h.category]));
  row.append(
    el("span", "cell-host", h.host),
    el("span", "cell-owner", shortOwner(h.owner)),
    cat,
    el("span", "cell-geo", h.country ? flagEmoji(h.country) || h.country : ""),
    verdictChip(h.verdict),
    qCell(h, busiest),
  );
  if (onClick) {
    row.style.cursor = "pointer";
    row.addEventListener("click", () => onClick(h));
  } else if (onExpand) {
    row.classList.add("expandable");
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.title = "Open the join path behind this destination";
    row.addEventListener("click", () => onExpand(row, h));
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        onExpand(row, h);
      }
    });
  }
  return row;
}

/**
 * The lookup count, against the busiest row on the list.
 *
 * A column of bare integers sorted descending tells a reader the order and
 * nothing else: 141 and 3 look the same width, and the shape of the tail -
 * one destination doing almost all the work, or fifty sharing it evenly - is
 * the actual finding. The mark is refused when every row is equal, because a
 * row of full bars would imply a ranking that was never measured.
 */
function qCell(h: ReportHost, busiest: number): HTMLElement {
  const cell = el("span", "cell-q");
  cell.appendChild(el("span", "q-num", String(h.q)));
  if (busiest > 1) {
    const bar = ratioBar(h.q, busiest, {
      width: 34,
      height: 3,
      tone: hostTone(h) === "hot" ? "hot" : "accent",
      title: `${h.q} of the busiest destination's ${busiest}`,
    });
    if (bar) {
      const mark = el("span", "q-bar");
      mark.appendChild(bar);
      cell.appendChild(mark);
    }
  }
  return cell;
}

function renderHostLedger(
  container: HTMLElement,
  hosts: ReportHost[],
  fresh: Set<string>,
  onClick?: (h: ReportHost) => void,
  onExpand?: (row: HTMLElement, h: ReportHost) => void,
): void {
  const busiest = hosts.reduce((m, h) => Math.max(m, h.q), 0);
  container.replaceChildren(...hosts.map((h) => hostRow(h, fresh, onClick, onExpand, busiest)));
}

// ----------------------------------------------------------- browser view

let lastBrowserHosts = new Map<string, number>();
let browserBusy = false;

async function refreshBrowser(): Promise<void> {
  if (browserBusy) return;
  browserBusy = true;
  try {
    const res = await send<{ ok: true; report: BrowserReport }>({ kind: "getBrowserReport" });
    if (!res.ok) return;
    const { hosts, totals } = res.report;
    const anyBrowser = hosts.length > 0;
    setAnalyticsShown(
      "b",
      anyBrowser,
      "This browser has not been seen visiting anywhere yet. Browse a little: every destination arrives here with the join path behind it, and none of it leaves this device.",
    );
    renderTiles($("b-tiles"), totalsTiles(totals));
    renderDonut($("b-donut"), $("b-donut-legend"), hosts);
    renderJoinFlow($("b-join"), $("b-join-note"), $("b-join-empty"), hosts, "this browser");
    renderConcentration($("b-conc"), $("b-conc-bar"), $("b-conc-cap"), hosts);
    renderWhenStrip($("b-when"), $("b-when-note"), $("b-when-empty"), hosts);

    // Rows whose lookup count grew since the last paint flash once.
    const fresh = new Set<string>();
    for (const h of hosts) {
      const prev = lastBrowserHosts.get(h.host);
      if (prev !== undefined && h.q > prev) fresh.add(h.host);
    }
    lastBrowserHosts = new Map(hosts.map((h) => [h.host, h.q]));
    // Every destination row opens the join path behind it, in place. It is
    // the same spine the panel draws, and it needs no account.
    openChains.clear();
    renderHostLedger($("b-ledger"), hosts, fresh, undefined, (row, h) => {
      void toggleChain(row, h.host);
    });
    $("b-count").textContent = `${hosts.length} destinations, 24h window`;
    $("b-empty").hidden = hosts.length > 0;
  } finally {
    browserBusy = false;
  }
}

// ------------------------------------------------------------ fleet view

const deviceLabels = new Map<string, string>();
let fleetTimer: ReturnType<typeof setInterval> | null = null;

function rosterCard(e: FleetEndpoint): HTMLElement {
  const card = el("button", "roster-card") as HTMLButtonElement;
  const label = el("div", "rc-label", e.label);
  if (e.device) label.appendChild(el("span", "w-chip accent", "DEVICE"));
  const meta = el("div", "rc-meta");
  meta.appendChild(el("span", `w-chip ${e.state === "active" ? "ok" : "unknown"}`, e.state.toUpperCase()));
  const addr = el("div", "rc-addr");
  addr.append(addressNode(e.address));
  card.append(label, addr, meta);
  card.addEventListener("click", () => {
    void openEndpoint(e.agent);
  });
  return card;
}

async function refreshFleet(): Promise<void> {
  const res = await send<{ ok: true; fleet: FleetReport } | { ok: false; error: string; nokey?: boolean }>({
    kind: "getFleetReport",
  });
  const lock = $("fleet-lock");
  const body = $("fleet-body");
  if (!res.ok) {
    lock.hidden = false;
    body.hidden = true;
    if (!res.nokey) {
      lock.querySelector("p")!.textContent = res.error;
    }
    setFeedBadge("offline", null);
    return;
  }
  lock.hidden = true;
  body.hidden = false;
  const f = res.fleet;
  deviceLabels.clear();
  for (const e of f.endpoints) deviceLabels.set(e.agent.replace(/^agent-/, ""), e.label);

  $("f-roster").replaceChildren(...f.endpoints.map(rosterCard));
  $("f-silent").textContent =
    f.silent.length > 0 ? `${f.silent.length} endpoint(s) did not answer; showing the rest` : "";
  renderTiles($("f-tiles"), [
    { label: "Endpoints", value: String(f.endpoints.length) },
    ...totalsTiles(f.totals).slice(0, 4),
    { label: "Flagged", value: String(f.totals.flagged), hot: f.totals.flagged > 0 },
  ]);
  setAnalyticsShown(
    "f",
    f.hosts.length > 0,
    f.endpoints.length === 0
      ? "No endpoints on this account yet. Give a device or an agent a Whisper address and its traffic appears here."
      : `${f.endpoints.length} endpoint${f.endpoints.length === 1 ? "" : "s"} on this account, none of them seen going anywhere in the last 24 hours.`,
  );
  renderDonut($("f-donut"), $("f-donut-legend"), f.hosts);
  renderJoinFlow($("f-join"), $("f-join-note"), $("f-join-empty"), f.hosts, "the fleet");
  renderConcentration($("f-conc"), $("f-conc-bar"), $("f-conc-cap"), f.hosts);
  renderWhenStrip($("f-when"), $("f-when-note"), $("f-when-empty"), f.hosts);

  const feed = $("f-feed");
  feed.replaceChildren(
    ...f.feed.slice(0, 120).map((r) => {
      const row = el("div", "w-ledger-row");
      row.append(
        el("span", "cell-ts", agoLabel(r.ts)),
        el("span", "cell-device", deviceLabels.get(r.agent) ?? r.agent),
        el("span", "cell-kind", r.kind),
        el("span", "cell-host", r.target),
        el("span", "cell-owner", r.decision ?? ""),
      );
      return row;
    }),
  );
  $("f-empty").hidden = f.feed.length > 0;
  $("f-feed-note").textContent = f.feedStatus.updatedAt
    ? `polling, updated ${agoLabel(f.feedStatus.updatedAt)}`
    : "polling";
  // A poll only moves the mark when the poll brought something NEW.
  //
  // Pushing on every completed poll was a heartbeat wearing an event's
  // clothes: the fleet is polled every fifteen seconds whether or not
  // anything happened, so the track would have ticked forever beside a
  // fleet doing nothing, which is precisely what this mark promises never
  // to do. That the control plane answered is already stated, in words,
  // by the "polling, updated Ns ago" line beside it.
  const newest = f.feed.reduce((a, r) => Math.max(a, r.ts), 0);
  if (newest > lastFleetEvent) {
    lastFleetEvent = newest;
    arrived(f.totals.flagged > 0 ? "hot" : "accent");
  }
  setFeedBadge(f.feedStatus.mode, f.feedStatus.updatedAt);
}

// --------------------------------------------------------- endpoint view

let currentAgent: string | null = null;
let endpointHosts: ReportHost[] = [];

function factorRow(f: { label: string; state: string; weight: number; detail: string }): HTMLElement {
  const row = el("div", `factor ${f.state}`);
  const mark = el("span", "mark", f.state === "met" ? "✓" : f.state === "unmet" ? "✗" : "?");
  row.append(mark, el("span", undefined, f.label), el("span", "fw", `${f.weight}`));
  row.title = f.detail;
  return row;
}

/**
 * Identity health, on the shared arc.
 *
 * This was a hand-rolled canvas ring that had to be redrawn from scratch on
 * every colour-scheme change and went soft on a HiDPI screen. The arc
 * primitive is the same measurement in SVG: it inherits the theme, stays
 * crisp, and opens at the bottom so the ring reads as a scale with two ends
 * rather than as a pie missing a slice.
 */
function drawGauge(mount: HTMLElement, score: number, level: string): void {
  const svg = arcGauge({
    size: 140,
    value: Math.max(0, Math.min(1, score / 100)),
    center: String(score),
    caption: "OF 100",
    tone: level === "strong" ? "ok" : level === "partial" ? "warn" : "hot",
    title: `identity health ${score} of 100 (${level})`,
  });
  // A score outside 0..100 is a bug upstream, and the primitive refuses it
  // rather than drawing a full ring over the top of it. Say so instead of
  // leaving a hole where a measurement should be.
  mount.replaceChildren(svg ?? el("div", "w-note", `identity health: ${score} (out of range)`));
}

/** Trim `text` to the widest ellipsised form that fits `maxWidth` px. */
function fitText(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string {
  if (maxWidth <= 0) return "";
  if (ctx.measureText(text).width <= maxWidth) return text;
  let out = text;
  while (out.length > 1 && ctx.measureText(`${out}…`).width > maxWidth) out = out.slice(0, -1);
  return `${out}…`;
}

function drawConstellation(canvas: HTMLCanvasElement, d: EndpointDetail): void {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.font = `10px ${CANVAS_MONO}`;
  const ink = chartInk();

  const top = d.topHosts.slice(0, 9);
  const cx = 80;
  const cy = H / 2;

  // The device node.
  ctx.fillStyle = ink.accent;
  ctx.beginPath();
  ctx.arc(cx, cy, 9, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = ink.text;
  ctx.textAlign = "center";
  const label = d.endpoint.label.length > 18 ? `${d.endpoint.label.slice(0, 17)}…` : d.endpoint.label;
  ctx.fillText(label, cx, cy - 16);

  if (top.length === 0) {
    ctx.fillStyle = ink.muted;
    ctx.fillText("no destinations in the last 24h", W / 2, cy);
    return;
  }

  top.forEach((h, i) => {
    const y = (H / (top.length + 1)) * (i + 1);
    const hx = W * 0.42;
    const flagged = isFlagged(h.verdict);
    // Edge device -> hostname.
    ctx.strokeStyle = flagged ? ink.crit : ink.line;
    ctx.lineWidth = flagged ? 1.6 : 1;
    ctx.beginPath();
    ctx.moveTo(cx + 9, cy);
    ctx.lineTo(hx - 6, y);
    ctx.stroke();
    // Hostname node.
    ctx.fillStyle = flagged ? ink.crit : categoryColor(h.category);
    ctx.beginPath();
    ctx.arc(hx, y, 4.5, 0, 2 * Math.PI);
    ctx.fill();
    ctx.fillStyle = flagged ? ink.crit : ink.muted;
    ctx.textAlign = "left";
    ctx.fillText(fitText(ctx, h.host, W * 0.72 - 6 - (hx + 9)), hx + 9, y + 3);

    // Hostname -> network/owner chain, when resolved.
    const net = h.asn;
    if (net) {
      const nx = W * 0.72;
      ctx.strokeStyle = ink.line;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(hx + 6, y);
      ctx.lineTo(nx - 6, y);
      ctx.stroke();
      ctx.fillStyle = ink.muted;
      ctx.beginPath();
      ctx.arc(nx, y, 3.5, 0, 2 * Math.PI);
      ctx.fill();
      // Clipped to what actually fits: the label used to be cut at a
      // fixed 30 characters and ran off the canvas' right edge, which is
      // only visible by looking at the drawing.
      const ownerLabel = `${net} ${shortOwner(h.owner)}`;
      ctx.fillStyle = ink.muted;
      ctx.fillText(fitText(ctx, ownerLabel, W - (nx + 8) - 6), nx + 8, y + 3);
    }
  });
}

/** The endpoint's own activity on a real 24h axis, blocks drawn hot. */
function renderActivityStrip(mount: HTMLElement, noteEl: HTMLElement, activity: ActivityRow[]): void {
  const events: TimeEvent[] = activity
    .filter((r) => r.ts > 0)
    .map((r) => ({
      at: r.ts,
      tone: (r.decision ?? "").toLowerCase().startsWith("block") ? ("hot" as const) : ("accent" as const),
      label: r.target,
    }));
  const svg = timeStrip(events, { width: 520, height: 56, hours: 24 });
  if (!svg) {
    mount.replaceChildren();
    noteEl.textContent = activity.length === 0 ? "nothing in the last 24 hours" : "";
    return;
  }
  mount.replaceChildren(svg);
  const blocked = events.filter((e) => e.tone === "hot").length;
  noteEl.textContent =
    blocked > 0 ? `${events.length} events, ${blocked} blocked` : `${events.length} events`;
}

function drillKv(k: string, v: string | HTMLElement): HTMLElement {
  const row = el("div", "drill-kv");
  const kEl = el("span", "k", k);
  const vEl = el("span", "v");
  if (typeof v === "string") vEl.textContent = v;
  else vEl.appendChild(v);
  row.append(kEl, vEl);
  return row;
}

async function showDrill(h: ReportHost): Promise<void> {
  const body = $("e-drill-body");
  body.textContent = "Fetching the receipts...";
  const rows = el("div", "drill-rows");
  rows.append(
    drillKv("Destination", h.host),
    drillKv("Who answers", h.owner),
    drillKv("Kind", CATEGORY_LABEL[h.category]),
  );
  if (h.ip) rows.append(drillKv("Resolves to", h.ip));
  if (h.city) rows.append(drillKv("Where", `${h.city}${h.country ? ` ${flagEmoji(h.country)}` : ""}`));
  if (h.asn) rows.append(drillKv("Network", `${h.asn}${h.asnName ? ` (${h.asnName})` : ""}`));
  const chip = verdictChip(h.verdict);
  rows.append(drillKv("Verdict", chip));

  const res = await send<{ ok: true; drill: DestinationDrill } | { ok: false; error: string }>({
    kind: "getDestinationDrill",
    host: h.host,
  });
  if (res.ok) {
    if (res.drill.cohosted !== null) {
      rows.append(
        drillKv(
          "Co-hosted names",
          `${res.drill.cohosted} other hostname(s) share this address`,
        ),
      );
    }
    if (res.drill.prefix) {
      rows.append(
        drillKv(
          "Announcing prefix",
          `${res.drill.prefix}${res.drill.threatNeighbors !== null ? `, ${res.drill.threatNeighbors} threat-listed neighbor(s)` : ""}`,
        ),
      );
    }
  }
  body.replaceChildren(rows);
}

async function openEndpoint(agent: string): Promise<void> {
  switchView("endpoint");
  const picker = $<HTMLSelectElement>("e-picker");
  picker.value = agent;
  await refreshEndpoint(agent);
}

async function refreshEndpoint(agent: string): Promise<void> {
  currentAgent = agent;
  const res = await send<{ ok: true; endpoint: EndpointDetail } | { ok: false; error: string; nokey?: boolean }>({
    kind: "getEndpointDetail",
    agent,
  });
  if (!res.ok) {
    $("e-feed-note").textContent = res.error;
    return;
  }
  const d = res.endpoint;
  endpointHosts = d.topHosts;

  $("e-address").replaceChildren(addressNode(d.endpoint.address));
  const state = $("e-state");
  state.textContent = d.endpoint.state.toUpperCase();
  state.className = `w-chip ${d.endpoint.state === "active" ? "ok" : "unknown"}`;
  const rdap = $<HTMLAnchorElement>("e-rdap");
  rdap.href = d.rdapUrl;
  rdap.textContent = "RDAP registration";
  $("e-fqdn").textContent = d.endpoint.fqdn ?? "";

  const c = d.counters;
  // Six bare integers in a row was the densest narration on this page.
  // "Blocked 14" is unreadable until you know it came out of 9,400 lookups,
  // and once you know that, the PAIR is the finding. Every counter that is a
  // part of another counter is drawn against its whole; the ones that are
  // not a part of anything (the query total, the last sighting) get no mark
  // rather than a meaningless one.
  const queries = c?.dnsQueries ?? null;
  const bytesTotal = (c?.bytesUp ?? 0) + (c?.bytesDown ?? 0);
  const ofQueries = (n: number | null | undefined, noun: string): TileSpec["of"] =>
    queries !== null && queries > 0 && n !== null && n !== undefined
      ? { part: n, whole: queries, caption: `${n} of ${queries} ${noun}` }
      : undefined;
  const ofBytes = (n: number | null | undefined): TileSpec["of"] =>
    bytesTotal > 0 && n !== null && n !== undefined
      ? { part: n, whole: bytesTotal, caption: `${fmtBytes(n)} of ${fmtBytes(bytesTotal)} moved` }
      : undefined;
  renderTiles($("e-tiles"), [
    { label: "DNS queries", value: c?.dnsQueries !== null && c ? String(c.dnsQueries) : "-" },
    {
      label: "Blocked",
      value: c?.dnsBlocked !== null && c ? String(c.dnsBlocked) : "-",
      hot: (c?.dnsBlocked ?? 0) > 0,
      of: ofQueries(c?.dnsBlocked, "lookups"),
    },
    {
      label: "NXDOMAIN",
      value: c?.dnsNxdomain !== null && c ? String(c.dnsNxdomain) : "-",
      of: ofQueries(c?.dnsNxdomain, "lookups"),
    },
    { label: "Connections", value: c?.connectionsTotal !== null && c ? String(c.connectionsTotal) : "-" },
    { label: "Bytes up", value: fmtBytes(c?.bytesUp ?? null), of: ofBytes(c?.bytesUp) },
    { label: "Bytes down", value: fmtBytes(c?.bytesDown ?? null), of: ofBytes(c?.bytesDown) },
    { label: "Last seen", value: c?.lastSeen ? agoLabel(c.lastSeen) : "-" },
  ]);

  drawGauge($("e-gauge"), d.health.score, d.health.level);
  $("e-health-headline").textContent =
    d.health.revoked ? "Revoked" : d.health.level === "strong" ? "Strongly trusted" : d.health.level === "partial" ? "Partially verified" : "Unverified";
  $("e-factors").replaceChildren(...d.health.factors.map(factorRow));
  $("e-threat-note").textContent = d.health.threatNote ?? "";

  drawConstellation($<HTMLCanvasElement>("e-constellation"), d);

  renderHostLedger($("e-hosts"), d.topHosts.slice(0, 40), new Set(), (h) => {
    void showDrill(h);
  });

  // WHEN it went there. The browser and fleet views both carry a time axis
  // and this one did not, so the surface that drills into a single endpoint
  // was the only one that could not show whether its twelve sightings were
  // spread over a day or fired inside four minutes - which is often the only
  // visible difference between a person browsing and something running on
  // its own.
  renderActivityStrip($("e-when"), $("e-when-note"), d.activity);

  $("e-activity").replaceChildren(
    ...d.activity.slice(0, 80).map((r) => {
      const row = el("div", "w-ledger-row");
      row.append(
        el("span", "cell-ts", agoLabel(r.ts)),
        el("span", "cell-kind", r.kind),
        el("span", "cell-host", r.target),
        el("span", "cell-owner", [r.qtype, r.decision].filter(Boolean).join(" ")),
      );
      return row;
    }),
  );
  $("e-feed-note").textContent = `polling, updated ${agoLabel(Date.now())}`;

  // The governor half: policy + danger zone. The policy loads once per
  // endpoint switch (never on the 15s poll, so it can't clobber an edit
  // in progress); the danger zone re-arms against this endpoint's label.
  governLabel = d.endpoint.label;
  $("d-hint").textContent = `Type "${governLabel.trim() || "revoke"}" to confirm.`;
  updateRevokeArmed();
  // Drop the previous endpoint's evidence BEFORE anything repaints. Without
  // this the governor's first frame draws one endpoint's destinations under
  // another endpoint's policy, which is a true picture of nothing.
  governFacts = null;
  governFactHosts = [];
  governFactsPending = false;
  void refreshGovern(agent);
  void refreshPolicyFacts(agent, d.topHosts);
}

async function populatePicker(): Promise<void> {
  const res = await send<{ ok: true; fleet: FleetReport } | { ok: false; error: string; nokey?: boolean }>({
    kind: "getFleetReport",
  });
  const lock = $("e-lock");
  const body = $("e-body");
  if (!res.ok) {
    lock.hidden = false;
    body.hidden = true;
    return;
  }
  lock.hidden = true;
  body.hidden = false;
  const picker = $<HTMLSelectElement>("e-picker");
  picker.replaceChildren(
    ...res.fleet.endpoints.map((e) => {
      const opt = document.createElement("option");
      opt.value = e.agent;
      opt.textContent = `${e.label} (${e.device ? "device" : "agent"})`;
      return opt;
    }),
  );
  const first = currentAgent ?? res.fleet.endpoints[0]?.agent;
  if (first) {
    picker.value = first;
    await refreshEndpoint(first);
  }
}

// ------------------------------------------------------------- govern
//
// The control half of the endpoint view: the same op:policy / op:revoke
// verbs the console's device controls speak, from the dashboard. Every
// change is ONE whole-value policy write; the UI always re-renders from
// the engine's own read-back, so what is shown is what is in force.

let governAgent: string | null = null;
let governLabel = "";
let governPolicy: DevicePolicy | null = null;
let governBusy = false;

// The evidence behind every control below: the destinations this endpoint
// actually reached, and the one fact each protection keys on for each of
// them. Held raw rather than pre-evaluated, because the blocked-countries
// preview depends on the policy currently on screen and the policy changes
// under the reader's hands; recomputing from the facts on every render costs
// nothing and cannot drift out of step with the checkboxes.
let governFacts: PolicyFactSet | null = null;
let governFactHosts: ReportHost[] = [];
let governFactsPending = false;

/** How many of this endpoint's destinations the preview is measured over. */
const PREVIEW_HOST_CAP = 60;

/**
 * Read the protection facts for this endpoint's destinations.
 *
 * Never on the poll: this is a graph read, and re-running it every fifteen
 * seconds would spend a reader's allowance on a number that does not move.
 * It runs once per endpoint switch, exactly like the policy read it sits
 * beside.
 */
async function refreshPolicyFacts(agent: string, hosts: ReportHost[]): Promise<void> {
  governFactHosts = hosts.slice(0, PREVIEW_HOST_CAP);
  governFacts = null;
  governFactsPending = governFactHosts.length > 0;
  renderGovern();
  if (governFactHosts.length === 0) return;
  const res = await send<{ ok: true; facts: PolicyFactSet } | { ok: false; error: string }>({
    kind: "getPolicyFacts",
    hosts: governFactHosts.map((h) => h.host),
  });
  if (governAgent !== agent) return; // switched away while reading
  governFactsPending = false;
  // A failed transport is NOT an empty answer: every destination becomes
  // unknown, which is what makes the counts below draw as "not checked"
  // rather than as "nothing matched".
  governFacts = res.ok
    ? res.facts
    : { byHost: {}, unread: governFactHosts.map((h) => h.host), error: res.error };
  renderGovern();
}

/** The preview, recomputed from the facts and the policy on screen now. */
function currentPreview(p: DevicePolicy): Record<string, BundlePreview> | null {
  if (!governFacts) return null;
  return previewBundles(governFactHosts.map((h) => h.host), governFacts, p.geoDeny);
}

/**
 * One protection's consequence, drawn: a bar of matched-against-checked and
 * the matched destinations themselves behind a disclosure.
 *
 * The three states are never collapsed. Matched is a count with the names
 * under it; checked-and-clear is a count; and a destination the graph holds
 * no record of is neither, so it is named separately every single time. A
 * "0 matched" with no denominator beside it is the shape of a survey that
 * never ran, and this product has already shipped one of those.
 */
function previewMark(p: BundlePreview | undefined): HTMLElement | null {
  if (!p || p.considered === 0) return null;
  const wrap = el("div", "b-preview");
  if (p.unavailable) {
    // Its own layout: the reason is a sentence, not a caption, and it reads
    // as an afterthought when it is set beside the words "not previewed"
    // rather than under them.
    wrap.classList.add("unavailable");
    wrap.appendChild(el("span", "b-count muted", "not previewed"));
    wrap.appendChild(el("div", "b-why", p.unavailable));
    return wrap;
  }
  // A read that FAILED is reported as a failed read. Borrowing the sentence
  // below - "none of these are in the graph" - for a request that never came
  // back would be a claim about the world made out of a network error, which
  // is the one defect this whole surface exists to not commit.
  if (p.error) {
    wrap.appendChild(el("span", "b-count muted", `not checked: ${p.error}`));
    return wrap;
  }
  const checked = p.considered - p.unknown;
  const n = p.matched.length;
  if (checked === 0) {
    wrap.appendChild(
      el("span", "b-count muted", `not checked: none of these ${p.considered} destinations are in the graph`),
    );
    return wrap;
  }
  const bar = ratioBar(n, checked, { width: 88, height: 5, tone: n > 0 ? "hot" : "ok" });
  if (bar) {
    const mark = el("span", "b-bar");
    mark.appendChild(bar);
    wrap.appendChild(mark);
  }
  wrap.appendChild(
    el(
      "span",
      `b-count${n > 0 ? " hot" : ""}`,
      `${n} of ${checked} checked${p.unknown > 0 ? `, ${p.unknown} not in the graph` : ""}`,
    ),
  );
  if (n > 0) {
    const det = document.createElement("details");
    det.className = "b-hits";
    const sum = document.createElement("summary");
    sum.textContent = n === 1 ? "which one" : "which ones";
    det.appendChild(sum);
    for (const host of p.matched) {
      const row = el("div", "b-hit");
      row.append(el("span", "b-hit-host", host), el("span", "b-hit-why", p.reasons[host] ?? ""));
      det.appendChild(row);
    }
    wrap.appendChild(det);
  }
  return wrap;
}

async function refreshGovern(agent: string, force = false): Promise<void> {
  if (!force && agent === governAgent && governPolicy) return;
  if (agent !== governAgent) {
    // A fresh endpoint gets a fresh danger zone: nothing typed, no stale outcome.
    $<HTMLInputElement>("d-confirm").value = "";
    $("d-status").textContent = "";
    updateRevokeArmed();
  }
  governAgent = agent;
  governPolicy = null;
  $("g-status").textContent = "loading…";
  renderGovern();
  const res = await send<{ ok: true; policy: DevicePolicy } | { ok: false; error: string; nokey?: boolean }>({
    kind: "getDevicePolicy",
    agent,
  });
  if (governAgent !== agent) return; // switched away while loading
  const err = $("g-error");
  $("g-status").textContent = "";
  if (!res.ok) {
    err.textContent = `Could not load this endpoint's policy: ${res.error}`;
    err.hidden = false;
    $("g-body").hidden = true;
    return;
  }
  err.hidden = true;
  governPolicy = res.policy;
  renderGovern();
}

/**
 * Apply one policy change: mutate the model, paint optimistically, send
 * the whole-value write, then adopt the engine's read-back as the truth.
 * A refused write reloads the real policy so the optimistic paint never
 * stands.
 */
async function applyGovern(mutate: (cur: DevicePolicy) => DevicePolicy | null): Promise<void> {
  if (governBusy || !governAgent || !governPolicy) return;
  const agent = governAgent;
  const next = mutate(governPolicy);
  if (!next) return;
  governBusy = true;
  governPolicy = next;
  renderGovern();
  $("g-status").textContent = "applying…";
  const res = await send<{ ok: true; policy: DevicePolicy } | { ok: false; error: string; nokey?: boolean }>({
    kind: "setDevicePolicy",
    agent,
    policy: next,
  });
  governBusy = false;
  if (governAgent !== agent) return; // switched away while applying
  if (res.ok) {
    governPolicy = res.policy;
    $("g-status").textContent = "applied, in force now";
    renderGovern();
  } else {
    await refreshGovern(agent, true);
    $("g-status").textContent = `⚠ ${res.error}`;
  }
}

function renderGovern(): void {
  const body = $("g-body");
  const p = governPolicy;
  if (!p) {
    body.hidden = true;
    return;
  }
  body.hidden = false;
  const busy = governBusy;

  const preview = currentPreview(p);
  renderConsequence(p, preview);

  const active = presetOf(p.bundles);
  $("g-presets").replaceChildren(
    ...PRESETS.map((info) => {
      const card = el("button", `preset-card${info.id === active ? " active" : ""}`) as HTMLButtonElement;
      card.type = "button";
      card.setAttribute("aria-pressed", info.id === active ? "true" : "false");
      card.append(el("div", "pc-label", info.label), el("div", "pc-promise", info.promise));
      // The consequence of CHOOSING this preset, on this endpoint's own
      // traffic. A preset that cannot show what it would change is a
      // checkbox asking to be trusted; one that says "blocks 2 of the 47
      // destinations you reached" is a decision a person can actually make.
      if (preview) {
        const want = info.id === "custom" ? p.bundles : (bundlesForPreset(info.id) ?? p.bundles);
        const roll = previewPreset(want, preview, governFactHosts.length);
        const line = el("div", "pc-consequence");
        const bar = ratioBar(roll.matched.length, Math.max(1, roll.considered - roll.unknown), {
          width: 132,
          height: 4,
          tone: roll.matched.length > 0 ? "hot" : "ok",
        });
        if (bar) {
          const mark = el("div", "pc-bar");
          mark.appendChild(bar);
          line.appendChild(mark);
        }
        line.appendChild(el("div", "pc-count", presetSentence(roll)));
        card.appendChild(line);
      }
      // Custom is a state you reach by mixing below, not a button target.
      card.disabled = busy || info.id === "custom";
      if (info.id !== "custom") {
        card.addEventListener("click", () => {
          void applyGovern((cur) => {
            const want = bundlesForPreset(info.id);
            return want ? { ...cur, bundles: want } : null;
          });
        });
      }
      return card;
    }),
  );

  const bundleRows: HTMLElement[] = BUNDLE_INFO.map((b) => {
    // The disclosure of matched destinations is a SIBLING of the label, not
    // a child: nested inside it, every click on "which ones" would also toggle
    // the checkbox it sits under.
    const row = el("div", "bundle-row");
    const label = el("label", "bundle");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = p.bundles.includes(b.id);
    box.disabled = busy;
    box.addEventListener("change", () => {
      void applyGovern((cur) => ({
        ...cur,
        bundles: box.checked ? [...cur.bundles.filter((x) => x !== b.id), b.id] : cur.bundles.filter((x) => x !== b.id),
      }));
    });
    label.append(box, el("span", "b-label", b.label), el("span", "b-desc", b.description));
    row.appendChild(label);
    const mark = preview ? previewMark(preview[b.id]) : null;
    if (mark) row.appendChild(mark);
    else if (governFactsPending) row.appendChild(el("div", "b-preview", "checking your destinations..."));
    return row;
  });
  if (p.passthrough.length > 0) {
    // Honesty: settings from another surface (console/CLI) we don't model
    // here ride along untouched on every write; say so instead of hiding it.
    bundleRows.push(
      el("div", "w-note", `${p.passthrough.length} advanced setting(s) from the console are preserved untouched.`),
    );
  }
  $("g-bundles").replaceChildren(...bundleRows);

  $("g-geo-chips").replaceChildren(
    ...p.geoDeny.map((cc) => {
      const chip = el("span", "g-chip");
      const remove = el("button", undefined, "×") as HTMLButtonElement;
      remove.type = "button";
      remove.title = `Unblock ${countryName(cc)}`;
      remove.disabled = busy;
      remove.addEventListener("click", () => {
        void applyGovern((cur) => ({ ...cur, geoDeny: cur.geoDeny.filter((c) => c !== cc) }));
      });
      chip.append(document.createTextNode(`${flagEmoji(cc)} ${countryName(cc)} `), el("span", "cc", cc), remove);
      return chip;
    }),
  );

  // What the country list currently costs, and what each further country
  // would cost, both read off the destinations already on this page.
  const geoCost = $("g-geo-cost");
  const geoMark = preview ? previewMark(preview[GEO_PREVIEW_ID]) : null;
  if (p.geoDeny.length > 0 && geoMark) {
    geoCost.replaceChildren(...geoMark.childNodes);
    geoCost.hidden = false;
  } else {
    geoCost.replaceChildren();
    geoCost.hidden = true;
  }
  renderGeoSuggestions(p, busy);

  const def = $<HTMLSelectElement>("g-default");
  def.value = p.defaultAction;
  def.disabled = busy;

  $("g-rules").replaceChildren(
    ...p.rules.map((r) => {
      const row = el("div", "w-ledger-row");
      const remove = el("button", "cell-rule-remove", "×") as HTMLButtonElement;
      remove.type = "button";
      remove.title = `Remove the ${r.action} rule for ${r.value}`;
      remove.disabled = busy;
      remove.addEventListener("click", () => {
        void applyGovern((cur) => ({
          ...cur,
          rules: cur.rules.filter((x) => !(x.value === r.value && x.action === r.action)),
        }));
      });
      row.append(
        el("span", `w-chip ${r.action === "block" ? "high" : "ok"} cell-action`, r.action.toUpperCase()),
        el("span", "cell-host", r.value),
        remove,
      );
      return row;
    }),
  );
  $("g-rules-empty").hidden = p.rules.length > 0;
}

/**
 * The countries this endpoint's traffic actually lands in, busiest first,
 * each one a single click away from being blocked and each one carrying the
 * price of that click.
 *
 * The country blocker was a text box over the whole atlas, which asks a
 * reader to already know the answer. Every count here comes from the
 * destination list this page has already drawn, so the whole row costs no
 * request; a country the graph could not place for a destination is not
 * guessed at, it simply does not appear.
 */
function renderGeoSuggestions(p: DevicePolicy, busy: boolean): void {
  const box = $("g-geo-suggest");
  const tally = new Map<string, number>();
  let placed = 0;
  for (const h of governFactHosts) {
    // EVERY country the name resolves into, from the same read enforcement
    // geolocates against. The enrichment column beside it holds one country
    // (the ASN's registration country), and a pill built from that would
    // quote a different number from the one the block would actually cost.
    const ccs = governFacts?.byHost[h.host.toLowerCase()]?.countries ?? [];
    if (ccs.length === 0) continue;
    placed++;
    for (const cc of ccs) tally.set(cc, (tally.get(cc) ?? 0) + 1);
  }
  const ranked = [...tally.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8);
  if (ranked.length === 0) {
    box.hidden = true;
    box.replaceChildren();
    return;
  }
  box.hidden = false;
  box.replaceChildren(
    el(
      "div",
      "w-note",
      `Where this endpoint's traffic lands, ${placed} of ${governFactHosts.length} destinations placed. ` +
        "A destination can land in several countries at once, and blocking any one of them stops it:",
    ),
    ...ranked.map(([cc, n]) => {
      const on = p.geoDeny.includes(cc);
      const btn = el("button", `geo-pill${on ? " on" : ""}`) as HTMLButtonElement;
      btn.type = "button";
      btn.disabled = busy || on;
      btn.title = on
        ? `${countryName(cc)} is blocked: ${n} of these destinations land there and do not resolve`
        : `Block ${countryName(cc)}: ${n} of these ${governFactHosts.length} destinations land there and would stop resolving`;
      btn.append(
        el("span", "gp-flag", flagEmoji(cc)),
        el("span", "gp-name", countryName(cc)),
        el("span", "gp-count", String(n)),
      );
      if (!on) {
        btn.addEventListener("click", () => {
          void applyGovern((cur) => (cur.geoDeny.includes(cc) ? null : { ...cur, geoDeny: [...cur.geoDeny, cc] }));
        });
      }
      return btn;
    }),
  );
}

/**
 * The headline of the governor: what the settings CURRENTLY on cost this
 * endpoint, over its own destinations, drawn as one bar.
 *
 * Three segments, never two: blocked by what is on, reaching the endpoint
 * untouched, and not in the graph at all. The third segment is the one that
 * makes the first two honest, so it is drawn in its own muted colour rather
 * than folded into either neighbour.
 */
function renderConsequence(p: DevicePolicy, preview: Record<string, BundlePreview> | null): void {
  const row = $("g-consequence");
  const head = $("g-cons-head");
  const note = $("g-cons-note");
  const mark = $("g-cons-mark");

  if (governFactHosts.length === 0) {
    // No destinations is not "nothing was blocked": it is a log with nothing
    // in it yet, and those are different facts. Drawing a bar of zeroes here
    // would say the settings were measured and found harmless, which is a
    // claim nobody made. Say the true thing instead.
    row.hidden = false;
    mark.replaceChildren();
    head.textContent = "Nothing to measure these settings against yet";
    note.textContent =
      "This endpoint has no recorded destinations in the window, so there is no traffic to test " +
      "the protections below on. The settings still apply the moment it starts resolving.";
    return;
  }
  row.hidden = false;

  if (!preview) {
    head.textContent = governFactsPending ? "Checking your destinations..." : "";
    note.textContent = governFactsPending
      ? `Reading the ${governFactHosts.length} destinations this endpoint reached against the graph.`
      : "";
    mark.replaceChildren();
    return;
  }

  const on = [...p.bundles, ...(p.geoDeny.length > 0 ? [GEO_PREVIEW_ID] : [])];
  const roll = previewPreset(on, preview, governFactHosts.length);
  const checked = roll.considered - roll.unknown;
  const blocked = roll.matched.length;

  const bar = stackShare(
    [
      { label: "blocked by what is on", value: blocked, color: "var(--w-v-high)" },
      // NOT the verdict green. That hue is reserved for safety meaning, and
      // a destination reaching this endpoint is not a statement that it is
      // safe - it is a statement that nothing currently on stopped it.
      { label: "reaches this endpoint", value: Math.max(0, checked - blocked), color: "var(--w-accent)" },
      { label: "not in the graph, so not checked", value: roll.unknown, color: "var(--w-line)" },
    ],
    {
      width: 260,
      height: 10,
      title: `${blocked} blocked, ${Math.max(0, checked - blocked)} reaching this endpoint, ${roll.unknown} not in the graph`,
    },
  );
  mark.replaceChildren(bar ?? el("span", "w-note", "nothing measured yet"));

  if (roll.error) {
    // Nothing was measured, so nothing is claimed. The bar above still draws
    // the whole list as "not checked" grey rather than as green.
    head.textContent = "These settings could not be checked against your traffic";
    note.textContent =
      `The read did not complete: ${roll.error}. Nothing on this page is claiming that these ` +
      `${governFactHosts.length} destinations are clear; it is claiming that we could not find out.`;
    return;
  }
  head.textContent =
    blocked === 0
      ? `Nothing currently on blocks any of the ${checked} destinations checked`
      : `${blocked} of ${checked} destinations checked would not resolve`;
  const parts: string[] = [
    `Measured over the ${governFactHosts.length} busiest destinations in this endpoint's log.`,
  ];
  if (roll.unknown > 0) {
    parts.push(
      `${roll.unknown} of them are not in the graph at all, so no protection can match them and they are not counted as clear.`,
    );
  }
  if (roll.partial) {
    parts.push(
      "Brand-new domains are not included in this count (see the reason under that protection), so the real figure can only be higher.",
    );
  }
  note.textContent = parts.join(" ");
}

function addRuleSubmit(ev: Event): void {
  ev.preventDefault();
  const input = $<HTMLInputElement>("g-rule-input");
  const action = $<HTMLSelectElement>("g-rule-action").value === "allow" ? "allow" : "block";
  const domain = normalizeDomain(input.value);
  if (!domain) {
    $("g-status").textContent = "⚠ that does not look like a domain";
    return;
  }
  input.value = "";
  void applyGovern((cur) => {
    if (cur.rules.length >= MAX_POLICY_ENTRIES) {
      $("g-status").textContent = `⚠ the rule list is full (${MAX_POLICY_ENTRIES})`;
      return null;
    }
    // One rule per name: re-adding a domain replaces its previous action.
    return { ...cur, rules: [...cur.rules.filter((r) => r.value !== domain), { action, value: domain }] };
  });
}

function addGeoSubmit(ev: Event): void {
  ev.preventDefault();
  const input = $<HTMLInputElement>("g-geo-input");
  const cc = resolveCountry(input.value);
  if (!cc) {
    $("g-status").textContent = "⚠ name a country or give its two-letter ISO code";
    return;
  }
  input.value = "";
  void applyGovern((cur) => {
    if (cur.geoDeny.includes(cc)) return null;
    if (cur.geoDeny.length >= MAX_GEO_CODES) {
      $("g-status").textContent = `⚠ the country list is full (${MAX_GEO_CODES})`;
      return null;
    }
    return { ...cur, geoDeny: [...cur.geoDeny, cc] };
  });
}

// --------------------------------------------------------- danger zone

function updateRevokeArmed(): void {
  const phrase = (governLabel.trim() || "revoke").toLowerCase();
  const typed = $<HTMLInputElement>("d-confirm").value.trim().toLowerCase();
  $<HTMLButtonElement>("d-revoke").disabled = typed !== phrase;
}

async function revokeClick(): Promise<void> {
  const agent = currentAgent;
  if (!agent || $<HTMLButtonElement>("d-revoke").disabled) return;
  $<HTMLButtonElement>("d-revoke").disabled = true;
  const status = $("d-status");
  status.textContent = "Revoking: withdrawing the address, reverse-DNS and egress credentials…";
  const res = await send<{ ok: true; revoked: RevokeResult } | { ok: false; error: string; nokey?: boolean }>({
    kind: "revokeEndpoint",
    agent,
  });
  if (!res.ok) {
    status.textContent = `⚠ ${res.error}`;
    updateRevokeArmed();
    return;
  }
  if (res.revoked.status === "not_found") {
    // Nothing was revoked: the plane holds no such agent for this account
    // (revoked already, from here or elsewhere). Not a success and not a
    // fault worth retrying. The roster is stale, so rebuild it.
    $<HTMLInputElement>("d-confirm").value = "";
    currentAgent = null;
    governAgent = null;
    governPolicy = null;
    await populatePicker();
    if ($<HTMLSelectElement>("e-picker").options.length === 0) {
      switchView("fleet");
    }
    status.textContent = `Nothing was revoked: ${
      res.revoked.message ??
      "no endpoint of yours matches this one. It was revoked already or is not in this account."
    }`;
    return;
  }
  if (res.revoked.status !== "revoked") {
    status.textContent = `The control plane answered "${res.revoked.status}"; nothing was changed.`;
    updateRevokeArmed();
    return;
  }
  $<HTMLInputElement>("d-confirm").value = "";
  // The roster shrank: rebuild the picker (it lands on the first remaining
  // endpoint) and refresh the identity chip in case the browser revoked
  // itself. With nothing left, the fleet view says so honestly.
  currentAgent = null;
  governAgent = null;
  governPolicy = null;
  await populatePicker();
  await refreshEgress();
  if ($<HTMLSelectElement>("e-picker").options.length === 0) {
    switchView("fleet");
  }
  status.textContent = "Endpoint revoked. Its /128 is retired everywhere.";
}

// -------------------------------------------------- identity + egress
//
// ONE control, mounted from shared/protect-control.ts - the same module,
// the same markup and the same words the panel offers. The dashboard used
// to carry its own two-step version of this (an "Enroll this browser"
// button plus a separate routing toggle), which is the idiom the panel
// replaced: one thing to do, two places to do it, and two vocabularies
// for it. Nothing here re-implements the control; it only adds the one
// affordance that belongs to this surface (the browser is a fleet endpoint
// like any other, so its policy and revoke live one click away in the
// endpoint view) and keeps the topbar chip in step.

let protectControl: ProtectControl | null = null;

function governAction(s: EgressStatus): HTMLElement[] {
  const agent = s.agent;
  if (!agent || !s.enrolled) return [];
  const govern = el("button", "w-btn small", "Govern this browser") as HTMLButtonElement;
  govern.type = "button";
  govern.addEventListener("click", () => {
    void openEndpoint(agent);
  });
  return [govern];
}

async function refreshEgress(): Promise<void> {
  protectControl ??= mountProtectControl({
    root: $("identity-control"),
    extraActions: governAction,
    onStatus: (s, verified) => {
      renderIdentityChip(s, verified);
    },
  });
  await protectControl.refresh();
}

/**
 * The topbar chip: the same identity fact the control states, said once
 * more where a reader who has scrolled away can still see it. It reads
 * from the control's own status rather than making its own RDAP call, so
 * the two can never disagree about what this browser is.
 */
function renderIdentityChip(s: EgressStatus, verified: boolean | null): void {
  const chip = $("identity-chip");
  if (!s.enrolled || !s.address) {
    chip.className = "w-chip unknown";
    chip.textContent = "NOT ON THE WHISPER NETWORK";
    chip.title = "Protect this browser below to give it its own verifiable Whisper identity.";
    return;
  }
  const routed = s.on ? "routed through it" : "identity reserved; routing off";
  if (verified === true) {
    chip.className = "w-chip ok";
    chip.textContent = "VERIFIED WHISPER ENDPOINT";
    chip.title = `${s.fqdn ?? s.address} (${routed})`;
  } else if (verified === false) {
    chip.className = "w-chip unknown";
    chip.textContent = "IDENTITY NOT VERIFIED";
    chip.title = `${s.address} (${routed})`;
  } else {
    chip.className = "w-chip accent";
    chip.textContent = "VERIFYING…";
    chip.title = `${s.address} (${routed})`;
  }
}

// --------------------------------------------------------------- shell

type ViewName = "browser" | "fleet" | "endpoint";

function setFeedBadge(mode: "live" | "polling" | "offline", updatedAt: number | null): void {
  const badge = $("feed-status");
  badge.className = `w-live ${mode}`;
  $("feed-label").textContent =
    mode === "live" ? "updating live" : mode === "polling" ? `polling${updatedAt ? `, updated ${agoLabel(updatedAt)}` : ""}` : "offline";
}

// ------------------------------------------------------------- the pulse

/**
 * The live mark, and the rule it carries.
 *
 * A surface that animates while nothing is happening teaches a reader that
 * motion here is decoration, and once they have learned that, no motion on
 * the surface can ever mean anything again. So this track is driven ONLY
 * from real arrivals: one mark per committed navigation, one per completed
 * fleet poll. When arrivals stop it goes quiet and SAYS it has gone quiet,
 * rather than idling in a way that looks like work.
 */
let pulse: PulseHandle | null = null;
let lastArrival = 0;
/** Newest fleet activity timestamp already accounted for, so a poll that
 *  re-reads the same rows is not counted a second time. */
let lastFleetEvent = 0;
let quietTimer: ReturnType<typeof setInterval> | null = null;

/** How long without an arrival before the track admits it is quiet. */
const QUIET_AFTER_MS = 75_000;

function mountPulse(): void {
  pulse = pulseTrack({ width: 64, height: 14, title: "one mark per arriving event" });
  $("live-pulse").replaceChildren(pulse.el);
  pulse.idle();
  quietTimer = setInterval(() => {
    if (!pulse) return;
    if (lastArrival === 0 || Date.now() - lastArrival > QUIET_AFTER_MS) pulse.idle();
  }, 10_000);
  void quietTimer;
}

/** Record that something really arrived. Never called on a timer alone. */
function arrived(tone: "accent" | "hot" = "accent"): void {
  lastArrival = Date.now();
  pulse?.push(tone);
}

let view: ViewName = "browser";

function switchView(next: ViewName): void {
  view = next;
  for (const v of ["browser", "fleet", "endpoint"] as const) {
    $(`view-${v}`).hidden = v !== next;
    const tab = $(`tab-${v}`);
    tab.classList.toggle("active", v === next);
    tab.setAttribute("aria-selected", v === next ? "true" : "false");
  }
  window.location.hash = next;
  if (next === "browser") {
    setFeedBadge("live", null);
    void refreshBrowser();
    void refreshEgress();
  } else if (next === "fleet") {
    setFeedBadge("polling", null);
    void refreshFleet();
  } else {
    setFeedBadge("polling", null);
    void populatePicker();
  }
}

async function startSignIn(statusId: string): Promise<void> {
  const status = $(statusId);
  status.hidden = false;
  status.textContent = "Opening the console…";
  await send({ kind: "signInStart" });
  for (;;) {
    const res = await send<{ ok: true; device: { phase: string; userCode: string | null; message: string | null } }>({
      kind: "signInStatus",
    });
    if (!res.ok) return;
    if (res.device.phase === "waiting") {
      status.textContent = `Approve the sign-in in the console tab (code ${res.device.userCode ?? "…"}).`;
    } else if (res.device.phase === "approved") {
      status.textContent = "Signed in.";
      switchView(view);
      return;
    } else if (res.device.phase === "expired" || res.device.phase === "error") {
      status.textContent = res.device.message ?? "Sign-in did not complete. Try again.";
      return;
    } else {
      return;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
}

let scaleTimer: ReturnType<typeof setInterval> | null = null;

function init(): void {
  $("tab-browser").addEventListener("click", () => switchView("browser"));
  $("tab-fleet").addEventListener("click", () => switchView("fleet"));
  $("tab-endpoint").addEventListener("click", () => switchView("endpoint"));
  $("fleet-signin").addEventListener("click", () => {
    void startSignIn("fleet-device-status");
  });
  $("e-signin").addEventListener("click", () => {
    void startSignIn("fleet-device-status");
  });
  $<HTMLSelectElement>("e-picker").addEventListener("change", (ev) => {
    void refreshEndpoint((ev.target as HTMLSelectElement).value);
  });

  // The governor's persistent controls (per-render elements wire inline).
  $<HTMLSelectElement>("g-default").addEventListener("change", (ev) => {
    const v = (ev.target as HTMLSelectElement).value === "deny" ? "deny" : "allow";
    void applyGovern((cur) => (cur.defaultAction === v ? null : { ...cur, defaultAction: v }));
  });
  $("g-rule-form").addEventListener("submit", addRuleSubmit);
  $("g-geo-form").addEventListener("submit", addGeoSubmit);
  $("d-confirm").addEventListener("input", updateRevokeArmed);
  $("d-revoke").addEventListener("click", () => {
    void revokeClick();
  });
  $("g-countries").replaceChildren(
    ...countryOptions().map((c) => {
      const opt = document.createElement("option");
      opt.value = `${c.name} (${c.iso})`;
      return opt;
    }),
  );

  // Live nudges: the background pokes this port on every committed
  // navigation; the browser view repaints (debounced) while the fleet
  // and endpoint views poll on their own honest cadence.
  const port = chrome.runtime.connect({ name: "dashboard" });
  let navTimer: ReturnType<typeof setTimeout> | null = null;
  port.onMessage.addListener((msg: { kind?: string }) => {
    if (msg.kind !== "nav") return;
    // The mark goes up for every committed navigation, whichever view is
    // open: the event happened, and a reader on the fleet tab watching the
    // track go still would otherwise conclude the browser had stopped.
    arrived();
    if (view !== "browser") return;
    if (navTimer) clearTimeout(navTimer);
    navTimer = setTimeout(() => {
      void refreshBrowser();
    }, 700);
  });

  fleetTimer = setInterval(() => {
    if (document.hidden) return;
    if (view === "fleet") void refreshFleet();
    else if (view === "endpoint" && currentAgent) void refreshEndpoint(currentAgent);
  }, 15_000);
  void fleetTimer;
  void endpointHosts;

  // A <canvas> keeps whatever ink it was drawn with, so a colour-scheme
  // flip has to redraw it: without this the donut, gauge and constellation
  // would sit in the old palette until the next poll.
  onThemeChange(() => {
    switchView(view);
  });

  // The scale band is about the product rather than about this browser, so
  // it is loaded once and does not repaint on every navigation nudge. Its
  // own memo (background/scale.ts) matches the endpoint's 30s cache, so a
  // periodic refresh costs at most one request every half minute.
  mountPulse();
  void loadScaleBand();
  // The tier meter only earns its place while the reader has no account:
  // with one, the identity control above it is the whole story.
  void (async () => {
    // getSettings is the one message that reports the key's presence
    // without spending a graph call to find out.
    const st = await send<{ ok: true; signedIn: boolean }>({ kind: "getSettings" });
    if (st.ok && st.signedIn) return;
    await mountTierMeter({
      root: $("tier-meter"),
      label: $("tier-label"),
      count: $("tier-count"),
      fill: $("tier-fill"),
      note: $("tier-note"),
    });
  })();
  scaleTimer = setInterval(() => {
    if (!document.hidden) void loadScaleBand();
  }, 60_000);
  void scaleTimer;

  const hash = window.location.hash.replace("#", "");
  switchView(hash === "fleet" || hash === "endpoint" ? (hash as ViewName) : "browser");
}

init();
