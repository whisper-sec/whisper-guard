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
import { EGRESS_REQUEST } from "../shared/config";
import { IS_FIREFOX } from "../shared/engine";
import type { EgressStatus, Enrollment, FleetEndpoint } from "../shared/types";
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
}

function renderTiles(container: HTMLElement, tiles: TileSpec[]): void {
  container.replaceChildren(
    ...tiles.map((t) => {
      const tile = el("div", `w-tile${t.hot ? " flagged-hot" : ""}`);
      tile.append(el("div", "w-label", t.label), el("div", "w-stat", t.value));
      return tile;
    }),
  );
}

function totalsTiles(totals: ReportTotals): TileSpec[] {
  return [
    { label: "Destinations", value: String(totals.destinations) },
    { label: "Companies", value: String(totals.companies) },
    { label: "Countries", value: String(totals.countries) },
    { label: "Networks", value: String(totals.networks) },
    { label: "Lookups", value: String(totals.lookups) },
    { label: "Flagged", value: String(totals.flagged), hot: totals.flagged > 0 },
  ];
}

// ------------------------------------------------------------ donut

function renderDonut(canvas: HTMLCanvasElement, legendEl: HTMLElement, hosts: ReportHost[]): void {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const cats = tallyCategory(hosts);
  const total = cats.reduce((s, [, n]) => s + n, 0);
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  const cx = W / 2;
  const cy = H / 2;
  const r = Math.min(W, H) / 2 - 6;
  let a = -Math.PI / 2;
  for (const [cat, n] of cats) {
    const sweep = total > 0 ? (n / total) * 2 * Math.PI : 0;
    ctx.beginPath();
    ctx.arc(cx, cy, r, a, a + sweep);
    ctx.arc(cx, cy, r * 0.62, a + sweep, a, true);
    ctx.closePath();
    ctx.fillStyle = CATEGORY_HEX[cat];
    ctx.fill();
    a += sweep;
  }
  ctx.fillStyle = "#e8e8f2";
  ctx.font = "300 26px system-ui";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(String(total), cx, cy - 6);
  ctx.font = "10px ui-monospace, monospace";
  ctx.fillStyle = "#62627a";
  ctx.fillText("DESTINATIONS", cx, cy + 14);

  legendEl.replaceChildren(
    ...cats.slice(0, 8).map(([cat, n]) => {
      const row = el("div", "legend-row");
      const dot = el("span", "w-dot");
      dot.style.background = CATEGORY_HEX[cat];
      row.append(dot, el("span", "name", CATEGORY_LABEL[cat]), el("span", "n", String(n)));
      return row;
    }),
  );
}

// ------------------------------------------------------------- bars

function renderBars(
  container: HTMLElement,
  rows: { name: string; count: number; color?: string; flag?: string }[],
  max: number,
): void {
  container.replaceChildren(
    ...rows.map((r) => {
      const row = el("div", "w-bar-row");
      const name = el("span", "w-bar-name", r.flag ? `${r.flag} ${r.name}` : r.name);
      name.title = r.name;
      const track = el("div", "w-bar-track");
      const fill = el("div", "w-bar-fill");
      fill.style.width = `${max > 0 ? Math.max(3, Math.round((r.count / max) * 100)) : 0}%`;
      if (r.color) fill.style.background = r.color;
      track.appendChild(fill);
      row.append(name, track, el("span", "w-bar-count", String(r.count)));
      return row;
    }),
  );
}

function renderOwnerBars(container: HTMLElement, hosts: ReportHost[]): void {
  const owners = tallyOwners(hosts).slice(0, 10);
  const max = owners[0]?.count ?? 0;
  renderBars(
    container,
    owners.map((o) => ({ name: o.owner, count: o.count, color: CATEGORY_HEX[o.category] })),
    max,
  );
}

// TODO(fleet-map): a small geo dot-map of where this browser / the fleet
// actually goes. The data already exists (ReportHost.country + .asn from the
// graph enrichment feeding tallyCountry below); the render would be one
// equirectangular canvas next to the country bars, no new permissions and no
// new network. Deferred rather than half-built: a map that renders badly is
// worse than bars that render well.
function renderCountryBars(container: HTMLElement, hosts: ReportHost[]): void {
  const countries = tallyCountry(hosts).slice(0, 10);
  const max = countries[0]?.[1] ?? 0;
  renderBars(
    container,
    countries.map(([cc, n]) => ({ name: cc, count: n, flag: flagEmoji(cc) })),
    max,
  );
}

// ------------------------------------------------------------ ledger

function hostRow(h: ReportHost, fresh: Set<string>, onClick?: (h: ReportHost) => void): HTMLElement {
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
    el("span", "cell-q", String(h.q)),
  );
  if (onClick) {
    row.style.cursor = "pointer";
    row.addEventListener("click", () => onClick(h));
  }
  return row;
}

function renderHostLedger(
  container: HTMLElement,
  hosts: ReportHost[],
  fresh: Set<string>,
  onClick?: (h: ReportHost) => void,
): void {
  container.replaceChildren(...hosts.map((h) => hostRow(h, fresh, onClick)));
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
    renderTiles($("b-tiles"), totalsTiles(totals));
    renderDonut($<HTMLCanvasElement>("b-donut"), $("b-donut-legend"), hosts);
    renderOwnerBars($("b-owners"), hosts);
    renderCountryBars($("b-countries"), hosts);

    const conc = concentration(hosts);
    const concCard = $("b-conc-card");
    if (conc.top.length >= 2 && totals.destinations >= 5) {
      concCard.hidden = false;
      const line = $("b-concentration");
      line.replaceChildren();
      line.append(document.createTextNode(""));
      const strong = el("strong", undefined, `${conc.pct}%`);
      line.append(strong, document.createTextNode(` of where this browser goes is ${conc.top.join(", ")}.`));
    } else {
      concCard.hidden = true;
    }

    // Rows whose lookup count grew since the last paint flash once.
    const fresh = new Set<string>();
    for (const h of hosts) {
      const prev = lastBrowserHosts.get(h.host);
      if (prev !== undefined && h.q > prev) fresh.add(h.host);
    }
    lastBrowserHosts = new Map(hosts.map((h) => [h.host, h.q]));
    renderHostLedger($("b-ledger"), hosts, fresh);
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
  card.append(label, el("div", "rc-addr", e.address), meta);
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
  renderDonut($<HTMLCanvasElement>("f-donut"), $("f-donut-legend"), f.hosts);
  renderOwnerBars($("f-owners"), f.hosts);
  renderCountryBars($("f-countries"), f.hosts);

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

function drawGauge(canvas: HTMLCanvasElement, score: number, level: string): void {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  const cx = W / 2;
  const cy = H / 2;
  const r = Math.min(W, H) / 2 - 8;
  ctx.lineWidth = 10;
  ctx.lineCap = "round";
  ctx.strokeStyle = "#16162a";
  ctx.beginPath();
  ctx.arc(cx, cy, r, -Math.PI / 2, 1.5 * Math.PI);
  ctx.stroke();
  const color = level === "strong" ? "#10b981" : level === "partial" ? "#f59e0b" : "#ef4444";
  ctx.strokeStyle = color;
  ctx.beginPath();
  ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + (score / 100) * 2 * Math.PI);
  ctx.stroke();
  ctx.fillStyle = "#e8e8f2";
  ctx.font = "300 30px system-ui";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(String(score), cx, cy - 4);
  ctx.font = "9px ui-monospace, monospace";
  ctx.fillStyle = "#62627a";
  ctx.fillText("OF 100", cx, cy + 16);
}

function drawConstellation(canvas: HTMLCanvasElement, d: EndpointDetail): void {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.font = "10px ui-monospace, monospace";

  const top = d.topHosts.slice(0, 9);
  const cx = 80;
  const cy = H / 2;

  // The device node.
  ctx.fillStyle = "#8a5cc7";
  ctx.beginPath();
  ctx.arc(cx, cy, 9, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = "#e8e8f2";
  ctx.textAlign = "center";
  const label = d.endpoint.label.length > 18 ? `${d.endpoint.label.slice(0, 17)}…` : d.endpoint.label;
  ctx.fillText(label, cx, cy - 16);

  if (top.length === 0) {
    ctx.fillStyle = "#62627a";
    ctx.fillText("no destinations in the last 24h", W / 2, cy);
    return;
  }

  top.forEach((h, i) => {
    const y = (H / (top.length + 1)) * (i + 1);
    const hx = W * 0.42;
    const flagged = isFlagged(h.verdict);
    // Edge device -> hostname.
    ctx.strokeStyle = flagged ? "rgba(239,68,68,0.7)" : "#2a2a44";
    ctx.lineWidth = flagged ? 1.6 : 1;
    ctx.beginPath();
    ctx.moveTo(cx + 9, cy);
    ctx.lineTo(hx - 6, y);
    ctx.stroke();
    // Hostname node.
    ctx.fillStyle = flagged ? "#ef4444" : CATEGORY_HEX[h.category];
    ctx.beginPath();
    ctx.arc(hx, y, 4.5, 0, 2 * Math.PI);
    ctx.fill();
    ctx.fillStyle = flagged ? "#ef4444" : "#9a9ab0";
    ctx.textAlign = "left";
    const hostLabel = h.host.length > 30 ? `${h.host.slice(0, 29)}…` : h.host;
    ctx.fillText(hostLabel, hx + 9, y + 3);

    // Hostname -> network/owner chain, when resolved.
    const net = h.asn ?? h.prefix;
    if (net) {
      const nx = W * 0.72;
      ctx.strokeStyle = "#2a2a44";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(hx + 6, y);
      ctx.lineTo(nx - 6, y);
      ctx.stroke();
      ctx.fillStyle = "#62627a";
      ctx.beginPath();
      ctx.arc(nx, y, 3.5, 0, 2 * Math.PI);
      ctx.fill();
      const ownerLabel = `${net} ${shortOwner(h.owner)}`;
      ctx.fillStyle = "#62627a";
      ctx.fillText(ownerLabel.length > 30 ? `${ownerLabel.slice(0, 29)}…` : ownerLabel, nx + 8, y + 3);
    }
  });
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

  $("e-address").textContent = d.endpoint.address;
  const state = $("e-state");
  state.textContent = d.endpoint.state.toUpperCase();
  state.className = `w-chip ${d.endpoint.state === "active" ? "ok" : "unknown"}`;
  const rdap = $<HTMLAnchorElement>("e-rdap");
  rdap.href = d.rdapUrl;
  rdap.textContent = "RDAP registration";
  $("e-fqdn").textContent = d.endpoint.fqdn ?? "";

  const c = d.counters;
  renderTiles($("e-tiles"), [
    { label: "DNS queries", value: c?.dnsQueries !== null && c ? String(c.dnsQueries) : "-" },
    { label: "Blocked", value: c?.dnsBlocked !== null && c ? String(c.dnsBlocked) : "-", hot: (c?.dnsBlocked ?? 0) > 0 },
    { label: "NXDOMAIN", value: c?.dnsNxdomain !== null && c ? String(c.dnsNxdomain) : "-" },
    { label: "Connections", value: c?.connectionsTotal !== null && c ? String(c.connectionsTotal) : "-" },
    { label: "Bytes up", value: fmtBytes(c?.bytesUp ?? null) },
    { label: "Bytes down", value: fmtBytes(c?.bytesDown ?? null) },
    { label: "Last seen", value: c?.lastSeen ? agoLabel(c.lastSeen) : "-" },
  ]);

  drawGauge($<HTMLCanvasElement>("e-gauge"), d.health.score, d.health.level);
  $("e-health-headline").textContent =
    d.health.revoked ? "Revoked" : d.health.level === "strong" ? "Strongly trusted" : d.health.level === "partial" ? "Partially verified" : "Unverified";
  $("e-factors").replaceChildren(...d.health.factors.map(factorRow));
  $("e-threat-note").textContent = d.health.threatNote ?? "";

  drawConstellation($<HTMLCanvasElement>("e-constellation"), d);

  renderHostLedger($("e-hosts"), d.topHosts.slice(0, 40), new Set(), (h) => {
    void showDrill(h);
  });

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

// -------------------------------------------------- identity + egress

// The last status the page saw: lets the toggle click decide its direction
// SYNCHRONOUSLY, so chrome.permissions.request rides the user gesture with
// no message round-trip in front of it (a round-trip can outlive the
// gesture and the request then fails as "not granted" without a prompt).
let lastEgress: EgressStatus | null = null;

async function refreshEgress(): Promise<void> {
  const res = await send<{ ok: true; egress: EgressStatus }>({ kind: "egressStatus" });
  if (!res.ok) return;
  lastEgress = res.egress;
  renderIdentity(res.egress);
  renderEgress(res.egress);
  await refreshIdentityChip(res.egress);
}

/** ENROLL: the identity half. Works signed-in, no permission, no proxy. */
function renderIdentity(s: EgressStatus): void {
  const btn = $<HTMLButtonElement>("enroll-btn");
  const detail = $("identity-detail");
  detail.replaceChildren();
  if (s.enrolled && s.address) {
    btn.hidden = true;
    const line = el("div");
    line.append(
      el("span", "w-chip ok", "ENROLLED"),
      document.createTextNode(" This browser's identity: "),
      el("span", "w-ip", s.address),
    );
    detail.append(line);
    if (s.fqdn) {
      const nameLine = el("div", "w-note");
      nameLine.append(document.createTextNode("Reverse-DNS: "), el("span", "w-mono", s.fqdn));
      detail.append(nameLine);
    }
    if (s.rdapUrl) {
      const proof = el("div", "w-note");
      const a = el("a", undefined, "RDAP registration (anyone can verify this address)") as HTMLAnchorElement;
      a.href = s.rdapUrl;
      a.target = "_blank";
      a.rel = "noopener";
      proof.append(a);
      detail.append(proof);
    }
  } else {
    btn.hidden = false;
  }
}

async function enrollClick(): Promise<void> {
  const btn = $<HTMLButtonElement>("enroll-btn");
  btn.disabled = true;
  btn.textContent = "Enrolling...";
  const detail = $("identity-detail");
  // Honest pending state: register + /128 allocation is a real control-plane
  // round-trip that legitimately takes a few seconds; say so instead of
  // looking hung.
  detail.replaceChildren(
    el("div", "w-note", "Reserving this browser's identity on the Whisper network. This can take a few seconds..."),
  );
  const res = await send<{ ok: true; enrollment: Enrollment } | { ok: false; error: string }>({
    kind: "enroll",
  });
  btn.disabled = false;
  btn.textContent = "Enroll this browser";
  if (!res.ok) {
    detail.replaceChildren(el("div", "w-note", `⚠ ${res.error}`));
    return;
  }
  await refreshEgress();
}

/** PROTECT: the routing half, honest about everything in its way. */
function renderEgress(s: EgressStatus): void {
  const btn = $<HTMLButtonElement>("egress-toggle");
  const detail = $("egress-detail");
  btn.textContent = s.on ? "Turn off" : "Turn on";
  btn.className = s.on ? "w-btn" : "w-btn primary";
  detail.replaceChildren();
  if (s.on && s.address) {
    const line = el("div");
    line.append(
      el("span", "w-chip ok", "ROUTED"),
      document.createTextNode(" This browser egresses as "),
      el("span", "w-ip", s.address),
    );
    detail.append(line);
    detail.append(
      el(
        "div",
        "w-note",
        "Profile-global: every profile window rides this route. WebRTC is hardened to proxied-only on Chromium.",
      ),
    );
  } else if (s.controlledByOther) {
    // Never a dead end: name the situation, keep what works, point at the fix.
    detail.append(
      el(
        "div",
        "w-note",
        "Another extension (a VPN or proxy manager) holds this browser's proxy setting, so routing cannot engage. " +
          "Your identity and site verdicts keep working. Disable that extension's proxy control, then try again.",
      ),
    );
    if (!IS_FIREFOX) {
      const open = el("button", "w-btn small", "Open the extensions page") as HTMLButtonElement;
      open.addEventListener("click", () => {
        chrome.tabs.create({ url: "chrome://extensions" }).catch(() => undefined);
      });
      detail.append(open);
    }
  }
  if (s.error && !(s.controlledByOther && !s.on)) detail.append(el("div", "w-note", `⚠ ${s.error}`));
}

function toggleEgress(): void {
  const btn = $<HTMLButtonElement>("egress-toggle");
  const wasOn = lastEgress?.on === true;

  const finish = async (p: Promise<void>): Promise<void> => {
    try {
      await p;
    } finally {
      btn.disabled = false;
      await refreshEgress();
    }
  };

  btn.disabled = true;
  if (wasOn) {
    void finish(send({ kind: "egressDisable" }).then(() => undefined));
    return;
  }

  // The permission request is the FIRST thing on this gesture: no awaits in
  // front of it. The per-engine set is a build-time constant (config.ts):
  // `proxy` is REQUIRED on Chromium (Chrome forbids it as optional and throws
  // on request), so it is never in the requested set there; Firefox requests
  // it at runtime.
  const set = IS_FIREFOX ? EGRESS_REQUEST.firefox : EGRESS_REQUEST.chromium;
  const want: chrome.permissions.Permissions = {
    permissions: [...set.permissions],
    origins: [...set.origins],
  };
  let request: Promise<boolean>;
  try {
    request = Promise.resolve(chrome.permissions.request(want));
  } catch {
    request = Promise.resolve(false);
  }
  void finish(
    request
      .catch(() => false)
      .then(async (granted) => {
        if (!granted) {
          $("egress-detail").replaceChildren(
            el(
              "div",
              "w-note",
              "⚠ the browser did not grant the proxy permission, so routing stayed off. " +
                "Your identity and verdicts keep working; try again to grant it.",
            ),
          );
          return;
        }
        await send({ kind: "egressEnable" });
      }),
  );
}

async function refreshIdentityChip(s: EgressStatus): Promise<void> {
  const chip = $("identity-chip");
  if (!s.enrolled || !s.address) {
    chip.className = "w-chip unknown";
    chip.textContent = "NOT ON THE WHISPER NETWORK";
    chip.title = "Enroll this browser below to give it its own verifiable Whisper identity.";
    return;
  }
  chip.className = "w-chip accent";
  chip.textContent = "VERIFYING…";
  const res = await send<{ ok: true; verification: { isWhisperAgent: boolean; fqdn: string | null } | null }>({
    kind: "verifyIdentity",
    ip: s.address,
  });
  const routed = s.on ? "routed through it" : "identity reserved; routing off";
  if (res.ok && res.verification?.isWhisperAgent) {
    chip.className = "w-chip ok";
    chip.textContent = "VERIFIED WHISPER ENDPOINT";
    chip.title = `${res.verification.fqdn ?? s.address} (${routed})`;
  } else if (res.ok && res.verification) {
    chip.className = "w-chip unknown";
    chip.textContent = "IDENTITY NOT VERIFIED";
    chip.title = `${s.address} (${routed})`;
  } else {
    chip.className = "w-chip unknown";
    chip.textContent = "COULD NOT VERIFY";
    chip.title = "rdap.whisper.online unreachable";
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

function init(): void {
  $("tab-browser").addEventListener("click", () => switchView("browser"));
  $("tab-fleet").addEventListener("click", () => switchView("fleet"));
  $("tab-endpoint").addEventListener("click", () => switchView("endpoint"));
  $("egress-toggle").addEventListener("click", toggleEgress);
  $("enroll-btn").addEventListener("click", () => {
    void enrollClick();
  });
  $("fleet-signin").addEventListener("click", () => {
    void startSignIn("fleet-device-status");
  });
  $("e-signin").addEventListener("click", () => {
    void startSignIn("fleet-device-status");
  });
  $<HTMLSelectElement>("e-picker").addEventListener("change", (ev) => {
    void refreshEndpoint((ev.target as HTMLSelectElement).value);
  });

  // Live nudges: the background pokes this port on every committed
  // navigation; the browser view repaints (debounced) while the fleet
  // and endpoint views poll on their own honest cadence.
  const port = chrome.runtime.connect({ name: "dashboard" });
  let navTimer: ReturnType<typeof setTimeout> | null = null;
  port.onMessage.addListener((msg: { kind?: string }) => {
    if (msg.kind !== "nav" || view !== "browser") return;
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

  const hash = window.location.hash.replace("#", "");
  switchView(hash === "fleet" || hash === "endpoint" ? (hash as ViewName) : "browser");
}

init();
