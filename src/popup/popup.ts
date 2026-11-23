// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The click-panel answers three questions in this order and nothing else:
//
//   1. is this site safe?      one mark, one pill, ONE sentence. The
//                              sentence never restates the pill. The chips
//                              under it are plain facts, and the coverage
//                              chip says in words that it is not a score.
//   2. am I protected?         ONE control. It reserves this browser's
//                              routable Whisper identity AND routes through
//                              it, asking for the permission routing needs
//                              at the moment it is needed. There is no
//                              second step and no hand-off to another page.
//   3. what has it done?       lines, not tiles. A count nobody can act on
//                              is not worth a card and a zero is not worth
//                              a number.
//
// UNKNOWN is the honest common state and reads as "not confirmed either
// way", never as green. The answers sit under three tabs (tabs.ts): This site
// holds the verdict, the evidence and who is behind the name, This page the link check and
// the indicator scan, This browser the identity and the activity. Every tab is
// filled when the popup opens, and that holds while a check waits and on a tab
// Guard has not checked yet: This site then shows a ring with placeholders, or a
// card with a button, and the verdict replaces either in place. This site's
// footer carries the per-host privacy line saying exactly what was sent.

import { send, type BgResponse, type BrowserReport } from "../shared/messages";
import {
  WIN_CATEGORIES,
  type CandidateVerdict,
  type ChainRungKind,
  type ExplainResult,
  type GraphBand,
  type LinkScanResult,
  type GraphScale,
  type Protection,
  type Settings,
  type SiteChain,
  type TabState,
  type WhyFactor,
  type WinCategory,
  type WinsToday,
} from "../shared/types";
import type { PageScanResult } from "../background/page-scan";
import { CONSOLE_URL, GRAPH_HOST, GRAPH_TIMEOUT_MS, NAV_DEBOUNCE_MS } from "../shared/config";
import { renderChain, renderChainPending } from "../shared/chain-view";
import { initTabs } from "./tabs";
import { compact, countUp, sparkline } from "../shared/spark";
import { countMarks, timeStrip, type TimeEvent } from "../shared/viz";
import { mountTierMeter } from "../shared/tier";
import { mountProtectControl, type ProtectControl } from "../shared/protect-control";
import { CANVAS_MONO, onThemeChange, redrawWhenMonoLoads, themeColor } from "../shared/theme";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let tabId = -1;
let state: TabState | null = null;
let settings: Settings | null = null;

/** Per band: the tone of the card, mark and pill, the pill's words, and the
 *  mark's glyph (null draws the check). */
const BAND_UI: Record<GraphBand, { tone: string; chip: string; glyph: string | null }> = {
  CRITICAL: { tone: "crit", chip: "MALICIOUS - evidenced", glyph: "⬣" },
  HIGH: { tone: "high", chip: "HIGH RISK", glyph: "⬣" },
  MEDIUM: { tone: "med", chip: "SUSPICIOUS", glyph: "▲" },
  LOW: { tone: "ok", chip: "NO KNOWN THREAT", glyph: null },
  INFO: { tone: "ok", chip: "NO KNOWN THREAT", glyph: null },
  NONE: { tone: "ok", chip: "NO KNOWN THREAT", glyph: null },
  UNKNOWN: { tone: "unknown", chip: "UNKNOWN", glyph: "?" },
};

/** The popup's own names for the seven facts. The shared chain keeps its own
 *  upper-case labels, which the dashboard and the check-link page draw. */
const FACT_LABEL: Record<ChainRungKind, string> = {
  name: "Name",
  vendor: "Runs on",
  address: "Address",
  prefix: "Prefix",
  network: "Network",
  operator: "Operator",
  presence: "Present at",
};

// Labels that are a synonym of the band already on the badge. Rendering one
// turns the verdict into "NO KNOWN THREAT / No known threat / clean", which
// is the same claim three times and reads as evasion. A label that carries
// real information ("credential-phishing suspect") is always shown.
const BAND_SYNONYM =
  /^(clean|none|no known threat|unknown|benign|safe|ok|low|info|informational|malicious|suspicious|high|medium|critical)$/i;

/** The single true sentence about this site. Said once, with the graph's own
 *  label folded in when the label adds something the band does not. */
function verdictSentence(band: GraphBand, label: string | null): string {
  const l = label && !BAND_SYNONYM.test(label.trim()) ? label.trim() : null;
  const q = l ? ` (${l})` : "";
  switch (band) {
    case "CRITICAL":
      return `Listed in the graph as a known threat${q}. Do not sign in or enter card details.`;
    case "HIGH":
      return `Strong risk signals in the graph${q}. Leave this site.`;
    case "MEDIUM":
      return `Some risk signals in the graph${q}. Do not enter anything private here.`;
    case "LOW":
      return `Nothing lists this site as a threat; only low-level signals${q}.`;
    case "INFO":
      return `Nothing lists this site as a threat; only informational signals${q}.`;
    case "NONE":
      return `Nothing in the graph lists this site${q}.`;
    case "UNKNOWN":
      return `Not confirmed safe or unsafe${q}. The graph has little or no data on this name.`;
  }
}

/** One CSS custom property, resolved. The canvas cannot use var(), so the
 *  neighborhood graph reads the live theme instead of hard-coding one, and
 *  stays legible when the reader's system is in light mode. */
/** Render key/value rows as a table, DOM-built (no HTML strings). */
function renderKV(rows: Record<string, unknown>[]): Node {
  if (rows.length === 0) return document.createTextNode("The graph returned nothing for this host.");
  const table = document.createElement("table");
  for (const row of rows) {
    for (const [k, v] of Object.entries(row)) {
      if (v === null || v === undefined || v === "") continue;
      const tr = document.createElement("tr");
      const key = document.createElement("td");
      key.textContent = k;
      const val = document.createElement("td");
      val.textContent = typeof v === "object" ? JSON.stringify(v) : String(v);
      tr.append(key, val);
      table.appendChild(tr);
    }
  }
  return table.childElementCount > 0
    ? table
    : document.createTextNode("No detail supplied for this host.");
}

async function loadExpander(kind: "explain" | "identify", host: string, bodyId: string): Promise<void> {
  const body = $(bodyId);
  body.textContent = "Asking the graph...";
  const res = await send<{ ok: true; explain: ExplainResult }>({ kind, host });
  if (!res.ok) {
    body.textContent = "Could not reach Whisper.";
    return;
  }
  body.replaceChildren(
    res.explain.ok ? renderKV(res.explain.rows) : document.createTextNode(res.explain.error ?? "unavailable"),
  );
}

function drawNeighborhood(canvas: HTMLCanvasElement, center: string, candidates: CandidateVerdict[]): void {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.font = `10px ${CANVAS_MONO}`;
  redrawWhenMonoLoads(canvas, () => drawNeighborhood(canvas, center, candidates));
  const cx = W / 2;
  const cy = H / 2;

  const line = themeColor("--w-line-strong", "#34343f");
  const muted = themeColor("--w-muted", "#8888a0");
  const text = themeColor("--w-text", "#eeeef0");
  const accent = themeColor("--w-accent", "#b49cf5");
  // --w-v-crit is the FILLED plate colour (white text sits on it), and as
  // a dot on the panel ground it measures under the 3:1 non-text floor.
  // The outer ring below is what says CRITICAL; both draw in the hue that
  // is meant to be drawn rather than filled.
  const crit = themeColor("--w-v-high", "#f87171");
  const colors: Record<string, string> = {
    CRITICAL: crit,
    HIGH: crit,
    MEDIUM: themeColor("--w-v-low", "#fbbf24"),
  };
  const n = candidates.length;
  candidates.forEach((c, i) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
    const r = Math.min(W, H) / 2 - 28;
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    ctx.strokeStyle = line;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(x, y);
    ctx.stroke();
    ctx.fillStyle = colors[c.band] ?? muted;
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, 2 * Math.PI);
    ctx.fill();
    if (c.band === "CRITICAL") {
      ctx.strokeStyle = crit;
      ctx.beginPath();
      ctx.arc(x, y, 8, 0, 2 * Math.PI);
      ctx.stroke();
    }
    ctx.fillStyle = muted;
    const label = c.host.length > 22 ? c.host.slice(0, 21) + "…" : c.host;
    ctx.fillText(label, x - ctx.measureText(label).width / 2, y + 18);
  });

  ctx.fillStyle = accent;
  ctx.beginPath();
  ctx.arc(cx, cy, 7, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = text;
  const cl = center.length > 26 ? center.slice(0, 25) + "…" : center;
  ctx.fillText(cl, cx - ctx.measureText(cl).width / 2, cy - 12);
}

async function loadNeighborhood(host: string): Promise<void> {
  const note = $("neighborhood-note");
  note.textContent = "Asking the graph for registered look-alikes of this name...";
  const res = await send<{ ok: true; candidates: CandidateVerdict[] }>({ kind: "confirmLookalikes", host });
  const canvas = $<HTMLCanvasElement>("graph-canvas");
  if (!res.ok) {
    note.textContent = "Could not reach Whisper; try again.";
    return;
  }
  drawNeighborhood(canvas, host, res.candidates);
  note.textContent =
    res.candidates.length === 0
      ? "No registered look-alike of this host is currently flagged in the graph."
      : `${res.candidates.length} registered look-alike(s) flagged in the graph. These are confirmed, not guesses.`;
}

async function loadSession(): Promise<void> {
  const res = await send<{ ok: true; session: { host: string; reason: string }[] }>({ kind: "getSession" });
  if (!res.ok) return;
  const body = $("session-body");
  $("session-summary").textContent = `This session - ${res.session.length} risky`;
  if (res.session.length === 0) {
    body.textContent = "No risky hosts seen this session.";
  } else {
    body.replaceChildren(
      ...res.session.map((r) => {
        const item = document.createElement("div");
        item.className = "session-item";
        const host = document.createElement("span");
        host.className = "session-host";
        host.textContent = r.host;
        const reason = document.createElement("span");
        reason.className = "session-reason";
        reason.textContent = r.reason;
        item.append(host, reason);
        return item;
      }),
    );
  }
}

/**
 * The session block ledger. Lists the hosts this session's pre-emptive
 * guard blocked, each with a one-click Clear (the existing session-allow +
 * unblock), so a block is never a dead end. When THIS tab is a blocked host (the
 * bare ERR_BLOCKED_BY_CLIENT page, no Whisper page to explain it), a banner names
 * it and Clear reloads the now-unblocked page. Keyless; no new permission.
 */
async function loadBlocked(activeHost: string): Promise<void> {
  const res = await send<{ ok: true; hosts: string[] }>({ kind: "listBlocked" });
  if (!res.ok) return;
  const hosts = res.hosts;
  const active = (activeHost ?? "").toLowerCase();
  const activeBlocked = hosts.includes(active);
  const card = $("blocked-card");
  if (hosts.length === 0) {
    // Cleared the last one: hide the card AND empty the list + banner, so no
    // stale row lingers in the DOM after an in-place refresh.
    card.hidden = true;
    $("blocked-banner").hidden = true;
    $("blocked-body").replaceChildren();
    return;
  }
  card.hidden = false;

  const banner = $("blocked-banner");
  if (activeBlocked) {
    banner.hidden = false;
    banner.textContent = `Whisper blocked ${activeHost} this session. Evidenced malicious. Clear it below to proceed, or keep it blocked.`;
  } else {
    banner.hidden = true;
  }

  const body = $("blocked-body");
  body.replaceChildren(
    ...hosts.map((h) => {
      const row = document.createElement("div");
      row.className = "blocked-item" + (h === active ? " blocked-active" : "");
      const name = document.createElement("span");
      name.className = "blocked-host";
      name.textContent = h;
      const clear = document.createElement("button");
      clear.className = "blocked-clear";
      clear.textContent = "Clear";
      clear.title = `Unblock ${h} for this session`;
      clear.addEventListener("click", async () => {
        clear.disabled = true;
        clear.textContent = "Clearing…";
        // Clear = the interstitial's Proceed: allow-for-session + lift the DNR block.
        await send({ kind: "allowHost", host: h, session: true });
        if (h === active) {
          // The active tab is the opaque block page: navigate it to the now-open host.
          chrome.tabs.update(tabId, { url: `https://${h}/` }).then(() => window.close());
          return;
        }
        void loadBlocked(activeHost); // refresh the list in place
      });
      row.append(name, clear);
      return row;
    }),
  );
}

/** One named weighted factor row: dot + name + weight, colored by kind. */
function factorRow(f: WhyFactor): HTMLElement {
  const row = document.createElement("div");
  row.className = `why-factor ${f.kind}`;
  const dot = document.createElement("span");
  dot.className = "w-dot";
  const name = document.createElement("span");
  name.className = "wf-name";
  name.textContent = f.name;
  name.title = f.kind === "threat" ? `${f.name}: a threat feed listing` : `${f.name}: a popularity/trust listing (good standing)`;
  const meta = document.createElement("span");
  meta.className = "wf-meta";
  meta.textContent =
    f.kind === "threat"
      ? `threat feed${f.weight !== null ? ` · weight ${f.weight}` : ""}`
      : `good standing${f.weight !== null ? ` · weight ${f.weight}` : ""}`;
  row.append(dot, name, meta);
  return row;
}

const MAX_FACTORS_SHOWN = 5;

interface WhyRender {
  /** The factor panel rendered at all. */
  shown: boolean;
  /** A factor was cut from the list, so a summary of them still adds. */
  truncated: boolean;
}

/** The WHY, front and center: the graph's score + its named weighted factors. */
function renderWhy(p: Protection): WhyRender {
  const panel = $("why-panel");
  const scoreChip = $("why-score");
  const box = $("why-factors");
  // Only a threat factor or a score above zero earns the card: a clean site
  // with nothing but a popularity listing has nothing to explain.
  const earned = p.whyFactors.some((f) => f.kind === "threat") || (p.score !== null && p.score !== 0);
  if (!earned) return { shown: false, truncated: false };
  panel.hidden = false;
  if (p.score !== null) {
    scoreChip.hidden = false;
    scoreChip.textContent = `graph score ${p.score}`;
  }
  const shown = p.whyFactors.slice(0, MAX_FACTORS_SHOWN);
  const truncated = p.whyFactors.length > shown.length;
  box.replaceChildren(...shown.map(factorRow));
  if (truncated) {
    const more = document.createElement("div");
    more.className = "why-factor more";
    more.textContent = `+ ${p.whyFactors.length - shown.length} more listing(s) in the full graph answer below`;
    box.appendChild(more);
  }
  if (shown.length === 0) {
    const none = document.createElement("div");
    none.className = "why-factor more";
    none.textContent = "No feed lists this name either way.";
    box.appendChild(none);
  }
  return { shown: true, truncated };
}

/** A chip is part of the row under the verdict only while it shows; the row
 *  hides when none does, so there is never an empty gap. */
function syncChips(): void {
  const row = $("site-chips");
  row.hidden = ![...row.children].some((c) => !(c as HTMLElement).hidden);
}

/**
 * Coverage: how much the graph KNOWS about this name. It is categorical and
 * it is NOT a safety score (a CRITICAL host can be known-clean coverage), so
 * the chip says so in words. "no-data" is the graph's answer for a name it
 * does not know: there is no coverage to state, so no chip.
 */
function renderCoverage(coverage: string | null): void {
  const el = $("coverage-chip");
  if (!coverage || coverage === "no-data") return;
  const val = document.createElement("span");
  val.className = "pp-val";
  val.textContent = coverage;
  el.replaceChildren(
    document.createTextNode("Coverage: "),
    val,
    document.createTextNode(" · not a safety score"),
  );
  el.hidden = false;
  syncChips();
}

/** The graph's score for this name, as a plain chip; 0 is a score and shows. */
function renderScoreChip(score: number | null): void {
  if (score === null) return;
  const el = $("score-chip");
  const num = document.createElement("span");
  num.className = "pp-num";
  num.textContent = String(score);
  el.replaceChildren(document.createTextNode("Graph score "), num);
  el.hidden = false;
  syncChips();
}

/** Whether the reader's own Trusted sites list holds this name, by the same
 *  rule the on-device detector applies, so the chip and the look-alike
 *  suppression can never disagree. */
function isTrusted(host: string, registrable: string | null, list: readonly string[]): boolean {
  const reg = (registrable ?? host).toLowerCase();
  const h = host.toLowerCase();
  return list.some((a) => {
    const al = a.toLowerCase();
    return reg === al || h === al || h.endsWith("." + al);
  });
}

/**
 * WHY the verdict says what it says: the graph's score and the named,
 * weighted factors behind it.
 *
 * Who runs it, where it sits and how old the name is used to live here as
 * three detached rows. They are all ON THE CHAIN now, said better there as
 * rungs of one walk. Keeping both was the panel telling the reader the same
 * thing twice in two vocabularies, which is how a surface starts to read as
 * padding, and it left two places for the same fact to disagree.
 */
async function loadProtection(host: string): Promise<void> {
  const res = await send<{ ok: true; protection: Protection }>({ kind: "getProtection", host });
  if (!res.ok) return;
  const p = res.protection;
  const why = renderWhy(p);
  const card = $("protect-card");
  const whyBox = $("why-chips");
  // p.why[0] is a summary we synthesise of the very factors listed directly
  // above it ("Listed in 2 threat feeds: a, b"). When every factor is on
  // screen that is the same sentence twice, which is what makes a panel read
  // as padding; when the list was cut short it is the only complete naming
  // of the feeds, so it stays. What follows it is the graph's own words and
  // is never dropped: it can carry more than the count it usually carries.
  const prose = why.shown && !why.truncated ? p.why.slice(1) : p.why;
  whyBox.replaceChildren(
    ...prose.map((w, i) => {
      const line = document.createElement("div");
      line.className = `why-line${i === 0 && !why.shown ? " threat" : ""}`;
      line.textContent = w;
      return line;
    }),
  );
  card.hidden = !why.shown;
  renderScoreChip(p.score);
}

// ---------------------------------------- this browser: the ONE control
//
// The control itself lives in shared/protect-control.ts and is mounted
// identically here and on the dashboard, so both surfaces offer the same
// one control with the same words. Nothing about it is panel-specific.

let protectControl: ProtectControl | null = null;

async function loadIdentity(): Promise<void> {
  $("identity-card").hidden = false;
  protectControl ??= mountProtectControl({ root: $("identity-control") });
  await protectControl.refresh();
}


// ----------------------------------------------------------- link sweep

function chipClsForBand(band: string): string {
  const b = band.toUpperCase();
  if (b === "CRITICAL") return "crit";
  if (b === "HIGH") return "high";
  if (b === "MEDIUM") return "med";
  if (b === "UNKNOWN") return "unknown";
  return "ok";
}

function linkRow(host: string, band: string, links: number): HTMLElement {
  const row = document.createElement("div");
  row.className = "link-row";
  const chip = document.createElement("span");
  chip.className = `w-chip ${chipClsForBand(band)}`;
  chip.textContent = band.toUpperCase() === "CRITICAL" ? "MALICIOUS" : band.toUpperCase();
  const name = document.createElement("span");
  name.className = "link-host";
  name.textContent = host;
  const n = document.createElement("span");
  n.className = "link-n";
  n.textContent = links > 1 ? `x${links}` : "";
  row.append(chip, name, n);
  return row;
}

/** One page-scan row. A null band was never assessed: it must not borrow the
 *  ok chip, nor UNKNOWN (which means the graph was asked). */
function iocRow(r: PageScanResult["rows"][number]): HTMLElement {
  const row = document.createElement("div");
  row.className = "link-row";
  const chip = document.createElement("span");
  if (r.band === null) {
    chip.className = "w-chip unassessed";
    chip.textContent = "Not assessed";
  } else {
    chip.className = `w-chip ${chipClsForBand(r.band)}`;
    chip.textContent = r.band === "CRITICAL" ? "MALICIOUS" : r.band;
  }
  const name = document.createElement("span");
  name.className = "link-host";
  name.textContent = r.value;
  name.title = r.value;
  row.append(chip, name);
  return row;
}

function renderLinkScan(scan: LinkScanResult): void {
  const summary = $("linkscan-summary");
  summary.hidden = false;
  const bits: string[] = [];
  if (scan.flagged > 0) bits.push(`${scan.flagged} malicious`);
  if (scan.suspicious > 0) bits.push(`${scan.suspicious} suspicious`);
  bits.push(`${scan.unknown} unknown`, `${scan.clean} clean`);
  summary.textContent = `${scan.hosts.length} destination(s) across ${scan.totalLinks} link(s): ${bits.join(", ")}.${scan.truncated ? " Showing the busiest; the page had more." : ""}`;
  summary.className = `linkscan-summary${scan.flagged > 0 ? " hot" : ""}`;
  const list = $("linkscan-list");
  list.hidden = scan.hosts.length === 0;
  // Clean rows collapse into the count above once anything is flagged;
  // otherwise show everything (short lists read better complete).
  const risky = scan.hosts.filter((h) => h.band !== "NONE" && h.band !== "LOW" && h.band !== "INFO");
  const rows = risky.length > 0 && scan.hosts.length > 24 ? risky : scan.hosts;
  list.replaceChildren(...rows.slice(0, 80).map((h) => linkRow(h.host, h.band, h.links)));
  const note = $("linkscan-note");
  note.hidden = false;
  note.textContent = "Only the link hostnames were checked, never the page, its text, or your history.";
}

// When the reader was blocked (the popup opened without host access to this
// tab), the next click first asks for THIS SITE's access before scanning.
let linkScanNeedsGrant = false;

/** Host access to the current site only, never the whole web. Covered by the
 *  manifest's optional_host_permissions (<all_urls>); requested per-site so
 *  Guard only ever gains access to sites the user actually scans. */
function linkScanOrigins(): string[] {
  const host = state?.hostname;
  return host ? [`https://${host}/*`, `http://${host}/*`] : ["<all_urls>"];
}

async function runLinkScan(btn: HTMLButtonElement, grant?: Promise<boolean>): Promise<void> {
  btn.disabled = true;
  btn.textContent = "Checking...";
  const summary = $("linkscan-summary");
  if (grant) {
    const ok = await grant.catch(() => false);
    if (!ok) {
      btn.disabled = false;
      btn.textContent = "Allow this page & check";
      summary.hidden = false;
      summary.textContent = "Whisper Guard needs your OK to read this page's link addresses. Nothing else is read.";
      return;
    }
    linkScanNeedsGrant = false;
  }
  const res = await send<{ ok: true; scan: LinkScanResult } | { ok: false; error: string; nohost?: boolean }>({
    kind: "scanLinks",
    tabId,
  });
  btn.disabled = false;
  if (res.ok) {
    btn.textContent = "Re-check";
    renderLinkScan(res.scan);
    return;
  }
  if (res.nohost) {
    // A fresh user gesture is required to request the permission, so arm the
    // next click instead of prompting from this (already-consumed) one.
    linkScanNeedsGrant = true;
    btn.textContent = "Allow this page & check";
  } else {
    btn.textContent = "Re-check";
  }
  summary.hidden = false;
  summary.textContent = res.error;
}

/* ------------------------------------------------------- indicators
 *
 * The IOC scanner has existed and been unreachable: `scanIocs` was handled in
 * the background and sent by nothing the reader could click. That is the state
 * this wiring ends, and it is why the disclosure changes ship in the SAME
 * version rather than after it. An extension that carries a page-text scanner
 * it cannot run has a listing that is true only by accident.
 *
 * Its note is deliberately NOT the link scan's note. The link scan reads href
 * hostnames and promises the page text is never read; this reads the visible
 * text. Sharing a sentence between them would make one of the two false.
 */
function renderIocScan(scan: PageScanResult): void {
  const summary = $("iocscan-summary");
  summary.hidden = false;
  const isFlagged = (r: PageScanResult["rows"][number]): boolean => r.band === "CRITICAL" || r.band === "HIGH" || r.band === "MEDIUM";
  const risky = scan.rows.filter(isFlagged);
  const notAssessed = scan.rows.filter((r: PageScanResult["rows"][number]) => r.band === null).length;
  const bits: string[] = [];
  if (risky.length > 0) bits.push(`${risky.length} flagged`);
  bits.push(`${scan.found} found`);
  if (notAssessed > 0) bits.push(`${notAssessed} not assessed`);
  if (scan.ignored > 0) bits.push(`${scan.ignored} ignored`);
  summary.textContent =
    `${bits.join(", ")}; ${scan.assessed} checked against the graph.` +
    (scan.truncated ? " Showing the first; the page had more." : "");
  summary.className = `linkscan-summary${risky.length > 0 ? " hot" : ""}`;

  const list = $("iocscan-list");
  list.hidden = scan.rows.length === 0;
  const shown = risky.length > 0 && scan.rows.length > 24 ? risky : scan.rows;
  // Flagged first, then assessed, then never assessed; found order within each.
  const rank = (r: PageScanResult["rows"][number]): number => (isFlagged(r) ? 0 : r.band === null ? 2 : 1);
  const rows = shown
    .map((r, i) => ({ r, i }))
    .sort((a, b) => rank(a.r) - rank(b.r) || a.i - b.i)
    .map((x) => x.r);
  list.replaceChildren(...rows.slice(0, 80).map(iocRow));

  const note = $("iocscan-note");
  note.hidden = false;
  // Says what actually leaves the browser, MEASURED rather than intended: only
  // hostnames go to the graph. IP literals, hashes and CVE ids stay on the
  // device and are listed as Not assessed. e2e/page-scan.spec.ts asserts the wire.
  note.textContent =
    "This reads the page's visible text. Only the hostnames found are checked against Whisper; IP addresses, file hashes and CVE ids are listed as Not assessed and are not sent. The page text itself never leaves your browser.";
}

let iocScanNeedsGrant = false;

async function runIocScan(btn: HTMLButtonElement, grant?: Promise<boolean>): Promise<void> {
  if (tabId < 0) return;
  btn.disabled = true;
  btn.textContent = "Scanning…";
  if (grant) {
    await grant;
    iocScanNeedsGrant = false;
  }
  const res = await send<{ ok: true; scan: PageScanResult } | { ok: false; error: string; nohost?: boolean }>({
    kind: "scanIocs",
    tabId,
  });
  btn.disabled = false;
  if (res.ok) {
    btn.textContent = "Re-scan";
    renderIocScan(res.scan);
    return;
  }
  if (res.nohost) {
    // Same recovery as the link scan: the permission needs a fresh gesture, so
    // arm the next click rather than prompting from this consumed one.
    iocScanNeedsGrant = true;
    btn.textContent = "Allow & scan";
    const note = $("iocscan-note");
    note.hidden = false;
    note.textContent = "Guard needs access to this site to read its text. Click again to allow it for this site only.";
    return;
  }
  btn.textContent = "Scan";
  const note = $("iocscan-note");
  note.hidden = false;
  note.textContent = `Could not scan this page: ${res.error}`;
}

function wireIocScan(): void {
  $("iocscan-card").hidden = false;
  const btn = $<HTMLButtonElement>("btn-iocscan");
  btn.addEventListener("click", () => {
    let grant: Promise<boolean> | undefined;
    if (iocScanNeedsGrant) {
      try {
        grant = Promise.resolve(chrome.permissions.request({ origins: linkScanOrigins() }));
      } catch {
        grant = Promise.resolve(false);
      }
    }
    void runIocScan(btn, grant);
  });
}

function wireLinkScan(): void {
  $("linkscan-card").hidden = false;
  const btn = $<HTMLButtonElement>("btn-linkscan");
  btn.addEventListener("click", () => {
    // If the reader was blocked, ask for this-site host access FIRST (no await
    // before it, so it counts as a user gesture); promptless if already held.
    let grant: Promise<boolean> | undefined;
    if (linkScanNeedsGrant) {
      try {
        grant = Promise.resolve(chrome.permissions.request({ origins: linkScanOrigins() }));
      } catch {
        grant = Promise.resolve(false);
      }
    }
    void runLinkScan(btn, grant);
  });
}

// ------------------------------------------------------------- activity

// One label per category, in both numbers: a tally that reads "1 risky
// clicks" is a small lie about its own arithmetic, and this line is the
// one place the count is ever shown.
const WIN_LABEL: Record<WinCategory, { one: string; many: string }> = {
  preemptBlock: {
    one: "risky click stopped before anything loaded",
    many: "risky clicks stopped before anything loaded",
  },
  identityVerified: { one: "endpoint identity verified", many: "endpoint identities verified" },
  cookieDecline: { one: "cookie prompt declined", many: "cookie prompts declined" },
};

/**
 * What Guard did today. Counted as categories only, never which sites, and
 * shown only here, on the reader's own click. A zero gets a sentence rather
 * than a number: a big 0 on a card is a stat about nothing.
 */
async function loadToday(): Promise<void> {
  const res = await send<{ ok: true; wins: WinsToday }>({ kind: "getWins" });
  if (!res.ok) return;
  const w = res.wins;
  $("today-hero").textContent = String(w.total);
  $("today-row").hidden = w.total === 0;
  const rows: HTMLElement[] = [];
  for (const c of WIN_CATEGORIES) {
    const n = w.counts[c];
    if (n <= 0) continue;
    rows.push(winLine(n, n === 1 ? WIN_LABEL[c].one : WIN_LABEL[c].many));
  }
  $("today-breakdown").replaceChildren(...rows);
  $("today-note").textContent =
    w.total === 0
      ? "Nothing needed your attention today; checks ran on every site."
      : "Counted by category only, never which sites.";
}

/** One category of today's work: the count drawn as that many marks, then
 *  the words. Three interruptions is a quantity a reader sees; the number
 *  three in a sentence is one they skim. */
function winLine(n: number, words: string): HTMLElement {
  const line = document.createElement("div");
  line.className = "today-line";
  // Decorative: the words for this count are the next node along.
  const marks = countMarks(n, { perRow: 20, size: 4, gap: 2, tone: "accent" });
  if (marks) {
    const wrap = document.createElement("span");
    wrap.className = "today-marks";
    wrap.appendChild(marks);
    line.appendChild(wrap);
  }
  const text = document.createElement("span");
  text.textContent = `${n} ${words}`;
  line.appendChild(text);
  return line;
}

/** The last 24h in one line. The only number worth a reader's attention is
 *  the flagged one, so that is the only one that gets emphasis. */
async function loadBrowser24h(): Promise<void> {
  const res = await send<{ ok: true; report: BrowserReport }>({ kind: "getBrowserReport", limit: 200 });
  if (!res.ok) return;
  const t = res.report.totals;
  const el = $("browser-24h");
  if (t.destinations === 0) {
    el.className = "w-note";
    el.textContent = "No destinations recorded in this browser yet.";
    return;
  }

  // The same report, drawn. Nothing extra is fetched and nothing extra is
  // sent: these timestamps are already on this device, which is why the
  // strip can exist on a surface that promises never to build a history
  // anywhere else.
  const events: TimeEvent[] = res.report.hosts
    .filter((h) => h.lastAt > 0)
    .map((h) => ({
      at: h.lastAt,
      tone:
        h.verdict === "CRITICAL" || h.verdict === "HIGH"
          ? ("hot" as const)
          : h.verdict === "MEDIUM" || h.verdict === "LOW"
            ? ("warn" as const)
            : ("accent" as const),
      label: h.host,
    }));
  const strip = timeStrip(events, {
    width: 368,
    height: 40,
    hours: 24,
    title: `${events.length} sightings in the last 24 hours`,
  });
  // No strip when there is nothing timed to put on it. An axis with no
  // marks says "we watched and saw nothing", which is not what an empty
  // timestamp list means.
  $("browser-strip").replaceChildren(...(strip ? [strip] : []));
  const d = `${t.destinations} destination${t.destinations === 1 ? "" : "s"}`;
  el.className = t.flagged > 0 ? "w-note hot" : "w-note";
  el.textContent =
    t.flagged > 0
      ? `${t.flagged} of ${d} flagged in the last 24h.`
      : `${d} in the last 24h, none flagged.`;
}

// ---------------------------------------------------------- sign-in tier

async function pollDeviceFlow(): Promise<void> {
  const el = $("device-status");
  el.hidden = false;
  for (;;) {
    const res = await send<{ ok: true; device: { phase: string; userCode: string | null; message: string | null } }>({ kind: "signInStatus" });
    if (!res.ok) return;
    const d = res.device;
    if (d.phase === "waiting") {
      el.textContent = `Approve the sign-in in the console tab (code ${d.userCode ?? "..."}). Waiting...`;
    } else if (d.phase === "approved") {
      el.textContent = "Signed in. Lighting up...";
      setTimeout(() => window.location.reload(), 600);
      return;
    } else if (d.phase === "expired" || d.phase === "error") {
      el.textContent = d.message ?? "Sign-in did not complete. Try again.";
      return;
    } else {
      return;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
}

function wireSignin(): void {
  $("signin-pitch").hidden = false;
  $("btn-signin").addEventListener("click", async () => {
    $("btn-signin").textContent = "Opening the console...";
    await send({ kind: "signInStart" });
    void pollDeviceFlow();
  });
}

// ------------------------------------------------------- the live scale
//
// The masthead says how big the graph behind the verdict actually is, read
// from the public stats endpoint on every open. It is never a constant in
// this build: a figure about our own coverage is stale the day after it is
// written, and quoting a stale one is worse than quoting none. When the
// endpoint cannot be read the readout stays hidden rather than showing a
// remembered number.

async function loadScale(): Promise<void> {
  const res = await send<{ ok: true; scale: GraphScale | null }>({ kind: "getScale" });
  if (!res.ok || !res.scale) return;
  const sc = res.scale;
  const box = $("scale");
  box.hidden = false;

  const nodes = $("scale-nodes");
  countUp(nodes, sc.nodes, compact);

  // The tooltip carries the full picture, so the masthead can stay a
  // glance: exact figures, the resolvers' window, and when it was measured.
  const measured = new Date(sc.updated);
  const lat = sc.p50Us !== null ? `, p50 ${Math.round(sc.p50Us)}us` : "";
  box.title =
    `${sc.nodes.toLocaleString("en")} nodes and ${sc.edges.toLocaleString("en")} edges. ` +
    `${sc.queries.toLocaleString("en")} DNS questions answered in the last ${sc.windowHours}h${lat}. ` +
    `Read live at ${measured.toLocaleTimeString()}${sc.degraded ? " (the endpoint reports degraded input)" : ""}.`;

  // The pulse: the resolvers' own trailing window. A shape, not a chart,
  // and it refuses to draw at all when there is nothing to show.
  const spark = sparkline(sc.pulse.slice(-48), {
    width: 34,
    height: 14,
    title: `DNS questions answered per 5 minutes over the last ${sc.windowHours} hours`,
  });
  if (spark) $("scale-pulse").replaceChildren(spark);
}

// ------------------------------------------------------------- the chain
//
// The join path behind the name. This is the section that needs a graph
// rather than a feed, and it is the reason the panel is worth opening on a
// site that turns out to be fine.

/** The words shown when the walk itself could not be read at all. */
const FACTS_UNREAD =
  "The facts behind this name could not be read just now. Unknown, not clear.";

/** The check mark of a clean verdict, drawn as the disc's glyph. */
function checkMark(): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", "22");
  svg.setAttribute("height", "22");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", "M5 12.5l4.5 4.5L19 7.5");
  svg.appendChild(path);
  return svg;
}

/** "registered 12 years ago" as a sentence for the reason line. */
function sentenceOf(fact: string): string {
  return fact.charAt(0).toUpperCase() + fact.slice(1) + ".";
}

async function loadChain(host: string, band: GraphBand | null): Promise<void> {
  const card = $("chain-card");
  const mount = $("chain-mount");
  card.hidden = false;
  renderChainPending(mount, 7, "WHO IS BEHIND IT");
  const res = await send<{ ok: true; chain: SiteChain }>({ kind: "getChain", host });
  const note = $("chain-note");
  if (!res.ok) {
    // The transport failed, which is a different fact from "the graph knows
    // nothing", and the panel has to say which one happened. The link and the
    // drawers stay: they do not depend on this read.
    // Only the rows are replaced: the heading stays, the waiting count goes.
    const lost = document.createElement("div");
    lost.className = "pp-note lost";
    lost.textContent = FACTS_UNREAD;
    mount.querySelector(".ch-count")?.remove();
    mount.querySelector(".ch-spine")?.replaceWith(lost);
    note.hidden = true;
    return;
  }
  const chain = res.chain;
  renderChain(
    mount,
    { ...chain, rungs: chain.rungs.map((r) => ({ ...r, label: FACT_LABEL[r.kind] })) },
    { heading: "WHO IS BEHIND IT", completeness: false },
  );

  // Read means answered: a row the graph answered with nothing counts, a row
  // that could not be asked does not.
  const total = chain.rungs.length;
  const read = total - chain.unavailable;
  const count = document.createElement("span");
  count.id = "facts-count";
  count.className = chain.unavailable > 0 ? "ch-count ch-count-lost" : "ch-count";
  const figure = document.createElement("span");
  figure.className = "pp-count-n";
  figure.textContent = `${read}/${total}`;
  count.append(figure, document.createTextNode(" facts read"));
  mount.querySelector(".ch-head")?.appendChild(count);
  mount.querySelectorAll<HTMLElement>(".ch-rung").forEach((li, i) => {
    const kind = chain.rungs[i]?.kind;
    if (kind) li.dataset.kind = kind;
  });

  // The age joins the reason line only now that the history read came back.
  const name = chain.rungs.find((r) => r.kind === "name");
  if (name && name.state === "live" && name.fact) {
    const age = $("band-age");
    age.textContent = sentenceOf(name.fact);
    age.hidden = false;
  }

  if (chain.unavailable > 0) {
    note.hidden = false;
    note.textContent =
      `${chain.unavailable} step${chain.unavailable === 1 ? "" : "s"} of the walk could not be read just now. ` +
      "Those are unknown, not clear.";
  } else if (chain.live <= 2) {
    note.hidden = false;
    note.textContent =
      "The graph holds almost nothing about this name. That is common for a name registered days ago.";
  } else {
    note.hidden = true;
  }

  // Flagged neighbours on a range the graph classes as a CDN are common and
  // say nothing about a clean site: said only where all of that holds.
  const prefix = chain.rungs.find((r) => r.kind === "prefix");
  const cdn = [chain.vendorCategory, chain.identifyCategory].some((c) => c?.toLowerCase() === "cdn");
  $("neighbours-note").hidden = !(
    (band === "LOW" || band === "INFO" || band === "NONE") &&
    prefix?.state === "live" &&
    (chain.threatNeighbors ?? 0) > 0 &&
    cdn
  );
}

// -------------------------------------------------------- the keyless tier
//
// One implementation (shared/tier.ts), mounted here and on the dashboard.

async function loadTier(): Promise<void> {
  await mountTierMeter({
    root: $("tier-meter"),
    label: $("tier-label"),
    count: $("tier-count"),
    fill: $("tier-fill"),
    note: $("tier-note"),
  });
}

// ---------------------------------------------------------------- render

/** Everything that does not depend on this site's check: drawn once at open,
 *  in every case, so every tab is filled while a check waits or a press is due. */
function renderShell(signedIn: boolean, activeHost: string, first: TabState | null): void {
  void loadScale();
  void loadToday();
  void loadBrowser24h();
  $("btn-dashboard").addEventListener("click", () => {
    void send({ kind: "openDashboard" }).then(() => window.close());
  });

  // This browser's protection is on every page, signed in or not: keyed
  // readers get the one control, keyless readers get the one thing that
  // unlocks it. Two tiers, both honest, one action either way.
  if (signedIn) void loadIdentity();
  else {
    wireSignin();
    void loadTier();
  }

  // a session block must be discoverably clearable - list the hosts
  // blocked this session and, when THIS tab is one (the opaque
  // ERR_BLOCKED_BY_CLIENT page), explain it and offer a one-click clear. The
  // list is session-wide, not tab-scoped, so it runs BEFORE the eligibility
  // gate: even on an ineligible tab (a browser page, or the block page itself)
  // a session block stays visible and clearable, never a silent dead end.
  void loadBlocked(activeHost);

  // The on-device look-alike catch needs no check and sends nothing.
  if (first) drawLookalike(first);
}

let lookalikeDrawn = false;

/** The look-alike card and its report button, from the on-device detector. */
function drawLookalike(s: TabState): void {
  if (lookalikeDrawn || !s.detector || !s.hostname) return;
  lookalikeDrawn = true;
  const host = s.hostname;
  const d = s.detector;
  $("lookalike").hidden = false;
  const kindText: Record<string, string> = {
    confusable: "is a confusable look-alike of",
    tldswap: "uses the name of",
    combosquat: "embeds the name of",
    "brand-subdomain": "impersonates",
    nearmiss: "is one keystroke away from",
  };
  $("lookalike-text").textContent = `This site ${kindText[d.kind] ?? "looks like"} ${d.brandDomain}. Caught on-device.`;
  const go = $<HTMLAnchorElement>("btn-goto");
  go.textContent = `Go to the real ${d.brandDomain}`;
  go.addEventListener("click", (ev) => {
    ev.preventDefault();
    chrome.tabs.update(tabId, { url: d.goTo }).then(() => window.close());
  });

  if (s.signedIn) {
    const report = $("btn-report");
    report.hidden = false;
    report.addEventListener("click", async () => {
      report.textContent = "Reporting...";
      const res = await send({ kind: "report", host, note: "reported from Whisper Guard" });
      const status = $("report-status");
      status.hidden = false;
      status.textContent = res.ok ? "Reported. Thank you." : "Could not submit the report; try again.";
      report.hidden = true;
    });
  }
}

let siteRendered = false;

/** The part of the popup that is this site's answer: drawn at most once, so
 *  its listeners are attached once, either at open or after the press. */
function renderSite(s: TabState): void {
  const cloudCheck = settings?.cloudCheck ?? true;
  $("checking-view").hidden = true;
  $("not-checked-view").hidden = true;
  // A tab with no answer is never drawn as a verdict: it gets the card.
  if (cloudCheck && s.lost && s.eligible && s.hostname) {
    drawNotChecked();
    return;
  }
  if (siteRendered) return;
  siteRendered = true;
  drawLookalike(s);

  if (!s.eligible || !s.hostname) {
    $("ineligible").hidden = false;
    $("host-row").hidden = true;
    setPrivacyLine("Privacy: nothing was sent.");
    // The words of the message this tab shows, so they have one source.
    syncPageNote($("ineligible").textContent?.trim() ?? null);
    return;
  }
  const host = s.hostname;

  // opening the popup is a real invocation of Guard on this tab, so
  // arm the pre-emptive click/submit guard here: under activeTab this
  // works even without the broad Active-Shield grant. Fire-and-forget;
  // the background fails silently where the page is not scriptable.
  void send({ kind: "preemptArm", tabId });

  $("host-row").hidden = false;
  $("hostname").textContent = host;
  const band: GraphBand | null = s.verdict?.band ?? null;
  if (cloudCheck) {
    wireLinkScan();
    wireIocScan();
    // The chain is the keyless payload and does not wait on a verdict:
    // whether the name is flagged or unremarkable, the path behind it is
    // the thing the panel was opened to see.
    void loadChain(host, band);
    wireGraphPath(host);
    $("footer-page-line").hidden = false;
    syncPageNote(null);
  } else {
    syncPageNote("The link check and the indicator scan need the live check. Turn it on in settings.");
  }

  if (settings && isTrusted(host, s.registrable, settings.allowlist)) {
    $("allow-chip").hidden = false;
    syncChips();
  }

  if (band) {
    const ui = BAND_UI[band];
    paintVerdict(ui.tone, ui.tone, ui.glyph, ui.chip, verdictSentence(band, s.verdict?.label ?? null));
    renderCoverage(s.verdict?.coverage ?? null);
    void loadProtection(host);
  } else if (cloudCheck && s.graphError) {
    // The check was made and Whisper did not answer. Its own word, glyph and
    // amber, so it is never read as SUSPICIOUS or as a clean "unknown".
    paintVerdict("err", "err", "!", "COULD NOT CHECK", "Not confirmed either way. On-device checks still ran.");
    void loadProtection(host);
  } else if (cloudCheck) {
    paintVerdict("unknown", "unknown", "?", "UNKNOWN", "No verdict yet for this site.");
    void loadProtection(host);
  } else {
    // A plain ring: no reading was taken. U+26BF has no glyph in a good many
    // system font stacks and falls back to a tofu box, which reads as a
    // rendering fault rather than a state.
    paintVerdict("off", "unknown", "○", "LIVE CHECK OFF", "On-device protection only. Turn the live check back on in settings.");
  }

  if (s.graphError) {
    $("graph-error").hidden = false;
    $("graph-error").textContent = `${s.graphError} Re-check with the arrow at the top.`;
  }

  // The analyst drawers ride the public tier: available keyless and keyed.
  if (cloudCheck) {
    $("expanders").hidden = false;
    let whyLoaded = false;
    $("exp-why").addEventListener("toggle", () => {
      if (!whyLoaded && ($("exp-why") as HTMLDetailsElement).open) {
        whyLoaded = true;
        void loadExpander("explain", host, "why-body");
      }
    });
    let whoLoaded = false;
    $("exp-who").addEventListener("toggle", () => {
      if (!whoLoaded && ($("exp-who") as HTMLDetailsElement).open) {
        whoLoaded = true;
        void loadExpander("identify", host, "who-body");
      }
    });
    let hoodLoaded = false;
    $("exp-neighborhood").addEventListener("toggle", () => {
      if (!hoodLoaded && ($("exp-neighborhood") as HTMLDetailsElement).open) {
        hoodLoaded = true;
        void loadNeighborhood(host);
      }
    });
    void loadSession();
  }

  if (s.signedIn) {
    $("footer-actions").hidden = false;
    $("btn-console").hidden = false;
    $("btn-console").addEventListener("click", () => {
      chrome.tabs.create({ url: CONSOLE_URL });
    });
    $("btn-dossier").hidden = false;
    $("btn-dossier").addEventListener("click", async () => {
      const [explain, identify] = await Promise.all([
        send<{ ok: true; explain: ExplainResult }>({ kind: "explain", host }),
        send<{ ok: true; explain: ExplainResult }>({ kind: "identify", host }),
      ]);
      const lines = [
        `# Whisper Guard dossier: ${host}`,
        ``,
        `- band: ${s.verdict?.band ?? "(no live check)"}`,
        `- coverage: ${s.verdict?.coverage ?? "n/a"} (categorical, not a safety score)`,
        `- label: ${s.verdict?.label ?? "n/a"}`,
        `- on-device look-alike: ${s.detector ? `${s.detector.kind} of ${s.detector.brandDomain}` : "none"}`,
        ``,
        `## explain`,
        "```json",
        JSON.stringify(explain.ok ? explain.explain.rows : [], null, 2),
        "```",
        `## identify`,
        "```json",
        JSON.stringify(identify.ok ? identify.explain.rows : [], null, 2),
        "```",
      ];
      await navigator.clipboard.writeText(lines.join("\n"));
      $("btn-dossier").textContent = "Copied";
    });
  }

  setPrivacyLine(
    cloudCheck
      ? liveCheckLine(host)
      : s.detector
        ? `Privacy: nothing left your browser. The look-alike check ran on-device.`
        : `Privacy: nothing was sent. The live check is off; on-device checks still ran.`,
  );
}

/** Draw the verdict card: the tone of the card and mark, the pill's own tone
 *  (the live-check-off state keeps the unknown pill), the glyph (null is the
 *  check), the pill's words and the one reason. */
function paintVerdict(tone: string, pill: string, glyph: string | null, chip: string, reason: string): void {
  $("host-row").className = `pp-card pp-verdict ${tone}`;
  const disc = $("band-glyph");
  if (glyph === null) disc.replaceChildren(checkMark());
  else disc.textContent = glyph;
  const pillEl = $("band-chip");
  pillEl.className = `pp-pill ${pill}`;
  pillEl.textContent = chip;
  $("band-note").textContent = reason;
}

/** The one writer of the privacy line: text to show it, null to hide it.
 *  A direct write to the line's element would erase its lock. */
function setPrivacyLine(text: string | null): void {
  $("privacy-text").textContent = text ?? "";
  $("privacy-line").hidden = text === null || text === "";
}

/** What went out for a live check: the exact name the worker sent, where it
 *  went, and what did not. */
function liveCheckLine(host: string): string {
  return `Privacy: Only “${host}” was sent, to ${GRAPH_HOST}. Never the page, the path or your history.`;
}

/** "Show the graph path": the check-link page for this hostname. A real link,
 *  so it is in the Tab order and answers Enter; opened as the context menu
 *  opens it, which sends what that page sends for this one name and no more. */
function wireGraphPath(host: string): void {
  const page = `check-link.html?host=${encodeURIComponent(host)}`;
  const link = $<HTMLAnchorElement>("graph-path");
  link.href = page;
  link.addEventListener("click", (ev) => {
    ev.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL(page) });
  });
}


/** The one writer of the sentence that says why This page has nothing to
 *  show: text to show it, null to hide it. */
function syncPageNote(text: string | null): void {
  const note = $("page-empty");
  note.textContent = text ?? "";
  note.hidden = text === null;
}

async function init(): Promise<void> {
  // First, before any await: the tabs work while a check is in flight and
  // when the tab's state cannot be read.
  initTabs();
  // A <canvas> keeps the ink it was drawn with, so a colour-scheme flip
  // has to redraw the look-alike neighbourhood.
  onThemeChange(() => {
    const open = ($("exp-neighborhood") as HTMLDetailsElement).open;
    if (open && state?.hostname) void loadNeighborhood(state.hostname);
  });
  $("btn-settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("btn-refresh").addEventListener("click", () => window.location.reload());
  $("btn-check-now").addEventListener("click", () => void checkNow());

  // Normally the active tab; ?tab=<id> pins the panel to a specific tab
  // (debugging and UI testing when the panel is opened as a full page).
  const pinned = new URLSearchParams(window.location.search).get("tab");
  if (pinned && /^\d+$/.test(pinned)) {
    tabId = Number(pinned);
  } else {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    tabId = tab?.id ?? -1;
  }
  const [stateRes, settingsRes] = await Promise.all([
    send({ kind: "getTabState", tabId }).catch(() => null),
    send<{ ok: true; settings: Settings; signedIn: boolean; corpusVersion: number; corpusUpdated: string }>({
      kind: "getSettings",
    }).catch(() => null),
  ]);
  if (settingsRes?.ok) settings = settingsRes.settings;
  const first = tabStateOf(stateRes);
  if (!first) {
    // The worker could not answer. The shell still draws, and the card offers
    // the check, which needs no hostname from here.
    renderShell(settingsRes?.ok ? settingsRes.signedIn : false, "", null);
    drawNotChecked();
    return;
  }
  state = first;
  const cloudCheck = settings?.cloudCheck ?? true;
  renderShell(first.signedIn, first.hostname ?? "", first);
  // Only after BOTH answers: a tab with the live check off must never flash
  // the checking view. renderSite() attaches listeners and runs at most once,
  // so while a check is in flight only the checking view is drawn and the
  // verdict replaces it in place.
  if (first.icon === "checking" && first.eligible && first.hostname && cloudCheck) {
    drawChecking(first.hostname);
    try {
      state = await waitUntilSettled(first);
    } catch {
      // The worker stopped while waiting: no answer to draw.
      drawNotChecked();
      return;
    }
  }
  if (cloudCheck && state.lost && state.eligible && state.hostname) {
    drawNotChecked();
    return;
  }
  renderSite(state);
}

function tabStateOf(res: BgResponse | null): TabState | null {
  return res && res.ok && "tabState" in res ? res.tabState : null;
}

/** The waiting view: the site's name and placeholders that the verdict replaces. */
function drawChecking(host: string): void {
  $("not-checked-view").hidden = true;
  $("host-row").hidden = true;
  $("checking-host").textContent = host;
  $("checking-host").hidden = host === "";
  $("checking-view").hidden = false;
  syncPageNote($("checking-text").textContent?.trim() ?? null);
  // After a press on a tab whose hostname the popup could not read, there is
  // no name to report yet; the verdict view writes the line.
  if (host) setPrivacyLine(liveCheckLine(host));
}

/** The card for a tab with no answer. It sends nothing and says nothing was
 *  sent or checked beyond its own words; the footer has nothing to show. */
function drawNotChecked(): void {
  $("checking-view").hidden = true;
  $("host-row").hidden = true;
  $("not-checked-view").hidden = false;
  ($("btn-check-now") as HTMLButtonElement).disabled = false;
  // Hidden, so the footer takes no space while nothing was sent.
  setPrivacyLine(null);
  // The words of the card, so This page has one source for them.
  syncPageNote($("not-checked-title").textContent?.trim() ?? null);
}

/** "Check this site now": one check of this tab's page by the worker, drawn in
 *  place. The popup and the page are never reloaded. */
async function checkNow(): Promise<void> {
  const button = $("btn-check-now") as HTMLButtonElement;
  const hadFocus = document.activeElement === button;
  button.disabled = true;
  drawChecking(state?.hostname ?? "");
  let next: TabState | null = null;
  try {
    next = tabStateOf(await send({ kind: "checkTab", tabId }));
    if (next && next.icon === "checking" && next.eligible && next.hostname) next = await waitUntilSettled(next);
  } catch {
    next = null;
  }
  if (next && !(next.lost && next.eligible && next.hostname)) {
    state = next;
    renderSite(next);
    // The pressed button is gone; keep focus inside the panel.
    if (hadFocus) $("panel-site").focus();
  } else {
    drawNotChecked();
    if (hadFocus) button.focus();
  }
}

/** Poll the worker until the check settles; bounded by the longest the worker
 *  itself can take, after which the latest state is rendered as it is. */
async function waitUntilSettled(first: TabState): Promise<TabState> {
  let latest = first;
  const deadline = Date.now() + GRAPH_TIMEOUT_MS + NAV_DEBOUNCE_MS + 1500;
  while (latest.icon === "checking" && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 200));
    const res = await send<{ ok: true; tabState: TabState }>({ kind: "getTabState", tabId });
    if (res.ok) latest = res.tabState;
  }
  return latest;
}

void init();
