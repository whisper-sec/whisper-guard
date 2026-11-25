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
//   3. what has it done?       the last 24 hours: how many destinations
//                              and how many flagged (counted over the
//                              whole log as the dashboard counts them),
//                              today's quiet tally beside them, a time strip
//                              and one caption. A figure shows only once the
//                              read behind it has answered.
//
// UNKNOWN is the honest common state and reads as "not confirmed either
// way", never as green. The answers sit in one scrolling region, in three parts
// one after the other: This site holds the verdict, the evidence and who is
// behind the name, This page the link check and the indicator scan (and, when
// Guard declined a cookie prompt on the page, a line saying so), This browser
// the identity and the activity. Every part is filled when the popup opens, and
// that holds while a check waits and on a page Guard has not checked yet: This
// site then shows a ring with placeholders, or a card with a button, and the
// verdict replaces either in place. This page is not shown while its cards
// would have nothing to say. The one footer carries the per-host privacy line
// saying exactly what was sent, wherever the reader has scrolled.

import { send, type BgResponse, type BrowserReport } from "../shared/messages";
import {
  WIN_CATEGORIES,
  type CandidateVerdict,
  type ChainRungKind,
  type DetectorHit,
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
import { CHECK_LIMIT_MS, CONSOLE_URL, EVIDENCE_LIMIT_MS, GRAPH_HOST } from "../shared/config";
import { renderChain, renderChainPending } from "../shared/chain-view";
import { cookieDeclinedKey } from "../shared/tab-flags";
import { initFade } from "./fade";
import { compact3, countUp } from "../shared/spark";
import { timeStrip, type TimeEvent } from "../shared/viz";
import { mountTierMeter } from "../shared/tier";
import { mountProtectControl, type ProtectControl } from "../shared/protect-control";
import { chooseTheme } from "../shared/theme-press";
import { nextTheme, normalizeTheme, themeName, themeTitle, type ThemeChoice } from "../shared/theme-choice";
import { CANVAS_MONO, onThemeChange, redrawWhenMonoLoads, themeColor } from "../shared/theme";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let tabId = -1;
let state: TabState | null = null;
let settings: Settings | null = null;

/** The mark in the verdict disc: a character, a drawn mark, or null for the check. */
type Glyph = string | (() => SVGSVGElement) | null;

/** Per band: the tone of the card, mark and pill, the pill's words, and the
 *  mark's glyph (null draws the check). */
const BAND_UI: Record<GraphBand, { tone: string; chip: string; glyph: Glyph }> = {
  CRITICAL: { tone: "crit", chip: "MALICIOUS - evidenced", glyph: "⬣" },
  HIGH: { tone: "high", chip: "HIGH RISK", glyph: "⬣" },
  MEDIUM: { tone: "med", chip: "SUSPICIOUS · MEDIUM", glyph: warnMark },
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

/** What to do about a suspicious site, said after the reason and the age. */
const ADVICE: Partial<Record<GraphBand, string>> = {
  MEDIUM: "Be careful with passwords and payment details.",
};

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
      return `Some risk signals in the graph${q}.`;
    case "LOW":
      return `Nothing lists this site as a threat; only low-level signals${q}.`;
    case "INFO":
      return `Nothing lists this site as a threat; only informational signals${q}.`;
    case "NONE":
      return `Nothing in the graph lists this site${q}.`;
    case "UNKNOWN":
      return `The graph has no evidence on this name yet${q}. Absence of evidence is not safety.`;
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
  // The drawer belongs to the name drawn now; an answer for another is dropped.
  if (drawnState?.hostname !== host) return;
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
  if (drawnState?.hostname !== host) return;
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

const round1 = (x: number): number => Math.round(x * 10) / 10;

/** The weights are drawn only when they can be believed: the score is known,
 *  every listed factor carries a weight, and the weights as shown add up to the
 *  score as shown. Anything else lists the names alone. */
function weightsAddUp(p: Protection): boolean {
  if (p.score === null || p.whyFactors.length === 0) return false;
  if (p.whyFactors.some((f) => f.weight === null)) return false;
  const sum = p.whyFactors.reduce((acc, f) => acc + round1(f.weight as number), 0);
  return round1(sum) === p.score;
}

function factorTitle(f: WhyFactor): string {
  return f.kind === "threat" ? `${f.name}: a threat feed listing` : `${f.name}: a popularity/trust listing (good standing)`;
}

/** One named factor row with no weight: dot, name, and what kind of listing it is. */
function factorRow(f: WhyFactor): HTMLElement {
  const row = document.createElement("div");
  row.className = `why-factor ${f.kind}`;
  const dot = document.createElement("span");
  dot.className = "w-dot";
  const name = document.createElement("span");
  name.className = "wf-name";
  name.textContent = f.name;
  name.title = factorTitle(f);
  const meta = document.createElement("span");
  meta.className = "wf-meta";
  meta.textContent = f.kind === "threat" ? "threat feed" : "good standing";
  row.append(dot, name, meta);
  return row;
}

/** The text of a weight: a sign, then the number. */
function weightText(w: number): string {
  const r = round1(w);
  if (r > 0) return `+${r}`;
  if (r < 0) return `\u2212${-r}`;
  return "0";
}

/** One factor row with its weight and a bar sized to its share of the score. */
function weightedRow(f: WhyFactor, score: number): HTMLElement {
  const w = f.weight as number;
  const row = document.createElement("div");
  row.className = `why-factor ${f.kind} weighted`;
  const line = document.createElement("div");
  line.className = "wf-line";
  const name = document.createElement("span");
  name.className = "wf-name";
  name.textContent = f.name;
  name.title = factorTitle(f);
  const weight = document.createElement("span");
  weight.className = "wf-weight";
  weight.textContent = weightText(w);
  line.append(name, weight);
  const bar = document.createElement("div");
  bar.className = "wf-bar";
  const fill = document.createElement("span");
  fill.className = "wf-fill";
  // Capped: a weight above the score (a negative one elsewhere in the list can allow it) must not run past its track.
  fill.style.width = `${score > 0 ? Math.min(100, (Math.max(0, round1(w)) / score) * 100) : 0}%`;
  bar.appendChild(fill);
  row.append(line, bar);
  return row;
}

const MAX_FACTORS_SHOWN = 5;

interface WhyRender {
  /** The factor panel rendered at all. */
  shown: boolean;
  /** A factor was cut from the list, so a summary of them still adds. */
  truncated: boolean;
}

/** The WHY, front and center: the graph's score + its named factors. With
 *  weights that add up to the score, every factor is listed with its weight
 *  and a bar; otherwise the names stand alone and a long list is cut. */
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
    scoreChip.textContent = `score ${p.score}`;
  }
  const weighted = weightsAddUp(p);
  box.classList.toggle("weighted", weighted);
  if (weighted) {
    box.replaceChildren(...p.whyFactors.map((f) => weightedRow(f, p.score as number)));
    return { shown: true, truncated: false };
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
function applyProtection(p: Protection | null, band: GraphBand | null, coverage: string | null): void {
  // A read that failed draws nothing: Why this verdict stays hidden.
  if (!p) return;
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
  card.classList.toggle("hot", band === "HIGH" || band === "CRITICAL");
  // The coverage chip under the verdict already says "partial"; the card adds
  // what that means, and only while it shows.
  $("why-coverage").hidden = !(why.shown && coverage === "partial");
  // The score is said once: in the card's head when the card shows, in the
  // chip row when it does not.
  if (!why.shown) renderScoreChip(p.score);
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

/** The four kinds a destination falls into, best first: the order of the bar. */
type LinkKind = "clean" | "unknown" | "suspicious" | "malicious";
const LINK_KINDS: readonly LinkKind[] = ["clean", "unknown", "suspicious", "malicious"];

/** What a destination's band is called, drawn and counted: CRITICAL and HIGH
 *  are malicious (as the link check counts them), MEDIUM suspicious, LOW, INFO
 *  and NONE clean. */
function kindOfBand(band: string): LinkKind {
  const b = band.toUpperCase();
  if (b === "CRITICAL" || b === "HIGH") return "malicious";
  if (b === "MEDIUM") return "suspicious";
  if (b === "UNKNOWN") return "unknown";
  return "clean";
}

const LINK_PILL: Record<LinkKind, { tone: string; word: string }> = {
  clean: { tone: "ok", word: "CLEAN" },
  unknown: { tone: "unknown", word: "UNKNOWN" },
  suspicious: { tone: "med", word: "SUSPICIOUS" },
  malicious: { tone: "crit", word: "MALICIOUS" },
};

/** One destination: the host on the left, its word on the right. */
function linkRow(host: string, band: string): HTMLElement {
  const kind = kindOfBand(band);
  const row = document.createElement("div");
  row.className = kind === "malicious" ? "link-row bad" : "link-row";
  const name = document.createElement("span");
  name.className = "link-host";
  name.textContent = host;
  const pill = document.createElement("span");
  pill.className = `pp-pill ${LINK_PILL[kind].tone}`;
  pill.textContent = LINK_PILL[kind].word;
  row.append(name, pill);
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

/** The destinations shown before "See all" is pressed. */
const LINK_ROWS_FIRST = 3;

let linkHosts: LinkScanResult["hosts"] = [];
let linkAllOpen = false;

/** Draw the rows of the current result: the first few, or all of them. */
function drawLinkRows(): void {
  const n = linkHosts.length;
  const shown = linkAllOpen ? linkHosts : linkHosts.slice(0, LINK_ROWS_FIRST);
  const list = $("linkscan-list");
  list.hidden = n === 0;
  list.replaceChildren(...shown.map((h) => linkRow(h.host, h.band)));
  const all = $<HTMLButtonElement>("linkscan-all");
  all.hidden = n <= LINK_ROWS_FIRST;
  all.setAttribute("aria-expanded", String(linkAllOpen));
  if (linkAllOpen) {
    all.textContent = "Show fewer";
  } else {
    const arrow = document.createElement("span");
    arrow.setAttribute("aria-hidden", "true");
    arrow.textContent = "→";
    all.replaceChildren(`See all ${n} `, arrow);
  }
}

let linkCheckedAt = 0;
let linkAgeShown = "";
let linkAgeTimer: number | undefined;

/** How long ago the result on screen arrived, in words. */
function checkedWords(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 1) return "checked just now";
  if (s < 60) return `checked ${s} s ago`;
  return `checked ${Math.floor(s / 60)} min ago`;
}

/** Rewrite the age only when its words change. Reads the clock and nothing else. */
function paintLinkAge(): void {
  const words = checkedWords(Date.now() - linkCheckedAt);
  if (words === linkAgeShown) return;
  linkAgeShown = words;
  $("linkscan-age").textContent = words;
}

/** A result has just been drawn: date it now (a re-check restamps) and keep it
 *  current while the popup is open. A failed check never calls this. */
function stampLinkAge(): void {
  linkCheckedAt = Date.now();
  linkAgeShown = "";
  $("linkscan-age").hidden = false;
  paintLinkAge();
  linkAgeTimer ??= window.setInterval(paintLinkAge, 1000);
}

function renderLinkScan(scan: LinkScanResult): void {
  const n = scan.hosts.length;
  $("linkscan-msg").hidden = true;

  const summary = $("linkscan-summary");
  summary.hidden = false;
  summary.className = `pp-headline${scan.flagged > 0 ? " hot" : ""}`;
  $("linkscan-count").textContent = String(n);
  $("linkscan-words").textContent = `${n === 1 ? "destination" : "destinations"}, ${scan.flagged === 0 ? "none" : scan.flagged} malicious`;

  // One segment and one count per kind that has any; a kind with none is left out.
  const counts: Record<LinkKind, number> = {
    clean: scan.clean,
    unknown: scan.unknown,
    suspicious: scan.suspicious,
    malicious: scan.flagged,
  };
  const bar = $("linkscan-bar");
  const tally = $("linkscan-counts");
  bar.hidden = n === 0;
  tally.hidden = n === 0;
  const segs: HTMLElement[] = [];
  const items: HTMLElement[] = [];
  for (const kind of LINK_KINDS) {
    const count = counts[kind];
    if (count <= 0) continue;
    const seg = document.createElement("span");
    seg.className = `pp-seg ${kind}`;
    seg.style.flexGrow = String(count);
    segs.push(seg);
    const item = document.createElement("span");
    item.className = "pp-count";
    const swatch = document.createElement("span");
    swatch.className = `pp-swatch ${kind}`;
    item.append(swatch, `${count} ${kind}`);
    items.push(item);
  }
  bar.replaceChildren(...segs);
  tally.replaceChildren(...items);

  linkHosts = scan.hosts;
  linkAllOpen = false;
  drawLinkRows();

  const cut = $("linkscan-cut");
  cut.hidden = !scan.truncated;
  cut.textContent = scan.truncated ? `Showing the ${n} busiest destinations; the page links to more.` : "";

  const note = $("linkscan-note");
  note.hidden = false;
  note.textContent = "Only the link hostnames were checked, never the page, its text, or your history.";

  stampLinkAge();
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
  const msg = $("linkscan-msg");
  msg.hidden = true;
  if (grant) {
    const ok = await grant.catch(() => false);
    if (!ok) {
      btn.disabled = false;
      btn.textContent = "Allow this page & check";
      msg.hidden = false;
      msg.textContent = "Whisper Guard needs your OK to read this page's link addresses. Nothing else is read.";
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
  msg.hidden = false;
  msg.textContent = res.error;
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

  $("iocscan-msg").hidden = true;
}

let iocScanNeedsGrant = false;

async function runIocScan(btn: HTMLButtonElement, grant?: Promise<boolean>): Promise<void> {
  if (tabId < 0) return;
  btn.disabled = true;
  btn.textContent = "Scanning…";
  $("iocscan-msg").hidden = true;
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
    const msg = $("iocscan-msg");
    msg.hidden = false;
    msg.textContent = "Guard needs access to this site to read its text. Click again to allow it for this site only.";
    return;
  }
  btn.textContent = "Scan page";
  const msg = $("iocscan-msg");
  msg.hidden = false;
  msg.textContent = `Could not scan this page: ${res.error}`;
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

/** What the link check sends, said before the reader presses it. A finished
 *  check replaces it with what that check did (renderLinkScan). */
const LINK_NOTE_BEFORE = "Link check sends link hostnames only, never paths or the page.";

function wireLinkScan(): void {
  $("linkscan-card").hidden = false;
  const note = $("linkscan-note");
  note.textContent = LINK_NOTE_BEFORE;
  note.hidden = false;
  // "See all" opens the whole list in place and goes back; it sends nothing and
  // keeps focus on itself.
  $("linkscan-all").addEventListener("click", () => {
    linkAllOpen = !linkAllOpen;
    drawLinkRows();
  });
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
// clicks" is a small lie about its own arithmetic, and this caption is the
// one place the count is ever broken down.
const WIN_LABEL: Record<WinCategory, { one: string; many: string }> = {
  preemptBlock: {
    one: "risky click stopped before anything loaded",
    many: "risky clicks stopped before anything loaded",
  },
  identityVerified: { one: "endpoint identity verified", many: "endpoint identities verified" },
  cookieDecline: { one: "cookie prompt declined", many: "cookie prompts declined" },
};

/**
 * What Guard did today, as the third figure and the caption under the strip.
 * Counted as categories only, never which sites, and shown only here, on the
 * reader's own click. A zero is a figure like any other (the read answered),
 * and its caption says so in words instead of naming categories.
 */
let todayWins: WinsToday | null = null;
/** How many destinations the report flags; null until the report has answered. */
let flaggedToday: number | null = null;

async function loadToday(): Promise<void> {
  const res = await send<{ ok: true; wins: WinsToday }>({ kind: "getWins" });
  if (!res.ok) return;
  const w = res.wins;
  todayWins = w;
  $("today-hero").textContent = String(w.total);
  $("today-row").hidden = false;
  const parts: string[] = [];
  for (const c of WIN_CATEGORIES) {
    const n = w.counts[c];
    if (n <= 0) continue;
    parts.push(`${n} ${n === 1 ? WIN_LABEL[c].one : WIN_LABEL[c].many}`);
  }
  $("today-breakdown").textContent = parts.join(", ");
  drawDayLine();
}

/**
 * The caption under the strip. With something handled it names the categories.
 * With nothing handled it says nothing needed attention, which is only true
 * beside a figure of no flagged destinations: with one flagged (or before the
 * report has said) the caption is left out rather than contradict the figures.
 */
function drawDayLine(): void {
  const w = todayWins;
  if (!w) return;
  const any = w.total > 0;
  $("today-lead").hidden = !any;
  $("today-stop").hidden = !any;
  $("today-note").textContent = any
    ? "Counted by category only, never which sites."
    : "Nothing needed your attention today; checks ran on every site.";
  $("today-caption").hidden = !any && flaggedToday !== 0;
}

/** The destination and flagged figures and the strip. The counts cover every
 *  destination in the log, the way the dashboard counts them. The background
 *  enriches only the busiest ones; for the rest it counts a flagged host only
 *  from what the browser already holds (a verdict it has cached or an
 *  enrichment it kept), so a host past the busiest 200 whose flag only a fresh
 *  enrichment would show is counted as not flagged here. */
async function loadBrowser24h(): Promise<void> {
  const res = await send<{ ok: true; report: BrowserReport }>({ kind: "getBrowserReport", limit: 200 });
  if (!res.ok) return;
  const t = res.report.totals;
  $("activity-destinations").textContent = String(t.destinations);
  $("fig-destinations").hidden = false;
  const flagged = $("activity-flagged");
  flagged.textContent = String(t.flagged);
  flaggedToday = t.flagged;
  drawDayLine();
  flagged.className = t.flagged > 0 ? "pp-fig-n hot" : "pp-fig-n ok";
  $("fig-flagged").hidden = false;

  const none = $("browser-24h");
  if (t.destinations === 0) {
    none.textContent = "No destinations recorded in this browser yet.";
    none.hidden = false;
    $("browser-strip").replaceChildren();
    return;
  }
  none.hidden = true;

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
    width: 350,
    height: 35,
    hours: 24,
    // Worded from what is drawn: every destination, or only the busiest that have a
    // time (then at least two are logged, so "out of" is always plural).
    title: stripTitle(events.length, t.destinations),
  });
  // No strip when there is nothing timed to put on it. An axis with no
  // marks says "we watched and saw nothing", which is not what an empty
  // timestamp list means.
  $("browser-strip").replaceChildren(...(strip ? [strip] : []));
}

/** What the strip draws, in words that are true for every count. `drawn` is how many
 *  destinations have a mark; `logged` is how many the log holds (never fewer). */
function stripTitle(drawn: number, logged: number): string {
  const when = "in the last 24 hours";
  if (drawn === logged) {
    return drawn === 1
      ? `The last sighting of the one destination ${when}`
      : `The last sighting of each of the ${drawn} destinations ${when}`;
  }
  const these = drawn === 1 ? "the 1 destination" : `each of the ${drawn} destinations`;
  return `The last sighting of ${these} drawn here, out of ${logged}, ${when}`;
}

/** "Open in console" in the footer, for a signed-in reader on every page,
 *  checked or not. Wired once, when the popup opens. */
function wireConsoleButton(): void {
  $("footer-actions").hidden = false;
  const button = $("btn-console");
  button.hidden = false;
  button.addEventListener("click", () => {
    chrome.tabs.create({ url: CONSOLE_URL });
  });
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

  // Three digits: never more than five characters, so the figure keeps the
  // header's room for its buttons as the graph grows.
  const nodes = $("scale-nodes");
  countUp(nodes, sc.nodes, compact3);

  // The tooltip carries the full picture, so the masthead can stay a
  // glance: exact figures, the resolvers' window, and when it was measured.
  const measured = new Date(sc.updated);
  const lat = sc.p50Us !== null ? `, p50 ${Math.round(sc.p50Us)}us` : "";
  box.title =
    `${sc.nodes.toLocaleString("en")} nodes and ${sc.edges.toLocaleString("en")} edges. ` +
    `${sc.queries.toLocaleString("en")} DNS questions answered in the last ${sc.windowHours}h${lat}. ` +
    `Read live at ${measured.toLocaleTimeString()}${sc.degraded ? " (the endpoint reports degraded input)" : ""}.`;
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

/** The warning triangle of a suspicious verdict, drawn as the disc's glyph. */
function warnMark(): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", "22");
  svg.setAttribute("height", "22");
  svg.setAttribute("viewBox", "0 0 40 40");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("aria-hidden", "true");
  const tri = document.createElementNS(ns, "path");
  tri.setAttribute("d", "M20 5 L36 33 H4 Z");
  tri.setAttribute("stroke-width", "3.6");
  tri.setAttribute("stroke-linejoin", "round");
  const bar = document.createElementNS(ns, "path");
  bar.setAttribute("d", "M20 15v8");
  bar.setAttribute("stroke-width", "3.6");
  bar.setAttribute("stroke-linecap", "round");
  const dot = document.createElementNS(ns, "circle");
  dot.setAttribute("cx", "20");
  dot.setAttribute("cy", "28");
  dot.setAttribute("r", "2");
  dot.setAttribute("fill", "currentColor");
  dot.setAttribute("stroke", "none");
  svg.append(tri, bar, dot);
  return svg;
}

/** "registered 12 years ago" as a sentence for the reason line. */
function sentenceOf(fact: string): string {
  return fact.charAt(0).toUpperCase() + fact.slice(1) + ".";
}

function applyChain(chain: SiteChain | null, band: GraphBand | null): void {
  const card = $("chain-card");
  const mount = $("chain-mount");
  const note = $("chain-note");
  card.hidden = false;
  if (!chain) {
    // The transport failed, which is a different fact from "the graph knows
    // nothing", and the panel has to say which one happened. The link and the
    // drawers stay: they do not depend on this read.
    // Only the rows are replaced: the heading stays, the waiting count goes.
    renderChainPending(mount, 7, "WHO IS BEHIND IT");
    const lost = document.createElement("div");
    lost.className = "pp-note lost";
    lost.textContent = FACTS_UNREAD;
    mount.querySelector(".ch-count")?.remove();
    mount.querySelector(".ch-spine")?.replaceWith(lost);
    note.hidden = true;
    return;
  }
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

  // The age is part of the reason line, drawn with the rest of the answer.
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

/** The cookie line on This page: shown only while the worker's record says
 *  Guard declined a cookie prompt on this tab's current page. Reads storage
 *  only and sends nothing; anything unknown keeps the line hidden, and so does
 *  a live check that is turned off (This page then has nothing to say but why). */
function watchCookieLine(): void {
  if (tabId < 0) return;
  const key = cookieDeclinedKey(tabId);
  // Unknown settings keep the line hidden, like any other unknown.
  const live = settings?.cloudCheck === true;
  const show = (v: unknown): void => {
    $("cookie-line").hidden = !live || v !== true;
  };
  // Without Active Shield, opening the popup arms the page, so a decline can
  // land after the first read: follow the record for as long as the popup is open.
  let changed = false;
  chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area !== "session" || !(key in changes)) return;
    changed = true;
    show(changes[key]?.newValue);
  });
  chrome.storage?.session?.get(key).then(
    (got) => {
      if (!changed) show(got[key]);
    },
    () => undefined,
  );
}

/** Everything that does not depend on this site's check: drawn once at open,
 *  in every case, so every part is filled while a check waits or a press is due. */
function renderShell(signedIn: boolean, activeHost: string, first: TabState | null): void {
  void loadScale();
  void loadToday();
  void loadBrowser24h();
  $("btn-dashboard").addEventListener("click", (ev) => {
    ev.preventDefault();
    void send({ kind: "openDashboard" }).then(() => window.close());
  });
  if (signedIn) wireConsoleButton();

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

  watchCookieLine();

  // The on-device look-alike catch needs no check and sends nothing.
  if (first) drawLookalike(first);
}

let lookalikeDrawn = false;

/** How each kind of catch is worded in the trick line. */
const KIND_TEXT: Record<string, string> = {
  confusable: "is a confusable look-alike of",
  tldswap: "uses the name of",
  combosquat: "embeds the name of",
  "brand-subdomain": "impersonates",
  nearmiss: "is one keystroke away from",
};

/** The one character a confusable name swaps: where it sits in the host, what
 *  the host has and what the brand has. */
interface Swap {
  at: number;
  got: string;
  want: string;
}

/**
 * The swap, worked out on the device from the two names. The detector's hit does
 * not carry the character, so it is derived only when it is certain: a
 * confusable catch between plain ASCII names whose first labels have the same
 * length and differ in exactly one place, on a host that is, or sits under, the
 * name the detector matched. Anything else singles out no character.
 */
function swapOf(host: string, d: DetectorHit): Swap | null {
  if (d.kind !== "confusable") return null;
  const matched = d.matched.toLowerCase();
  const brand = d.brandDomain.toLowerCase();
  const plain = /^[\x21-\x7e]+$/;
  if (!plain.test(matched) || !plain.test(brand)) return null;
  if ([...matched.split("."), ...brand.split(".")].some((l) => l.startsWith("xn--"))) return null;
  const ours = matched.split(".")[0] ?? "";
  const theirs = brand.split(".")[0] ?? "";
  if (ours.length === 0 || ours.length !== theirs.length) return null;
  let i = -1;
  for (let k = 0; k < ours.length; k++) {
    if (ours[k] === theirs[k]) continue;
    if (i !== -1) return null;
    i = k;
  }
  if (i === -1) return null;
  const h = host.toLowerCase();
  if (h !== matched && !h.endsWith(`.${matched}`)) return null;
  const at = h.length - matched.length + i;
  return { at, got: h.charAt(at), want: theirs.charAt(i) };
}

/** Write a name with its swapped character marked. The text is always the full
 *  name: nothing is cut, so a long name cannot hide a look-alike. */
function writeName(el: HTMLElement, host: string, swap: Swap | null): void {
  if (!swap) {
    el.textContent = host;
    return;
  }
  const mark = document.createElement("span");
  mark.className = "pp-swap";
  mark.textContent = host.charAt(swap.at);
  el.replaceChildren(host.slice(0, swap.at), mark, host.slice(swap.at + 1));
}

/** The trick, said from what was read on the device. */
function trickText(swap: Swap | null, d: DetectorHit): string {
  if (swap) {
    const say = (c: string): string => (/[0-9]/.test(c) ? `the digit \u201c${c}\u201d` : `\u201c${c}\u201d`);
    return `Trick: homoglyph, ${say(swap.got)} in place of ${say(swap.want)}.`;
  }
  return `Trick: this site ${KIND_TEXT[d.kind] ?? "looks like"} ${d.brandDomain}.`;
}

/** The look-alike card and its report button, from the on-device detector. */
function drawLookalike(s: TabState): void {
  if (lookalikeDrawn || !s.detector || !s.hostname) return;
  lookalikeDrawn = true;
  const host = s.hostname;
  const d = s.detector;
  const swap = swapOf(host, d);
  $("lookalike").hidden = false;
  $("lookalike-text").textContent = `This site looks like ${d.brandDomain} but is not it.`;
  writeName($("lookalike-on"), host, swap);
  $("lookalike-real").textContent = d.brandDomain;
  $("lookalike-trick").textContent = trickText(swap, d);
  const go = $<HTMLAnchorElement>("btn-goto");
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

/** The reads behind a verdict: why it says what it says, and who is behind the
 *  name. They start while the loader shows and are drawn with the verdict, in
 *  one draw. undefined is "not in yet", null is "could not be read". */
interface Evidence {
  host: string;
  startedAt: number;
  protection: Protection | null | undefined;
  chain: SiteChain | null | undefined;
  ready: Promise<void>;
}

let evidence: Evidence | null = null;

/** Start the reads for a name, once: asking again for the same name joins them. */
function startEvidence(host: string): Evidence {
  if (evidence && evidence.host === host) return evidence;
  const ev: Evidence = { host, startedAt: Date.now(), protection: undefined, chain: undefined, ready: Promise.resolve() };
  const protection = send<{ ok: true; protection: Protection }>({ kind: "getProtection", host }).then(
    (res) => {
      ev.protection = res.ok ? res.protection : null;
    },
    () => {
      ev.protection = null;
    },
  );
  const chain = send<{ ok: true; chain: SiteChain }>({ kind: "getChain", host }).then(
    (res) => {
      ev.chain = res.ok ? res.chain : null;
    },
    () => {
      ev.chain = null;
    },
  );
  ev.ready = Promise.all([protection, chain]).then(() => undefined);
  evidence = ev;
  return ev;
}

/** Wait until both reads have answered or failed, or until they have had the
 *  longest the worker can honestly take for them. */
function evidenceIn(ev: Evidence): Promise<void> {
  const left = Math.max(0, ev.startedAt + EVIDENCE_LIMIT_MS - Date.now());
  return Promise.race([ev.ready, new Promise<void>((r) => setTimeout(r, left))]);
}

/** What the popup says when the check outlasted its limit, in the worker's own words for a call that did not answer. */
const LIMIT_ERROR = "could not reach Whisper; showing on-device checks only";

let siteWired = false;
/** Which drawers have read for the name drawn now. */
const drawerLoaded = { why: false, who: false, hood: false };
/** The state the site part shows now: what "Copy dossier" reads. */
let drawnState: TabState | null = null;

/** The site part's listeners, attached once however often it is drawn. */
function wireSite(cloudCheck: boolean): void {
  if (siteWired) return;
  siteWired = true;

  // opening the popup is a real invocation of Guard on this tab, so
  // arm the pre-emptive click/submit guard here: under activeTab this
  // works even without the broad Active-Shield grant. Fire-and-forget;
  // the background fails silently where the page is not scriptable.
  void send({ kind: "preemptArm", tabId });

  if (cloudCheck) {
    wireLinkScan();
    wireIocScan();
    wireGraphPath();
    // The analyst drawers ride the public tier: available keyless and keyed.
    // Each reads the name from the state drawn now, never from the first one.
    $("expanders").hidden = false;
    $("exp-why").addEventListener("toggle", () => {
      const h = drawnState?.hostname;
      if (h && !drawerLoaded.why && ($("exp-why") as HTMLDetailsElement).open) {
        drawerLoaded.why = true;
        void loadExpander("explain", h, "why-body");
      }
    });
    $("exp-who").addEventListener("toggle", () => {
      const h = drawnState?.hostname;
      if (h && !drawerLoaded.who && ($("exp-who") as HTMLDetailsElement).open) {
        drawerLoaded.who = true;
        void loadExpander("identify", h, "who-body");
      }
    });
    $("exp-neighborhood").addEventListener("toggle", () => {
      const h = drawnState?.hostname;
      if (h && !drawerLoaded.hood && ($("exp-neighborhood") as HTMLDetailsElement).open) {
        drawerLoaded.hood = true;
        void loadNeighborhood(h);
      }
    });
    void loadSession();
  }

  if (state?.signedIn) {
    // The footer's other button: a dossier needs a site that was checked.
    $("footer-actions").hidden = false;
    $("btn-dossier").hidden = false;
    $("btn-dossier").addEventListener("click", async () => {
      const s = drawnState;
      const host = s?.hostname;
      if (!host) return;
      const [explain, identify] = await Promise.all([
        send<{ ok: true; explain: ExplainResult }>({ kind: "explain", host }),
        send<{ ok: true; explain: ExplainResult }>({ kind: "identify", host }),
      ]);
      const lines = [
        `# Whisper Guard dossier: ${host}`,
        ``,
        `- band: ${s?.verdict?.band ?? "(no live check)"}`,
        `- coverage: ${s?.verdict?.coverage ?? "n/a"} (categorical, not a safety score)`,
        `- label: ${s?.verdict?.label ?? "n/a"}`,
        `- on-device look-alike: ${s?.detector ? `${s.detector.kind} of ${s.detector.brandDomain}` : "none"}`,
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
}

/** A different name is drawn: what the drawers read for the last one goes. */
function resetDrawers(): void {
  drawerLoaded.why = drawerLoaded.who = drawerLoaded.hood = false;
  for (const id of ["exp-why", "exp-who", "exp-neighborhood"]) ($(id) as HTMLDetailsElement).open = false;
  $("why-body").textContent = "Loading...";
  $("who-body").textContent = "Loading...";
  $("neighborhood-note").textContent = "";
}

/** Put the site part back to nothing drawn, so a second draw starts clean. */
function clearSiteDraw(): void {
  for (const id of ["coverage-chip", "score-chip", "allow-chip"]) $(id).hidden = true;
  $("coverage-chip").replaceChildren();
  $("score-chip").replaceChildren();
  syncChips();
  $("band-age").hidden = true;
  $("band-age").textContent = "";
  $("why-panel").hidden = true;
  $("why-score").hidden = true;
  $("why-factors").replaceChildren();
  $("why-chips").replaceChildren();
  $("why-coverage").hidden = true;
  $("protect-card").hidden = true;
  $("chain-card").hidden = true;
  $("chain-mount").replaceChildren();
  $("chain-note").hidden = true;
  $("neighbours-note").hidden = true;
  $("graph-error").hidden = true;
}

/** A tab whose check is still running is never drawn as a verdict. */
function isRunning(s: TabState): boolean {
  return (settings?.cloudCheck ?? true) && s.icon === "checking" && s.eligible && !!s.hostname;
}

/** The part of the popup that is this site's answer, drawn in one go from a
 *  state that is settled (or, past the limit, one that stands for could not
 *  check) and the reads behind it. It can be drawn again for a later state:
 *  every write replaces what an earlier draw left, and the listeners are
 *  attached once. */
function drawSite(s: TabState, ev: Evidence | null): void {
  const cloudCheck = settings?.cloudCheck ?? true;
  // The reads are for the name drawn, and no other: for any other name the
  // site part starts over with its own reads, and nothing is written here.
  if (ev && s.hostname !== ev.host) {
    void showSite(s).catch(() => drawNotChecked());
    return;
  }
  $("checking-view").hidden = true;
  $("not-checked-view").hidden = true;
  drawLookalike(s);

  if (!s.eligible || !s.hostname) {
    $("ineligible").hidden = false;
    $("host-row").hidden = true;
    setPrivacyLine("Privacy: nothing was sent.");
    // The site's message is the only sentence about this page: This page
    // does not repeat it.
    showPagePart("hidden");
    return;
  }
  const host = s.hostname;
  if (drawnState?.hostname !== host) resetDrawers();
  drawnState = s;
  wireSite(cloudCheck);
  clearSiteDraw();
  if (cloudCheck) pointGraphPath(host);

  $("host-row").hidden = false;
  writeName($("hostname"), host, s.detector ? swapOf(host, s.detector) : null);
  const band: GraphBand | null = s.verdict?.band ?? null;
  // The reads that did not answer (or are not wanted) draw nothing of their own.
  const protection = ev?.protection ?? null;
  const chain = ev?.chain ?? null;
  if (cloudCheck) {
    // The chain is the keyless payload and does not wait on a verdict:
    // whether the name is flagged or unremarkable, the path behind it is
    // the thing the panel was opened to see.
    applyChain(chain, band);
    showPagePart("cards");
  } else {
    showPagePart("live-off");
  }

  if (settings && isTrusted(host, s.registrable, settings.allowlist)) {
    $("allow-chip").hidden = false;
    syncChips();
  }

  if (band) {
    const ui = BAND_UI[band];
    paintVerdict(ui.tone, ui.tone, ui.glyph, ui.chip, verdictSentence(band, s.verdict?.label ?? null), ADVICE[band] ?? null);
    renderCoverage(s.verdict?.coverage ?? null);
    applyProtection(protection, band, s.verdict?.coverage ?? null);
  } else if (cloudCheck && s.graphError) {
    // The check was made and Whisper did not answer. Its own word, glyph and
    // amber, so it is never read as SUSPICIOUS or as a clean "unknown".
    paintVerdict("err", "err", "!", "COULD NOT CHECK", "Not confirmed either way. On-device checks still ran.");
    applyProtection(protection, null, null);
  } else if (cloudCheck) {
    // Reached only by a state that holds no answer and no check running: one
    // kept from a time the live check was off and opened after it was turned
    // on. It is not a check that was made, and it is not drawn as one that is
    // still running.
    paintVerdict("unknown", "unknown", "?", "UNKNOWN", "No verdict yet for this site.");
    applyProtection(protection, null, null);
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
 *  check), the pill's words, the one reason and, for a suspicious site, what
 *  to do about it. */
function paintVerdict(
  tone: string,
  pill: string,
  glyph: Glyph,
  chip: string,
  reason: string,
  advice: string | null = null,
): void {
  $("host-row").className = `pp-card pp-verdict ${tone}`;
  // The facts card colours its counter by the verdict above it.
  $("chain-card").dataset["tone"] = tone;
  const disc = $("band-glyph");
  if (glyph === null) disc.replaceChildren(checkMark());
  else if (typeof glyph === "function") disc.replaceChildren(glyph());
  else disc.textContent = glyph;
  const pillEl = $("band-chip");
  pillEl.className = `pp-pill ${pill}`;
  pillEl.textContent = chip;
  $("band-note").textContent = reason;
  const note = $("band-advice");
  note.textContent = advice ?? "";
  note.hidden = advice === null;
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
function wireGraphPath(): void {
  $<HTMLAnchorElement>("graph-path").addEventListener("click", (ev) => {
    ev.preventDefault();
    const href = $<HTMLAnchorElement>("graph-path").dataset["page"];
    if (href) chrome.tabs.create({ url: chrome.runtime.getURL(href) });
  });
}

/** Point the graph path link at the check-link page for the name drawn. */
function pointGraphPath(host: string): void {
  const page = `check-link.html?host=${encodeURIComponent(host)}`;
  const link = $<HTMLAnchorElement>("graph-path");
  link.href = page;
  link.dataset["page"] = page;
}

/** The one sentence This page shows while the live check is off. */
const PAGE_NEEDS_LIVE_CHECK = "The link check and the indicator scan need the live check. Turn it on in settings.";

/** What This page shows. It is the one writer of that.
 *  - "cards": the link check, the indicator scan and the cookie line.
 *  - "live-off": one sentence, since both checks need the live check.
 *  - "hidden": nothing. While a check runs, before one was made, and on a page
 *    that cannot be checked, the site part already says why, in its own
 *    words, and this part would only repeat it. */
function showPagePart(what: "cards" | "live-off" | "hidden"): void {
  const note = $("page-empty");
  note.textContent = what === "live-off" ? PAGE_NEEDS_LIVE_CHECK : "";
  note.hidden = what !== "live-off";
  $("panel-page").hidden = what === "hidden";
}

/**
 * The theme button: its name and tooltip say the current choice, and a press
 * moves Auto, Light, Dark, Auto. The choice is drawn on this page at once, and
 * the background keeps it (local storage, never synced). The name follows the
 * page's own attribute, so a choice made in another Guard page shows here too.
 */
function initThemeButton(): void {
  const btn = $("btn-theme");
  const live = $("theme-live");
  const root = document.documentElement;
  const choice = (): ThemeChoice => normalizeTheme(root.getAttribute("data-theme"));
  const show = (): void => {
    btn.setAttribute("aria-label", themeName(choice()));
    btn.setAttribute("title", themeTitle(choice()));
  };
  show();
  new MutationObserver(show).observe(root, { attributes: true, attributeFilter: ["data-theme"] });
  btn.addEventListener("click", () => {
    const next = nextTheme(choice());
    chooseTheme(next);
    live.textContent = themeName(next);
  });
}

async function init(): Promise<void> {
  // First, before any await: the popup opens at the top, and the fade
  // follows the scroll while a check is in flight and when the page's state
  // cannot be read.
  $("popup-scroll").scrollTop = 0;
  initFade();
  // A <canvas> keeps the ink it was drawn with, so a colour-scheme flip
  // has to redraw the look-alike neighbourhood.
  onThemeChange(() => {
    const open = ($("exp-neighborhood") as HTMLDetailsElement).open;
    if (open && state?.hostname) void loadNeighborhood(state.hostname);
  });
  initThemeButton();
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
  if (cloudCheck && first.lost && first.eligible && first.hostname) {
    drawNotChecked();
    return;
  }
  try {
    await showSite(first);
  } catch {
    // The worker stopped while waiting: no answer to draw.
    drawNotChecked();
  }
}

function tabStateOf(res: BgResponse | null): TabState | null {
  return res && res.ok && "tabState" in res ? res.tabState : null;
}

/** How often the popup asks the worker whether the check has settled. */
const POLL_MS = 200;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Which draw of the site part is current: a newer one (a press of "Check this
 *  site now") takes over from an older one that is still waiting. */
let siteRun = 0;

/**
 * Draw This site for a tab. While its check is running only the loader shows;
 * the reads behind the verdict start with it. The verdict, Why this verdict,
 * the age line and the facts are then drawn together, once the check has
 * settled and the reads have answered or failed. A check that is still running
 * at its limit (counted from when the worker scheduled it) is drawn as could
 * not check, and the popup keeps listening: when the check settles later the
 * site part is drawn again from the settled state.
 */
async function showSite(first: TabState): Promise<void> {
  const run = ++siteRun;
  const cloudCheck = settings?.cloudCheck ?? true;
  let s = first;
  // One pass per name: when the tab moves to another name while the popup
  // waits, the loader shows again and the reads start for the new name.
  for (;;) {
    if (!cloudCheck || !s.eligible || !s.hostname) {
      state = s;
      drawSite(s, null);
      return;
    }
    const host = s.hostname;
    const ev = startEvidence(host);
    drawChecking(host);

    if (isRunning(s)) {
      const limit = (s.checkStartedAt ?? Date.now()) + CHECK_LIMIT_MS;
      while (isRunning(s) && Date.now() < limit && s.hostname === host) {
        await sleep(Math.min(POLL_MS, Math.max(0, limit - Date.now())));
        const res = await send<{ ok: true; tabState: TabState }>({ kind: "getTabState", tabId });
        if (res.ok) {
          s = res.tabState;
          // A state that gained its detector since the last one still shows the card beside the loader.
          if (s.hostname === host) drawLookalike(s);
        }
      }
    }
    if (run !== siteRun) return;
    if (s.hostname !== host) continue;
    if (s.lost && s.eligible) {
      drawNotChecked();
      return;
    }
    if (isRunning(s)) {
      // The limit passed with the check still going: could not check, drawn
      // with whatever the reads have brought so far, and the popup keeps
      // listening until twice the limit has passed since the check began.
      state = s;
      drawSite({ ...s, icon: "unknown", graphError: LIMIT_ERROR }, ev);
      void listenForSettled(run, host, ev, (s.checkStartedAt ?? Date.now()) + LISTEN_LIMIT_MS);
      return;
    }
    await evidenceIn(ev);
    if (run !== siteRun) return;
    state = s;
    drawSite(s, ev);
    return;
  }
}

/** How long after a check began the popup goes on listening for it to settle. */
const LISTEN_LIMIT_MS = 2 * CHECK_LIMIT_MS;

/** After the limit: ask until the check settles, then draw the site part again from its answer. */
async function listenForSettled(run: number, host: string, ev: Evidence, until: number): Promise<void> {
  while (run === siteRun && Date.now() < until) {
    await sleep(POLL_MS);
    let s: TabState;
    try {
      const res = await send<{ ok: true; tabState: TabState }>({ kind: "getTabState", tabId });
      if (!res.ok) continue;
      s = res.tabState;
    } catch {
      return;
    }
    if (run !== siteRun) return;
    // The tab moved on to another page: it is drawn as its own page, with its own reads.
    if (s.hostname !== host) {
      void showSite(s).catch(() => drawNotChecked());
      return;
    }
    if (isRunning(s)) continue;
    if (s.lost) {
      drawNotChecked();
      return;
    }
    await evidenceIn(ev);
    if (run !== siteRun) return;
    state = s;
    drawSite(s, ev);
    return;
  }
}

/** The waiting view: the site's name and placeholders that the verdict replaces. */
function drawChecking(host: string): void {
  $("not-checked-view").hidden = true;
  $("host-row").hidden = true;
  $("checking-host").textContent = host;
  $("checking-host").hidden = host === "";
  $("checking-view").hidden = false;
  showPagePart("hidden");
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
  // The card says it all; This page does not repeat it.
  showPagePart("hidden");
}

/** "Check this site now": one check of this tab's page by the worker, drawn in
 *  place by the same rules as a check at open. The popup and the page are
 *  never reloaded. */
async function checkNow(): Promise<void> {
  const button = $("btn-check-now") as HTMLButtonElement;
  const hadFocus = document.activeElement === button;
  button.disabled = true;
  // Reads from an earlier look at this name are not this check's.
  evidence = null;
  drawChecking(state?.hostname ?? "");
  if (state?.hostname && state.eligible) startEvidence(state.hostname);
  let next: TabState | null = null;
  try {
    next = tabStateOf(await send({ kind: "checkTab", tabId }));
  } catch {
    next = null;
  }
  if (next && !(next.lost && next.eligible && next.hostname)) {
    state = next;
    try {
      await showSite(next);
    } catch {
      drawNotChecked();
      if (hadFocus) button.focus();
      return;
    }
    if (!$("not-checked-view").hidden) {
      if (hadFocus) button.focus();
      return;
    }
    // The pressed button is gone; keep focus inside This site. Whether the
    // press focused the button first depends on the browser (a mouse click on
    // macOS Firefox does not), so it moves on every successful press.
    $("panel-site").focus({ preventScroll: true });
  } else {
    drawNotChecked();
    if (hadFocus) button.focus();
  }
}

void init();
