// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The click-panel answers three questions in this order and nothing else:
//
//   1. is this site safe?      one glyph, one badge, ONE sentence. The
//                              sentence never restates the badge, and
//                              coverage lives with the evidence, not beside
//                              the verdict where it reads as a score.
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
// way", never as green. Every view carries the per-host privacy line saying
// exactly what was sent.

import { send, type BrowserReport } from "../shared/messages";
import {
  WIN_CATEGORIES,
  type CandidateVerdict,
  type ExplainResult,
  type GraphBand,
  type LinkScanResult,
  type Protection,
  type Settings,
  type TabState,
  type WhyFactor,
  type WinCategory,
  type WinsToday,
} from "../shared/types";
import { CATEGORY_LABEL, flagEmoji, type ReportCategory } from "../shared/report";
import { CONSOLE_URL, GRAPH_HOST } from "../shared/config";
import { mountProtectControl, type ProtectControl } from "../shared/protect-control";
import { CANVAS_MONO, onThemeChange, themeColor } from "../shared/theme";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let tabId = -1;
let state: TabState | null = null;
let settings: Settings | null = null;

const BAND_UI: Record<GraphBand, { glyphCls: string; chipCls: string; chip: string; glyph: string }> = {
  CRITICAL: { glyphCls: "malicious", chipCls: "crit", chip: "MALICIOUS - evidenced", glyph: "⬣" },
  HIGH: { glyphCls: "malicious", chipCls: "high", chip: "HIGH RISK", glyph: "⬣" },
  MEDIUM: { glyphCls: "suspicious", chipCls: "med", chip: "SUSPICIOUS", glyph: "▲" },
  LOW: { glyphCls: "benign", chipCls: "ok", chip: "NO KNOWN THREAT", glyph: "✓" },
  INFO: { glyphCls: "benign", chipCls: "ok", chip: "NO KNOWN THREAT", glyph: "✓" },
  NONE: { glyphCls: "benign", chipCls: "ok", chip: "NO KNOWN THREAT", glyph: "✓" },
  UNKNOWN: { glyphCls: "unknown", chipCls: "unknown", chip: "UNKNOWN", glyph: "?" },
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
  const cx = W / 2;
  const cy = H / 2;

  const line = themeColor("--w-line-strong", "#2c2c3c");
  const muted = themeColor("--w-muted", "#9a9aae");
  const text = themeColor("--w-text", "#ececf1");
  const accent = themeColor("--w-accent", "#6ea8ff");
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

function protectKv(k: string, v: string): HTMLElement {
  const row = document.createElement("div");
  row.className = "protect-kv";
  const kEl = document.createElement("span");
  kEl.className = "k";
  kEl.textContent = k;
  const vEl = document.createElement("span");
  vEl.className = "v";
  vEl.textContent = v;
  row.append(kEl, vEl);
  return row;
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
  if (p.whyFactors.length === 0 && p.score === null) return { shown: false, truncated: false };
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

/**
 * Coverage: how much the graph KNOWS about this name. It is categorical and
 * it is NOT a safety score (a CRITICAL host can be known-clean coverage),
 * which is why it belongs down here with the machine vocabulary instead of
 * next to the verdict, where a reader takes any second badge for a grade.
 */
function renderCoverage(coverage: string | null): boolean {
  const el = $("coverage-chip");
  if (!coverage) return false;
  const val = document.createElement("span");
  val.className = "cov";
  val.textContent = coverage;
  el.replaceChildren(
    document.createTextNode("Coverage "),
    val,
    document.createTextNode(": what the graph knows about this name, not a safety score."),
  );
  el.hidden = false;
  return true;
}

/** The composed picture: who runs it, where, how old, why flagged. */
async function loadProtection(host: string): Promise<void> {
  const res = await send<{ ok: true; protection: Protection }>({ kind: "getProtection", host });
  if (!res.ok) return;
  const p = res.protection;
  const why = renderWhy(p);
  const rows: HTMLElement[] = [];
  if (p.who) {
    // The owner chain falls back to the registrable domain when the graph
    // has no organization and no canonical name for the host, so "Who:
    // example.com" is the shape of "not known" wearing the shape of an
    // answer. Say the unknown out loud instead: on a security panel, "we
    // could not identify who runs this" is information, and echoing the
    // hostname back at the reader is not.
    const fallback = (state?.registrable ?? "").toLowerCase();
    const named = p.who.toLowerCase() !== fallback && p.who.toLowerCase() !== host.toLowerCase();
    const category =
      p.category && p.category in CATEGORY_LABEL ? CATEGORY_LABEL[p.category as ReportCategory] : null;
    const known = category && category !== CATEGORY_LABEL.unresolved ? category : null;
    if (named) rows.push(protectKv("Who", known ? `${p.who} · ${known}` : p.who));
    else rows.push(protectKv("Who", known ? `not identified · ${known}` : "not identified in the graph"));
  }
  if (p.where && (p.where.city || p.where.country)) {
    const flag = flagEmoji(p.where.country ?? undefined);
    rows.push(protectKv("Where", `${p.where.city ?? p.where.country}${flag ? ` ${flag}` : ""}`));
  }
  if (p.ageDays !== null) {
    const label =
      p.ageDays < 32 ? `${p.ageDays} days (new domains deserve suspicion)` : p.ageDays < 366 ? `${Math.round(p.ageDays / 30.4)} months` : `${Math.floor(p.ageDays / 365.25)} years`;
    rows.push(protectKv("Age", label));
  }
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
  if (rows.length > 0 || prose.length > 0 || why.shown) {
    card.hidden = false;
    $("protect-rows").replaceChildren(...rows);
  }
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
    const line = document.createElement("div");
    line.className = "today-line";
    line.textContent = `${n} ${n === 1 ? WIN_LABEL[c].one : WIN_LABEL[c].many}`;
    rows.push(line);
  }
  $("today-breakdown").replaceChildren(...rows);
  $("today-note").textContent =
    w.total === 0
      ? "Nothing needed your attention today; checks ran on every site."
      : "Counted by category only, never which sites.";
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

// ---------------------------------------------------------------- render

function render(): void {
  if (!state) return;
  const s = state;
  const cloudCheck = settings?.cloudCheck ?? true;

  void loadToday();
  void loadBrowser24h();
  $("btn-dashboard").addEventListener("click", () => {
    void send({ kind: "openDashboard" }).then(() => window.close());
  });

  // This browser's protection is on every page, signed in or not: keyed
  // readers get the one control, keyless readers get the one thing that
  // unlocks it. Two tiers, both honest, one action either way.
  if (s.signedIn) void loadIdentity();
  else wireSignin();

  // a session block must be discoverably clearable - list the hosts
  // blocked this session and, when THIS tab is one (the opaque
  // ERR_BLOCKED_BY_CLIENT page), explain it and offer a one-click clear. The
  // list is session-wide, not tab-scoped, so it runs BEFORE the eligibility
  // gate: even on an ineligible tab (a browser page, or the block page itself)
  // a session block stays visible and clearable, never a silent dead end.
  void loadBlocked(s.hostname ?? "");

  if (!s.eligible || !s.hostname) {
    $("ineligible").hidden = false;
    $("privacy-line").textContent = "Privacy: nothing was sent.";
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
  if (cloudCheck) wireLinkScan();

  const band: GraphBand | null = s.verdict?.band ?? null;
  const glyph = $("band-glyph");
  const chip = $("band-chip");
  const note = $("band-note");

  if (band) {
    const ui = BAND_UI[band];
    glyph.className = `glyph ${ui.glyphCls}`;
    glyph.textContent = ui.glyph;
    chip.className = `w-chip ${ui.chipCls}`;
    chip.textContent = ui.chip;
    note.textContent = verdictSentence(band, s.verdict?.label ?? null);
    if (renderCoverage(s.verdict?.coverage ?? null)) $("protect-card").hidden = false;
    void loadProtection(host);
  } else if (cloudCheck) {
    glyph.className = "glyph unknown";
    glyph.textContent = "?";
    chip.className = "w-chip unknown";
    chip.textContent = "UNKNOWN";
    note.textContent = "No verdict yet for this site.";
    void loadProtection(host);
  } else {
    glyph.className = "glyph signedout";
    // A plain ring: no reading was taken. U+26BF has no glyph in a good many
    // system font stacks and falls back to a tofu box, which reads as a
    // rendering fault rather than a state.
    glyph.textContent = "○";
    chip.className = "w-chip unknown";
    chip.textContent = "LIVE CHECK OFF";
    note.textContent = "On-device protection only. Turn the live check back on in settings.";
  }

  if (s.detector) {
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
  }

  if (s.signedIn && (band === "CRITICAL" || band === "HIGH" || band === "MEDIUM" || s.detector)) {
    const report = $("btn-report");
    if (s.detector) $("lookalike").hidden = false;
    report.hidden = !s.detector;
    report.addEventListener("click", async () => {
      report.textContent = "Reporting...";
      const res = await send({ kind: "report", host, note: "reported from Whisper Guard" });
      const status = $("report-status");
      status.hidden = false;
      status.textContent = res.ok ? "Reported. Thank you." : "Could not submit the report; try again.";
      report.hidden = true;
    });
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

  $("privacy-line").textContent = cloudCheck
    ? `Privacy: only "${host}" was sent, to ${GRAPH_HOST}. Never the page, path, or your history.`
    : s.detector
      ? `Privacy: nothing left your browser. The look-alike check ran on-device.`
      : `Privacy: nothing was sent. The live check is off; on-device checks still ran.`;
}

async function init(): Promise<void> {
  // A <canvas> keeps the ink it was drawn with, so a colour-scheme flip
  // has to redraw the look-alike neighbourhood.
  onThemeChange(() => {
    const open = ($("exp-neighborhood") as HTMLDetailsElement).open;
    if (open && state?.hostname) void loadNeighborhood(state.hostname);
  });
  $("btn-settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("btn-refresh").addEventListener("click", () => window.location.reload());

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
    send<{ ok: true; tabState: TabState }>({ kind: "getTabState", tabId }),
    send<{ ok: true; settings: Settings; signedIn: boolean; corpusVersion: number; corpusUpdated: string }>({
      kind: "getSettings",
    }),
  ]);
  if (settingsRes.ok) settings = settingsRes.settings;
  if (stateRes.ok) {
    state = stateRes.tabState;
    render();
  }
}

void init();
