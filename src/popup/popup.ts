// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The click-panel: a verdict and one action above the fold; the composed
// protection picture (who runs it, where, how old, why) right under it; a
// mini "this browser" dashboard; analyst affordances collapsed. UNKNOWN is
// the honest common state and reads as "not confirmed either way", never
// as green. Every view carries the per-host privacy line saying exactly
// what was sent.

import { send, type BrowserReport } from "../shared/messages";
import type {
  CandidateVerdict,
  EgressStatus,
  Enrollment,
  ExplainResult,
  GraphBand,
  LinkScanResult,
  Protection,
  Settings,
  TabState,
  WhyFactor,
} from "../shared/types";
import { CATEGORY_LABEL, flagEmoji, type ReportCategory } from "../shared/report";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let tabId = -1;
let state: TabState | null = null;
let settings: Settings | null = null;

const BAND_UI: Record<GraphBand, { glyphCls: string; chipCls: string; chip: string; glyph: string; note: string }> = {
  CRITICAL: { glyphCls: "malicious", chipCls: "crit", chip: "MALICIOUS - evidenced", glyph: "⬣", note: "Known threat, listed in the graph. Do not enter credentials." },
  HIGH: { glyphCls: "malicious", chipCls: "high", chip: "HIGH RISK", glyph: "⬣", note: "Strong risk signals in the graph. Stay away." },
  MEDIUM: { glyphCls: "suspicious", chipCls: "med", chip: "SUSPICIOUS", glyph: "▲", note: "Some risk signals. Be careful." },
  LOW: { glyphCls: "benign", chipCls: "ok", chip: "NO KNOWN THREAT", glyph: "✓", note: "Low-level signals only. Not a warranty." },
  INFO: { glyphCls: "benign", chipCls: "ok", chip: "NO KNOWN THREAT", glyph: "✓", note: "Informational signals only. Not a warranty." },
  NONE: { glyphCls: "benign", chipCls: "ok", chip: "NO KNOWN THREAT", glyph: "✓", note: "No known threat. Not a warranty." },
  UNKNOWN: { glyphCls: "unknown", chipCls: "unknown", chip: "UNKNOWN", glyph: "?", note: "New or low-coverage site. Not confirmed safe or unsafe." },
};

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
  ctx.font = "10px ui-monospace, monospace";
  const cx = W / 2;
  const cy = H / 2;

  const colors: Record<string, string> = { CRITICAL: "#dc2626", HIGH: "#ef4444", MEDIUM: "#f59e0b" };
  const n = candidates.length;
  candidates.forEach((c, i) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
    const r = Math.min(W, H) / 2 - 28;
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    ctx.strokeStyle = "#2a2a44";
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(x, y);
    ctx.stroke();
    ctx.fillStyle = colors[c.band] ?? "#62627a";
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, 2 * Math.PI);
    ctx.fill();
    if (c.band === "CRITICAL") {
      ctx.strokeStyle = "#dc2626";
      ctx.beginPath();
      ctx.arc(x, y, 8, 0, 2 * Math.PI);
      ctx.stroke();
    }
    ctx.fillStyle = "#9a9ab0";
    const label = c.host.length > 22 ? c.host.slice(0, 21) + "…" : c.host;
    ctx.fillText(label, x - ctx.measureText(label).width / 2, y + 18);
  });

  ctx.fillStyle = "#8a5cc7";
  ctx.beginPath();
  ctx.arc(cx, cy, 7, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = "#e8e8f2";
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

/** The WHY, front and center: the graph's score + its named weighted factors. */
function renderWhy(p: Protection): boolean {
  const panel = $("why-panel");
  const scoreChip = $("why-score");
  const box = $("why-factors");
  if (p.whyFactors.length === 0 && p.score === null) return false;
  panel.hidden = false;
  if (p.score !== null) {
    scoreChip.hidden = false;
    scoreChip.textContent = `graph score ${p.score}`;
  }
  const shown = p.whyFactors.slice(0, MAX_FACTORS_SHOWN);
  box.replaceChildren(...shown.map(factorRow));
  if (p.whyFactors.length > shown.length) {
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
  return true;
}

/** The composed picture: who runs it, where, how old, why flagged. */
async function loadProtection(host: string): Promise<void> {
  const res = await send<{ ok: true; protection: Protection }>({ kind: "getProtection", host });
  if (!res.ok) return;
  const p = res.protection;
  const hasWhy = renderWhy(p);
  const rows: HTMLElement[] = [];
  if (p.who) {
    const catLabel =
      p.category && p.category in CATEGORY_LABEL
        ? ` · ${CATEGORY_LABEL[p.category as ReportCategory]}`
        : "";
    rows.push(protectKv("Who", `${p.who}${catLabel}`));
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
  whyBox.replaceChildren(
    ...p.why.map((w, i) => {
      const line = document.createElement("div");
      line.className = `why-line${i === 0 ? " threat" : ""}`;
      line.textContent = w;
      return line;
    }),
  );
  if (rows.length > 0 || p.why.length > 0 || hasWhy) {
    card.hidden = false;
    $("protect-rows").replaceChildren(...rows);
  }
}

// ------------------------------------------------------ browser identity

function chipClsForBand(band: string): string {
  const b = band.toUpperCase();
  if (b === "CRITICAL") return "crit";
  if (b === "HIGH") return "high";
  if (b === "MEDIUM") return "med";
  if (b === "UNKNOWN") return "unknown";
  return "ok";
}

function identityLine(label: string, value: string, mono = true): HTMLElement {
  const row = document.createElement("div");
  row.className = "protect-kv";
  const k = document.createElement("span");
  k.className = "k";
  k.textContent = label;
  const v = document.createElement("span");
  v.className = mono ? "v w-mono" : "v";
  v.textContent = value;
  row.append(k, v);
  return row;
}

function renderEnrolled(address: string, fqdn: string | null, rdapUrl: string | null, verified: boolean | null): void {
  const stateChip = $("identity-state");
  if (verified === true) {
    stateChip.className = "w-chip ok";
    stateChip.textContent = "VERIFIED";
    stateChip.title = "This address resolves as a Whisper endpoint via keyless RDAP verify-identity.";
  } else {
    stateChip.className = "w-chip accent";
    stateChip.textContent = "ENROLLED";
    stateChip.title = verified === false ? "Identity reserved; public verification pending." : "Identity reserved.";
  }
  const detail = $("identity-detail");
  detail.hidden = false;
  const lines: HTMLElement[] = [identityLine("Address", address)];
  if (fqdn) lines.push(identityLine("Name", fqdn));
  if (rdapUrl) {
    const row = document.createElement("div");
    row.className = "protect-kv";
    const k = document.createElement("span");
    k.className = "k";
    k.textContent = "Proof";
    const v = document.createElement("span");
    v.className = "v";
    const a = document.createElement("a");
    a.href = rdapUrl;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = "RDAP registration (anyone can check)";
    v.appendChild(a);
    row.append(k, v);
    lines.push(row);
  }
  detail.replaceChildren(...lines);
  $("identity-pitch").hidden = true;
  $("btn-enroll").hidden = true;
  $("btn-identity-dash").hidden = false;
}

async function loadIdentityCard(): Promise<void> {
  const card = $("identity-card");
  card.hidden = false;
  $("btn-identity-dash").addEventListener("click", () => {
    void send({ kind: "openDashboard", view: "browser" }).then(() => window.close());
  });
  const res = await send<{ ok: true; egress: EgressStatus }>({ kind: "egressStatus" });
  if (res.ok && res.egress.enrolled && res.egress.address) {
    renderEnrolled(res.egress.address, res.egress.fqdn, res.egress.rdapUrl, null);
    // Verify keylessly in the background; upgrade the chip when it lands.
    const v = await send<{ ok: true; verification: { isWhisperAgent: boolean; fqdn: string | null } | null }>({
      kind: "verifyIdentity",
      ip: res.egress.address,
    });
    if (v.ok && v.verification) {
      renderEnrolled(
        res.egress.address,
        res.egress.fqdn ?? v.verification.fqdn,
        res.egress.rdapUrl,
        v.verification.isWhisperAgent,
      );
    }
    return;
  }
  // Not enrolled yet: the CTA is the card.
  $("identity-pitch").hidden = false;
  const btn = $<HTMLButtonElement>("btn-enroll");
  btn.hidden = false;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Enrolling...";
    const note = $("identity-note");
    const r = await send<{ ok: true; enrollment: Enrollment } | { ok: false; error: string }>({ kind: "enroll" });
    if (r.ok) {
      renderEnrolled(
        r.enrollment.address,
        r.enrollment.fqdn,
        r.enrollment.rdapUrl,
        r.enrollment.verification?.isWhisperAgent ?? null,
      );
      note.hidden = false;
      note.textContent = "Enrolled. Routing stays off until you turn it on in the dashboard.";
    } else {
      btn.disabled = false;
      btn.textContent = "Enroll this browser";
      note.hidden = false;
      note.textContent = r.error;
    }
  });
}

// ----------------------------------------------------------- link sweep

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
  $("linkscan-note").textContent =
    "Only the link hostnames were checked, never the page, its text, or your history.";
}

function wireLinkScan(): void {
  $("linkscan-card").hidden = false;
  const btn = $<HTMLButtonElement>("btn-linkscan");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Checking...";
    const res = await send<{ ok: true; scan: LinkScanResult } | { ok: false; error: string }>({
      kind: "scanLinks",
      tabId,
    });
    btn.disabled = false;
    btn.textContent = "Re-check";
    if (res.ok) {
      renderLinkScan(res.scan);
    } else {
      const summary = $("linkscan-summary");
      summary.hidden = false;
      summary.textContent = res.error;
    }
  });
}

async function loadMiniDash(): Promise<void> {
  const res = await send<{ ok: true; report: BrowserReport }>({ kind: "getBrowserReport", limit: 200 });
  if (!res.ok) return;
  const t = res.report.totals;
  const tiles: { n: number; l: string; hot?: boolean }[] = [
    { n: t.destinations, l: "Destinations" },
    { n: t.companies, l: "Companies" },
    { n: t.countries, l: "Countries" },
    { n: t.flagged, l: "Flagged", hot: t.flagged > 0 },
  ];
  $("mini-tiles").replaceChildren(
    ...tiles.map((tile) => {
      const box = document.createElement("div");
      box.className = "mini-tile";
      const n = document.createElement("div");
      n.className = `n${tile.hot ? " hot" : ""}`;
      n.textContent = String(tile.n);
      const l = document.createElement("div");
      l.className = "l";
      l.textContent = tile.l;
      box.append(n, l);
      return box;
    }),
  );
}

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

function render(): void {
  if (!state) return;
  const s = state;
  const cloudCheck = settings?.cloudCheck ?? true;

  $("signin-dot").classList.toggle("on", s.signedIn);
  $("signin-dot").title = s.signedIn ? "signed in" : "not signed in";

  void loadMiniDash();
  $("btn-dashboard").addEventListener("click", () => {
    void send({ kind: "openDashboard" }).then(() => window.close());
  });

  // Enrollment is front and center on every page, signed in or not:
  // keyed users see their browser's identity (or the one-click enroll),
  // keyless users see what signing in unlocks. Two tiers, both honest.
  if (s.signedIn) void loadIdentityCard();
  else wireSignin();

  if (!s.eligible || !s.hostname) {
    $("ineligible").hidden = false;
    $("privacy-line").textContent = "Privacy: nothing was sent.";
    return;
  }
  const host = s.hostname;

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
    note.textContent = s.verdict?.label ? `${ui.note} ${s.verdict.label}` : ui.note;
    const cov = s.verdict?.coverage;
    if (cov) {
      const covChip = $("coverage-chip");
      covChip.hidden = false;
      covChip.textContent = `coverage: ${cov} (not a safety score)`;
    }
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
    glyph.textContent = "⚿";
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
    $("graph-error").textContent = `${s.graphError} Retry from the circular arrow below.`;
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
    $("btn-console").hidden = false;
    $("btn-console").addEventListener("click", () => {
      chrome.tabs.create({ url: "https://console.whisper.security" });
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
    ? `Privacy: only "${host}" was sent, to graph.whisper.security. Never the page, path, or your history.`
    : s.detector
      ? `Privacy: nothing left your browser. The look-alike check ran on-device.`
      : `Privacy: nothing was sent. The live check is off; on-device checks still ran.`;
}

async function init(): Promise<void> {
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
