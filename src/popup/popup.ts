// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The click-panel: a verdict and one action above the fold; analyst
// affordances collapsed. UNKNOWN is the honest common state and reads as
// "not confirmed either way", never as green. Every view carries the
// per-host privacy line saying exactly what was sent.

import { send } from "../shared/messages";
import type { CandidateVerdict, ExplainResult, GraphBand, TabState } from "../shared/types";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let tabId = -1;
let state: TabState | null = null;

const BAND_UI: Record<GraphBand, { cls: string; chip: string; glyph: string; note: string }> = {
  CRITICAL: { cls: "malicious", chip: "MALICIOUS - evidenced", glyph: "⬣", note: "Known threat, listed in the graph. Do not enter credentials." },
  HIGH: { cls: "suspicious", chip: "SUSPICIOUS - HIGH", glyph: "▲", note: "Strong risk signals. Be careful." },
  MEDIUM: { cls: "suspicious", chip: "SUSPICIOUS", glyph: "▲", note: "Some risk signals. Be careful." },
  LOW: { cls: "benign", chip: "NO KNOWN THREAT", glyph: "✓", note: "Low-level signals only. Not a warranty." },
  INFO: { cls: "benign", chip: "NO KNOWN THREAT", glyph: "✓", note: "Informational signals only. Not a warranty." },
  NONE: { cls: "benign", chip: "NO KNOWN THREAT", glyph: "✓", note: "No known threat. Not a warranty." },
  UNKNOWN: { cls: "unknown", chip: "UNKNOWN", glyph: "?", note: "New or low-coverage site. Not confirmed safe or unsafe." },
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
  ctx.font = "10px system-ui";
  const cx = W / 2;
  const cy = H / 2;

  const colors: Record<string, string> = { CRITICAL: "#dc2626", HIGH: "#f59e0b", MEDIUM: "#f59e0b" };
  const n = candidates.length;
  candidates.forEach((c, i) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
    const r = Math.min(W, H) / 2 - 28;
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    ctx.strokeStyle = "#374151";
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(x, y);
    ctx.stroke();
    ctx.fillStyle = colors[c.band] ?? "#6b7280";
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, 2 * Math.PI);
    ctx.fill();
    if (c.band === "CRITICAL") {
      ctx.strokeStyle = "#dc2626";
      ctx.beginPath();
      ctx.arc(x, y, 8, 0, 2 * Math.PI);
      ctx.stroke();
    }
    ctx.fillStyle = "#9ca3af";
    const label = c.host.length > 22 ? c.host.slice(0, 21) + "…" : c.host;
    ctx.fillText(label, x - ctx.measureText(label).width / 2, y + 18);
  });

  ctx.fillStyle = "#38bdf8";
  ctx.beginPath();
  ctx.arc(cx, cy, 7, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = "#e5e7eb";
  const cl = center.length > 26 ? center.slice(0, 25) + "…" : center;
  ctx.fillText(cl, cx - ctx.measureText(cl).width / 2, cy - 12);
}

async function loadNeighborhood(host: string): Promise<void> {
  const note = $("neighborhood-note");
  note.textContent = "Generating look-alike candidates and confirming each against the graph...";
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

function render(): void {
  if (!state) return;
  const s = state;

  $("signin-dot").classList.toggle("on", s.signedIn);
  $("signin-dot").title = s.signedIn ? "signed in" : "not signed in";

  if (!s.eligible || !s.hostname) {
    $("ineligible").hidden = false;
    $("privacy-line").textContent = "Privacy: nothing was sent.";
    return;
  }
  const host = s.hostname;

  $("host-row").hidden = false;
  $("hostname").textContent = host;

  const band: GraphBand | null = s.verdict?.band ?? null;
  const glyph = $("band-glyph");
  const chip = $("band-chip");
  const note = $("band-note");

  if (band) {
    const ui = BAND_UI[band];
    glyph.className = `glyph ${ui.cls}`;
    glyph.textContent = ui.glyph;
    chip.className = `chip ${ui.cls}`;
    chip.textContent = ui.chip;
    note.textContent = s.verdict?.label ? `${ui.note} ${s.verdict.label}` : ui.note;
    const cov = s.verdict?.coverage;
    if (cov) {
      const covChip = $("coverage-chip");
      covChip.hidden = false;
      covChip.textContent = `coverage: ${cov} (not a safety score)`;
    }
  } else if (s.signedIn) {
    glyph.className = "glyph unknown";
    glyph.textContent = "?";
    chip.className = "chip unknown";
    chip.textContent = "UNKNOWN";
    note.textContent = "No verdict yet for this site.";
  } else {
    glyph.className = "glyph signedout";
    glyph.textContent = "⚿";
    chip.className = "chip unknown";
    chip.textContent = "LIVE SIGNAL LOCKED";
    note.textContent = "On-device protection is active. Sign in free to light up the live signal.";
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
    $("lookalike-text").textContent = s.signedIn
      ? `This site ${kindText[d.kind] ?? "looks like"} ${d.brandDomain}.`
      : `Heads up: this site ${kindText[d.kind] ?? "looks like"} ${d.brandDomain}. Caught on-device; nothing left your browser.`;
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

  if (s.signedIn) {
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
        `- band: ${s.verdict?.band ?? "(keyless)"}`,
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
  } else {
    $("signin-pitch").hidden = false;
    $("btn-signin").addEventListener("click", async () => {
      $("btn-signin").textContent = "Opening the console...";
      await send({ kind: "signInStart" });
      void pollDeviceFlow();
    });
  }

  $("privacy-line").textContent = s.signedIn
    ? `Privacy: only "${host}" was sent, to graph.whisper.security. Never the page, path, or your history.`
    : s.detector
      ? `Privacy: nothing left your browser. The look-alike check ran on-device.`
      : `Privacy: nothing was sent. Sign in to run the live check (hostname only).`;
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
  const res = await send<{ ok: true; tabState: TabState }>({ kind: "getTabState", tabId });
  if (res.ok) {
    state = res.tabState;
    render();
  }
}

void init();
