// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// First run: protection is already on, keyless value first.
//
// THE PAGE IS A STATE, NOT A PREAMBLE. Everything a reader sees here is read
// at the moment it opens: a real verdict from the live graph, the live size
// of that graph and the pulse of the resolvers in front of it, and the
// actual on/off state of every protection off this browser's own settings.
// The one number that used to be typed into the page - "800+ brands" - is
// now counted from the corpus the detector actually loaded, so it cannot go
// stale against the thing it describes.
//
// Every read fails open and says which one failed. An unreachable statistics
// endpoint leaves the page making no claim about the graph's size rather
// than falling back to a remembered figure, and the sample verdict says
// UNAVAILABLE rather than quietly reading as clean.

import { send, type CheckHostResult } from "../shared/messages";
import type { GraphScale, Settings } from "../shared/types";
import { compact, countUp, sparkline } from "../shared/spark";

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

function el(tag: string, cls?: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// The live sample: one real verdict for a well-known host, fetched now.
// (A fixed public name, never anything about the user's browsing.)
async function loadSample(): Promise<void> {
  const chip = $("sample-chip");
  const note = $("sample-note");
  const rail = $("sample-rail");
  const res = await send<{ ok: true; check: CheckHostResult }>({ kind: "checkHost", host: "github.com" });
  if (!res.ok || !res.check.verdict) {
    chip.className = "w-chip unknown";
    chip.textContent = "UNAVAILABLE";
    rail.className = "band-rail unknown";
    note.textContent = res.ok ? (res.check.graphError ?? "the live check is off") : "could not reach Whisper";
    return;
  }
  const band = res.check.verdict.band.toUpperCase();
  const good = band === "NONE" || band === "LOW" || band === "INFO";
  chip.className = `w-chip ${good ? "ok" : band === "MEDIUM" ? "med" : band === "UNKNOWN" ? "unknown" : "crit"}`;
  chip.textContent = good ? "NO KNOWN THREAT" : band;
  // The verdict is legible from the left edge before a word is read: the
  // same rail the panel draws, so the two surfaces say it the same way.
  rail.className = `band-rail ${good ? "benign" : band === "MEDIUM" ? "suspicious" : band === "UNKNOWN" ? "unknown" : "malicious"}`;
  note.textContent = res.check.verdict.coverage ? `coverage: ${res.check.verdict.coverage}` : "";
}

/**
 * How big the graph is and how hard the resolvers in front of it are
 * working, both read live.
 *
 * The claim is only made when it was measured: an unreachable endpoint gets
 * a sentence saying so, never a number somebody typed here once.
 */
async function loadScale(): Promise<void> {
  const res = await send<{ ok: true; scale: GraphScale | null }>({ kind: "getScale" });
  if (!res.ok || !res.scale) {
    $("scale-down").hidden = false;
    return;
  }
  const sc = res.scale;
  const box = $("scale");
  box.hidden = false;
  countUp($("scale-nodes"), sc.nodes, compact);
  countUp($("scale-edges"), sc.edges, compact);
  countUp($("scale-ids"), sc.identities, compact);
  box.title =
    `${sc.nodes.toLocaleString("en")} nodes and ${sc.edges.toLocaleString("en")} edges, ` +
    `${sc.identities.toLocaleString("en")} identities on the network. Read live at ` +
    `${new Date(sc.updated).toLocaleTimeString()}${sc.degraded ? " (the endpoint reports degraded input)" : ""}.`;

  // The resolvers' own trailing window: a shape, not a chart, and the
  // primitive refuses to draw at all rather than draw a flat line out of
  // nothing.
  const spark = sparkline(sc.pulse.slice(-48), {
    width: 120,
    height: 20,
    fill: 0.16,
    head: true,
    title: `DNS questions answered per 5 minutes over the last ${sc.windowHours} hours`,
  });
  if (spark) {
    $("scale-pulse").replaceChildren(spark);
    $("scale-pulse-cap").textContent =
      `${sc.queries.toLocaleString("en")} questions answered in the last ${sc.windowHours}h`;
  } else {
    $("scale-pulse-cap").textContent = "";
  }
}

/**
 * A protection's state, drawn: a filled track when it is on, an empty one
 * when it is off.
 *
 * A word ("on") and a mark say the same thing, but only the mark can be read
 * without reading. Five of these in a column is the whole answer to "what is
 * this extension doing for me right now", which is the only question a first
 * run has to answer.
 */
function stateMark(on: boolean): SVGSVGElement {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 26 14");
  svg.setAttribute("width", "26");
  svg.setAttribute("height", "14");
  svg.setAttribute("role", "img");
  const t = document.createElementNS(NS, "title");
  t.textContent = on ? "on" : "off";
  svg.appendChild(t);
  const track = document.createElementNS(NS, "rect");
  track.setAttribute("x", "0.75");
  track.setAttribute("y", "0.75");
  track.setAttribute("width", "24.5");
  track.setAttribute("height", "12.5");
  track.setAttribute("rx", "6.25");
  track.setAttribute("fill", on ? "var(--w-ok)" : "transparent");
  track.setAttribute("stroke", on ? "var(--w-ok)" : "var(--w-line-strong)");
  track.setAttribute("stroke-width", "1.5");
  svg.appendChild(track);
  const knob = document.createElementNS(NS, "circle");
  knob.setAttribute("cx", on ? "18.5" : "7.5");
  knob.setAttribute("cy", "7");
  knob.setAttribute("r", "3.75");
  knob.setAttribute("fill", on ? "var(--w-bg)" : "var(--w-line-strong)");
  svg.appendChild(knob);
  return svg;
}

function activeRow(on: boolean, name: string, detail: string): HTMLElement {
  const row = el("div", `active-row${on ? "" : " off"}`);
  const mark = el("span", "active-mark");
  mark.appendChild(stateMark(on));
  row.append(mark, el("span", "active-name", name), el("span", "active-detail", detail));
  return row;
}

/** What is actually on, read from this browser's own settings. */
async function loadActive(): Promise<void> {
  const res = await send<{
    ok: true;
    settings: Settings;
    signedIn: boolean;
    corpusVersion: number;
    corpusUpdated: string;
    corpusBrands: number;
  }>({ kind: "getSettings" });
  const list = $("active-list");
  if (!res.ok) {
    list.replaceChildren(
      el("p", "w-note", "The extension's own settings could not be read just now, so this page is not claiming what is on."),
    );
    return;
  }
  const s = res.settings;
  // The brand figure is the corpus the detector loaded, counted. When it
  // could not be counted the sentence simply does not carry a number.
  const brands = res.corpusBrands > 0 ? `${res.corpusBrands.toLocaleString("en")} heavily phished brands` : "the bundled brand list";
  list.replaceChildren(
    activeRow(
      s.cloudCheck,
      "Live graph verdict",
      s.cloudCheck
        ? "Every site you open is checked against the graph, by name only."
        : "Turned off: on-device checks still run, nothing leaves this browser.",
    ),
    activeRow(true, "Look-alike detector", `On-device, watching ${brands}. Sends nothing.`),
    activeRow(
      s.fieldGuard,
      "Credential-field guard",
      "Warns before a password or card is typed into a site the graph does not vouch for.",
    ),
    activeRow(
      s.cookieDecline,
      "Cookie-banner auto-decline",
      "Clicks reject, never accept, entirely on this device.",
    ),
    activeRow(
      s.amberBanner,
      "In-page warning banner",
      "Says so on the page itself when a site is only partly trusted.",
    ),
    activeRow(
      s.shield,
      "Active Shield",
      s.shield
        ? "Known-bad destinations are blocked before they load."
        : "Off until you grant it: it needs permission for every site.",
    ),
  );
}

void loadSample();
void loadScale();
void loadActive();

$("btn-later").addEventListener("click", () => {
  window.close();
});

$("btn-dashboard").addEventListener("click", () => {
  void send({ kind: "openDashboard" });
});

$("btn-signin").addEventListener("click", async () => {
  const status = $("device-status");
  status.hidden = false;
  status.textContent = "Opening the Whisper console...";
  await send({ kind: "signInStart" });
  for (;;) {
    const res = await send<{
      ok: true;
      device: { phase: string; userCode: string | null; message: string | null };
    }>({ kind: "signInStatus" });
    if (!res.ok) return;
    const d = res.device;
    if (d.phase === "waiting") {
      status.textContent = `Approve the sign-in in the console tab (code ${d.userCode ?? "..."}). Waiting...`;
    } else if (d.phase === "approved") {
      status.textContent = "Signed in. The live signal is active on every site you visit.";
      return;
    } else if (d.phase === "expired" || d.phase === "error") {
      status.textContent = d.message ?? "Sign-in did not complete. Try again.";
      return;
    } else {
      return;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
});
