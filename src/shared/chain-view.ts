// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The chain, drawn.
//
// A spine of rungs on a single rail: name, vendor, address, prefix,
// network, operator, physical presence. It is the one thing on any Guard
// surface that a competitor cannot copy by buying a feed, because it is
// not a lookup, it is a join, and the join is the product.
//
// Three rules the renderer holds to:
//
//   1. A rung NEVER renders blank. It has a value, or it says the graph
//      holds nothing here, or it says it could not be read. Those are
//      three different sentences because they are three different facts,
//      and collapsing them is how an outage comes to look like safety.
//   2. Colour means risk and nothing else. A rung is ink unless the rung
//      itself carries a signal (a prefix full of listed neighbours), and
//      then it carries a word as well as a hue.
//   3. The rungs arrive. Each one fades up a beat after the one above it,
//      so the reader watches a path being walked rather than finding a
//      table already sitting there. Reduced motion turns it off whole.

import { send } from "./messages";
import type { ChainRung, RungDetail, SiteChain } from "./types";

const TONE_CLASS: Record<ChainRung["tone"], string> = {
  neutral: "",
  warn: " ch-warn",
  hot: " ch-hot",
};

const STATE_CLASS: Record<ChainRung["state"], string> = {
  live: " ch-live",
  empty: " ch-empty",
  unavailable: " ch-lost",
};

/**
 * Expanding a rung: the free detail the walk already carried, plus, for the
 * two rungs where one more call buys a fact nothing else on the surface
 * has, a lazy read. Lazy because the public tier's hourly budget is a real
 * number and a reader who never expands a rung must never spend one.
 */
async function expand(row: HTMLElement, host: string, r: ChainRung): Promise<void> {
  const existing = row.nextElementSibling;
  if (existing?.classList.contains("ch-detail")) {
    existing.remove();
    row.setAttribute("aria-expanded", "false");
    return;
  }
  const box = document.createElement("li");
  box.className = "ch-detail";
  row.setAttribute("aria-expanded", "true");

  const list = document.createElement("div");
  list.className = "ch-detail-lines";
  // The free half renders instantly, so the panel never looks stalled while
  // the paid half is in flight.
  for (const line of r.detail) list.appendChild(detailLine(line));
  if (r.drillable) {
    const pending = detailLine("reading...");
    pending.classList.add("ch-detail-pending");
    list.appendChild(pending);
  }
  box.appendChild(list);
  row.after(box);

  if (!r.drillable) return;

  const res = await send<{ ok: true; detail: RungDetail }>({
    kind: "getRungDetail",
    host,
    rung: r.kind,
  }).catch(() => ({ ok: false as const }));
  if (!box.isConnected) return;

  const fresh = document.createElement("div");
  fresh.className = "ch-detail-lines";
  for (const line of r.detail) fresh.appendChild(detailLine(line));

  if (!res.ok) {
    const err = detailLine("That read did not come back. Unknown, not clear.");
    err.classList.add("ch-detail-lost");
    fresh.appendChild(err);
  } else if (res.detail.error !== null) {
    const err = detailLine(res.detail.error);
    err.classList.add("ch-detail-lost");
    fresh.appendChild(err);
  } else {
    for (const line of res.detail.lines) fresh.appendChild(detailLine(line));
    const ratio = res.detail.ratio;
    if (ratio && ratio.whole > 0) {
      // A ratio drawn as a ratio. "5 listed of 9,216 announced" is a
      // sentence; the bar is what makes it a scale, and the difference
      // between a huge clean network and a small dirty one is the whole
      // point of showing it at all.
      const wrap = document.createElement("div");
      wrap.className = "ch-ratio";
      const track = document.createElement("span");
      track.className = "ch-ratio-track";
      const fill = document.createElement("span");
      fill.className = "ch-ratio-fill";
      // A floor of a hairline, so a real but tiny value is visible AS tiny
      // rather than as nothing.
      const pct = Math.max(0.6, Math.min(100, (ratio.part / ratio.whole) * 100));
      track.appendChild(fill);
      const cap = document.createElement("span");
      cap.className = "ch-ratio-cap";
      cap.textContent = ratio.label;
      wrap.append(track, cap);
      fresh.appendChild(wrap);
      requestAnimationFrame(() => {
        fill.style.width = `${pct.toFixed(2)}%`;
      });
    }
  }
  if (fresh.childElementCount === 0) {
    fresh.appendChild(detailLine("The graph holds nothing more about this step."));
  }
  box.replaceChildren(fresh);
}

function detailLine(text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = "ch-detail-line";
  el.textContent = text;
  return el;
}

function rungEl(r: ChainRung, index: number, host?: string): HTMLElement {
  const row = document.createElement("li");
  row.className = `ch-rung${STATE_CLASS[r.state]}${TONE_CLASS[r.tone]}`;
  // The stagger is a CSS custom property rather than a per-element
  // animation so one media query can switch the whole spine off.
  row.style.setProperty("--ch-i", String(index));

  const rail = document.createElement("span");
  rail.className = "ch-rail";
  const dot = document.createElement("span");
  dot.className = "ch-dot";
  rail.appendChild(dot);

  const body = document.createElement("span");
  body.className = "ch-body";

  const label = document.createElement("span");
  label.className = "ch-label";
  label.textContent = r.label;

  const value = document.createElement("span");
  value.className = "ch-value";
  value.textContent = r.value ?? "-";
  // The full string for a name too long for 400 pixels.
  if (r.value) value.title = r.value;

  body.append(label, value);

  if (r.fact) {
    const fact = document.createElement("span");
    fact.className = "ch-fact";
    fact.textContent = r.fact;
    body.appendChild(fact);
  }

  // A rung with more behind it is a control. One that has nothing more is
  // not dressed up as one: a button that does nothing when pressed teaches
  // a reader that the surface is broken.
  if (host && (r.detail.length > 0 || r.drillable)) {
    row.classList.add("ch-open");
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.setAttribute("aria-expanded", "false");
    row.title = `What the graph holds behind ${r.label.toLowerCase()}`;
    const toggle = (): void => void expand(row, host, r);
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        toggle();
      }
    });
  }

  row.append(rail, body);
  return row;
}

export interface ChainViewOptions {
  /** The heading line above the spine. */
  heading?: string;
  /** Show the "n of 7 joined" completeness readout. Default true. */
  completeness?: boolean;
  /** Let rungs expand. Default true; pass false for a static capture. */
  expandable?: boolean;
}

/**
 * Render a chain into `root`, replacing whatever was there. Returns the
 * number of rungs the graph actually answered, so a caller can decide
 * whether the section earned its space.
 */
export function renderChain(
  root: HTMLElement,
  chain: SiteChain,
  opts: ChainViewOptions = {},
): number {
  const frag = document.createDocumentFragment();

  if (opts.heading !== "" ) {
    const head = document.createElement("div");
    head.className = "ch-head";

    const title = document.createElement("span");
    title.className = "w-label";
    title.textContent = opts.heading ?? "THE CHAIN";
    head.appendChild(title);

    if (opts.completeness !== false) {
      const count = document.createElement("span");
      const total = chain.rungs.length;
      // The honest completeness line: how much of the path the graph could
      // walk, and separately how much of it we could not even ask about.
      count.className = chain.unavailable > 0 ? "ch-count ch-count-lost" : "ch-count";
      count.textContent =
        chain.unavailable > 0
          ? `${chain.live} of ${total} joined · ${chain.unavailable} unreadable`
          : `${chain.live} of ${total} joined`;
      head.appendChild(count);
    }
    frag.appendChild(head);
  }

  const list = document.createElement("ol");
  list.className = "ch-spine";
  const host = opts.expandable === false ? undefined : chain.host;
  chain.rungs.forEach((r, i) => list.appendChild(rungEl(r, i, host)));
  frag.appendChild(list);

  // The graph's own account of how it made the vendor attribution. Shown
  // verbatim, because "we joined RESOLVES_TO then DELEGATED_TO" is a
  // stronger claim than any sentence we could write about it.
  const evidence = chain.evidence.filter((e) => e.includes("->"));
  if (evidence.length > 0) {
    const ev = document.createElement("div");
    ev.className = "ch-evidence";
    const lead = document.createElement("span");
    lead.className = "ch-ev-lead";
    lead.textContent = "joined by ";
    const path = document.createElement("span");
    path.className = "ch-ev-path";
    path.textContent = evidence[0] ?? "";
    ev.append(lead, path);
    frag.appendChild(ev);
  }

  root.replaceChildren(frag);
  return chain.live;
}

/** A placeholder spine, drawn while the real one is in flight. Same
 *  geometry, so nothing moves when the answer lands. */
export function renderChainPending(root: HTMLElement, rungs = 7, heading = "THE CHAIN"): void {
  const frag = document.createDocumentFragment();
  const head = document.createElement("div");
  head.className = "ch-head";
  const title = document.createElement("span");
  title.className = "w-label";
  title.textContent = heading;
  const count = document.createElement("span");
  count.className = "ch-count";
  count.textContent = "walking the graph...";
  head.append(title, count);
  frag.appendChild(head);

  const list = document.createElement("ol");
  list.className = "ch-spine ch-pending";
  for (let i = 0; i < rungs; i++) {
    const row = document.createElement("li");
    row.className = "ch-rung ch-wait";
    row.style.setProperty("--ch-i", String(i));
    const rail = document.createElement("span");
    rail.className = "ch-rail";
    const dot = document.createElement("span");
    dot.className = "ch-dot";
    rail.appendChild(dot);
    const body = document.createElement("span");
    body.className = "ch-body";
    const bar = document.createElement("span");
    bar.className = "ch-skel";
    body.appendChild(bar);
    row.append(rail, body);
    list.appendChild(row);
  }
  frag.appendChild(list);
  root.replaceChildren(frag);
}
