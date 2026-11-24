// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The popup's three tabs: This site, This page, This browser.
//
// Every panel is filled when the popup opens (popup.ts), so choosing a tab
// only shows what is already drawn. Nothing here talks to the extension, reads
// the page's address or remembers the choice: a reload always lands on
// This site. The one thing it keeps besides the selection is the red dot on
// the This page tab (setPageFlagCount), which only shows a count it is given.
//
// The tabs follow the WAI-ARIA tabs pattern with automatic activation: Left
// and Right move and select, wrapping at the ends; Home and End go to the
// first and the last tab; only the selected tab is in the Tab order.
//
// This file also keeps the soft fade above the footer: it shows while the
// content region has more to scroll below, and is gone at the end of it.

export type PopupTab = "site" | "page" | "browser";

const TABS: readonly PopupTab[] = ["site", "page", "browser"];

// Elements whose entrance animation must not play again when their panel is
// shown again after a tab change: a hidden element's animation restarts as
// soon as it is displayed. Only elements that have already been drawn are
// marked, so one that arrives late, or a rung detail the reader opens later,
// still animates, and a waiting animation (never marked) keeps running.
const ENTRANCES = ".pp-disc, .ch-rung, .ch-detail";

const el = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

/** Show the tab named `name` and hide the other two. Sends nothing, stores
 *  nothing and never moves focus. */
export function selectTab(name: PopupTab): void {
  for (const t of TABS) {
    const selected = t === name;
    const tab = el(`tab-${t}`);
    const panel = el(`panel-${t}`);
    const slot = el(`footer-${t}`);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (!selected && !panel.hidden) {
      for (const node of panel.querySelectorAll<HTMLElement>(ENTRANCES)) node.dataset.seen = "";
    }
    panel.hidden = !selected;
    slot.hidden = !selected;
  }
  el("tab-content").scrollTop = 0;
  updateFade();
}

/** The fade shows only while the content region can scroll further down.
 *  Within a pixel of the end, or with nothing to scroll, it is hidden. */
export function updateFade(): void {
  const region = el("tab-content");
  const more = region.scrollHeight - region.clientHeight - region.scrollTop > 1;
  el("tab-fade").hidden = !more;
}

/**
 * Show how many malicious links the link result on This page holds.
 *
 * Call it with the result's `flagged` count (critical and high link results, as
 * the link check counts them) each time a link result is drawn, including after
 * a re-check. A count above zero shows the red dot on the This page tab and
 * gives the tab a text alternative ("1 malicious link on this page", or "N
 * malicious links on this page"); zero or null hides both and empties the text.
 * Calling it again with the same count changes nothing. It sends nothing,
 * stores nothing, never selects a tab, never moves focus and touches nothing
 * outside the This page tab. A failed check does not call it, so the last
 * result's dot stays; the result is not kept once the popup closes.
 */
export function setPageFlagCount(n: number | null): void {
  const count = n !== null && Number.isFinite(n) && n > 0 ? Math.trunc(n) : 0;
  const dot = el("tab-page-dot");
  const text = el("tab-page-flags");
  dot.hidden = count === 0;
  text.hidden = count === 0;
  text.textContent =
    count === 0 ? "" : count === 1 ? "1 malicious link on this page" : `${count} malicious links on this page`;
}

export function initTabs(): void {
  const bar = el("tab-bar");
  for (const t of TABS) el(`tab-${t}`).addEventListener("click", () => selectTab(t));

  bar.addEventListener("keydown", (ev) => {
    const at = TABS.findIndex((t) => el(`tab-${t}`).getAttribute("aria-selected") === "true");
    let next = -1;
    if (ev.key === "ArrowRight") next = (at + 1) % TABS.length;
    else if (ev.key === "ArrowLeft") next = (at - 1 + TABS.length) % TABS.length;
    else if (ev.key === "Home") next = 0;
    else if (ev.key === "End") next = TABS.length - 1;
    if (next < 0) return;
    ev.preventDefault();
    const to = TABS[next] as PopupTab;
    selectTab(to);
    el(`tab-${to}`).focus();
  });

  // The fade follows the scroll position, the region's own size and the size
  // of each panel (content arrives after the popup opens).
  const region = el("tab-content");
  region.addEventListener("scroll", updateFade, { passive: true });
  const watch = new ResizeObserver(() => updateFade());
  watch.observe(region);
  for (const t of TABS) watch.observe(el(`panel-${t}`));
  updateFade();
}
