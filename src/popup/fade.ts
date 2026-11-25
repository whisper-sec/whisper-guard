// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The soft fade above the popup's footer: it shows while the scrolling region
// has more below it, and is gone at the end of it. The popup is one scroll of
// three parts (This site, This page, This browser), so the fade is the one cue
// that the popup goes on. Nothing here talks to the extension or reads the
// page's address.

const PARTS = ["panel-site", "panel-page", "panel-browser"] as const;

const el = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

/** The fade shows only while the region can scroll further down. Within a
 *  pixel of the end, or with nothing to scroll, it is hidden. */
export function updateFade(): void {
  const region = el("popup-scroll");
  const more = region.scrollHeight - region.clientHeight - region.scrollTop > 1;
  el("popup-fade").hidden = !more;
}

/** Keep the fade current: it follows the scroll position, the region's own
 *  size and the size of each part (content arrives after the popup opens, and
 *  a part appears or goes as a check starts and ends). */
export function initFade(): void {
  const region = el("popup-scroll");
  region.addEventListener("scroll", updateFade, { passive: true });
  const watch = new ResizeObserver(() => updateFade());
  watch.observe(region);
  for (const id of PARTS) watch.observe(el(id));
  updateFade();
}
