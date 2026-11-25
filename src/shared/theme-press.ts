// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// What happens when the reader picks a theme, for every page that offers the
// choice (the popup's header button, the settings page's row).
//
// It lives apart from theme-choice.ts on purpose: that module is bundled into
// the boot script every page loads first, and must stay free of messaging.

import { send } from "./messages";
import { applyTheme, normalizeTheme, THEME_PENDING_ATTR, writeThemeMirror, type ThemeChoice } from "./theme-choice";

/**
 * Draw a choice on this page at once, keep the copy the next first frame
 * reads, and ask the background to store it. The write is counted while it is
 * in flight, so its late echo from storage is not taken for a newer choice.
 * When the last one is done, storage is read once and the page draws what it
 * says.
 */
export function chooseTheme(next: ThemeChoice): void {
  const root = document.documentElement;
  applyTheme(next);
  writeThemeMirror(next);
  const left = Number(root.getAttribute(THEME_PENDING_ATTR)) + 1;
  root.setAttribute(THEME_PENDING_ATTR, String(left));
  void send({ kind: "setSettings", patch: { theme: next } })
    .catch(() => undefined)
    .then(async () => {
      const rest = Number(root.getAttribute(THEME_PENDING_ATTR)) - 1;
      if (rest > 0) return void root.setAttribute(THEME_PENDING_ATTR, String(rest));
      root.removeAttribute(THEME_PENDING_ATTR);
      try {
        const got = await chrome.storage.local.get("settings");
        const stored = (got["settings"] as { theme?: unknown } | undefined)?.theme;
        // A press made while that read ran is newer than the read.
        if (root.hasAttribute(THEME_PENDING_ATTR)) return;
        const truth = normalizeTheme(stored);
        writeThemeMirror(truth);
        applyTheme(truth);
      } catch {
        // keep what is drawn
      }
    });
}
