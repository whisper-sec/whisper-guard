// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Loaded first, as a blocking script in the <head> of every Guard page, so
// the page draws the reader's chosen scheme in its first frame.
//
// It does four things and nothing else:
//   1. synchronously, reads the copy of the choice kept in this origin's
//      localStorage and sets the scheme on <html> before the body is parsed;
//   2. follows the system's light/dark setting while the choice is Auto;
//   3. reads `settings.theme` from local extension storage once and, when it
//      differs from what was drawn, draws it and corrects the copy (storage
//      is the truth, the copy is only there to be fast);
//   4. follows a later change of `settings.theme`, so an open page flips when
//      the choice is made in another one.
//
// It never throws: a page with no extension API (a file render in a test), no
// localStorage, or a stored value that is not a choice simply stays on what it
// could read. The page it runs in may be reachable from a web page (the
// warning page), so it reads and writes the theme choice and nothing else.

import { applyTheme, normalizeTheme, readThemeMirror, THEME_PENDING_ATTR, writeThemeMirror, type ThemeChoice } from "./theme-choice";

function current(): ThemeChoice {
  return normalizeTheme(document.documentElement.getAttribute("data-theme"));
}

function settingsTheme(settings: unknown): ThemeChoice {
  return normalizeTheme(settings && typeof settings === "object" ? (settings as { theme?: unknown }).theme : undefined);
}

try {
  applyTheme(readThemeMirror());
  const start = current();

  try {
    matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => applyTheme(current()));
  } catch {
    // no matchMedia: the page stays on the scheme it drew
  }

  try {
    const local = chrome.storage.local;
    void Promise.resolve(local.get("settings")).then(
      (got: Record<string, unknown> | undefined) => {
        // A choice made or heard on this page while the read was in flight is newer than the read.
        if (current() !== start) return;
        const truth = settingsTheme(got?.["settings"]);
        if (truth === current()) return;
        writeThemeMirror(truth);
        applyTheme(truth);
      },
      () => undefined,
    );
    chrome.storage.onChanged?.addListener((changes, area) => {
      const change = changes["settings"];
      if (area !== "local" || !change) return;
      const next = settingsTheme(change.newValue);
      // This page's own writes are in flight: what comes back is an echo of an
      // earlier press, and the page's own choice is newer.
      if (Number(document.documentElement.getAttribute(THEME_PENDING_ATTR)) > 0 && next !== current()) return;
      writeThemeMirror(next);
      applyTheme(next);
    });
  } catch {
    // no extension API: the copy alone decides
  }
} catch {
  // never block a page on its theme
}
