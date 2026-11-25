// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The reader's theme choice: Auto, Light or Dark.
//
// The pure parts live here so the background, the popup's button and the
// boot script every page loads first all agree on them: what counts as a
// choice, the order a press steps through, the words the button carries,
// and which scheme a choice draws.
//
// The truth is `settings.theme` in local extension storage. A page cannot
// wait for an asynchronous read before its first frame, so a copy of the
// choice is also kept in the extension origin's localStorage, which a
// script can read synchronously. Every access to it is guarded: storage can
// be blocked, partitioned or missing, and then the choice reads as Auto.

export type ThemeChoice = "auto" | "light" | "dark";
export type ThemeScheme = "light" | "dark";

/** In the order a press steps through them. */
export const THEME_CHOICES: readonly ThemeChoice[] = ["auto", "light", "dark"];

/** Where the synchronous copy of the choice lives. */
export const THEME_MIRROR_KEY = "guard.theme";

/**
 * Set on <html> by a page while its own theme writes are in flight (a count).
 * The storage change those writes cause comes back to the page late, and it
 * must not overwrite a newer press, so the boot script skips a value that
 * differs from the page's own while this is above zero.
 */
export const THEME_PENDING_ATTR = "data-theme-pending";

/** Anything that is not "light" or "dark" is Auto: a bad stored value never sticks. */
export function normalizeTheme(v: unknown): ThemeChoice {
  return v === "light" || v === "dark" ? v : "auto";
}

/** What a press on the button changes the choice to. */
export function nextTheme(c: ThemeChoice): ThemeChoice {
  return THEME_CHOICES[(THEME_CHOICES.indexOf(c) + 1) % THEME_CHOICES.length]!;
}

const WORD: Record<ThemeChoice, string> = { auto: "Auto", light: "Light", dark: "Dark" };

/** The button's accessible name, and what the live region says after a press. */
export function themeName(c: ThemeChoice): string {
  return `Theme: ${WORD[c]}`;
}

/** The button's tooltip: its name, and on Auto what it follows. */
export function themeTitle(c: ThemeChoice): string {
  return c === "auto" ? `${themeName(c)} (follows your system)` : themeName(c);
}

/** The scheme a choice draws, given whether the system is on light. */
export function resolveScheme(c: ThemeChoice, systemIsLight: boolean): ThemeScheme {
  if (c === "auto") return systemIsLight ? "light" : "dark";
  return c;
}

/** The synchronous copy of the choice; Auto when there is none or it cannot be read. */
export function readThemeMirror(): ThemeChoice {
  try {
    return normalizeTheme(localStorage.getItem(THEME_MIRROR_KEY));
  } catch {
    return "auto";
  }
}

export function writeThemeMirror(c: ThemeChoice): void {
  try {
    localStorage.setItem(THEME_MIRROR_KEY, c);
  } catch {
    // blocked or partitioned storage: the page still follows storage.local
  }
}

/**
 * Draw a choice on this page: the choice itself and the scheme it resolves to,
 * as attributes on <html>. The stylesheet reads `data-scheme` only; Auto is
 * resolved here, through the system's setting, so there is one place that
 * decides and no stylesheet asks the system.
 */
export function applyTheme(c: ThemeChoice, root: HTMLElement = document.documentElement): void {
  const systemIsLight = typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: light)").matches;
  root.setAttribute("data-theme", c);
  const scheme = resolveScheme(c, systemIsLight);
  if (root.getAttribute("data-scheme") !== scheme) root.setAttribute("data-scheme", scheme);
}
