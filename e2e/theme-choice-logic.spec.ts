// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The pure half of the theme choice: what counts as a choice, the cycle, the
// button's words, which scheme a choice draws, and the guarded copy of the
// choice that the pages read before their first frame. No browser: the same
// runner as the rest of the suite.

import { test, expect } from "@playwright/test";
import {
  nextTheme,
  normalizeTheme,
  readThemeMirror,
  resolveScheme,
  themeName,
  themeTitle,
  THEME_MIRROR_KEY,
  writeThemeMirror,
} from "../src/shared/theme-choice";
import { DEFAULT_SETTINGS } from "../src/shared/types";
import { MIRROR_KEY } from "./helpers/theme";

test("only light and dark are choices of their own; anything else reads as auto", () => {
  expect(normalizeTheme("light")).toBe("light");
  expect(normalizeTheme("dark")).toBe("dark");
  expect(normalizeTheme("auto")).toBe("auto");
  for (const odd of ["purple", "", "LIGHT", " dark", undefined, null, 0, 1, true, {}, [], ["dark"], { theme: "dark" }]) {
    expect(normalizeTheme(odd), `${JSON.stringify(odd)}`).toBe("auto");
  }
});

test("a press moves auto, light, dark, auto", () => {
  expect(nextTheme("auto")).toBe("light");
  expect(nextTheme("light")).toBe("dark");
  expect(nextTheme("dark")).toBe("auto");
});

test("the button names the current choice, and auto says what it follows in its title", () => {
  expect(themeName("auto")).toBe("Theme: Auto");
  expect(themeName("light")).toBe("Theme: Light");
  expect(themeName("dark")).toBe("Theme: Dark");
  expect(themeTitle("auto")).toBe("Theme: Auto (follows your system)");
  expect(themeTitle("light")).toBe("Theme: Light");
  expect(themeTitle("dark")).toBe("Theme: Dark");
});

test("auto draws the system's scheme; light and dark ignore it", () => {
  expect(resolveScheme("auto", true)).toBe("light");
  expect(resolveScheme("auto", false)).toBe("dark");
  for (const systemIsLight of [true, false]) {
    expect(resolveScheme("light", systemIsLight)).toBe("light");
    expect(resolveScheme("dark", systemIsLight)).toBe("dark");
  }
});

test("a new profile starts on auto", () => {
  expect(DEFAULT_SETTINGS.theme).toBe("auto");
});

test("the copy of the choice is read and written under the one key, and never throws", () => {
  expect(THEME_MIRROR_KEY).toBe(MIRROR_KEY);
  const g = globalThis as unknown as { localStorage?: unknown };
  const had = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const set = (v: unknown): void => {
    Object.defineProperty(globalThis, "localStorage", { value: v, configurable: true, writable: true });
  };
  try {
    // No storage at all (the global is missing): auto, and a write is a no-op.
    set(undefined);
    expect(readThemeMirror()).toBe("auto");
    expect(() => writeThemeMirror("dark")).not.toThrow();

    // Storage that throws on every access (blocked or partitioned).
    const blocked = {
      getItem: (): never => {
        throw new Error("blocked");
      },
      setItem: (): never => {
        throw new Error("blocked");
      },
    };
    set(blocked);
    expect(readThemeMirror()).toBe("auto");
    expect(() => writeThemeMirror("light")).not.toThrow();

    // Working storage: round trip, and a value that is not a choice reads as auto.
    const data = new Map<string, string>();
    set({
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
    });
    writeThemeMirror("light");
    expect(data.get(THEME_MIRROR_KEY)).toBe("light");
    expect(readThemeMirror()).toBe("light");
    data.set(THEME_MIRROR_KEY, "purple");
    expect(readThemeMirror()).toBe("auto");
    data.delete(THEME_MIRROR_KEY);
    expect(readThemeMirror()).toBe("auto");
  } finally {
    if (had) Object.defineProperty(globalThis, "localStorage", had);
    else delete g.localStorage;
  }
});

// ------------------------------------------------------------ the write queue

test("two settings writes at once both land, and a patch that is not an object changes nothing", async () => {
  // A stub of the extension's storage whose reads yield once before answering,
  // so two reads that start together both see the same stored copy.
  const store: Record<string, unknown> = {};
  const g = globalThis as unknown as { chrome?: unknown };
  const had = Object.getOwnPropertyDescriptor(globalThis, "chrome");
  Object.defineProperty(globalThis, "chrome", {
    configurable: true,
    writable: true,
    value: {
      storage: {
        local: {
          get: async (key: string) => {
            const copy = structuredClone(store);
            await new Promise((r) => setImmediate(r));
            return key in copy ? { [key]: copy[key] } : {};
          },
          set: async (items: Record<string, unknown>) => {
            Object.assign(store, structuredClone(items));
          },
        },
        onChanged: { addListener: () => undefined },
      },
    },
  });
  try {
    const { setSettings, getSettings } = await import("../src/background/settings");
    await Promise.all([setSettings({ theme: "light" }), setSettings({ cloudCheck: false })]);
    const saved = store["settings"] as { theme?: unknown; cloudCheck?: unknown };
    expect(saved.theme, "the first write was lost").toBe("light");
    expect(saved.cloudCheck, "the second write was lost").toBe(false);

    // A patch that is not an object is no patch: it neither throws nor changes anything.
    const before = structuredClone(store);
    for (const odd of [null, undefined, "dark", 7, ["dark"]]) {
      await expect(setSettings(odd as never)).resolves.toBeTruthy();
      expect(store, `the patch ${JSON.stringify(odd)} changed what is stored`).toEqual(before);
    }
    expect((await getSettings()).theme).toBe("light");
    expect((await getSettings()).cloudCheck).toBe(false);
  } finally {
    if (had) Object.defineProperty(globalThis, "chrome", had);
    else delete g.chrome;
  }
});
