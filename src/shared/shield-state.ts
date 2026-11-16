// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Whether Active Shield can actually run, for the pages that draw it.
//
// The runtime gate is the stored setting AND the browser's all-sites grant
// (background/index.ts). The two on-page protections (the credential-field
// guard and the warning banner) cannot run until both hold, so a page that
// draws them "on" from their own setting alone claims what is not happening.
// Reading the two together here keeps the pages and the runtime in step.

import { ext } from "./api";
import type { Settings } from "./types";

/** Whether the browser currently holds the all-sites grant. Any failure is "no". */
export async function shieldGranted(): Promise<boolean> {
  try {
    return (await ext.permissions.contains({ origins: ["<all_urls>"] })) === true;
  } catch {
    return false;
  }
}

/** Active Shield is effectively on only with the setting and the grant together. */
export function shieldActive(s: Pick<Settings, "shield">, granted: boolean): boolean {
  return s.shield && granted;
}

/**
 * Numbers each re-render of a page's Active Shield state. A read takes its
 * number when it STARTS and asks `isLatest()` after its last await, right
 * before it touches the page: two reads that overlap finish in any order, and
 * only the newest may draw, so a slow older read cannot put a stale state back.
 */
export function newestRead(): () => () => boolean {
  let latest = 0;
  return () => {
    const mine = ++latest;
    return () => mine === latest;
  };
}
