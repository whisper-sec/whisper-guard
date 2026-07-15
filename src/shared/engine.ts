// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Which engine is this build running on? Decided at BUILD TIME (each target
// is bundled separately), never guessed from a permission-gated API.
//
// The old detection probed `browser.proxy.onRequest`, which only exists once
// the OPTIONAL "proxy" permission has been granted, so a Firefox build asked
// itself "am I Firefox?" before the very grant that would let it answer, took
// the Chromium path, requested Chromium-only permissions, and dead-ended with
// "permissions were not granted". The build already knows its target; use it.

declare const __FIREFOX__: boolean | undefined;

/** Runtime fallback (unbundled contexts only): runtime.getBrowserInfo is
 *  Firefox-only and needs no permission, so it is safe to probe anytime. */
function runtimeIsFirefox(): boolean {
  const b = (globalThis as { browser?: { runtime?: { getBrowserInfo?: unknown } } }).browser;
  return typeof b?.runtime?.getBrowserInfo === "function";
}

export const IS_FIREFOX: boolean =
  typeof __FIREFOX__ === "boolean" ? __FIREFOX__ : runtimeIsFirefox();
