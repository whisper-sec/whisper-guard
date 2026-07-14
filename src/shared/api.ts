// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// One tiny seam over the WebExtension API namespace. Chromium exposes
// promise-capable APIs on `chrome`; Firefox exposes the same surface on
// `browser` (and mirrors most of it on `chrome`). Preferring `browser`
// when present gives us native promises on both engines with no polyfill
// dependency: the smallest thing that works everywhere.

declare const browser: typeof chrome | undefined;

export const ext: typeof chrome =
  typeof browser !== "undefined" && browser !== null ? browser : chrome;
