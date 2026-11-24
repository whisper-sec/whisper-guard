// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The key of the one per-tab record the popup and the worker share: that Guard
// declined a cookie prompt on the page a tab is showing.
//
// The rule it keeps: a storage.session record whose value is `true`, keyed by
// the tab's id and nothing else. It holds no host and no URL. It is written only
// for a tab known to be in a normal window, and dropped when the tab's main
// frame commits a new page and when the tab closes. The popup shows its line
// only while the value is exactly `true`; anything else, or no record, is
// "unknown" and shows nothing.

export const cookieDeclinedKey = (tabId: number): string => `cookieDeclined:${tabId}`;
