// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The short text badge each toolbar state carries, as pure data so the
// background painter and the toolbar-states capture read one table. The
// colours are literal hex values: neither the background script nor a
// capture page can read a stylesheet token. Each names its role.

import type { IconState } from "./types";

export interface ToolbarBadge {
  text: string;
  /** Badge ground. */
  ground: string;
  /** Badge text colour. */
  ink: string;
}

export const TOOLBAR_BADGE: Record<IconState, ToolbarBadge | null> = {
  benign: {
    text: "✓",
    ground: "#34d399", // ground of the check badge
    ink: "#06060c", // text of the check badge
  },
  suspicious: {
    text: "!",
    ground: "#f59e0b", // ground of the ! badge
    ink: "#1c1917", // text of the ! badge
  },
  malicious: {
    text: "STOP",
    ground: "#b8202a", // ground of the STOP badge: the red of the malicious tile
    ink: "#ffffff", // text of the STOP badge
  },
  unknown: {
    text: "?",
    ground: "#c3c3cd", // ground of the ? badge
    ink: "#06060c", // text of the ? badge
  },
  checking: {
    text: "…",
    ground: "#7d5ce0", // ground of the checking badge: the violet of the checking tile's ring
    ink: "#ffffff", // text of the checking badge
  },
  // The live check is off: a muted tile with no badge.
  signedout: null,
  // A page Guard does not check: a muted tile with no badge.
  neutral: null,
};
