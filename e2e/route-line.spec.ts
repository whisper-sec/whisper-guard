// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The route line the panel and the dashboard show while routing is on, pinned
// branch by branch at the unit layer (no browser): the private-window sentence
// for true, false and unknown, times the WebRTC clause for hardened, not
// hardened and unknown. The rendered check stays in protect.spec.ts.

import { test, expect } from "@playwright/test";

const g = globalThis as Record<string, unknown>;

// The one static sentence (owner decision D2), verbatim.
const BASE =
  "Every window in this profile leaves from this address, except tailnet and private-network destinations, which connect directly.";
const PRIVATE = " Private windows are not routed unless Whisper Guard is allowed in them.";
const HARDENED = " WebRTC is hardened to proxied-only.";
const NOT_PINNED =
  " WebRTC is not pinned to this address, so a page can still learn your real address through a peer connection.";

test.afterEach(() => {
  delete g["chrome"];
});

test("the route line, all nine branches: the D2 sentence is always there, verbatim", async () => {
  // The module reaches for the browser namespace when it loads; give it an empty one.
  g["chrome"] = { runtime: {} };
  const { routeLineText } = await import("../src/shared/protect-control");
  const priv: Array<[boolean | null, string]> = [
    [true, ""],
    [false, PRIVATE],
    [null, PRIVATE],
  ];
  const rtc: Array<[boolean | null, string]> = [
    [true, HARDENED],
    [false, NOT_PINNED],
    [null, NOT_PINNED],
  ];
  let n = 0;
  for (const [privateWindowsRouted, p] of priv) {
    for (const [webrtcHardened, w] of rtc) {
      const text = routeLineText({ privateWindowsRouted, webrtcHardened });
      const label = `privateWindowsRouted=${privateWindowsRouted} webrtcHardened=${webrtcHardened}`;
      expect(text, label).toBe(`${BASE}${p}${w}`);
      expect(text.startsWith(BASE), `${label}: starts with the D2 sentence`).toBe(true);
      n++;
    }
  }
  expect(n).toBe(9);
});

test("the route line never claims Firefox cannot pin WebRTC, and never names a local address", async () => {
  g["chrome"] = { runtime: {} };
  const { routeLineText } = await import("../src/shared/protect-control");
  const text = routeLineText({ privateWindowsRouted: false, webrtcHardened: null });
  expect(text).not.toContain("cannot be pinned");
  expect(text).not.toContain("local address");
});
