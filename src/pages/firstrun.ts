// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// First run: two cards, no config, no account wall. The privacy promise and
// the honest scope, then an optional one-tap sign-in (the same RFC 8628
// device flow as everywhere else). "Not now" is a first-class choice:
// on-device protection is already live either way.

import { send } from "../shared/messages";

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

$("btn-later").addEventListener("click", () => {
  window.close();
});

$("btn-signin").addEventListener("click", async () => {
  const status = $("device-status");
  status.hidden = false;
  status.textContent = "Opening the Whisper console...";
  await send({ kind: "signInStart" });
  for (;;) {
    const res = await send<{
      ok: true;
      device: { phase: string; userCode: string | null; message: string | null };
    }>({ kind: "signInStatus" });
    if (!res.ok) return;
    const d = res.device;
    if (d.phase === "waiting") {
      status.textContent = `Approve the sign-in in the console tab (code ${d.userCode ?? "..."}). Waiting...`;
    } else if (d.phase === "approved") {
      status.textContent = "Signed in. The live signal is active on every site you visit.";
      return;
    } else if (d.phase === "expired" || d.phase === "error") {
      status.textContent = d.message ?? "Sign-in did not complete. Try again.";
      return;
    } else {
      return;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
});
