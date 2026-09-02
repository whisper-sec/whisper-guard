// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// First run: protection is already on, keyless value first. A LIVE sample
// verdict proves the graph tier in one glance, then the privacy promise,
// then an optional one-tap sign-in (the same RFC 8628 device flow as
// everywhere else). "Not now" is a first-class choice.

import { send, type CheckHostResult } from "../shared/messages";
import type { GraphScale } from "../shared/types";
import { compact } from "../shared/spark";

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

// The live sample: one real verdict for a well-known host, fetched now.
// (A fixed public name, never anything about the user's browsing.)
async function loadSample(): Promise<void> {
  const chip = $("sample-chip");
  const note = $("sample-note");
  const res = await send<{ ok: true; check: CheckHostResult }>({ kind: "checkHost", host: "github.com" });
  if (!res.ok || !res.check.verdict) {
    chip.className = "w-chip unknown";
    chip.textContent = "UNAVAILABLE";
    note.textContent = res.ok ? (res.check.graphError ?? "the live check is off") : "could not reach Whisper";
    return;
  }
  const band = res.check.verdict.band.toUpperCase();
  const good = band === "NONE" || band === "LOW" || band === "INFO";
  chip.className = `w-chip ${good ? "ok" : band === "MEDIUM" ? "med" : band === "UNKNOWN" ? "unknown" : "crit"}`;
  chip.textContent = good ? "NO KNOWN THREAT" : band;
  note.textContent = res.check.verdict.coverage ? `coverage: ${res.check.verdict.coverage}` : "";
}
/**
 * How big the graph is, read live. The claim is only made when it was
 * measured: an unreachable endpoint leaves the sentence standing without a
 * number rather than falling back to one somebody typed here once.
 */
async function loadScaleClaim(): Promise<void> {
  const res = await send<{ ok: true; scale: GraphScale | null }>({ kind: "getScale" });
  if (!res.ok || !res.scale) return;
  $("scale-claim").textContent =
    `, ${compact(res.scale.nodes)} nodes and ${compact(res.scale.edges)} edges of internet ground truth`;
}

void loadSample();
void loadScaleClaim();

$("btn-later").addEventListener("click", () => {
  window.close();
});

$("btn-dashboard").addEventListener("click", () => {
  void send({ kind: "openDashboard" });
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
