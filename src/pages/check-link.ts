// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The pre-click result window: vet a link's DESTINATION before navigating.
// The truly pre-autofill surface: nothing has loaded, no password manager
// has fired, no page has run. On-device detector always; the keyed live
// band joins when signed in.

import { send, type CheckHostResult } from "../shared/messages";

const params = new URLSearchParams(window.location.search);
const host = (params.get("host") ?? "").toLowerCase();

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

const BAND_TEXT: Record<string, { cls: string; text: string }> = {
  CRITICAL: { cls: "malicious", text: "Known threat, evidenced in the graph. Do not open." },
  HIGH: { cls: "suspicious", text: "Strong risk signals in the graph. Be careful." },
  MEDIUM: { cls: "suspicious", text: "Some risk signals in the graph. Be careful." },
  LOW: { cls: "benign", text: "No known threat (not a warranty)." },
  INFO: { cls: "benign", text: "No known threat (not a warranty)." },
  NONE: { cls: "benign", text: "No known threat (not a warranty)." },
  UNKNOWN: { cls: "unknown", text: "New or low-coverage host. Not confirmed either way." },
};

async function init(): Promise<void> {
  if (host === "") {
    $("host").textContent = "No checkable link found (only http/https destinations can be vetted).";
    ($("btn-open") as HTMLAnchorElement).hidden = true;
    $("privacy").textContent = "Privacy: nothing was sent.";
    return;
  }
  $("host").textContent = host;
  ($("btn-open") as HTMLAnchorElement).href = `https://${host}/`;

  const res = await send<{ ok: true; check: CheckHostResult }>({ kind: "checkHost", host });
  if (!res.ok) return;
  const c = res.check;
  $("result").hidden = false;

  const copyLines = [`whisper guard check: ${host}`];

  if (c.detector) {
    $("detector-row").hidden = false;
    $("detector-text").textContent = `Looks like ${c.detector.brandDomain} (${c.detector.kind}, caught on-device).`;
    const real = $("btn-real") as HTMLAnchorElement;
    real.hidden = false;
    real.textContent = `Go to the real ${c.detector.brandDomain}`;
    real.href = c.detector.goTo;
    copyLines.push(`on-device: ${c.detector.kind} look-alike of ${c.detector.brandDomain}`);
  } else {
    copyLines.push("on-device: no look-alike match");
  }

  if (c.verdict) {
    const ui = BAND_TEXT[c.verdict.band] ?? BAND_TEXT["UNKNOWN"]!;
    $("band-row").hidden = false;
    $("band-tag").className = `tag ${ui.cls}`;
    $("band-tag").textContent = c.verdict.band;
    $("band-text").textContent = c.verdict.label ? `${ui.text} ${c.verdict.label}` : ui.text;
    copyLines.push(`graph band: ${c.verdict.band}${c.verdict.coverage ? ` (coverage: ${c.verdict.coverage}, categorical)` : ""}`);
  } else if (!c.graphError) {
    $("keyless-note").hidden = false;
    copyLines.push("graph band: (live check off)");
  }

  if (c.graphError) {
    $("error-note").hidden = false;
    $("error-note").textContent = c.graphError;
  }

  // The live check ran iff a verdict or a graph error came back; otherwise
  // the check was on-device only (live check switched off).
  $("privacy").textContent =
    c.verdict || c.graphError
      ? `Privacy: only "${host}" was sent, to graph.whisper.security.`
      : `Privacy: nothing left your browser. The check ran on-device.`;

  $("btn-copy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(copyLines.join("\n"));
    $("btn-copy").textContent = "Copied";
  });
}

void init();
