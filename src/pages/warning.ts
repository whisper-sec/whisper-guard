// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The full-page warning (Active Shield, evidenced-malicious only). Reached
// two ways: a DNR session rule (cached-bad, pre-render) or tabs.update on
// verdict (novel-bad). Back-to-safety always works, Escape works, and the
// page never traps: continue-anyway is one click, honest and available.
// The composed protection picture supplies the receipts: which feeds list
// it, who runs it, how old the name is.

import { send } from "../shared/messages";
import type { Protection } from "../shared/types";

const params = new URLSearchParams(window.location.search);
const host = (params.get("host") ?? "").toLowerCase();
const brand = params.get("brand");
const brandDomain = params.get("brandDomain");

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

$("detail").textContent = host
  ? brandDomain
    ? `${host} is flagged as a known threat impersonating ${brand ?? brandDomain}. It was blocked before any credentials could be entered.`
    : `${host} is flagged as a known threat in the Whisper security graph. It was blocked before any credentials could be entered.`
  : "This page was flagged as a known threat.";

$("privacy").textContent = host
  ? `Privacy: only "${host}" was checked. Your browsing stays yours.`
  : "";

function backToSafety(): void {
  if (window.history.length > 1) window.history.back();
  else window.location.href = "about:blank";
}

$("btn-back").addEventListener("click", backToSafety);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") backToSafety();
});

if (brandDomain) {
  const real = $("btn-real") as HTMLAnchorElement;
  real.hidden = false;
  real.textContent = `Go to the real ${brandDomain}`;
  real.href = `https://${brandDomain}/`;
}

$("btn-continue").addEventListener("click", async () => {
  if (host === "") return;
  await send({ kind: "allowHost", host, session: true });
  window.location.href = `https://${host}/`;
});

// The receipts: feed citations, who runs it, domain age. Best-effort; the
// warning stands on its own if the graph is unreachable.
async function loadReceipts(): Promise<void> {
  if (host === "") return;
  const res = await send<{ ok: true; protection: Protection }>({ kind: "getProtection", host });
  if (!res.ok) return;
  const p = res.protection;
  const box = $("receipts");
  const rows: HTMLElement[] = [];
  const kv = (k: string, v: string): HTMLElement => {
    const row = document.createElement("div");
    const kEl = document.createElement("span");
    kEl.className = "k";
    kEl.textContent = k;
    row.append(kEl, document.createTextNode(v));
    return row;
  };
  for (const w of p.why) rows.push(kv("why", w));
  if (p.who) rows.push(kv("who", p.who));
  if (p.ageDays !== null && p.ageDays < 366) {
    rows.push(kv("age", `registered ${p.ageDays} day(s) ago`));
  }
  if (rows.length > 0) {
    box.hidden = false;
    box.replaceChildren(...rows);
  }
}
void loadReceipts();
