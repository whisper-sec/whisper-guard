// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Settings page. The Active Shield toggle performs the runtime broad-host
// permission request right here (a user gesture), so the browser's own
// consent dialog makes the grant knowing and revocable. Declining is fine:
// everything except on-page warnings keeps working.

import { send } from "../shared/messages";
import type { Settings } from "../shared/types";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const check = (id: string): HTMLInputElement => $(id) as unknown as HTMLInputElement;

async function refresh(): Promise<void> {
  const res = await send<{
    ok: true;
    settings: Settings;
    signedIn: boolean;
    corpusVersion: number;
    corpusUpdated: string;
  }>({ kind: "getSettings" });
  if (!res.ok) return;

  $("account-signedout").hidden = res.signedIn;
  $("account-signedin").hidden = !res.signedIn;

  const granted = await chrome.permissions.contains({ origins: ["<all_urls>"] });
  check("opt-shield").checked = res.settings.shield && granted;
  check("opt-banner").checked = res.settings.amberBanner;
  check("opt-fieldguard").checked = res.settings.fieldGuard;
  check("opt-nearmiss").checked = res.settings.nearMiss;
  check("opt-corpusupdate").checked = res.settings.corpusAutoUpdate;
  ($("opt-allowlist") as unknown as HTMLTextAreaElement).value = res.settings.allowlist.join("\n");
  $("corpus-info").textContent = `Corpus v${res.corpusVersion} (${res.corpusUpdated === "bundled" ? "bundled with the extension" : `updated ${res.corpusUpdated.slice(0, 10)}`}).`;
}

function wire(): void {
  check("opt-shield").addEventListener("change", async (ev) => {
    const on = (ev.target as HTMLInputElement).checked;
    if (on) {
      const granted = await chrome.permissions.request({ origins: ["<all_urls>"] });
      if (!granted) {
        (ev.target as HTMLInputElement).checked = false;
        return;
      }
    }
    await send({ kind: "setSettings", patch: { shield: on } });
  });

  for (const [id, key] of [
    ["opt-banner", "amberBanner"],
    ["opt-fieldguard", "fieldGuard"],
    ["opt-nearmiss", "nearMiss"],
    ["opt-corpusupdate", "corpusAutoUpdate"],
  ] as const) {
    check(id).addEventListener("change", async (ev) => {
      await send({ kind: "setSettings", patch: { [key]: (ev.target as HTMLInputElement).checked } });
    });
  }

  $("opt-allowlist").addEventListener("change", async (ev) => {
    const lines = (ev.target as HTMLTextAreaElement).value
      .split("\n")
      .map((l) => l.trim().toLowerCase())
      .filter((l) => l !== "");
    await send({ kind: "setSettings", patch: { allowlist: lines } });
  });

  $("btn-signin").addEventListener("click", async () => {
    $("device-status").textContent = "Opening the console...";
    await send({ kind: "signInStart" });
    for (;;) {
      const res = await send<{ ok: true; device: { phase: string; userCode: string | null; message: string | null } }>({ kind: "signInStatus" });
      if (!res.ok) return;
      const d = res.device;
      if (d.phase === "waiting") {
        $("device-status").textContent = `Approve in the console tab (code ${d.userCode ?? "..."}).`;
      } else if (d.phase === "approved") {
        $("device-status").textContent = "Signed in.";
        await refresh();
        return;
      } else {
        $("device-status").textContent = d.message ?? "Sign-in did not complete. Try again.";
        return;
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
  });

  $("btn-savekey").addEventListener("click", async () => {
    const input = $("key-input") as unknown as HTMLInputElement;
    if (input.value.trim() === "") return;
    const res = await send({ kind: "saveKey", key: input.value });
    input.value = "";
    if (res.ok) await refresh();
  });

  $("btn-signout").addEventListener("click", async () => {
    await send({ kind: "signOut" });
    await refresh();
  });

  $("btn-corpusnow").addEventListener("click", async () => {
    $("corpus-status").textContent = "Checking...";
    const res = await send({ kind: "updateCorpusNow" });
    $("corpus-status").textContent = res.ok ? "Updated." : (res as { error?: string }).error ?? "No update.";
    await refresh();
  });
}

wire();
void refresh();
