// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Settings page. The Active Shield toggle performs the runtime broad-host
// permission request right here (a user gesture), so the browser's own
// consent dialog makes the grant knowing and revocable. Declining is fine:
// everything except on-page warnings keeps working.

import { send } from "../shared/messages";
import { CONSOLE_URL } from "../shared/config";
import type { Settings } from "../shared/types";
import { ext } from "../shared/api";
import { shieldActive, shieldGranted } from "../shared/shield-state";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const check = (id: string): HTMLInputElement => $(id) as unknown as HTMLInputElement;

/**
 * The Active Shield block. The two sub-toggles cannot do anything until
 * Active Shield is on (setting and grant), so until then they are drawn
 * unchecked and disabled with a note. The stored preference is never touched
 * here: render only, no writes.
 */
async function renderShieldDeps(settings: Settings): Promise<void> {
  const granted = await shieldGranted();
  const active = shieldActive(settings, granted);
  check("opt-shield").checked = active;
  for (const [id, noteId, pref] of [
    ["opt-banner", "banner-needs", settings.amberBanner],
    ["opt-fieldguard", "fieldguard-needs", settings.fieldGuard],
  ] as const) {
    check(id).checked = active && pref;
    check(id).disabled = !active;
    $(noteId).hidden = active;
  }
}

async function readSettings(): Promise<Settings | null> {
  const res = await send<{ ok: true; settings: Settings }>({ kind: "getSettings" });
  return res.ok ? res.settings : null;
}

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

  await renderShieldDeps(res.settings);
  check("opt-cookiedecline").checked = res.settings.cookieDecline;
  check("opt-nearmiss").checked = res.settings.nearMiss;
  check("opt-corpusupdate").checked = res.settings.corpusAutoUpdate;
  check("opt-cloudcheck").checked = res.settings.cloudCheck;
  ($("opt-allowlist") as unknown as HTMLTextAreaElement).value = res.settings.allowlist.join("\n");
  $("corpus-info").textContent = `Corpus v${res.corpusVersion} (${res.corpusUpdated === "bundled" ? "bundled with the extension" : `updated ${res.corpusUpdated.slice(0, 10)}`}).`;

  const egress = await send<{ ok: true; egress: { on: boolean; address: string | null } }>({
    kind: "egressStatus",
  });
  $("egress-state").textContent = egress.ok
    ? egress.egress.on
      ? `on, routed as ${egress.egress.address ?? "(pending)"}`
      : "off"
    : "";
}

async function rerenderShield(): Promise<void> {
  const s = await readSettings();
  if (s) await renderShieldDeps(s);
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
    await rerenderShield();
  });

  ext.permissions.onAdded.addListener(() => void rerenderShield());
  ext.permissions.onRemoved.addListener(() => void rerenderShield());
  ext.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && "settings" in changes) void rerenderShield();
  });

  for (const [id, key] of [
    ["opt-banner", "amberBanner"],
    ["opt-fieldguard", "fieldGuard"],
    ["opt-cookiedecline", "cookieDecline"],
    ["opt-nearmiss", "nearMiss"],
    ["opt-corpusupdate", "corpusAutoUpdate"],
    ["opt-cloudcheck", "cloudCheck"],
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

  $("btn-dashboard").addEventListener("click", () => {
    void send({ kind: "openDashboard" });
  });
  $("btn-console").addEventListener("click", () => {
    void chrome.tabs.create({ url: CONSOLE_URL });
  });
  $("btn-egress-dash").addEventListener("click", () => {
    void send({ kind: "openDashboard", view: "browser" });
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
