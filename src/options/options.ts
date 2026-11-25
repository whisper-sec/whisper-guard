// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Settings page. The Active Shield toggle performs the runtime broad-host
// permission request right here (a user gesture), so the browser's own
// consent dialog makes the grant knowing and revocable. Declining is fine:
// everything except on-page warnings keeps working.

import { send } from "../shared/messages";
import { CONSOLE_URL } from "../shared/config";
import type { FleetEndpoint, Settings } from "../shared/types";
import { ext } from "../shared/api";
import { newestRead, shieldActive, shieldGranted } from "../shared/shield-state";
import { mountProtectControl, type ProtectControl } from "../shared/protect-control";
import { chooseTheme } from "../shared/theme-press";
import { normalizeTheme, THEME_CHOICES } from "../shared/theme-choice";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const check = (id: string): HTMLInputElement => $(id) as unknown as HTMLInputElement;

const nextShieldRead = newestRead();
/** Numbers each full refresh, apart from the shield redraws, for the parts only a refresh draws. */
const nextRefresh = newestRead();
/** The Active Shield permission request is open: the box stays disabled whatever redraws. */
let requesting = false;

const COOKIE_REACH_TAB_ONLY = "Runs only on a tab where you open Guard. Active Shield runs it on every page.";

/** The Active Shield block with no grant: nothing on, both sub-toggles disabled. */
function drawShieldOff(): void {
  check("opt-shield").checked = false;
  for (const [id, noteId] of [
    ["opt-banner", "banner-needs"],
    ["opt-fieldguard", "fieldguard-needs"],
  ] as const) {
    check(id).checked = false;
    check(id).disabled = true;
    $(noteId).hidden = false;
  }
  // The cookie decline note, when shown, no longer says it runs everywhere.
  const reach = $("cookiedecline-reach");
  if (!reach.hidden) reach.textContent = COOKIE_REACH_TAB_ONLY;
}

/** Every switch the settings read draws, and the trusted sites list. */
const SETTING_INPUTS = [
  "opt-cloudcheck",
  "opt-nearmiss",
  "opt-shield",
  "opt-banner",
  "opt-fieldguard",
  "opt-cookiedecline",
  "opt-corpusupdate",
] as const;

/**
 * Whether the settings could be read. While they could not, the page says so
 * and locks every switch rather than show a state nothing has read.
 */
let allowlistDrawn = false;
function drawSettingsDown(down: boolean): void {
  $("settings-down").hidden = !down;
  if (down) {
    // Whatever was drawn is no longer known to be true: the next read that
    // works draws the trusted sites list again as well.
    allowlistDrawn = false;
    for (const id of SETTING_INPUTS) check(id).disabled = true;
    ($("opt-allowlist") as unknown as HTMLTextAreaElement).disabled = true;
    $("hold-state").textContent = "";
    $("hold-note").hidden = true;
  } else {
    check("opt-cloudcheck").disabled = false;
    check("opt-nearmiss").disabled = false;
    check("opt-shield").disabled = requesting;
    check("opt-cookiedecline").disabled = false;
    check("opt-corpusupdate").disabled = false;
    // The trusted sites list is drawn by refresh; it is unlocked there.
    if (allowlistDrawn) ($("opt-allowlist") as unknown as HTMLTextAreaElement).disabled = false;
  }
}

/**
 * The settings-driven part of the page: the Active Shield block, the four
 * other switches and the state of Hold dangerous clicks. The two sub-toggles
 * cannot do anything until Active Shield is on (setting and grant), so until
 * then they are drawn unchecked and disabled with a note. The stored
 * preference is never touched here: render only, no writes. Only the newest
 * read draws, so a slow older one cannot put a stale state back.
 */
async function renderShieldDeps(settings: Settings | null, isLatest: () => boolean): Promise<void> {
  const granted = await shieldGranted();
  // A newer read has started since this one did: let it draw.
  if (!isLatest()) return;
  drawSettingsDown(settings === null);
  if (!settings) {
    // The settings could not be read: the grant alone decides. Without it
    // nothing is drawn on. With it the preferences are unknown, so the
    // page is left as it is rather than guessed.
    if (!granted) drawShieldOff();
    return;
  }
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
  check("opt-cookiedecline").checked = settings.cookieDecline;
  check("opt-nearmiss").checked = settings.nearMiss;
  check("opt-corpusupdate").checked = settings.corpusAutoUpdate;
  check("opt-cloudcheck").checked = settings.cloudCheck;
  $("hold-state").textContent = settings.cloudCheck ? "On" : "Limited";
  $("hold-note").hidden = settings.cloudCheck;
  // The cookie decline toggle stays usable and keeps the stored preference;
  // the note only says where it can run.
  const reach = $("cookiedecline-reach");
  reach.hidden = !settings.cookieDecline;
  reach.textContent = !settings.cookieDecline
    ? ""
    : active
      ? "Runs on every page."
      : COOKIE_REACH_TAB_ONLY;
}

async function readSettings(): Promise<Settings | null> {
  // A read that rejects (the worker stopped mid-request) is a failed read.
  const res = await send<{ ok: true; settings: Settings }>({ kind: "getSettings" }).catch(() => null);
  return res?.ok ? res.settings : null;
}

async function refresh(): Promise<void> {
  const isLatest = nextShieldRead();
  const refreshLatest = nextRefresh();
  const res = await send<{
    ok: true;
    settings: Settings;
    signedIn: boolean;
    corpusVersion: number;
    corpusUpdated: string;
    corpusBrands: number;
  }>({ kind: "getSettings" }).catch(() => null);
  if (!res?.ok) {
    await renderShieldDeps(null, isLatest);
    return;
  }

  await renderShieldDeps(res.settings, isLatest);
  // A newer refresh has started since this one did: its answer is the one to
  // draw, and an older one finishing last must not put its values back.
  if (!refreshLatest()) return;

  $("account-signedout").hidden = res.signedIn;
  $("account-signedin").hidden = !res.signedIn;
  void drawIdentities(res.signedIn, refreshLatest);

  $("lookalike-line").textContent = `Catches homoglyphs, TLD swaps and combosquats of ${
    res.corpusBrands > 0 ? `${res.corpusBrands.toLocaleString("en")} brands` : "the bundled brand list"
  }, on this device.`;

  const list = $("opt-allowlist") as unknown as HTMLTextAreaElement;
  list.value = res.settings.allowlist.join("\n");
  allowlistDrawn = true;
  if ($("settings-down").hidden) list.disabled = false;
  $("corpus-info").textContent = `Brand list v${res.corpusVersion} (${res.corpusUpdated === "bundled" ? "bundled with the extension" : `updated ${res.corpusUpdated.slice(0, 10)}`}).`;
}

/** The count of identities on the account, read live; left out when the read fails. */
async function drawIdentities(signedIn: boolean, isLatest: () => boolean): Promise<void> {
  const out = $("account-identities");
  if (!signedIn) {
    out.hidden = true;
    return;
  }
  const res = await send<{ ok: true; fleet: { endpoints: FleetEndpoint[] } } | { ok: false; error: string }>({
    kind: "getFleetReport",
    cached: true,
  }).catch(() => null);
  if (!isLatest()) return;
  if (!res?.ok) {
    out.hidden = true;
    out.textContent = "";
    return;
  }
  const n = res.fleet.endpoints.length;
  out.textContent = `${n} ${n === 1 ? "identity" : "identities"} on the account`;
  out.hidden = false;
}

async function rerenderShield(): Promise<void> {
  const isLatest = nextShieldRead();
  const settings = await readSettings();
  // The trusted sites list was never drawn (the first read failed): a read
  // that works now is a full refresh, so the list is not unlocked empty.
  if (settings && !allowlistDrawn) {
    await refresh();
    return;
  }
  await renderShieldDeps(settings, isLatest);
}

function wire(): void {
  check("opt-shield").addEventListener("change", async (ev) => {
    const box = ev.target as HTMLInputElement;
    if (box.checked) {
      if (requesting) return;
      // The box stays unchecked until the grant is decided. The request is the
      // first call on the gesture, with nothing awaited ahead of it.
      requesting = true;
      box.checked = false;
      box.disabled = true;
      let granted = false;
      try {
        granted = (await chrome.permissions.request({ origins: ["<all_urls>"] })) === true;
      } catch {
        // A request that rejects is a decline.
      }
      if (granted) await send({ kind: "setSettings", patch: { shield: true } }).catch(() => undefined);
    } else {
      await send({ kind: "setSettings", patch: { shield: false } }).catch(() => undefined);
    }
    requesting = false;
    await rerenderShield();
    // Disabling the box took the focus off it: give it back, unless the reader moved on.
    const now = document.activeElement;
    if (now === null || now === document.body) box.focus();
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
    const key = input.value;
    if (key.trim() === "") return;
    let ok = false;
    try {
      ok = (await send({ kind: "saveKey", key })).ok;
    } catch {
      // The worker did not answer: the key is not saved.
    } finally {
      // Whatever the answer, the key does not stay in the field.
      input.value = "";
    }
    if (ok) await refresh();
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

  $("btn-corpusnow").addEventListener("click", async () => {
    $("corpus-status").textContent = "Checking...";
    const res = await send({ kind: "updateCorpusNow" });
    $("corpus-status").textContent = res.ok ? "Updated." : (res as { error?: string }).error ?? "No update.";
    await refresh();
  });
}

/** The protect control, as the popup mounts it, with the action that opens its dashboard view. */
function mountProtect(): ProtectControl {
  const control = mountProtectControl({
    root: $("protect-control"),
    extraActions: () => {
      const dash = document.createElement("button");
      dash.id = "btn-egress-dash";
      dash.type = "button";
      dash.className = "w-btn small";
      dash.textContent = "Open it on the dashboard";
      dash.addEventListener("click", () => {
        void send({ kind: "openDashboard", view: "browser" });
      });
      return [dash];
    },
  });
  void control.refresh();
  return control;
}

/** The theme row: shows the page's own choice, which follows a choice made in another Guard page. */
function initThemeRow(): void {
  const root = document.documentElement;
  const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("#theme-choice button"));
  const show = (): void => {
    const now = normalizeTheme(root.getAttribute("data-theme"));
    for (const b of buttons) b.setAttribute("aria-pressed", String(b.dataset["themeChoice"] === now));
  };
  show();
  new MutationObserver(show).observe(root, { attributes: true, attributeFilter: ["data-theme"] });
  for (const b of buttons) {
    const choice = THEME_CHOICES.find((c) => c === b.dataset["themeChoice"]);
    if (choice) b.addEventListener("click", () => chooseTheme(choice));
  }
}

const SECTION_IDS = ["protection", "account", "browser", "privacy", "about"] as const;

/** The menu: the link of the section in view carries aria-current. */
function initMenu(): void {
  const links = Array.from(document.querySelectorAll<HTMLAnchorElement>('nav[aria-label="Settings sections"] a'));
  const mark = (id: string): void => {
    for (const a of links) {
      if (a.getAttribute("href") === `#${id}`) a.setAttribute("aria-current", "true");
      else a.removeAttribute("aria-current");
    }
  };
  const inView = (): string => {
    const line = 120;
    const doc = document.documentElement;
    if (innerHeight + scrollY >= doc.scrollHeight - 2 && scrollY > 0) {
      // At the very end: the last section whose top is on screen.
      const onScreen = SECTION_IDS.filter((id) => document.getElementById(id)!.getBoundingClientRect().top < innerHeight - 40);
      return onScreen[onScreen.length - 1] ?? SECTION_IDS[0];
    }
    let current: string = SECTION_IDS[0];
    for (const id of SECTION_IDS) if (document.getElementById(id)!.getBoundingClientRect().top <= line) current = id;
    return current;
  };
  let queued = false;
  const follow = (): void => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      mark(inView());
    });
  };
  addEventListener("scroll", follow, { passive: true });
  addEventListener("resize", follow);
  addEventListener("hashchange", () => {
    const id = location.hash.slice(1);
    if (SECTION_IDS.some((s) => s === id)) mark(id);
    follow();
  });
  const first = location.hash.slice(1);
  mark(SECTION_IDS.some((s) => s === first) ? first : SECTION_IDS[0]);
}

/** A direct link opens at its section, also after the page's own drawing has moved things. */
function scrollToHash(): void {
  const id = location.hash.slice(1);
  if (SECTION_IDS.some((s) => s === id)) document.getElementById(id)?.scrollIntoView();
}

const version = ext.runtime.getManifest().version;
$("menu-version").textContent = `v${version} · MIT · open source`;
$("about-version").textContent = version;

wire();
initMenu();
initThemeRow();
mountProtect();
void refresh().finally(scrollToHash);
