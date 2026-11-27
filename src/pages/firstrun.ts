// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// First run: protection is already on, and three steps make it work fully.
//
// THE PAGE IS A STATE, NOT A PREAMBLE. Every step's state is READ when the
// page opens and again whenever it could have changed: the toolbar pin from
// the browser, Active Shield from the stored setting AND the all-sites grant,
// the account from the stored key. The counter at the top is the number of
// steps that are done or skipped, so it moves in both directions: a grant
// taken away in the browser's own site-access control moves it back.
//
// The side column reads the same way: a real verdict from the live graph,
// the live size of that graph, and the brand count of the corpus the
// detector loaded. Nothing in it is typed into the build, and a read that
// fails says so and shows no number.

import { send, type CheckHostResult } from "../shared/messages";
import type { GraphScale, Settings } from "../shared/types";
import { compact, countUp } from "../shared/spark";
import { ext } from "../shared/api";
import { newestRead, shieldActive, shieldGranted } from "../shared/shield-state";

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

type StepState = "done" | "current" | "skipped" | "todo";

const STATE_TEXT: Record<StepState, string> = {
  done: "Done",
  current: "Next",
  skipped: "Skipped",
  todo: "Not started",
};

const DECLINED = "Not turned on. Everything else still works. You can turn it on here or in Settings.";

/** What the page knows right now. `null` is "not read (yet)", never a guess. */
const st = {
  /** The browser's own answer for the toolbar, or null when it could not be read. */
  pinned: null as boolean | null,
  /** The first pin read has finished, so "could not read" is an answer, not a wait. */
  pinAsked: false,
  /** The reader's word that Guard is pinned, used only when the browser cannot say. */
  pinnedByWord: false,
  shieldOn: false,
  /** The settings could not be read the last time they were asked for. */
  settingsUnread: false,
  /** The last click on the Active Shield button did not end with it on. */
  declined: false,
  signedIn: false,
  /** Step 3 was set aside with Later, for this page only. */
  skipped: false,
};

/** A sign-in loop is running (declared up here because render() reads it). */
let signingIn = false;

// ------------------------------------------------------------ the steps

function stepStates(): { pin: StepState; shield: StepState; account: StepState } {
  const settled = {
    pin: st.pinned === true || st.pinnedByWord ? "done" : null,
    shield: st.shieldOn ? "done" : null,
    account: st.signedIn ? "done" : st.skipped ? "skipped" : null,
  } as const;
  // The current step is the first one that is neither done nor skipped.
  let currentTaken = false;
  const pick = (s: StepState | null): StepState => {
    if (s) return s;
    if (!currentTaken) {
      currentTaken = true;
      return "current";
    }
    return "todo";
  };
  return { pin: pick(settled.pin), shield: pick(settled.shield), account: pick(settled.account) };
}

function setResult(id: string, text: string | null): void {
  const p = $(id);
  p.hidden = text === null;
  p.textContent = text ?? "";
}

function render(): void {
  const s = stepStates();
  const ids = { pin: "step-pin", shield: "step-shield", account: "step-account" } as const;
  let done = 0;
  for (const key of ["pin", "shield", "account"] as const) {
    const li = $(ids[key]);
    li.dataset["state"] = s[key];
    if (s[key] === "current") li.setAttribute("aria-current", "step");
    else li.removeAttribute("aria-current");
    li.querySelector(".step-state")!.textContent = STATE_TEXT[s[key]];
    if (s[key] === "done" || s[key] === "skipped") done++;
  }
  $("setup-count").textContent = `${done} of 3`;

  // Step 1: a read, or the reader's own word when the browser cannot say.
  const pinDone = s.pin === "done";
  const unreadable = st.pinAsked && st.pinned === null;
  if (pinDone) setResult("pin-result", st.pinned === true ? "Pinned. Done." : "You said it is pinned. Done.");
  else if (unreadable) setResult("pin-result", "Guard could not read whether it is pinned.");
  else setResult("pin-result", null);
  $("btn-pinned").hidden = pinDone || !unreadable;

  // Step 2: done only from the setting AND the grant together.
  const shieldDone = s.shield === "done";
  $("shield-ask").hidden = shieldDone;
  if (shieldDone) setResult("shield-result", "Active Shield is on.");
  else if (st.declined) setResult("shield-result", DECLINED);
  else if (st.settingsUnread)
    setResult(
      "shield-result",
      "The extension’s own settings could not be read just now, so this step is not claiming Active Shield is on.",
    );
  else setResult("shield-result", null);

  // Step 3 and the header block share one account state.
  setResult(
    "account-result",
    s.account === "done"
      ? "Signed in."
      : s.account === "skipped"
        ? "Skipped. You can sign in any time from the toolbar panel or Settings."
        : null,
  );
  // A status from a sign-in that finished elsewhere is not true any more.
  if (!st.signedIn && !signingIn && !$("device-status").hidden && $("device-status").dataset["done"] === "1") {
    $("device-status").hidden = true;
    $("device-status").textContent = "";
    delete $("device-status").dataset["done"];
  }
  $("account-ask").hidden = s.account === "done";
  $("btn-later").hidden = s.account !== "current" && s.account !== "todo";
  $("btn-create").hidden = st.signedIn;
  $("cta-have").hidden = st.signedIn;
  $("cta-signed-in").hidden = !st.signedIn;
}

// ----------------------------------------------------------- step 1: pin

const nextPinRead = newestRead();

/**
 * Whether Guard's icon is on the toolbar, asked of the browser. Chromium 91+
 * and Firefox 116+ answer it, and this extension requires newer than both.
 * Firefox places the button on the toolbar at install (the manifest's
 * default_area), while Chromium keeps it in the Extensions menu until the
 * reader pins it. Either way the browser's own answer decides here: nothing
 * about the browser is assumed.
 */
async function readPin(): Promise<void> {
  const isLatest = nextPinRead();
  let pinned: boolean | null = null;
  try {
    const action = ext.action as unknown as { getUserSettings?: () => Promise<{ isOnToolbar?: unknown }> };
    if (typeof action?.getUserSettings === "function") {
      const got = await action.getUserSettings();
      if (typeof got?.isOnToolbar === "boolean") pinned = got.isOnToolbar;
    }
  } catch {
    pinned = null;
  }
  if (!isLatest()) return;
  st.pinned = pinned;
  st.pinAsked = true;
  // The reader's word only stands in for a read that is impossible.
  if (pinned !== null) st.pinnedByWord = false;
  render();
}

$("btn-pinned").addEventListener("click", () => {
  st.pinnedByWord = true;
  render();
});

// The browser says when the pin changes (Chromium 130+); everywhere else the
// page re-reads when it is looked at again, and slowly while it waits.
try {
  const action = ext.action as unknown as { onUserSettingsChanged?: chrome.events.Event<() => void> };
  action?.onUserSettingsChanged?.addListener(() => void readPin());
} catch {
  // No such event: the focus, visibility and timer reads below cover it.
}
window.addEventListener("focus", () => void readPin());
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") void readPin();
});
setInterval(() => {
  // Only while the last read said "not pinned": no reads once it is pinned,
  // none when the browser cannot answer (focus and visibility still re-read),
  // and none for a page nobody can see.
  if (st.pinned !== false || st.pinnedByWord || document.visibilityState !== "visible") return;
  void readPin();
}, 2000);

// ------------------------------------------------------- step 2: shield

const nextShieldRead = newestRead();

/** The brand figure: the corpus the detector loaded, counted; unread says so. */
function drawBrands(brands: number | null): void {
  if (brands !== null && brands > 0) {
    $("brand-count").textContent = brands.toLocaleString("en");
    $("fig-brands").hidden = false;
    $("brand-down").hidden = true;
  } else if (brands === null && !$("fig-brands").hidden) {
    // A later read failed: keep the number the page already read.
  } else {
    $("fig-brands").hidden = true;
    $("brand-down").hidden = false;
  }
}

/** Read the stored settings and the grant together, and draw what they say. */
async function readShield(): Promise<void> {
  const isLatest = nextShieldRead();
  const res = await send<{
    ok: true;
    settings: Settings;
    signedIn: boolean;
    corpusBrands: number;
  }>({ kind: "getSettings" }).catch(() => null);
  const granted = await shieldGranted();
  // A newer read has started since this one did: let it draw.
  if (!isLatest()) return;
  if (!res?.ok) {
    st.settingsUnread = true;
    st.shieldOn = false;
    drawBrands(null);
  } else {
    st.settingsUnread = false;
    st.shieldOn = shieldActive(res.settings, granted);
    st.signedIn = res.signedIn === true;
    drawBrands(res.corpusBrands);
  }
  if (st.shieldOn) st.declined = false;
  render();
  // The first settings read has landed and been drawn (a marker for tests).
  $("steps").dataset["read"] = "settings";
}

$("btn-shield").addEventListener("click", () => {
  // The permission request is the FIRST thing on the click: no await, no
  // message and no read ahead of it, or the browser no longer sees a user
  // gesture and (Firefox) refuses it.
  let asked: Promise<boolean>;
  try {
    asked = ext.permissions.request({ origins: ["<all_urls>"] });
  } catch (e) {
    asked = Promise.reject(e);
  }
  void finishShieldAsk(asked);
});

async function finishShieldAsk(asked: Promise<boolean>): Promise<void> {
  const button = $("btn-shield") as HTMLButtonElement;
  button.disabled = true;
  st.declined = false;
  let ok = false;
  try {
    if ((await asked) === true) {
      const stored = await send({ kind: "setSettings", patch: { shield: true } });
      ok = stored.ok;
    }
  } catch {
    ok = false;
  }
  // Declined or refused: nothing was stored. Either way the step is drawn
  // from a fresh read, so it shows what was granted and stored.
  st.declined = !ok;
  await readShield();
  button.disabled = false;
}

// A grant or a settings change elsewhere (Settings, the browser's own
// site-access control) re-reads the state in place. The grant lands before
// the setting does, so the storage listener settles the final picture.
ext.permissions.onAdded.addListener(() => void readShield());
ext.permissions.onRemoved.addListener(() => void readShield());
ext.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && ("settings" in changes || "apiKey" in changes)) void readShield();
});

// ------------------------------------------------------ step 3: account

/** Both the header and step 3 start the same sign-in and report in one place. */
async function signIn(): Promise<void> {
  if (signingIn) return;
  signingIn = true;
  const status = $("device-status");
  delete status.dataset["done"];
  status.hidden = false;
  status.textContent = "Opening the Whisper console...";
  try {
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
        status.dataset["done"] = "1";
        st.signedIn = true;
        signingIn = false;
        render();
        return;
      } else if (d.phase === "expired" || d.phase === "denied" || d.phase === "error") {
        status.textContent = d.message ?? "Sign-in did not complete. Try again.";
        return;
      } else {
        return;
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
  } catch {
    // The worker stopped mid-request: say so, and let the next click start again.
    status.textContent = "Sign-in did not complete. Try again.";
  } finally {
    signingIn = false;
  }
}

for (const id of ["btn-create", "btn-signin-link", "btn-signin"]) {
  $(id).addEventListener("click", () => void signIn());
}

$("btn-later").addEventListener("click", () => {
  st.skipped = true;
  render();
});

// ------------------------------------------------------- see it work

// The live sample: one real verdict for a well-known host, fetched now.
// (A fixed public name, never anything about the user's browsing.)
async function loadSample(): Promise<void> {
  const chip = $("sample-chip");
  const note = $("sample-note");
  const res = await send<{ ok: true; check: CheckHostResult }>({ kind: "checkHost", host: "github.com" }).catch(
    () => ({ ok: false as const }),
  );
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
 * measured: an unreachable endpoint gets a sentence saying so, never a number
 * somebody typed here once.
 */
async function loadScale(): Promise<void> {
  const res = await send<{ ok: true; scale: GraphScale | null }>({ kind: "getScale" }).catch(() => null);
  if (!res?.ok || !res.scale) {
    $("scale-down").hidden = false;
    return;
  }
  $("fig-nodes").hidden = false;
  countUp($("scale-nodes"), res.scale.nodes, compact);
}

void loadSample();
void loadScale();
void readShield();
void readPin();
render();
