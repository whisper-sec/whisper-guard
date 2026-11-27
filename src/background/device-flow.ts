// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Sign in with Whisper: the RFC 8628 device-authorization flow, the same
// one the Whisper CLI uses. It runs against DEVICE_FLOW_ORIGIN, which is
// the sign-in origin and NOT the console this extension sends readers to:
// these two endpoints are unauthenticated by design and live only there
// (config.ts records the live probe behind that split).
//
//   POST /api/device/authorize  (no auth) -> device_code, user_code,
//                                            verification_uri[_complete],
//                                            interval, expires_in
//   POST /api/device/token      (no auth) -> { status, api_key } (polled)
//
// The approval page the reader lands on is the one the SERVER names in
// verification_uri; we open exactly what it hands us and never synthesise
// a console URL of our own, because only the server knows where a given
// code can be approved.
//
// The user never sees the string "API key": they approve in the console and
// the key lands in storage.local. Neither the device_code nor the key is
// ever logged. Flow state survives a service-worker restart via
// storage.session so a sleeping worker resumes polling on wake.

import {
  DEVICE_FLOW_ORIGIN,
  DEVICE_LIFETIME_DEFAULT_MS,
  DEVICE_POLL_DEFAULT_MS,
} from "../shared/config";
import { ext } from "../shared/api";
import type { DeviceFlowState } from "../shared/types";

interface PendingFlow {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  intervalMs: number;
  deadline: number;
  /** The tab this flow opened on the approval page; null when it could not be opened. */
  tabId: number | null;
}

/** What the reader is told when a code runs out, in the popup and on the poll alike. */
const EXPIRED_TEXT = "This code expired before it was approved.";
/** What the reader is told when the approval page answered Deny. */
const DENIED_TEXT = "The sign-in was refused in the console.";

/** A state with nothing waiting: every field but the phase and the words is empty. */
function rest(phase: DeviceFlowState["phase"], message: string | null = null): DeviceFlowState {
  return { phase, userCode: null, verificationUri: null, expiresAt: null, message };
}

let state: DeviceFlowState = rest("idle");
let pending: PendingFlow | null = null;
let pollTimer: ReturnType<typeof setTimeout> | null = null;

// Fired whenever the signed-in state changes (sign-in approved, key pasted,
// sign-out), so the background can light up / dim open tabs immediately
// instead of waiting for the next navigation.
let authChanged: (() => void) | null = null;
export function onAuthChanged(cb: () => void): void {
  authChanged = cb;
}
function notifyAuthChanged(): void {
  try {
    authChanged?.();
  } catch {
    // repainting is best-effort
  }
}

export function deviceFlowState(): DeviceFlowState {
  // The popup counts down to the deadline, so the answer must agree with it
  // at that moment instead of waiting for the next poll to notice.
  if (pending && state.phase === "waiting" && Date.now() >= pending.deadline) {
    state = rest("expired", EXPIRED_TEXT);
    void clearPending();
  }
  return state;
}

async function postJson(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = await fetch(`${DEVICE_FLOW_ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`the console returned HTTP ${res.status}`);
  const parsed: unknown = await res.json();
  if (!parsed || typeof parsed !== "object") throw new Error("unparseable console reply");
  return parsed as Record<string, unknown>;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

async function persist(): Promise<void> {
  try {
    await chrome.storage.session.set({ deviceFlow: pending });
  } catch {
    // memory-only fallback is acceptable
  }
}

/** Resume a poll loop after a service-worker restart. */
export async function resumeDeviceFlow(): Promise<void> {
  try {
    const stored = (await chrome.storage.session.get("deviceFlow"))["deviceFlow"] as PendingFlow | null;
    if (stored && typeof stored.deviceCode === "string" && stored.deadline > Date.now()) {
      pending = stored;
      state = {
        phase: "waiting",
        userCode: stored.userCode,
        verificationUri: stored.verificationUri,
        expiresAt: stored.deadline,
        message: null,
      };
      schedulePoll(0);
    }
  } catch {
    // nothing to resume
  }
}

export async function startDeviceFlow(): Promise<DeviceFlowState> {
  cancelDeviceFlow();
  let auth: Record<string, unknown>;
  try {
    // The body names the client and nothing else: no browser, no system.
    auth = await postJson("/api/device/authorize", { client: "whisper-guard" });
  } catch (e) {
    state = rest("error", String(e instanceof Error ? e.message : e));
    return state;
  }

  const deviceCode = str(auth["device_code"]);
  const userCode = str(auth["user_code"]);
  // Only an https address is ever opened, whichever of the two the console names.
  const uri = [str(auth["verification_uri_complete"]), str(auth["verification_uri"])].find(isHttps) ?? "";
  if (deviceCode === "" || uri === "") {
    state = rest("error", "incomplete device-authorize reply from the console");
    return state;
  }
  const intervalS = typeof auth["interval"] === "number" ? (auth["interval"] as number) : 0;
  const expiresS = typeof auth["expires_in"] === "number" ? (auth["expires_in"] as number) : 0;

  pending = {
    deviceCode,
    userCode,
    verificationUri: uri,
    intervalMs: intervalS > 0 ? intervalS * 1000 : DEVICE_POLL_DEFAULT_MS,
    deadline: Date.now() + (expiresS > 0 ? expiresS * 1000 : DEVICE_LIFETIME_DEFAULT_MS),
    tabId: null,
  };
  const flow = pending;
  state = { phase: "waiting", userCode, verificationUri: uri, expiresAt: flow.deadline, message: null };

  // Open the approval page: usually one tap for a signed-in console user. The
  // tab is remembered so it can be brought forward, and closed once the poll
  // has an answer.
  const opened = await openApprovalTab(uri);
  if (pending !== flow) {
    // The flow ended while the tab was opening (cancelled or replaced): leave nothing behind.
    await closeApprovalTab({ tabId: opened, verificationUri: uri });
    return deviceFlowState();
  }
  flow.tabId = opened;
  await persist();
  schedulePoll(flow.intervalMs);
  return state;
}

function isHttps(address: string): boolean {
  try {
    return new URL(address).protocol === "https:";
  } catch {
    return false;
  }
}

async function openApprovalTab(uri: string): Promise<number | null> {
  try {
    const tab = await ext.tabs.create({ url: uri });
    return typeof tab.id === "number" ? tab.id : null;
  } catch {
    return null;
  }
}

function originOf(address: string | undefined): string | null {
  try {
    // An opaque origin ("null") is never the same as another.
    const origin = address ? new URL(address).origin : null;
    return origin === "null" ? null : origin;
  } catch {
    return null;
  }
}

/** The remembered tab, when it still exists and still shows the sign-in origin. */
async function liveApprovalTab(flow: Pick<PendingFlow, "tabId" | "verificationUri">): Promise<chrome.tabs.Tab | null> {
  if (flow.tabId === null) return null;
  try {
    const tab = await ext.tabs.get(flow.tabId);
    const origin = originOf(flow.verificationUri);
    // A tab that has only just been created reports its address as pending
    // until it loads. No readable address is no match.
    return origin !== null && originOf(tab.pendingUrl || tab.url) === origin ? tab : null;
  } catch {
    return null;
  }
}

/** Close the tab Guard opened, unless the reader has taken it somewhere else. */
async function closeApprovalTab(flow: Pick<PendingFlow, "tabId" | "verificationUri">): Promise<void> {
  const tab = await liveApprovalTab(flow);
  if (tab?.id === undefined) return;
  try {
    await ext.tabs.remove(tab.id);
  } catch {
    // already gone
  }
}

/**
 * Bring the approval page forward while a sign-in waits: the tab Guard opened
 * when it is still there, else the same address in a new tab. The address is
 * always the one the console named.
 */
export async function showApprovalTab(): Promise<DeviceFlowState> {
  const current = deviceFlowState();
  const flow = pending;
  if (current.phase !== "waiting" || !flow) return current;
  const tab = await liveApprovalTab(flow);
  if (tab?.id !== undefined) {
    try {
      await ext.tabs.update(tab.id, { active: true });
    } catch {
      // fall through to a new tab
      return openAgain(flow);
    }
    try {
      if (tab.windowId !== undefined) await ext.windows.update(tab.windowId, { focused: true });
    } catch {
      // the tab is forward; a window that would not take the focus is not a reason for a second tab
    }
    return deviceFlowState();
  }
  return openAgain(flow);
}

async function openAgain(flow: PendingFlow): Promise<DeviceFlowState> {
  const opened = await openApprovalTab(flow.verificationUri);
  if (pending !== flow) {
    // The flow ended while the tab was opening: close it rather than remember it.
    await closeApprovalTab({ tabId: opened, verificationUri: flow.verificationUri });
    return deviceFlowState();
  }
  flow.tabId = opened;
  await persist();
  return deviceFlowState();
}

function schedulePoll(delayMs: number): void {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(() => {
    pollOnce().catch(() => undefined);
  }, delayMs);
}

async function pollOnce(): Promise<void> {
  if (!pending) return;
  if (Date.now() >= pending.deadline) {
    state = rest("expired", EXPIRED_TEXT);
    await clearPending();
    return;
  }
  const flow = pending;
  let tok: Record<string, unknown>;
  try {
    tok = await postJson("/api/device/token", { device_code: flow.deviceCode });
  } catch {
    // A transient blip never aborts an otherwise-fine sign-in: keep polling.
    if (pending === flow) schedulePoll(flow.intervalMs);
    return;
  }
  // A late answer for a flow that has since ended (expired, cancelled, signed
  // out or replaced) changes nothing: no key, no phase, no clearing of the new flow.
  if (pending !== flow) return;
  const status = str(tok["status"]);
  if (status === "approved") {
    const key = str(tok["api_key"]);
    if (key === "") {
      state = rest("error", "approved, but the console returned no key; try again");
      await clearPending();
    } else {
      await chrome.storage.local.set({ apiKey: key });
      // The flow may have been replaced while the key was being written.
      if (pending !== flow) return;
      await clearPending();
      // The approval page has done its work; it is gone before the answer
      // reads approved, so a reader who sees "approved" sees no stale tab.
      await closeApprovalTab(flow);
      state = rest("approved");
      notifyAuthChanged();
    }
    return;
  }
  if (status === "denied") {
    // Refused in the console: stop at once, with no further token request.
    await clearPending();
    await closeApprovalTab(flow);
    state = rest("denied", DENIED_TEXT);
    return;
  }
  if (status === "expired") {
    state = rest("expired", EXPIRED_TEXT);
    await clearPending();
    return;
  }
  // pending, or an unknown status (liberal-accept): keep polling.
  schedulePoll(flow.intervalMs);
}

async function clearPending(): Promise<void> {
  pending = null;
  if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  try {
    await chrome.storage.session.remove("deviceFlow");
  } catch {
    // fine
  }
}

export function cancelDeviceFlow(): void {
  state = rest("idle");
  void clearPending();
}

export async function signOut(): Promise<void> {
  cancelDeviceFlow();
  await chrome.storage.local.remove("apiKey");
  notifyAuthChanged();
}

/** Enterprise/power-user fallback: paste a key directly (settings). */
export async function saveKey(key: string): Promise<void> {
  const k = key.trim();
  if (k === "") throw new Error("empty key");
  await chrome.storage.local.set({ apiKey: k });
  state = rest("approved");
  notifyAuthChanged();
}
