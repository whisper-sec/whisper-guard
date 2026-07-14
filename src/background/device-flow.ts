// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Sign in with Whisper: the RFC 8628 device-authorization flow, the same
// one the Whisper CLI uses against console.whisper.security:
//
//   POST /api/device/authorize  (no auth) -> device_code, user_code,
//                                            verification_uri[_complete],
//                                            interval, expires_in
//   POST /api/device/token      (no auth) -> { status, api_key } (polled)
//
// The user never sees the string "API key": they approve in the console and
// the key lands in storage.local. Neither the device_code nor the key is
// ever logged. Flow state survives a service-worker restart via
// storage.session so a sleeping worker resumes polling on wake.

import {
  CONSOLE_URL,
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
}

let state: DeviceFlowState = { phase: "idle", userCode: null, verificationUri: null, message: null };
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
  return state;
}

async function postJson(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = await fetch(`${CONSOLE_URL}${path}`, {
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
    auth = await postJson("/api/device/authorize", {});
  } catch (e) {
    state = { phase: "error", userCode: null, verificationUri: null, message: String(e instanceof Error ? e.message : e) };
    return state;
  }

  const deviceCode = str(auth["device_code"]);
  const userCode = str(auth["user_code"]);
  const uri = str(auth["verification_uri_complete"]) || str(auth["verification_uri"]);
  if (deviceCode === "" || uri === "") {
    state = { phase: "error", userCode: null, verificationUri: null, message: "incomplete device-authorize reply from the console" };
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
  };
  await persist();
  state = { phase: "waiting", userCode, verificationUri: uri, message: null };

  // Open the approval page: usually one tap for a signed-in console user.
  ext.tabs.create({ url: uri }).catch(() => undefined);
  schedulePoll(pending.intervalMs);
  return state;
}

function schedulePoll(delayMs: number): void {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(() => {
    pollOnce().catch(() => undefined);
  }, delayMs);
}

async function pollOnce(): Promise<void> {
  if (!pending) return;
  if (Date.now() > pending.deadline) {
    state = { phase: "expired", userCode: null, verificationUri: null, message: "the sign-in was not approved in time; try again" };
    await clearPending();
    return;
  }
  let tok: Record<string, unknown>;
  try {
    tok = await postJson("/api/device/token", { device_code: pending.deviceCode });
  } catch {
    // A transient blip never aborts an otherwise-fine sign-in: keep polling.
    schedulePoll(pending.intervalMs);
    return;
  }
  const status = str(tok["status"]);
  if (status === "approved") {
    const key = str(tok["api_key"]);
    if (key === "") {
      state = { phase: "error", userCode: null, verificationUri: null, message: "approved, but the console returned no key; try again" };
    } else {
      await chrome.storage.local.set({ apiKey: key });
      state = { phase: "approved", userCode: null, verificationUri: null, message: null };
      notifyAuthChanged();
    }
    await clearPending();
    return;
  }
  if (status === "expired") {
    state = { phase: "expired", userCode: null, verificationUri: null, message: "the sign-in code expired; try again" };
    await clearPending();
    return;
  }
  // pending, or an unknown status (liberal-accept): keep polling.
  schedulePoll(pending.intervalMs);
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
  state = { phase: "idle", userCode: null, verificationUri: null, message: null };
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
  state = { phase: "approved", userCode: null, verificationUri: null, message: null };
  notifyAuthChanged();
}
