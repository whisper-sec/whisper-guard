// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Browser-as-endpoint: the opt-in, off-by-default toggle that gives THIS
// browser its own routable Whisper identity and routes it through the
// Whisper HTTPS egress, so it shows up in the fleet like any other device.
//
//   register-once   op:register {label, device:true} exactly once; the
//                   identity (agent + /128) persists and is reused forever.
//                   If the account already holds a device with our exact
//                   label, it is ADOPTED, never duplicated (registration
//                   writes durable state).
//   connect         op:connect {agent} -> an authenticated HTTPS-CONNECT
//                   egress endpoint bound to the browser's own /128. The
//                   token is cached locally, refreshed only when refused.
//   route           ONE HTTPS-CONNECT code path for both engines:
//                   Chromium fixed_servers + onAuthRequired credentials;
//                   Firefox proxy.onRequest + proxyAuthorizationHeader.
//   WebRTC          disable_non_proxied_udp rides the toggle on Chromium,
//                   or the "everything sources from the /128" claim would
//                   be false. (Firefox has no such extension control; the
//                   limit is stated in the UI, not papered over.)
//
// Honest limits, surfaced not hidden: the proxy setting is PROFILE-GLOBAL
// and single-owner; when another extension controls it we say so plainly.

import { ext } from "../shared/api";
import type { EgressStatus } from "../shared/types";
import { controlCall, ControlError } from "./control";
import { GraphError } from "./graph-client";

const DEVICE_LABEL = "This browser (Whisper Guard)";

interface EgressIdentity {
  agent: string;
  address: string;
  label: string;
}

interface EgressConfig {
  /** The proxy transport to the egress endpoint: "https" in production
   *  (TLS to the endpoint on :443), "http" only for a local test endpoint. */
  scheme: "http" | "https";
  host: string;
  port: number;
  username: string;
  token: string;
}

interface StoredEgress {
  on: boolean;
  identity: EgressIdentity | null;
  config: EgressConfig | null;
  error: string | null;
}

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function getStored(): Promise<StoredEgress> {
  try {
    const s = (await chrome.storage.local.get("egress"))["egress"] as
      | Partial<StoredEgress>
      | undefined;
    if (s && typeof s === "object") {
      return {
        on: s.on === true,
        identity: s.identity ?? null,
        config: s.config ?? null,
        error: s.error ?? null,
      };
    }
  } catch {
    // fall through
  }
  return { on: false, identity: null, config: null, error: null };
}

async function setStored(patch: Partial<StoredEgress>): Promise<StoredEgress> {
  const cur = await getStored();
  const next = { ...cur, ...patch };
  await chrome.storage.local.set({ egress: next }).catch(() => undefined);
  return next;
}

// Engine split by CAPABILITY, not by the `browser` global (modern Chrome
// aliases `browser` to `chrome`, so its mere presence proves nothing).
// Firefox routes per-request via proxy.onRequest; Chromium has no such API
// and drives the profile proxy through proxy.settings instead.
interface MaybeProxy {
  proxy?: { onRequest?: { addListener?: unknown } };
}
const isFirefox =
  typeof (globalThis as { browser?: MaybeProxy }).browser?.proxy?.onRequest?.addListener ===
  "function";

// -------------------------------------------------------------- identity

/** Register-once: reuse the stored identity, adopt an existing device with
 *  our label, or mint a fresh one; in that order. */
async function ensureIdentity(): Promise<EgressIdentity> {
  const stored = await getStored();
  if (stored.identity) return stored.identity;

  // Adoption: the account may already hold this browser's device (e.g. a
  // reinstall). Registration writes durable state, so never duplicate.
  try {
    const list = await controlCall("list", { kind: "agents" });
    for (const row of list.rows) {
      const item = row["item"];
      if (!isObject(item)) continue;
      if (str(item["label"]) !== DEVICE_LABEL) continue;
      if (str(item["state"]) !== "active") continue;
      const agent = str(item["agent"]);
      const address = str(item["address"]);
      if (agent && address) {
        const identity = { agent, address, label: DEVICE_LABEL };
        await setStored({ identity });
        return identity;
      }
    }
  } catch {
    // listing failed: fall through to register (it will fail loudly if truly broken)
  }

  const res = await controlCall("register", { label: DEVICE_LABEL, device: true });
  const row = res.rows[0] ?? {};
  const agent = str(row["agent"]);
  const address = str(row["address"]);
  if (!agent || !address) throw new ControlError(0, "register returned no identity");
  const identity = { agent, address, label: DEVICE_LABEL };
  await setStored({ identity });
  return identity;
}

// ------------------------------------------------------------------ token

/** Parse an authenticated proxy URL into its parts. */
function parseProxyUrl(raw: string): EgressConfig | null {
  try {
    const u = new URL(raw);
    const scheme = u.protocol === "http:" ? "http" : "https";
    const port = u.port !== "" ? Number(u.port) : scheme === "http" ? 80 : 443;
    if (!u.hostname || !Number.isFinite(port)) return null;
    return {
      scheme,
      host: u.hostname,
      port,
      username: decodeURIComponent(u.username || "w"),
      token: decodeURIComponent(u.password),
    };
  } catch {
    return null;
  }
}

async function provisionEgress(identity: EgressIdentity): Promise<EgressConfig> {
  const res = await controlCall("connect", { agent: identity.agent });
  const row = res.rows[0] ?? {};
  // Liberal-accept the field the platform returns the HTTP(S) form under
  // (production hands back an https egress endpoint; the field name varies).
  const candidates = [row["http_proxy"], row["https_proxy"], row["connection_string"]];
  for (const c of candidates) {
    const s = str(c);
    if (!s || s.startsWith("socks5")) continue;
    const cfg = parseProxyUrl(s);
    if (cfg && cfg.token !== "") return cfg;
  }
  // Only a SOCKS5 string came back: it carries the same token + endpoint;
  // reuse its credentials on the HTTPS-CONNECT endpoint the platform docs.
  const socks = str(row["connection_string"]) ?? str(row["socks5_endpoint"]);
  if (socks) {
    const cfg = parseProxyUrl(socks.replace(/^socks5h?:/, "https:"));
    if (cfg && cfg.token !== "") return { ...cfg, scheme: "https", port: cfg.port === 80 ? 443 : cfg.port };
  }
  throw new ControlError(0, "connect returned no egress endpoint");
}

// ------------------------------------------------------------ proxy wiring

let authListenerInstalled = false;

/** Supply the egress credentials to Chromium's proxy-auth challenge. */
function installAuthListener(): void {
  if (isFirefox || authListenerInstalled) return;
  if (!chrome.webRequest?.onAuthRequired) return;
  const attempts = new Map<string, number>();
  chrome.webRequest.onAuthRequired.addListener(
    (details, callback) => {
      void (async () => {
        const s = await getStored();
        if (!s.on || !s.config || !details.isProxy) {
          callback?.({});
          return;
        }
        // Never loop on a refused credential: one retry per request id.
        const n = (attempts.get(details.requestId) ?? 0) + 1;
        attempts.set(details.requestId, n);
        if (attempts.size > 512) attempts.clear();
        if (n > 2) {
          callback?.({ cancel: true });
          return;
        }
        callback?.({
          authCredentials: { username: s.config.username, password: s.config.token },
        });
      })();
    },
    { urls: ["<all_urls>"] },
    ["asyncBlocking"],
  );
  authListenerInstalled = true;
}

// Firefox: one per-request hook, registered lazily once the permission
// exists; answers direct until the toggle is on.
let ffProxyInstalled = false;
interface FirefoxProxyInfo {
  type: string;
  host?: string;
  port?: number;
  proxyAuthorizationHeader?: string;
}
interface FirefoxProxyApi {
  onRequest: {
    addListener(
      cb: (details: { url: string }) => Promise<FirefoxProxyInfo | FirefoxProxyInfo[]>,
      filter: { urls: string[] },
    ): void;
  };
}

function installFirefoxProxy(): void {
  if (!isFirefox || ffProxyInstalled) return;
  const proxyApi = (globalThis as { browser?: { proxy?: FirefoxProxyApi } }).browser?.proxy;
  if (!proxyApi?.onRequest) return;
  proxyApi.onRequest.addListener(
    async () => {
      const s = await getStored();
      if (!s.on || !s.config) return { type: "direct" };
      return {
        type: s.config.scheme,
        host: s.config.host,
        port: s.config.port,
        proxyAuthorizationHeader: `Basic ${btoa(`${s.config.username}:${s.config.token}`)}`,
      };
    },
    { urls: ["<all_urls>"] },
  );
  ffProxyInstalled = true;
}

async function applyChromiumProxy(cfg: EgressConfig): Promise<void> {
  await chrome.proxy.settings.set({
    value: {
      mode: "fixed_servers",
      rules: {
        singleProxy: { scheme: cfg.scheme, host: cfg.host, port: cfg.port },
        // Loopback destinations go direct (local dev servers); this never
        // affects reaching the proxy endpoint itself.
        bypassList: ["localhost", "127.0.0.1", "[::1]", "<local>"],
      },
    },
    scope: "regular",
  });
}

async function hardenWebRtc(on: boolean): Promise<boolean | null> {
  const policy = chrome.privacy?.network?.webRTCIPHandlingPolicy;
  if (!policy) return null;
  try {
    if (on) {
      await policy.set({ value: "disable_non_proxied_udp" });
      return true;
    }
    await policy.clear({});
    return false;
  } catch {
    return null;
  }
}

async function proxyControlledByOther(): Promise<boolean> {
  try {
    const details = await new Promise<chrome.types.ChromeSettingGetResultDetails>((resolve) =>
      chrome.proxy.settings.get({}, resolve),
    );
    return details.levelOfControl === "controlled_by_other_extensions";
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ public

export const EGRESS_PERMISSIONS = {
  chromium: {
    permissions: ["proxy", "webRequest", "webRequestAuthProvider", "privacy"],
    origins: ["<all_urls>"],
  },
  firefox: { permissions: ["proxy"], origins: ["<all_urls>"] },
} as const;

async function permissionsGranted(): Promise<boolean> {
  const want = isFirefox ? EGRESS_PERMISSIONS.firefox : EGRESS_PERMISSIONS.chromium;
  try {
    return await ext.permissions.contains({
      permissions: [...want.permissions],
      origins: [...want.origins],
    });
  } catch {
    return false;
  }
}

export async function egressStatus(): Promise<EgressStatus> {
  const s = await getStored();
  return {
    on: s.on,
    agent: s.identity?.agent ?? null,
    address: s.identity?.address ?? null,
    label: s.identity?.label ?? null,
    controlledByOther: !isFirefox && !s.on ? await proxyControlledByOther() : false,
    webrtcHardened: isFirefox ? null : s.on,
    error: s.error,
  };
}

/**
 * Turn the browser into a Whisper endpoint. The PAGE requests the optional
 * permissions on the user gesture BEFORE messaging this; here we verify,
 * provision and route. Every failure is a clear message, never silence.
 */
export async function egressEnable(): Promise<EgressStatus> {
  try {
    if (!(await permissionsGranted())) {
      await setStored({ on: false, error: "the browser permissions were not granted" });
      return egressStatus();
    }
    if (!isFirefox && (await proxyControlledByOther())) {
      await setStored({
        on: false,
        error: "another extension controls this browser's proxy; disable it first",
      });
      return egressStatus();
    }

    const identity = await ensureIdentity();
    const stored = await getStored();
    const config = stored.config ?? (await provisionEgress(identity));
    await setStored({ config, error: null });

    if (isFirefox) {
      installFirefoxProxy();
      await setStored({ on: true, error: null });
    } else {
      installAuthListener();
      await applyChromiumProxy(config);
      await setStored({ on: true, error: null });
      await hardenWebRtc(true);
    }
    return egressStatus();
  } catch (e) {
    const message =
      e instanceof GraphError && e.reason === "nokey"
        ? "sign in first; the browser identity lives on your Whisper account"
        : e instanceof ControlError || e instanceof GraphError
          ? e.message
          : `could not enable egress: ${String(e instanceof Error ? e.message : e)}`;
    await setStored({ on: false, error: message });
    return egressStatus();
  }
}

/** Refresh the egress token after a refusal (one re-provision, then apply). */
export async function egressReprovision(): Promise<EgressStatus> {
  const s = await getStored();
  if (!s.identity) return egressStatus();
  try {
    const config = await provisionEgress(s.identity);
    await setStored({ config, error: null });
    if (s.on && !isFirefox) await applyChromiumProxy(config);
    return egressStatus();
  } catch (e) {
    await setStored({ error: String(e instanceof Error ? e.message : e) });
    return egressStatus();
  }
}

export async function egressDisable(): Promise<EgressStatus> {
  await setStored({ on: false, error: null });
  if (!isFirefox) {
    try {
      await chrome.proxy.settings.clear({ scope: "regular" });
    } catch {
      // permission may already be revoked; the setting dies with it
    }
    await hardenWebRtc(false);
  }
  return egressStatus();
}

/** Re-arm listeners + proxy after a service-worker restart. */
export async function resumeEgress(): Promise<void> {
  const s = await getStored();
  if (!s.on) return;
  if (isFirefox) {
    installFirefoxProxy();
    return;
  }
  installAuthListener();
  if (s.config) {
    try {
      await applyChromiumProxy(s.config);
    } catch {
      // proxy permission revoked while we slept: reflect the truth
      await setStored({ on: false, error: "the proxy permission was revoked" });
    }
  }
}
