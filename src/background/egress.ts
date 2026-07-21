// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Browser-as-endpoint, two cleanly separated ideas:
//
//   ENROLL    reserve this browser's own routable Whisper identity (an
//             agent + /128, verifiable via reverse-DNS and RDAP). Pure
//             control plane: works whenever the user is signed in, needs
//             NO browser permission, and never touches the proxy setting.
//             register-once: op:register {label, device:true} exactly once;
//             the identity persists and is reused forever. If the account
//             already holds a device with our exact label it is ADOPTED,
//             never duplicated (registration writes durable state).
//   PROTECT   route this browser's traffic through that identity via the
//             authenticated Whisper HTTPS-CONNECT egress (op:connect).
//             This half needs the optional proxy permission and a proxy
//             setting nothing else owns; when it cannot engage, enrollment
//             stands and the UI says exactly what is in the way.
//
//   route     ONE HTTPS-CONNECT code path for both engines:
//             Chromium fixed_servers + onAuthRequired credentials;
//             Firefox proxy.onRequest + proxyAuthorizationHeader.
//   WebRTC    disable_non_proxied_udp rides the toggle on Chromium, or the
//             "everything sources from the /128" claim would be false.
//             (Firefox has no such extension control; the limit is stated
//             in the UI, not papered over.)
//
// Honest limits, surfaced not hidden: the proxy setting is PROFILE-GLOBAL
// and single-owner; when another extension controls it we say so plainly,
// keep the identity, and point at the fix instead of dead-ending.

import { ext } from "../shared/api";
import { CONTROL_PROVISION_TIMEOUT_MS, EGRESS_REQUEST } from "../shared/config";
import { IS_FIREFOX } from "../shared/engine";
import type { EgressStatus, Enrollment } from "../shared/types";
import { controlCall, ControlError } from "./control";
import { GraphError } from "./graph-client";
import { rdapIpUrl, verifyIdentity } from "./rdap";

const DEVICE_LABEL = "This browser (Whisper Guard)";

interface EgressIdentity {
  agent: string;
  address: string;
  label: string;
  fqdn: string | null;
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
        // Identities stored by older versions carry no fqdn yet.
        identity: s.identity ? { ...s.identity, fqdn: s.identity.fqdn ?? null } : null,
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

// -------------------------------------------------------------- identity

/** Register-once: reuse the stored identity, adopt an existing device with
 *  our label, or mint a fresh one; in that order. Control plane only: no
 *  browser permission is involved anywhere in here. */
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
        const identity: EgressIdentity = {
          agent,
          address,
          label: DEVICE_LABEL,
          fqdn: str(item["fqdn"])?.replace(/\.$/, "") ?? null,
        };
        await setStored({ identity });
        return identity;
      }
    }
  } catch {
    // listing failed: fall through to register (it will fail loudly if truly broken)
  }

  const res = await controlCall(
    "register",
    { label: DEVICE_LABEL, device: true },
    CONTROL_PROVISION_TIMEOUT_MS,
  );
  const row = res.rows[0] ?? {};
  const agent = str(row["agent"]);
  const address = str(row["address"]);
  if (!agent || !address) throw new ControlError(0, "register returned no identity");
  const identity: EgressIdentity = {
    agent,
    address,
    label: DEVICE_LABEL,
    fqdn: str(row["fqdn"])?.replace(/\.$/, "") ?? null,
  };
  await setStored({ identity });
  return identity;
}

/**
 * ENROLL this browser: reserve (or re-find) its identity and verify it
 * against keyless RDAP. Succeeds for any signed-in user, independent of the
 * proxy permission, other extensions, or the egress endpoint.
 */
export async function enrollBrowser(): Promise<Enrollment> {
  const identity = await ensureIdentity();
  const verification = await verifyIdentity(identity.address);
  if (verification?.fqdn && !identity.fqdn) {
    // The reverse-DNS name came back from verification: remember it.
    const fqdn = verification.fqdn.replace(/\.$/, "");
    await setStored({ identity: { ...identity, fqdn } });
    identity.fqdn = fqdn;
  }
  return {
    agent: identity.agent,
    address: identity.address,
    label: identity.label,
    fqdn: identity.fqdn,
    rdapUrl: rdapIpUrl(identity.address),
    verification,
  };
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
  const res = await controlCall("connect", { agent: identity.agent }, CONTROL_PROVISION_TIMEOUT_MS);
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
  if (IS_FIREFOX || authListenerInstalled) return;
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
  if (!IS_FIREFOX || ffProxyInstalled) return;
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

// The honest, actionable messages for the two ways routing (not identity)
// can be blocked. Neither is a dead end: enrollment and verdicts stand.
const MSG_NO_PERMISSION =
  "the browser did not grant the proxy permission, so routing stayed off. " +
  "Your browser identity and site verdicts keep working; grant the permission to route.";
const MSG_PROXY_CONFLICT =
  "another extension (a VPN or proxy manager) holds this browser's proxy setting, " +
  "so routing cannot engage. Your identity is reserved and verdicts keep working. " +
  "Disable that extension's proxy control, then turn this on again.";

async function permissionsGranted(): Promise<boolean> {
  const want = IS_FIREFOX ? EGRESS_REQUEST.firefox : EGRESS_REQUEST.chromium;
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
    enrolled: s.identity !== null,
    agent: s.identity?.agent ?? null,
    address: s.identity?.address ?? null,
    label: s.identity?.label ?? null,
    fqdn: s.identity?.fqdn ?? null,
    rdapUrl: s.identity ? rdapIpUrl(s.identity.address) : null,
    controlledByOther: !IS_FIREFOX && !s.on ? await proxyControlledByOther() : false,
    webrtcHardened: IS_FIREFOX ? null : s.on,
    error: s.error,
  };
}

/**
 * PROTECT: route the browser through its Whisper identity. The PAGE requests
 * the optional permissions on the user gesture BEFORE messaging this; here
 * we enroll (always, first, so identity survives any routing failure), then
 * verify permissions, take the proxy, and route. Every failure is a clear,
 * actionable message, never silence and never a dead end.
 */
export async function egressEnable(): Promise<EgressStatus> {
  try {
    // 1) ENROLL first. Identity is control-plane only; nothing below may
    //    stop this browser from having its verifiable /128.
    const identity = await ensureIdentity();

    // 2) Routing needs the optional permissions.
    if (!(await permissionsGranted())) {
      await setStored({ on: false, error: MSG_NO_PERMISSION });
      return egressStatus();
    }

    // 3) The proxy setting is single-owner; if someone else holds it, say
    //    who can fix it and keep everything else alive. (Chromium only:
    //    Firefox proxy.onRequest handlers compose instead of owning.)
    if (!IS_FIREFOX) {
      if (!chrome.proxy?.settings) {
        // Defensive: the API binding should appear the moment the optional
        // permission is granted; if it has not, one more toggle picks it up.
        await setStored({ on: false, error: "the proxy API is not up yet; toggle once more" });
        return egressStatus();
      }
      if (await proxyControlledByOther()) {
        await setStored({ on: false, error: MSG_PROXY_CONFLICT });
        return egressStatus();
      }
    }

    const stored = await getStored();
    const config = stored.config ?? (await provisionEgress(identity));
    await setStored({ config, error: null });

    if (IS_FIREFOX) {
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
    if (s.on && !IS_FIREFOX) await applyChromiumProxy(config);
    return egressStatus();
  } catch (e) {
    await setStored({ error: String(e instanceof Error ? e.message : e) });
    return egressStatus();
  }
}

export async function egressDisable(): Promise<EgressStatus> {
  await setStored({ on: false, error: null });
  if (!IS_FIREFOX) {
    try {
      await chrome.proxy.settings.clear({ scope: "regular" });
    } catch {
      // permission may already be revoked; the setting dies with it
    }
    await hardenWebRtc(false);
  }
  return egressStatus();
}

/**
 * After an op:revoke that retired THIS browser's own agent: drop the
 * stored identity and disengage routing, so the UI never keeps claiming
 * an identity (or riding a proxy credential) that is gone. A revoke of
 * any other endpoint is a no-op here.
 */
export async function forgetIdentity(agent: string): Promise<void> {
  const s = await getStored();
  if (!s.identity || s.identity.agent !== agent) return;
  await egressDisable();
  await setStored({ identity: null, config: null, error: null });
}

/** Re-arm listeners + proxy after a service-worker restart. */
export async function resumeEgress(): Promise<void> {
  const s = await getStored();
  if (!s.on) return;
  if (IS_FIREFOX) {
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
