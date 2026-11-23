// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Browser-as-endpoint, two cleanly separated ideas:
//
//   ENROLL    reserve this browser's own routable Whisper identity (an
//             agent + /128, verifiable via reverse-DNS and RDAP). Pure
//             control plane: works whenever the user is signed in, needs
//             NO browser permission, and never touches the proxy setting.
//             register-once: op:register {label, device:true} goes out at
//             most once per reservation; the identity persists and is reused
//             forever. If the account already holds a device with our exact
//             label it is ADOPTED, never duplicated (registration writes
//             durable state). A new device can take a few seconds to show on
//             the account's list, and the registration answer does not carry
//             its id, so after the one registration the reservation is tried
//             up to RESERVE_TRIES times, one at a time, each only re-reading
//             the account. The try it is on is part of the status the
//             surfaces read.
//   PROTECT   route this browser's traffic through that identity via the
//             authenticated Whisper HTTPS-CONNECT egress (op:connect).
//             This half needs the optional proxy permission and a proxy
//             setting nothing else owns; when it cannot engage, enrollment
//             stands and the UI says exactly what is in the way.
//
//   route     ONE HTTPS-CONNECT code path for both engines (private-network
//             and tailnet destinations excepted: they go direct, see
//             shared/direct-destinations.ts):
//             Chromium pac_script (mandatory) + onAuthRequired credentials;
//             Firefox proxy.onRequest + proxyAuthorizationHeader.
//   WebRTC    disable_non_proxied_udp rides the toggle on Chromium, or the
//             "everything sources from the /128" claim would be false.
//             (Firefox has the control too, privacy.network.webRTCIPHandlingPolicy
//             behind the optional `privacy` permission, but Guard does not
//             request it there: STUN then goes out over direct UDP and a page
//             can learn the browser's real public address. The UI says so.)
//
// Honest limits, surfaced not hidden: the proxy setting is PROFILE-GLOBAL
// and single-owner; when another extension controls it we say so plainly,
// keep the identity, and point at the fix instead of dead-ending.

import { ext } from "../shared/api";
import { CONTROL_PROVISION_TIMEOUT_MS, EGRESS_REQUEST } from "../shared/config";
import { egressPacScript, goesDirectForUrl, isValidEgressEndpoint } from "../shared/direct-destinations";
import { IS_FIREFOX } from "../shared/engine";
import type { EgressStatus, Enrollment } from "../shared/types";
import { controlCall, ControlError } from "./control";
import { GraphError } from "./graph-client";
import { rdapIpUrl, verifyIdentity } from "./rdap";

const DEVICE_LABEL = "This browser (Whisper Guard)";

/** How many times the reservation is tried before it gives up. */
export const RESERVE_TRIES = 3;
/** The wait before the second try, then before the third. */
export const RESERVE_WAITS_MS: readonly number[] = [2_000, 4_000];
/** The longest one try may take. A call that never answers counts as a failed try. */
export const RESERVE_TRY_DEADLINE_MS = 45_000;

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

/**
 * True when a stored config can be applied as it is: a transport the proxy
 * accepts, a plain host and port, and a Basic credential that is printable
 * ASCII (btoa throws on anything else, which Firefox turns into a direct
 * connection that still looks Protected).
 */
function isUsableConfig(c: unknown): c is EgressConfig {
  if (!isObject(c)) return false;
  const printable = (v: unknown): boolean => typeof v === "string" && /^[\x20-\x7e]*$/.test(v);
  return (
    (c["scheme"] === "http" || c["scheme"] === "https") &&
    isValidEgressEndpoint(c["host"] as string, c["port"] as number) &&
    printable(c["username"]) &&
    printable(c["token"])
  );
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

function identityFrom(row: Record<string, unknown>): EgressIdentity | null {
  const agent = str(row["agent"]);
  const address = str(row["address"]);
  if (!agent || !address) return null;
  return { agent, address, label: DEVICE_LABEL, fqdn: str(row["fqdn"])?.replace(/\.$/, "") ?? null };
}

/** Thrown when every try ended without an address. Typed, so the caller
 *  never has to read the message to tell it from any other failure. */
export class ReservationExhausted extends Error {
  constructor() {
    super("could not reserve an address after several tries");
    this.name = "ReservationExhausted";
  }
}

/** Only what carries no verdict on the request itself is worth another try:
 *  a transport failure or timeout, or an error the plane calls retryable. A
 *  refusal, a missing or rejected key, a spent quota and a malformed answer
 *  are final. */
function worthRetrying(e: unknown): boolean {
  if (e instanceof GraphError) return e.reason === "timeout" || e.reason === "connect" || e.reason === "server";
  if (e instanceof ControlError) return e.retryable === true;
  return false;
}

/** What one reservation remembers across its tries. */
interface Sent {
  /** A registration has gone out. It may have created the device, so no
   *  second one is ever sent: later tries only re-read the account. */
  register: boolean;
}

/** One try: the stored identity, else this browser's device already on the
 *  account (adopted), else the reservation's one registration. null = not
 *  ready yet. `live.over` turns true when the try's deadline passed, so a try
 *  that is still running then never sends a registration. */
async function findOrMint(sent: Sent, live: { over: boolean }): Promise<EgressIdentity | null> {
  const stored = await getStored();
  if (stored.identity) return stored.identity;

  // Adoption: the account may already hold this browser's device (a reinstall,
  // or a registration that has not shown on the list yet). Registration writes
  // durable state, so never duplicate.
  let listedWithoutAddress = false;
  try {
    const found = await scanRoster(null);
    if (found.identity) return found.identity;
    listedWithoutAddress = found.listedWithoutAddress;
  } catch (e) {
    // A final answer (signed out, a rejected key, a spent quota, a refusal)
    // is never swallowed once a registration went out: it is the real reason.
    if (sent.register && !worthRetrying(e)) throw e;
    // Before any registration went out, fall through to register (it will
    // fail loudly if truly broken). After one did, that device may exist
    // already, so registering blind could add a second.
    if (sent.register) return null;
  }
  // The device exists and has no address yet: registering again would add a
  // second one. This try is "not ready yet".
  if (listedWithoutAddress) return null;
  // Not listed, but a registration already went out: wait for it to show.
  if (sent.register || live.over) return null;

  sent.register = true;
  let res: Awaited<ReturnType<typeof controlCall>>;
  try {
    res = await controlCall("register", { label: DEVICE_LABEL, device: true }, CONTROL_PROVISION_TIMEOUT_MS);
  } catch (e) {
    // The device exists already and has not shown on the list yet.
    if (e instanceof ControlError && e.code === "ALREADY_REGISTERED") return null;
    throw e;
  }
  const row = res.rows[0] ?? {};
  const direct = identityFrom(row);
  if (direct) {
    await setStored({ identity: direct });
    return direct;
  }
  // The service creates the device at once, but its answer does not carry the
  // device's id. Read the account again right away: the device is usually
  // listed already. When the answer carried an address, the listed one must
  // match it. Not listed yet: this try is "not ready", and the next ones re-read.
  try {
    return (await scanRoster(str(row["address"]))).identity;
  } catch (e) {
    if (!worthRetrying(e)) throw e;
    return null;
  }
}

/** Read the account's list for this browser's device. `address`, when given,
 *  must be the listed device's address too. */
async function scanRoster(
  address: string | null,
): Promise<{ identity: EgressIdentity | null; listedWithoutAddress: boolean }> {
  const list = await controlCall("list", { kind: "agents" });
  let listedWithoutAddress = false;
  for (const row of list.rows) {
    const item = row["item"];
    if (!isObject(item)) continue;
    if (str(item["label"]) !== DEVICE_LABEL) continue;
    if (str(item["state"]) !== "active") continue;
    const identity = identityFrom(item);
    if (identity) {
      if (address && identity.address !== address) continue;
      await setStored({ identity });
      return { identity, listedWithoutAddress };
    }
    listedWithoutAddress = true;
  }
  return { identity: null, listedWithoutAddress };
}

/** One try, with a hard deadline: past it the try is a failed one, so the
 *  reservation always settles however a call behaves. */
async function tryOnce(sent: Sent): Promise<EgressIdentity | null> {
  const live = { over: false };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const work = findOrMint(sent, live);
  work.catch(() => undefined); // a late failure after the deadline is not news
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new GraphError("timeout", "a try took too long")), RESERVE_TRY_DEADLINE_MS);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    live.over = true;
  }
}

// Progress lives in memory, exactly as long as the work it describes.
let reservation: Promise<EgressIdentity> | null = null;
let reserving: { attempt: number; of: number } | null = null;
let reserveFailed = false;

/** Forget the last reservation's failure: it belongs to the account it ran against. */
export function forgetReserveFailure(): void {
  reserveFailed = false;
}

const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function reserveWithRetries(): Promise<EgressIdentity> {
  const sent: Sent = { register: false };
  for (let attempt = 1; attempt <= RESERVE_TRIES; attempt++) {
    reserving = { attempt, of: RESERVE_TRIES };
    if (attempt > 1) await pause(RESERVE_WAITS_MS[attempt - 2] ?? RESERVE_WAITS_MS[RESERVE_WAITS_MS.length - 1]!);
    try {
      const identity = await tryOnce(sent);
      if (identity) return identity;
    } catch (e) {
      if (!worthRetrying(e)) throw e;
    }
  }
  reserveFailed = true;
  throw new ReservationExhausted();
}

/**
 * Register-once: reuse the stored identity, adopt an existing device with
 * our label, or register (once per reservation) and then find the new device
 * on the account; in that order, retried (see RESERVE_TRIES). At most one
 * reservation runs at a time: a second request joins it and gets its result,
 * so there is never more than one registration in flight. Control plane only:
 * no browser permission is involved anywhere in here.
 */
async function ensureIdentity(): Promise<EgressIdentity> {
  if (reservation) return reservation;
  // A stored identity is returned before any progress is marked, and leaves
  // the outcome of an earlier reservation as it was.
  const stored = await getStored();
  if (stored.identity) return stored.identity;
  if (reservation) return reservation;
  reserveFailed = false;
  const run = reserveWithRetries().finally(() => {
    reserving = null;
    reservation = null;
  });
  reservation = run;
  return run;
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
    // Refused here so a bad endpoint is never stored (it would end up in a PAC directive).
    if (!isValidEgressEndpoint(u.hostname, port)) return null;
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
  // Only a config that passes isUsableConfig is ever returned, so no caller
  // can store or apply one that would not work as written.
  const candidates = [row["http_proxy"], row["https_proxy"], row["connection_string"]];
  for (const c of candidates) {
    const s = str(c);
    if (!s || s.startsWith("socks5")) continue;
    const cfg = parseProxyUrl(s);
    if (cfg && cfg.token !== "" && isUsableConfig(cfg)) return cfg;
  }
  // Only a SOCKS5 string came back: it carries the same token + endpoint;
  // reuse its credentials on the HTTPS-CONNECT endpoint the platform docs.
  const socks = str(row["connection_string"]) ?? str(row["socks5_endpoint"]);
  if (socks) {
    const cfg = parseProxyUrl(socks.replace(/^socks5h?:/, "https:"));
    if (cfg && cfg.token !== "") {
      const https: EgressConfig = { ...cfg, scheme: "https", port: cfg.port === 80 ? 443 : cfg.port };
      if (isUsableConfig(https)) return https;
    }
  }
  throw new ControlError(0, "connect returned no egress endpoint");
}

// ------------------------------------------------------------ proxy wiring

let authListenerInstalled = false;

/**
 * Supply the egress credentials to Chromium's proxy-auth challenge.
 *
 * Call this synchronously, in the service worker's first turn. Chromium
 * builds its record of which events may wake a dormant worker out of the
 * listeners registered in that turn, and one added after an await is not in
 * that record. The proxy setting persists across a restart, so the browser
 * comes back routing through egress with nobody awake to answer the 407,
 * and asks the human instead. The callback re-reads storage on every
 * challenge and defers to the default handler unless egress is on and the
 * challenge is the proxy's, so arming it early costs nothing and changes
 * nothing while egress is off.
 */
function installChromiumAuthListener(): void {
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

/**
 * Arm this platform's egress hook. THE ONE THING BOTH PLATFORMS NEED EARLY.
 *
 * Chromium answers a 407 the proxy sends; Firefox is asked to choose a route
 * for every request and answers with the credential inline. Different hooks,
 * different failures, same cause when they are late: on Chromium the browser
 * comes back already routed and asks the human for a password (#29), and on
 * Firefox there is no handler to ask yet, so the request goes DIRECT and the
 * traffic quietly does not take the identity it was supposed to (#30).
 *
 * The loud one gets noticed. The quiet one does not, which is why both are
 * armed from the same call, in the worker's first turn, before any await.
 * Both listeners re-read storage per request and both defer when egress is
 * off, so arming them early is free.
 */
export function armEgressRouting(): void {
  if (IS_FIREFOX) {
    installFirefoxProxy();
    return;
  }
  installChromiumAuthListener();
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
interface FirefoxDnsApi {
  resolve(name: string, flags?: string[]): Promise<{ addresses: string[] }>;
}
interface FirefoxProxyApi {
  onRequest: {
    addListener(
      cb: (details: { url: string }) => Promise<FirefoxProxyInfo | FirefoxProxyInfo[]>,
      filter: { urls: string[] },
    ): void;
  };
}

// The request waits on the lookup, so it is bounded. A slower answer is not
// waited for: the name stays routed (fails closed). Matches Firefox's own TRR
// request timeout; in TRR-first mode Firefox only then falls back to native DNS.
const FF_LOOKUP_TIMEOUT_MS = 1500;

// The one local lookup: a `.ts.net` name, to tell a tailnet node from a
// public Funnel host. Throws when the `dns` permission is absent or the
// lookup is slow, which the caller reads as "keep it routed". No flags: the
// browser's own resolver settings decide how the name is asked.
async function resolveLocally(name: string): Promise<string[]> {
  const dns = (globalThis as { browser?: { dns?: FirefoxDnsApi } }).browser?.dns;
  if (!dns) throw new Error("dns permission missing");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const answer = await Promise.race([
      dns.resolve(name),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("dns lookup timed out")), FF_LOOKUP_TIMEOUT_MS);
      }),
    ]);
    return answer.addresses;
  } finally {
    clearTimeout(timer);
  }
}

function installFirefoxProxy(): void {
  if (!IS_FIREFOX || ffProxyInstalled) return;
  const proxyApi = (globalThis as { browser?: { proxy?: FirefoxProxyApi } }).browser?.proxy;
  if (!proxyApi?.onRequest) return;
  proxyApi.onRequest.addListener(
    async (details) => {
      const before = await getStored();
      if (!before.on || !before.config) return { type: "direct" };
      // Tailnet, intranet and private-range destinations never take the route.
      // An unparsable URL is routed, never guessed at.
      if (await goesDirectForUrl(details.url, resolveLocally)) return { type: "direct" };
      // The decision may have waited on a lookup: decide on the state NOW, so a
      // toggle turned off meanwhile is honoured and a refreshed token is used.
      const s = await getStored();
      if (!s.on || !s.config) return { type: "direct" };
      return {
        type: s.config.scheme === "http" ? "http" : "https",
        host: s.config.host,
        port: s.config.port,
        proxyAuthorizationHeader: `Basic ${btoa(`${s.config.username}:${s.config.token}`)}`,
      };
    },
    { urls: ["<all_urls>"] },
  );
  ffProxyInstalled = true;
}

/** Throws (before touching the browser) when the endpoint is not a plain host and port. */
async function applyChromiumProxy(cfg: EgressConfig): Promise<void> {
  const data = egressPacScript({ scheme: cfg.scheme, host: cfg.host, port: cfg.port });
  await chrome.proxy.settings.set({
    value: {
      // A PAC script, not fixed_servers: the `.ts.net` rule needs a lookup.
      // Tailnet, intranet and private-range destinations go direct (one
      // table, shared with Firefox); everything else takes the route.
      // `mandatory`: a script that cannot load must stop traffic, not let the
      // browser fall back to a direct connection that looks Protected.
      mode: "pac_script",
      pacScript: { data, mandatory: true },
    },
    scope: "regular",
  });
}

/**
 * Routing cannot be applied: turn it off in the stored state AND in the
 * browser, so the UI never says Protected over a direct connection. The
 * setting is cleared best-effort (our own scope only; it dies with a revoked
 * permission anyway).
 */
async function failRoutingOff(error: string, forgetConfig = false): Promise<void> {
  await setStored(forgetConfig ? { on: false, error, config: null } : { on: false, error });
  if (IS_FIREFOX) return;
  try {
    await chrome.proxy.settings.clear({ scope: "regular" });
  } catch {
    // permission may already be revoked; the setting dies with it
  }
  await hardenWebRtc(false);
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

// Whether the user allowed this extension in private windows. By default
// neither engine routes them (Chromium skips an extension-controlled proxy
// there, Firefox's proxy.onRequest never sees private requests), so the route
// line has to say so unless this is true. null when the browser cannot say.
async function privateWindowsRouted(): Promise<boolean | null> {
  try {
    const fn = ext.extension?.isAllowedIncognitoAccess;
    if (typeof fn !== "function") return null;
    return (await ext.extension.isAllowedIncognitoAccess()) === true;
  } catch {
    return null;
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
    privateWindowsRouted: await privateWindowsRouted(),
    error: s.error,
    reserving: reserving ? { ...reserving } : null,
    reserveFailed,
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
  let touchedProxy = false;
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

    // A stored config is reused only while it is still usable as written;
    // anything else is dropped and a fresh endpoint is provisioned, which
    // provisionEgress returns only when it is usable too.
    const stored = await getStored();
    const reusable = isUsableConfig(stored.config) ? stored.config : null;
    const config = reusable ?? (await provisionEgress(identity));
    await setStored({ config, error: null });

    /* Same call on both platforms; it picks the hook. Here it is the
       mid-session case the first-turn call cannot cover: the optional
       permission was granted a moment ago, so the binding did not exist at
       module scope. */
    armEgressRouting();
    if (IS_FIREFOX) {
      await setStored({ on: true, error: null });
    } else {
      touchedProxy = true;
      await applyChromiumProxy(config);
      await setStored({ on: true, error: null });
      await hardenWebRtc(true);
    }
    return egressStatus();
  } catch (e) {
    if (e instanceof ReservationExhausted) {
      // The status carries it (reserveFailed); nothing was half-applied.
      await setStored({ on: false, error: null });
      return egressStatus();
    }
    const message =
      e instanceof GraphError && e.reason === "nokey"
        ? "sign in first; the browser identity lives on your Whisper account"
        : e instanceof ControlError || e instanceof GraphError
          ? e.message
          : `could not enable egress: ${String(e instanceof Error ? e.message : e)}`;
    // Off in the state and, when the setting may be half-applied, in the browser.
    if (touchedProxy) await failRoutingOff(message);
    else await setStored({ on: false, error: message });
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

/**
 * Re-arm the proxy after a service-worker restart.
 *
 * The hooks themselves are armed from the module body (armEgressRouting), not
 * here: this function reads storage first, and a listener registered after an
 * await is already too late for both #29 and #30. What is left for this to do
 * is the Chromium proxy setting, which is state rather than a listener.
 */
export async function resumeEgress(): Promise<void> {
  const s = await getStored();
  if (!s.on) return;
  // Idempotent. Armed before the checks below, so the hook exists whichever way they go.
  armEgressRouting();
  // A config stored before endpoints were validated could still be bad, and
  // "on" with no config at all is no state this code writes. Neither may be
  // applied, and the state must not keep saying Protected over it.
  if (!isUsableConfig(s.config)) {
    await failRoutingOff(
      "the stored egress endpoint is not a plain host and port with a valid scheme and credentials, so routing was turned off. Turn it on again to fetch a fresh one.",
      true,
    );
    return;
  }
  if (IS_FIREFOX) return;
  try {
    await applyChromiumProxy(s.config);
  } catch {
    // proxy permission revoked while we slept: reflect the truth
    await setStored({ on: false, error: "the proxy permission was revoked" });
  }
}
