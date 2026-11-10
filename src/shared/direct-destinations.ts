// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The one table of destinations that are NEVER sent through the egress
// proxy: tailnet names, mDNS and intranet names, and private-range IP
// literals. They are unreachable from the egress node (or meaningless
// there), and internal tools should see the person, not the egress node.
//
// The table also sends direct the this-host addresses 0.0.0.0, :: and
// ::ffff:0:0 (URL-canonical form of [::ffff:0.0.0.0]). Chromium 159 and later
// bypass those three themselves (the "implicit bypass rules", net/docs/proxy.md);
// earlier Chrome hands them to the PAC script, which sends them direct. Chrome
// also bypasses IPv4-mapped loopback [::ffff:127.0.0.0]/104 and link-local
// [::ffff:169.254.0.0]/112. This table routes those, so Firefox sends them to
// the egress: a known difference between the engines.
//
// Decided on the NAME or LITERAL alone, with ONE exception. While routed,
// names are resolved at the egress, and resolving them locally would show
// every visited hostname to the local resolver, so nothing is looked up. A
// public name that happens to resolve to a private address is therefore still
// proxied.
//
// The exception is `*.ts.net`. That suffix is a PUBLIC namespace (Tailscale
// Funnel publishes any node there), so the name alone proves nothing: such a
// name goes direct only when it resolves to a Tailscale address. Only `.ts.net`
// names are ever looked up locally. MagicDNS answers your own on-device when
// the lookup reaches the system resolver; if the browser uses DNS over HTTPS
// with no fallback, your own names are not found and stay routed. Someone
// else's Funnel host stays routed, and a failed lookup stays routed.
//
// Both engines share this table: Chromium gets it inside a PAC script
// (egressPacScript), Firefox asks goesDirectForUrl() per request.

/** Whole-label name suffixes (no leading dot). */
export const DIRECT_SUFFIXES = ["local", "home.arpa", "internal", "localhost"] as const;

/** The tailnet name suffix: public, so only a Tailscale answer sends it direct. */
export const TAILNET_SUFFIX = "ts.net";

/** IPv4 literal ranges as [address, prefix length]. */
export const DIRECT_IPV4_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ["10.0.0.0", 8],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
];

/** IPv6 literal ranges as [first 16 bits of the address, prefix length], plus ::1. */
const DIRECT_IPV6_PREFIXES: ReadonlyArray<readonly [string, number]> = [
  ["fc00::", 7],
  ["fe80::", 10],
];

function parseIpv4(h: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i] ?? NaN);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n;
}

/** First 16-bit group of an IPv6 literal, or null when it is not one. */
function ipv6Head(h: string): { head: number; loopback: boolean } | null {
  if (!/^[0-9a-f:.]+$/.test(h) || !h.includes(":")) return null;
  if (h === "::1") return { head: 0, loopback: true };
  if (h.startsWith("::")) return { head: 0, loopback: false };
  const first = h.split(":")[0] ?? "";
  if (!/^[0-9a-f]{1,4}$/.test(first)) return null;
  return { head: parseInt(first, 16), loopback: false };
}

/** A leading dot, "..", or a trailing dot left after the root dot is stripped. */
function hasEmptyLabel(h: string): boolean {
  return h.startsWith(".") || h.endsWith(".") || h.includes("..");
}

/** True for a name under `.ts.net` (the bare suffix is not a node). */
export function isTailnetName(hostname: string): boolean {
  let h = hostname.trim().toLowerCase();
  if (h.endsWith(".") && h.length > 1) h = h.slice(0, -1);
  if (hasEmptyLabel(h)) return false;
  return h.endsWith(`.${TAILNET_SUFFIX}`);
}

/** Expand an IPv6 literal to its eight 16-bit groups, or null. */
function parseIpv6Groups(a: string): number[] | null {
  if (!/^[0-9a-f:]+$/.test(a) || (a.match(/::/g) ?? []).length > 1) return null;
  const [headStr, tailStr] = a.split("::");
  const head = headStr ? headStr.split(":") : [];
  const tail = tailStr ? tailStr.split(":") : [];
  const fill = 8 - head.length - tail.length;
  // "::" stands for at least one group; more groups than that cannot be an address.
  if (a.includes("::") && fill < 1) return null;
  const all = a.includes("::") ? [...head, ...Array(fill).fill("0"), ...tail] : head;
  if (all.length !== 8 || !all.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return all.map((g) => parseInt(g, 16));
}

/** True for an address in Tailscale's own ranges: 100.64.0.0/10 or fd7a:115c:a1e0::/48. */
export function isTailnetAddress(address: string): boolean {
  let a = address.trim().toLowerCase();
  if (a.startsWith("[") && a.endsWith("]")) a = a.slice(1, -1);
  const v4 = parseIpv4(a);
  if (v4 !== null) return Math.floor(v4 / 2 ** 22) === Math.floor((100 * 2 ** 24 + 64 * 2 ** 16) / 2 ** 22);
  const g = parseIpv6Groups(a);
  return g !== null && g[0] === 0xfd7a && g[1] === 0x115c && g[2] === 0xa1e0;
}

/**
 * goesDirect() plus the one lookup: a `.ts.net` name goes direct only when
 * EVERY address it resolves to is a Tailscale address. `resolve` failing,
 * throwing or returning nothing keeps it routed. No other name is looked up.
 */
export async function goesDirectResolving(
  hostname: string,
  resolve: (name: string) => Promise<string[]>,
): Promise<boolean> {
  if (goesDirect(hostname)) return true;
  if (!isTailnetName(hostname)) return false;
  try {
    // Blank answers are noise (the PAC drops them too); no answer at all stays routed.
    const addrs = (await resolve(hostname.trim().toLowerCase().replace(/\.$/, ""))).filter((x) => x.trim() !== "");
    return addrs.length > 0 && addrs.every(isTailnetAddress);
  } catch {
    return false;
  }
}

/**
 * The per-request decision Firefox makes: parse the URL, then goesDirectResolving
 * on its host. An unparsable URL or an empty host is routed, never guessed at.
 */
export async function goesDirectForUrl(
  url: string,
  resolve: (name: string) => Promise<string[]>,
): Promise<boolean> {
  let host = "";
  try {
    host = new URL(url).hostname;
  } catch {
    return false;
  }
  if (!host) return false;
  return goesDirectResolving(host, resolve);
}

/** True when this URL host must connect directly, never via the egress. */
export function goesDirect(hostname: string): boolean {
  let h = hostname.trim().toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  const rooted = h.endsWith(".") && h.length > 1;
  if (rooted) h = h.slice(0, -1);
  if (!h) return false;

  // This-host addresses (Chromium 159+ bypass them itself; earlier Chrome lets
  // the PAC send them direct). Not 0.0.0.0/8, and no other IPv4-mapped form.
  if (h === "0.0.0.0" || h === "::" || h === "::ffff:0:0") return true;

  const v4 = parseIpv4(h);
  if (v4 !== null) {
    return DIRECT_IPV4_CIDRS.some(([addr, bits]) => {
      const base = parseIpv4(addr) as number;
      const size = 2 ** (32 - bits);
      return Math.floor(v4 / size) === Math.floor(base / size);
    });
  }
  const v6 = ipv6Head(h);
  if (v6) {
    if (v6.loopback) return true;
    return DIRECT_IPV6_PREFIXES.some(([addr, bits]) => {
      const base = parseInt(addr.split(":")[0] ?? "", 16);
      const shift = 2 ** (16 - bits);
      return Math.floor(v6.head / shift) === Math.floor(base / shift);
    });
  }
  // A dotted-quad lookalike that failed to parse is not a name.
  if (/^[\d.]+$/.test(h)) return false;
  // An empty label is not a name (the PAC script decides the same way).
  if (hasEmptyLabel(h)) return false;

  // Plain intranet name, or localhost (rooted or not, as Chrome treats it). A
  // rooted single label ("ai.") is a public TLD.
  if (!h.includes(".")) return !rooted || h === "localhost";
  // Subdomains only. `.ts.net` is deliberately absent: see goesDirectResolving.
  return DIRECT_SUFFIXES.some((s) => h.endsWith(`.${s}`));
}

const LDH_HOSTNAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/** The host as it may follow "HTTPS " in a PAC directive (an IPv6 literal bracketed once), or null. */
function egressHostLiteral(host: string): string | null {
  const inner = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (inner.includes(":")) return parseIpv6Groups(inner.toLowerCase()) ? `[${inner}]` : null;
  if (host !== inner) return null;
  // Chrome parses the host in a PAC result with the URL rules. A form the URL
  // parser refuses ("egress.1") makes Chrome go DIRECT despite `mandatory`; one
  // it rewrites ("010.1.1.1", "0x7f.0.0.1") sends the route to a different
  // address than written. Either is refused here.
  try {
    if (new URL(`http://${host}/`).hostname !== host.toLowerCase()) return null;
  } catch {
    return null;
  }
  if (/^[\d.]+$/.test(host)) return parseIpv4(host) !== null ? host : null;
  return LDH_HOSTNAME.test(host) ? host : null;
}

/**
 * True when this is an endpoint that is safe to write into a PAC directive: an
 * LDH hostname, an IPv4 literal or an IPv6 literal (bracketed or not), and an
 * integer port from 1 to 65535. Anything else could carry a second directive.
 */
export function isValidEgressEndpoint(host: unknown, port: unknown): boolean {
  // Total: a wrong-shape stored config is invalid, never a throw.
  if (typeof host !== "string" || typeof port !== "number") return false;
  return egressHostLiteral(host) !== null && Number.isInteger(port) && port >= 1 && port <= 65535;
}

/** "HTTPS host:port" / "PROXY host:port". Throws on an endpoint that fails isValidEgressEndpoint. */
function egressDirective(proxy: { scheme: "http" | "https"; host: string; port: number }): string {
  const host = egressHostLiteral(proxy.host);
  if (host === null || !isValidEgressEndpoint(proxy.host, proxy.port)) {
    throw new Error("the egress endpoint is not a plain host and port");
  }
  return `${proxy.scheme === "http" ? "PROXY" : "HTTPS"} ${host}:${proxy.port}`;
}

/**
 * The same table as a Chromium PAC script. A PAC script is the only Chromium
 * proxy mode that can look a name up, which the `.ts.net` rule needs. Plain
 * ES5 on purpose: it runs in the browser's PAC engine, not here. Everything
 * but `.ts.net` is decided on the name or literal with no lookup; a `.ts.net`
 * name goes direct only when every answer is a Tailscale address, and no
 * answer (or no dnsResolveEx, which is the only call that sees IPv6 and every
 * IPv4 answer) stays routed. Any error inside the script also stays routed.
 * Throws when `proxy` is not a plain host and port (see isValidEgressEndpoint).
 */
export function egressPacScript(proxy: { scheme: "http" | "https"; host: string; port: number }): string {
  const route = egressDirective(proxy);
  const v4 = DIRECT_IPV4_CIDRS.map(([a, b]) => [parseIpv4(a), b]);
  const v6 = DIRECT_IPV6_PREFIXES.map(([a, b]) => [parseInt(a.split(":")[0] ?? "", 16), b]);
  return `var ROUTE = ${JSON.stringify(route)};
function FindProxyForURL(url, host) {
  try {
    return decide(url, host);
  } catch (e) {
    return ROUTE;
  }
}
function decide(url, host) {
  var SUFFIXES = ${JSON.stringify(DIRECT_SUFFIXES)};
  var V4 = ${JSON.stringify(v4)};
  var V6 = ${JSON.stringify(v6)};
  var TS = ${JSON.stringify(TAILNET_SUFFIX)};
  function v4num(h) {
    var m = /^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/.exec(h);
    if (!m) return null;
    var n = 0;
    for (var i = 1; i <= 4; i++) { var o = Number(m[i]); if (o > 255) return null; n = n * 256 + o; }
    return n;
  }
  function groups(a) {
    if (!/^[0-9a-f:]+$/.test(a)) return null;
    var parts = a.split("::");
    if (parts.length > 2) return null;
    var head = parts[0] ? parts[0].split(":") : [];
    var tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
    var all = head;
    if (parts.length === 2 && head.length + tail.length > 7) return null;
    if (parts.length === 2) {
      all = head.slice();
      for (var i = head.length + tail.length; i < 8; i++) all.push("0");
      all = all.concat(tail);
    }
    if (all.length !== 8) return null;
    var out = [];
    for (var j = 0; j < 8; j++) { if (!/^[0-9a-f]{1,4}$/.test(all[j])) return null; out.push(parseInt(all[j], 16)); }
    return out;
  }
  function tailnetAddr(a) {
    a = a.toLowerCase();
    if (a.charAt(0) === "[" && a.charAt(a.length - 1) === "]") a = a.substring(1, a.length - 1);
    var n = v4num(a);
    if (n !== null) return Math.floor(n / 4194304) === Math.floor(1681915904 / 4194304);
    var g = groups(a);
    return g !== null && g[0] === 0xfd7a && g[1] === 0x115c && g[2] === 0xa1e0;
  }
  function endsWith(h, s) { return h.length > s.length && h.substring(h.length - s.length) === s; }
  var h = String(host).toLowerCase();
  if (h.charAt(0) === "[" && h.charAt(h.length - 1) === "]") h = h.substring(1, h.length - 1);
  var rooted = h.length > 1 && h.charAt(h.length - 1) === ".";
  if (rooted) h = h.substring(0, h.length - 1);
  if (!h) return ROUTE;
  // This-host addresses: Chromium 159+ bypass them itself, earlier Chrome asks here.
  if (h === "0.0.0.0" || h === "::" || h === "::ffff:0:0") return "DIRECT";
  var n4 = v4num(h), i, size;
  if (n4 !== null) {
    for (i = 0; i < V4.length; i++) {
      size = Math.pow(2, 32 - V4[i][1]);
      if (Math.floor(n4 / size) === Math.floor(V4[i][0] / size)) return "DIRECT";
    }
    return ROUTE;
  }
  if (h.indexOf(":") !== -1 && /^[0-9a-f:.]+$/.test(h)) {
    if (h === "::1") return "DIRECT";
    var first = h.indexOf("::") === 0 ? "0" : h.split(":")[0];
    if (!/^[0-9a-f]{1,4}$/.test(first)) return ROUTE;
    var head = parseInt(first, 16);
    for (i = 0; i < V6.length; i++) {
      size = Math.pow(2, 16 - V6[i][1]);
      if (Math.floor(head / size) === Math.floor(V6[i][0] / size)) return "DIRECT";
    }
    return ROUTE;
  }
  if (/^[\\d.]+$/.test(h)) return ROUTE;
  if (h.charAt(0) === "." || h.charAt(h.length - 1) === "." || h.indexOf("..") !== -1) return ROUTE;
  if (h.indexOf(".") === -1) return rooted && h !== "localhost" ? ROUTE : "DIRECT";
  for (i = 0; i < SUFFIXES.length; i++) if (endsWith(h, "." + SUFFIXES[i])) return "DIRECT";
  if (endsWith(h, "." + TS)) {
    if (typeof dnsResolveEx !== "function") return ROUTE;
    var raw = dnsResolveEx(h), parts = raw ? String(raw).split(";") : [], answers = [], k, a;
    for (k = 0; k < parts.length; k++) { a = String(parts[k]).trim(); if (a) answers.push(a); }
    if (answers.length === 0) return ROUTE;
    for (i = 0; i < answers.length; i++) if (!tailnetAddr(answers[i])) return ROUTE;
    return "DIRECT";
  }
  return ROUTE;
}
`;
}
