// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The never-proxied table (pure functions, no browser). Both engines share
// it: Chromium inside a PAC script (egressPacScript, evaluated below with
// Chrome's PAC semantics), Firefox per request through goesDirectForUrl().
// No import here but the module under test and node:vm, so the spec also runs
// under the plain-node mutation harness.

import vm from "node:vm";
import { test, expect } from "@playwright/test";
import {
  DIRECT_IPV4_CIDRS,
  DIRECT_SUFFIXES,
  egressPacScript,
  goesDirect,
  goesDirectForUrl,
  goesDirectResolving,
  isTailnetAddress,
  isTailnetName,
  isValidEgressEndpoint,
} from "../src/shared/direct-destinations";

test("mDNS, intranet and private-use names go direct", () => {
  for (const h of [
    "printer.local",
    "nas.home.arpa",
    "wiki.internal",
    "app.localhost",
    "localhost",
    "intranet",
    "localhost.",
    "LOCALHOST.",
    "x.localhost.",
  ]) {
    expect(goesDirect(h), h).toBe(true);
  }
});

// The this-host addresses 0.0.0.0, :: and ::ffff:0:0 (URL-canonical form of
// [::ffff:0.0.0.0]) go direct. Chromium 159 and later bypass them itself (the
// "implicit bypass rules",
// https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md);
// earlier Chrome hands them to the PAC script, which sends them direct. Known
// difference: Chrome also bypasses IPv4-mapped loopback [::ffff:127.0.0.0]/104
// and link-local [::ffff:169.254.0.0]/112, which this table routes, so Firefox
// sends those to the egress. The table is no wider than that: not 0.0.0.0/8,
// not any other IPv4-mapped form.
const IMPLICIT_BYPASS_DIRECT = [
  "0.0.0.0", "::", "[::]", "::ffff:0:0", "[::ffff:0:0]", "localhost", "localhost.", "LOCALHOST", "LOCALHOST.",
];
const IMPLICIT_BYPASS_NOT_WIDER = ["0.0.0.1", "0.255.255.255", "::2", "[::2]", "::ffff:0:1", "[::ffff:1:2]", "::ffff:1.2.3.4",
  // IPv4-mapped loopback and link-local: Chrome bypasses them, this table routes them
  "::ffff:7f00:1", "[::ffff:a9fe:1]"];
// A non-canonical spelling of the direct ::ffff:0:0. No URL produces it (the URL
// parser writes ::ffff:0:0) and the host parser does not accept it, so it is routed.
const NON_CANONICAL_THIS_HOST = "::ffff:0.0.0.0";

test("the this-host addresses and localhost go direct, bracketed or not, and nothing wider does", () => {
  for (const h of IMPLICIT_BYPASS_DIRECT) expect(goesDirect(h), h).toBe(true);
  for (const h of IMPLICIT_BYPASS_NOT_WIDER) expect(goesDirect(h), h).toBe(false);
});

test("a non-canonical spelling of ::ffff:0:0 that no URL produces is not accepted", () => {
  expect(goesDirect(NON_CANONICAL_THIS_HOST), NON_CANONICAL_THIS_HOST).toBe(false);
});

test("private, CGNAT, loopback, link-local and ULA literals go direct, bracketed or not", () => {
  for (const h of [
    "192.168.1.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "100.64.0.1",
    "100.127.255.255",
    "127.0.0.2",
    "169.254.1.1",
    "fd00::1",
    "[fd00::1]",
    "fc00::1",
    "[fe80::1]",
    "febf::1",
    "::1",
    "[::1]",
  ]) {
    expect(goesDirect(h), h).toBe(true);
  }
});

test("public hosts and literals stay proxied", () => {
  for (const h of [
    "www.whisper.security",
    "example.com",
    "ts.net",
    "box.e2e-tailnet.ts.net", // a public namespace: direct only after a Tailscale answer
    "home.arpa",
    "ai.",
    "evilts.net",
    "ts.net.example.com",
    "notlocal.com",
    "172.32.0.1",
    "172.15.255.255",
    "100.128.0.1",
    "100.63.255.255",
    "8.8.8.8",
    "999.1.1.1",
    "[2001:db8::1]",
    "2001:db8::1",
    "fec0::1",
    "",
  ]) {
    expect(goesDirect(h), h).toBe(false);
  }
});

test("tailnet addresses are exactly 100.64.0.0/10 and fd7a:115c:a1e0::/48", () => {
  for (const a of ["100.64.0.1", "100.127.255.255", "fd7a:115c:a1e0::1", "FD7A:115C:A1E0:ab12::5", "[fd7a:115c:a1e0::1]"]) {
    expect(isTailnetAddress(a), a).toBe(true);
  }
  for (const a of ["100.63.255.255", "100.128.0.0", "100.0.0.1", "100.128.0.1", "127.0.0.1", "8.8.8.8", "fd7a:115c:a1e1::1", "fd7a:115d:a1e0::1", "fd7b:115c:a1e0::1", "2001:115c:a1e0::1", "fd00::1", "::1", "2001:db8::1", "1:2:3:4:5:6:7:8::9", "nope", ""]) {
    expect(isTailnetAddress(a), a).toBe(false);
  }
  expect(isTailnetName("a.b.ts.net")).toBe(true);
  expect(isTailnetName("ts.net")).toBe(false);
  expect(isTailnetName("evilts.net")).toBe(false);
  // An empty label is not a name (the PAC decides the same way).
  for (const n of [".ts.net", "a..ts.net", "x.ts.net..", "..ts.net"]) expect(isTailnetName(n), n).toBe(false);
});

test("a .ts.net name goes direct only when every answer is a Tailscale address", async () => {
  const via = (answer: string[] | Error) => async () => {
    if (answer instanceof Error) throw answer;
    return answer;
  };
  expect(await goesDirectResolving("box.t.ts.net", via(["100.64.0.7"]))).toBe(true);
  expect(await goesDirectResolving("box.t.ts.net.", via(["fd7a:115c:a1e0::7", "100.100.1.1"]))).toBe(true);
  expect(await goesDirectResolving("funnel.t.ts.net", via(["203.0.113.9"]))).toBe(false);
  expect(await goesDirectResolving("mixed.t.ts.net", via(["100.64.0.7", "203.0.113.9"]))).toBe(false);
  expect(await goesDirectResolving("none.t.ts.net", via([]))).toBe(false);
  expect(await goesDirectResolving("fail.t.ts.net", via(new Error("no dns permission")))).toBe(false);
});

test("no name other than .ts.net is ever looked up", async () => {
  const looked: string[] = [];
  const spy = async (n: string) => {
    looked.push(n);
    return ["100.64.0.1"];
  };
  for (const h of ["example.com", "evilts.net", "printer.local", "intranet", "10.0.0.1", "[fd00::1]", "ts.net", "ai."]) {
    await goesDirectResolving(h, spy);
  }
  expect(looked).toEqual([]);
});

// ---------------------------------------------- every IPv4 range, edge-pinned

const RANGE_EDGES: Record<string, { first: string; last: string; before: string; after: string }> = {
  "10.0.0.0/8": { first: "10.0.0.0", last: "10.255.255.255", before: "9.255.255.255", after: "11.0.0.0" },
  "172.16.0.0/12": { first: "172.16.0.0", last: "172.31.255.255", before: "172.15.255.255", after: "172.32.0.0" },
  "192.168.0.0/16": { first: "192.168.0.0", last: "192.168.255.255", before: "192.167.255.255", after: "192.169.0.0" },
  "100.64.0.0/10": { first: "100.64.0.0", last: "100.127.255.255", before: "100.63.255.255", after: "100.128.0.0" },
  "127.0.0.0/8": { first: "127.0.0.0", last: "127.255.255.255", before: "126.255.255.255", after: "128.0.0.0" },
  "169.254.0.0/16": { first: "169.254.0.0", last: "169.254.255.255", before: "169.253.255.255", after: "169.255.0.0" },
};

test("every IPv4 range goes direct at its first and last address and is routed just outside it", () => {
  // The table and this list move together: a range added to one fails here until it is pinned.
  expect(DIRECT_IPV4_CIDRS.map(([a, b]) => `${a}/${b}`)).toEqual(Object.keys(RANGE_EDGES));
  for (const [range, e] of Object.entries(RANGE_EDGES)) {
    expect(goesDirect(e.first), `${range} first ${e.first}`).toBe(true);
    expect(goesDirect(e.last), `${range} last ${e.last}`).toBe(true);
    expect(goesDirect(e.before), `${range} just below ${e.before}`).toBe(false);
    expect(goesDirect(e.after), `${range} just above ${e.after}`).toBe(false);
  }
});

test("the IPv6 ULA and link-local ranges are edge-pinned too", () => {
  for (const h of ["fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]) {
    expect(goesDirect(h), h).toBe(true);
  }
  for (const h of ["fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe00::", "fe7f::", "fec0::"]) {
    expect(goesDirect(h), h).toBe(false);
  }
});

test("a host with an empty label is neither direct nor a tailnet name", () => {
  for (const h of [".local", "a..local", "..", ".", "...", ".internal", "x.local..", ".localhost", "a..ts.net", ".ts.net"]) {
    expect(goesDirect(h), h).toBe(false);
  }
  // One trailing root dot is still a name.
  expect(goesDirect("printer.local.")).toBe(true);
});

// ------------------------------------------------------- the Firefox decision

test("goesDirectForUrl decides on the URL's host, ports and schemes included, and looks up only .ts.net", async () => {
  const looked: string[] = [];
  const tailnet = async (n: string) => {
    looked.push(n);
    return ["100.64.0.7"];
  };
  const table: Array<[string, boolean]> = [
    ["http://192.168.1.1:8080/", true],
    ["http://printer.local:631/", true],
    ["http://[fd00::1]:3000/", true],
    ["https://[::1]/", true],
    ["ws://intranet:9000/socket", true],
    ["wss://nas.home.arpa/socket", true],
    ["http://10.0.0.1:1/", true],
    ["https://example.com/", false],
    ["http://172.32.0.1:80/", false],
    ["wss://example.com:8443/socket", false],
    ["ws://[2001:db8::1]:80/", false],
    ["not a url", false],
    ["", false],
    ["http:///", false],
    ["file:///etc/hosts", false],
  ];
  for (const [url, want] of table) expect(await goesDirectForUrl(url, tailnet), url).toBe(want);
  expect(looked, "nothing but .ts.net is looked up").toEqual([]);

  for (const url of ["http://box.t.ts.net:8443/", "wss://box.t.ts.net/socket", "ws://BOX.T.TS.NET.:80/x"]) {
    expect(await goesDirectForUrl(url, tailnet), url).toBe(true);
  }
  expect(looked).toEqual(["box.t.ts.net", "box.t.ts.net", "box.t.ts.net"]);

  const funnel = async () => ["203.0.113.9"];
  expect(await goesDirectForUrl("https://f.o.ts.net:8443/", funnel)).toBe(false);
  const failing = async () => {
    throw new Error("nxdomain");
  };
  expect(await goesDirectForUrl("https://gone.t.ts.net/", failing)).toBe(false);
});

// ------------------------------------------------ the egress endpoint in a PAC

function throws(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

test("the egress endpoint is validated before it reaches a PAC directive", () => {
  const pac = (host: string, port = 443) => egressPacScript({ scheme: "https", host, port });
  for (const host of ["a;b", "a,b", "a b", 'a"b', "a'b", "x.example\nDIRECT", "", "-bad.example", "a..b", "[::1", "[abc]", "999.1.1.1", "1:2:3:4:5:6:7:8::9", " x.example", "x.example;DIRECT", "a/b", "egress.1", "08.1.1.1", "a.0x1", "010.1.1.1", "0x7f.0.0.1"]) {
    expect(throws(() => pac(host)), `host ${JSON.stringify(host)}`).toBe(true);
    expect(isValidEgressEndpoint(host, 443), `host ${JSON.stringify(host)}`).toBe(false);
  }
  for (const port of [0, 65536, 1.5, -1, NaN, Infinity]) {
    expect(throws(() => pac("egress.example", port)), `port ${port}`).toBe(true);
    expect(isValidEgressEndpoint("egress.example", port), `port ${port}`).toBe(false);
  }
  // Hosts the URL parser keeps as typed are accepted, whatever their case or IPv6 spelling.
  for (const host of ["egress.example", "EGRESS.example", "203.0.113.7", "2001:db8::1", "[2001:db8::1]", "2001:DB8::1", "2001:DB8:0:0:0:0:0:1", "localhost", "a-b.example"]) {
    expect(throws(() => pac(host)), host).toBe(false);
    expect(isValidEgressEndpoint(host, 443), host).toBe(true);
  }
  // Total: a wrong-shape stored value is invalid, never a throw.
  for (const [h, p] of [[12345, 443], ["egress.example", "443"], [null, 443], ["egress.example", undefined], [undefined, undefined], [{}, []]] as Array<[unknown, unknown]>) {
    expect(isValidEgressEndpoint(h, p), `${JSON.stringify(h)} ${JSON.stringify(p)}`).toBe(false);
  }
  expect(isValidEgressEndpoint("egress.example", 1)).toBe(true);
  expect(isValidEgressEndpoint("egress.example", 65535)).toBe(true);
  expect(pac("2001:db8::1")).toContain('"HTTPS [2001:db8::1]:443"');
  expect(pac("[2001:db8::1]")).toContain('"HTTPS [2001:db8::1]:443"');
  expect(pac("egress.example", 8443)).toContain('"HTTPS egress.example:8443"');
  expect(egressPacScript({ scheme: "http", host: "203.0.113.7", port: 80 })).toContain('"PROXY 203.0.113.7:80"');
});

test("the shared table's suffixes and CIDRs appear in the PAC script", () => {
  const body = egressPacScript({ scheme: "http", host: "::1", port: 8080 });
  expect(body).toContain('"PROXY [::1]:8080"');
  for (const s of DIRECT_SUFFIXES) expect(body).toContain(`"${s}"`);
  for (const [, bits] of DIRECT_IPV4_CIDRS) expect(body).toContain(`,${bits}]`);
});

// --------------------------------------------------------------- the PAC script
//
// The PAC script is a second implementation of the table (the browser's PAC
// engine cannot import this module), so it is pinned to goesDirect() and to
// the ts.net rule on the same vectors, evaluated here as plain JS with
// CHROME's semantics: dnsResolveEx returns every answer joined with ";" (""
// on failure); dnsResolve returns ONE IPv4 address or null, never an IPv6 one.
// The script must use only dnsResolveEx, so dnsResolve is a spy that must
// never be called.

const ROUTE = "HTTPS egress.example:443";

// Every Chrome PAC built-in that can resolve a name or reveal an address.
// Each is bound as a recording spy; ANY call counts as a lookup. `ex` is
// dnsResolveEx (the one call the ts.net rule makes), `plain` is dnsResolve, and
// `other` is every remaining built-in, with its arguments.
interface Looked {
  ex: string[];
  plain: string[];
  other: string[];
}

const noLookups = (): Looked => ({ ex: [], plain: [], other: [] });

interface ChromePac {
  /** FindProxyForURL, with its fail-closed try/catch. */
  find: (url: string, host: string) => string;
  /** decide(): the same decision WITHOUT the catch, so an error inside it (a
   *  call to a built-in the spy does not hide, a typo) fails the test. */
  decide: (url: string, host: string) => string;
}

function chromePac(
  answers: Record<string, string | (() => string)>,
  looked: Looked,
  opts: { noEx?: boolean } = {},
): ChromePac {
  const body = egressPacScript({ scheme: "https", host: "egress.example", port: 443 });
  const dnsResolveEx = (n: string) => {
    looked.ex.push(n);
    const a = answers[n];
    return typeof a === "function" ? a() : (a ?? "");
  };
  const dnsResolve = (n: string) => {
    looked.plain.push(n);
    return "100.64.0.2";
  };
  const spy = (name: string, result: unknown) => (...args: unknown[]) => {
    looked.other.push(`${name}(${args.map(String).join(", ")})`);
    return result;
  };
  // The spies answer so that a call would NOT change a decision (no "in this range", "resolvable"):
  // a stray lookup is then caught by the recorded call, not by luck of the return value.
  // All 20 PAC globals Chrome defines (proxy_resolver_v8.cc natives and pac_js_library.h) are
  // present, so a call to any of them is recorded and never hidden by a ReferenceError.
  const globals: Record<string, unknown> = {
    dnsResolveEx: opts.noEx ? undefined : dnsResolveEx,
    dnsResolve,
    isInNet: spy("isInNet", false),
    isInNetEx: spy("isInNetEx", false),
    isResolvable: spy("isResolvable", true),
    isResolvableEx: spy("isResolvableEx", true),
    myIpAddress: spy("myIpAddress", "10.0.0.2"),
    myIpAddressEx: spy("myIpAddressEx", "10.0.0.2"),
    sortIpAddressList: spy("sortIpAddressList", ""),
    alert: spy("alert", undefined),
    dnsDomainIs: spy("dnsDomainIs", false),
    dnsDomainLevels: spy("dnsDomainLevels", 0),
    isPlainHostName: spy("isPlainHostName", false),
    isValidIpAddress: spy("isValidIpAddress", false),
    convert_addr: spy("convert_addr", 0),
    localHostOrDomainIs: spy("localHostOrDomainIs", false),
    shExpMatch: spy("shExpMatch", false),
    weekdayRange: spy("weekdayRange", false),
    dateRange: spy("dateRange", false),
    timeRange: spy("timeRange", false),
  };
  // A vm context, so the globals are real globals: reaching one through the global object
  // (this.dnsResolve) is seen too, which an argument-bound function would miss.
  const ctx = vm.createContext(globals);
  return vm.runInContext(`${body}\n;({ find: FindProxyForURL, decide: decide });`, ctx) as ChromePac;
}

const PARITY_VECTORS = [
  "printer.local", "nas.home.arpa", "wiki.internal", "app.localhost", "localhost", "intranet", "LOCALHOST",
  "192.168.1.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "100.64.0.1", "100.127.255.255", "127.0.0.2",
  "169.254.1.1", "fd00::1", "[fd00::1]", "fc00::1", "[fe80::1]", "febf::1", "::1", "[::1]",
  "www.whisper.security", "example.com", "ts.net", "home.arpa", "ai.", "evilts.net", "ts.net.example.com",
  "notlocal.com", "172.32.0.1", "172.15.255.255", "100.128.0.1", "100.63.255.255", "8.8.8.8", "999.1.1.1",
  "[2001:db8::1]", "2001:db8::1", "fec0::1", "printer.local.", "intranet.",
  // empty labels: the PAC and goesDirect must agree that they are not names. The
  // bare suffixes are routed by the length guard alone; the ones with a label
  // after the leading dot pin the PAC's leading-dot clause itself.
  ".local", "a..local", "..", ".", "...", ".internal", "x.local..", ".localhost", "a.localhost..", "",
  ".x.local", ".a.home.arpa", ".x.internal", ".x.localhost", ".node.t.ts.net",
  // This-host addresses and localhost (see above), and nothing wider
  ...IMPLICIT_BYPASS_DIRECT, ...IMPLICIT_BYPASS_NOT_WIDER, NON_CANONICAL_THIS_HOST, "x.localhost.", "ai.localhost.",
  // every range edge
  ...Object.values(RANGE_EDGES).flatMap((e) => [e.first, e.last, e.before, e.after]),
];

test("the Chromium PAC script decides exactly as goesDirect does, and calls no built-in for a non-ts.net host", () => {
  const looked = noLookups();
  const pac = chromePac({}, looked);
  for (const h of PARITY_VECTORS) {
    // decide(), not FindProxyForURL: its catch would hide a throwing call to a built-in.
    expect(pac.decide(`http://${h}/`, h), JSON.stringify(h)).toBe(goesDirect(h) ? "DIRECT" : ROUTE);
    expect(pac.find(`http://${h}/`, h), `find ${JSON.stringify(h)}`).toBe(goesDirect(h) ? "DIRECT" : ROUTE);
  }
  expect(looked.ex, "no lookup for anything but .ts.net").toEqual([]);
  expect(looked.plain, "dnsResolve is never called").toEqual([]);
  expect(looked.other, "no other resolving or address-revealing built-in is called").toEqual([]);
});

test("the PAC and goesDirectResolving agree on ts.net names (lookups included) and on empty labels", async () => {
  const answers: Record<string, string> = {
    "node.t.ts.net": "100.64.0.9",
    "funnel.t.ts.net": "203.0.113.9",
    "both.t.ts.net": "fd7a:115c:a1e0::9;100.64.0.9",
    "mixed.t.ts.net": "100.64.0.9;203.0.113.9",
    "trail.t.ts.net": "100.64.0.9;",
    "lead.t.ts.net": ";100.64.0.9",
    "brack.t.ts.net": "[fd7a:115c:a1e0::9]",
    "blank.t.ts.net": ";",
    "upper.t.ts.net": "FD7A:115C:A1E0::9",
    // would go DIRECT if a leading-dot name were looked up
    ".node.t.ts.net": "100.64.0.9",
  };
  const hosts = [
    ...Object.keys(answers), "gone.t.ts.net", "NODE.T.TS.NET", "node.t.ts.net.",
    ".ts.net", "a..ts.net", "x.ts.net..", "evilts.net", "ts.net",
  ];
  for (const h of hosts) {
    const looked = noLookups();
    const pac = chromePac(answers, looked);
    const ffLooked: string[] = [];
    const js = await goesDirectResolving(h, async (n) => {
      ffLooked.push(n);
      const a = answers[n];
      if (a === undefined) throw new Error("NXDOMAIN");
      return a.split(";");
    });
    expect(pac.decide(`http://${h}/`, h), JSON.stringify(h)).toBe(js ? "DIRECT" : ROUTE);
    expect(looked.ex, `dnsResolveEx calls for ${JSON.stringify(h)}`).toEqual(ffLooked);
    expect(looked.plain, "dnsResolve is never called").toEqual([]);
    expect(looked.other, "nothing but dnsResolveEx is called").toEqual([]);
  }
});

// Every address the table's tailnet predicate sees, run through the PAC as the
// ONLY dnsResolveEx answer for one ts.net name. DIRECT exactly when
// isTailnetAddress says so.
const ANSWER_VECTORS = [
  "100.64.0.0", "100.127.255.255", "100.63.255.255", "100.128.0.0", "100.0.0.1", "100.100.100.100", "100.64.0.1",
  "fd7a:115c:a1e0::", "fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff", "fd7a:115c:a1e0::1", "FD7A:115C:A1E0:ab12::5",
  "fd7a:115c:a1e1::1", "fd7a:115d:a1e0::1", "fd7b:115c:a1e0::1", "2001:115c:a1e0::1",
  "fd00::1", "::1", "2001:db8::1", "8.8.8.8", "203.0.113.9", "127.0.0.1", "192.168.1.1", "10.0.0.1",
  "garbage", "1:2:3:4:5:6:7:8::9",
  // "::" standing for exactly ONE zero group is an address (seven groups written)
  "fd7a:115c:a1e0:1:2:3::4",
  // "::" standing for ZERO groups is not an address: eight groups around it
  "fd7a:115c:a1e0:1::2:3:4:5", "fd7a:115c:a1e0:4:5:6:7::8", "::fd7a:115c:a1e0:1:2:3:4:5", "fd7a:115c:a1e0:1:2:3:4::5",
];
const ZERO_GROUP_ANSWERS = ANSWER_VECTORS.slice(-4);

test("every answer vector decides the PAC exactly as isTailnetAddress does, and the answer edges are right", () => {
  const ts = "node.t.ts.net";
  for (const v of ANSWER_VECTORS) {
    const looked = noLookups();
    const out = chromePac({ [ts]: v }, looked).decide(`http://${ts}/`, ts);
    expect(out, `answer ${v}`).toBe(isTailnetAddress(v) ? "DIRECT" : ROUTE);
    expect(looked.ex).toEqual([ts]);
    expect(looked.plain).toEqual([]);
    expect(looked.other).toEqual([]);
  }
  // "::" for exactly one group is a tailnet address in BOTH copies (seven written).
  expect(isTailnetAddress("fd7a:115c:a1e0:1:2:3::4")).toBe(true);
  expect(chromePac({ [ts]: "fd7a:115c:a1e0:1:2:3::4" }, noLookups()).decide(`http://${ts}/`, ts)).toBe("DIRECT");
  // "::" for zero groups routes in BOTH copies of the predicate.
  for (const v of ZERO_GROUP_ANSWERS) {
    expect(isTailnetAddress(v), `isTailnetAddress ${v}`).toBe(false);
    expect(chromePac({ [ts]: v }, noLookups()).decide(`http://${ts}/`, ts), `PAC ${v}`).toBe(ROUTE);
  }
  const want: Record<string, string> = {
    "100.64.0.0": "DIRECT", "100.127.255.255": "DIRECT", "100.63.255.255": ROUTE, "100.128.0.0": ROUTE, "100.0.0.1": ROUTE,
    "fd7a:115c:a1e0::": "DIRECT", "fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff": "DIRECT",
    "fd7a:115c:a1e1::1": ROUTE, "fd7a:115d:a1e0::1": ROUTE, "fd7b:115c:a1e0::1": ROUTE, "2001:115c:a1e0::1": ROUTE,
    "fd00::1": ROUTE, "::1": ROUTE, "2001:db8::1": ROUTE,
  };
  for (const [v, w] of Object.entries(want)) {
    expect(chromePac({ [ts]: v }, noLookups()).decide(`http://${ts}/`, ts), v).toBe(w);
  }
});

test("a ts.net name goes direct only when EVERY dnsResolveEx answer is a Tailscale address", () => {
  const ts = "node.t.ts.net";
  const run = (answer: string | (() => string), via: "decide" | "find" = "decide") => {
    const looked = noLookups();
    const out = chromePac({ [ts]: answer }, looked)[via](`http://${ts}/`, ts);
    expect(looked.plain, "dnsResolve is never called").toEqual([]);
    expect(looked.other, "nothing but dnsResolveEx is called").toEqual([]);
    return out;
  };
  expect(run("100.64.0.9")).toBe("DIRECT");
  expect(run("fd7a:115c:a1e0::5;100.64.0.2")).toBe("DIRECT");
  expect(run("100.64.0.9;")).toBe("DIRECT");
  expect(run(";100.64.0.9")).toBe("DIRECT");
  expect(run(" 100.64.0.9 ; fd7a:115c:a1e0::5 ")).toBe("DIRECT");
  expect(run("100.64.0.2;203.0.113.9")).toBe(ROUTE);
  expect(run("fd7a:115c:a1e0::5;2001:db8::9")).toBe(ROUTE);
  expect(run("")).toBe(ROUTE);
  expect(run(";;;")).toBe(ROUTE);
  expect(run(() => {
    throw new Error("resolver failed");
  }, "find"), "an error inside the script stays routed").toBe(ROUTE);
});

test("dual stack: the one IPv4 dnsResolve would report is not enough, the IPv6 answer decides", () => {
  // Chrome's dnsResolve sees only 100.64.0.2 (an A-only query). dnsResolveEx sees both.
  const looked = noLookups();
  const out = chromePac({ "dual.t.ts.net": "100.64.0.2;2001:db8::9" }, looked).decide("http://dual.t.ts.net/", "dual.t.ts.net");
  expect(out).toBe(ROUTE);
  expect(looked.ex).toEqual(["dual.t.ts.net"]);
  expect(looked.plain).toEqual([]);
  expect(looked.other).toEqual([]);
});

test("without dnsResolveEx a ts.net name is routed, never decided by dnsResolve", () => {
  const looked = noLookups();
  const pac = chromePac({}, looked, { noEx: true });
  expect(pac.decide("http://node.t.ts.net/", "node.t.ts.net")).toBe(ROUTE);
  expect(looked.plain, "dnsResolve (which would say 100.64.0.2) is not consulted").toEqual([]);
  expect(looked.other).toEqual([]);
  // The rest of the table needs no lookup and is unaffected.
  expect(pac.decide("http://printer.local/", "printer.local")).toBe("DIRECT");
  expect(pac.decide("http://10.0.0.1/", "10.0.0.1")).toBe("DIRECT");
  expect(pac.decide("http://example.com/", "example.com")).toBe(ROUTE);
});

test("a PAC script that throws inside fails closed to the route", () => {
  const body = egressPacScript({ scheme: "https", host: "egress.example", port: 443 });
  const pac = new Function("dnsResolveEx", `${body}; return FindProxyForURL;`)(() => {
    throw new Error("boom");
  }) as (u: string, h: string) => string;
  expect(pac("http://x.t.ts.net/", "x.t.ts.net")).toBe(ROUTE);
});
