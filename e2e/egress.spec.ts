// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Browser-as-endpoint, hermetic Chromium proof, driven from the DASHBOARD
// half of the one control (the panel's half is e2e/protect.spec.ts). This
// is the hard e2e the design demands, not a structural pass: click the one
// control and prove
//   (a) the browser is actually routed through the Whisper egress endpoint
//       (its own registered identity), captured on the proxy;
//   (b) that identity appears in the account's op:list roster;
//   (c) keyless rdap verify-identity of the routed /128 returns
//       is_whisper_agent: true, so the dashboard's chip reads VERIFIED.
//
// The optional proxy permissions are promoted to required at install time
// (makeEgressDist), because the browser's own consent dialog for optional
// permissions cannot be scripted; every code path exercised: register /
// connect, chrome.proxy.set, onAuthRequired, the WebRTC policy, is real.
//
// Firefox parity rides the SAME HTTPS-CONNECT code path (proxy.onRequest +
// proxyAuthorizationHeader). Its decision code is driven by
// e2e/firefox-decision.spec.ts against the real src/background/egress.ts
// (hermetic, with a fake `browser`); the web-ext load gate covers the install.
// The routed-traffic assertion here is Chromium, where Playwright can drive it.

import { test, expect } from "@playwright/test";
import { egressPacScript } from "../src/shared/direct-destinations";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, makeEgressDist, openDashboard, setKey, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  // The only spec that opens a LAN listener: the direct-arrival proof needs one.
  await net.start({ privateOrigin: true });
  net.setVerdict("example-egress-e2e.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  ext = await launchExtension({
    proxyPort: net.proxyPort,
    dist: makeEgressDist(),
    // A fixture tailnet node (a Tailscale address, unreachable from CI) and a
    // fixture public Funnel host (a public-looking answer: loopback stands in).
    hostResolverRules: "MAP box.e2e-tailnet.ts.net 100.64.0.7, MAP funnel.e2e-public.ts.net 127.0.0.1",
  });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("browser-as-endpoint: turning it on registers, routes, and verifies the browser's own identity", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearEndpoints();

  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#btn-protect")).toHaveText("Protect this browser", { timeout: 10_000 });

  // One click. The page requests the (pre-granted) permissions on the
  // gesture, then the background registers the device + provisions egress.
  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Protected", { timeout: 25_000 });
  await expect(dash.locator("#btn-protect")).toHaveText("Turn routing off");

  // (b) The browser now appears in the account roster as a device.
  const registered = net.endpoints.find((e) => e.label.includes("This browser"));
  expect(registered, "the browser registered itself as a device").toBeTruthy();

  // (c) The identity chip verifies the routed /128 against keyless rdap.
  await expect(dash.locator("#identity-chip")).toHaveText("VERIFIED WHISPER ENDPOINT", { timeout: 15_000 });

  // (a) A fresh page's traffic is now carried through the Whisper egress
  // endpoint (authenticated CONNECT), i.e. the browser sources from its own
  // identity, not direct. The egress endpoint recorded the CONNECT.
  net.clearEgressLog();
  const page = await ext.context.newPage();
  await page.goto("https://example-egress-e2e.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
  await page.waitForTimeout(600);
  expect(
    net.egressConnects("example-egress-e2e.com"),
    "site traffic routed via the Whisper egress endpoint",
  ).toBeGreaterThan(0);
  await page.close();

  // The same button turns it off and restores a direct route.
  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Identity reserved", { timeout: 20_000 });
  net.clearEgressLog();
  net.clearLog(); // so the control below counts THIS navigation, not the routed one above
  const page2 = await ext.context.newPage();
  await page2.goto("https://example-egress-e2e.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
  await page2.waitForTimeout(400);
  // CONTROL: goto's rejection is swallowed on the line above, so a page that
  // never loaded produces zero egress CONNECTs just as convincingly as one
  // that loaded directly. Prove the traffic HAPPENED before reading that it
  // did not go through the endpoint.
  expect(
    net.requestsTo("example-egress-e2e.com").length,
    "the page must actually have loaded, or a zero egress count proves nothing",
  ).toBeGreaterThan(0);
  expect(net.egressConnects("example-egress-e2e.com")).toBe(0);
  await page2.close();
  await dash.close();
});

test("browser-as-endpoint: tailnet names and private literals go direct, public hosts still take the route", async () => {
  await setKey(ext, MOCK_KEY);
  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#btn-protect")).toHaveText(/Protect this browser|Turn routing on/, { timeout: 10_000 });
  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Protected", { timeout: 25_000 });
  await expect(dash.locator("#route-line")).toContainText("tailnet and private-network destinations");
  // Private windows are not routed by default (the extension is not allowed in
  // them in this run), and the line says so.
  await expect(dash.locator("#route-line")).toContainText("Private windows are not routed unless Whisper Guard is allowed in them.");

  // The proxy setting is the PAC script that carries the shared never-proxied
  // table, MANDATORY so a script that cannot load stops traffic instead of
  // falling back to a direct connection, and exactly the script the shared
  // generator makes for this endpoint (the egress stand-in the mock hands out).
  const pac = await dash.evaluate(
    () =>
      new Promise<{ mode?: string; data?: string; mandatory?: boolean }>((resolve) =>
        chrome.proxy.settings.get({}, (d) =>
          resolve({ mode: d.value?.mode, data: d.value?.pacScript?.data, mandatory: d.value?.pacScript?.mandatory }),
        ),
      ),
  );
  expect(pac.mode).toBe("pac_script");
  expect(pac.mandatory).toBe(true);
  expect(pac.data).toBe(egressPacScript({ scheme: "http", host: "127.0.0.1", port: net.egressPort }));

  net.clearEgressLog();
  net.directHosts.length = 0;

  // (1) A tailnet node (resolves to a Tailscale address): never touches the
  // egress. The address is unreachable from CI, so only the absence is
  // asserted; the Funnel host below is the positive control that makes a
  // zero meaningful.
  const tailnetHost = "box.e2e-tailnet.ts.net";
  const page = await ext.context.newPage();
  await page.goto(`http://${tailnetHost}:${net.directPort}/`, { timeout: 3_000 }).catch(() => undefined);
  expect(net.egressAttempts.filter((a) => a.host === tailnetHost)).toHaveLength(0);

  // (1b) A public Funnel host on the same suffix (resolves outside the
  // tailnet's ranges) is NOT a bypass: it takes the route.
  const funnelHost = "funnel.e2e-public.ts.net";
  await page.goto(`http://${funnelHost}:${net.directPort}/`, { timeout: 5_000 }).catch(() => undefined);
  expect(net.egressAttempts.filter((a) => a.host === funnelHost).length, "a Funnel host stays routed").toBeGreaterThan(0);
  expect(net.directHosts, "the Funnel host never reached the direct origin").not.toContain(
    `${funnelHost}:${net.directPort}`,
  );

  // (2) A private literal that nothing answers on the routed side: assert that
  // it never reached the egress or the capture proxy. Where this machine has a
  // private address of its own (the private origin below), that address is the
  // literal, so no packet leaves for a device this test does not own (nothing
  // listens on its port 80, so the connection is refused on the spot);
  // otherwise 192.168.1.1. On a given machine this step therefore covers only
  // the own address's private range; direct-destinations.spec pins every range
  // edge. An absence, so the public navigation in (3) is the
  // positive control that makes a zero meaningful, and (2a) proves the arrival.
  const privateLiteral = net.directPrivateHost ?? "192.168.1.1";
  net.clearLog();
  await page.goto(`http://${privateLiteral}/`, { timeout: 2_000 }).catch(() => undefined);
  expect(net.egressAttempts.filter((a) => a.host === privateLiteral)).toHaveLength(0);
  expect(net.requestsTo(privateLiteral)).toHaveLength(0);

  // (2a) DIRECT, not merely "not routed": an origin bound to this machine's
  // own private address must RECEIVE the request. Skipped (and annotated) when
  // there is no such origin (no private, non-loopback address, or a probe from
  // node could not reach it). A browser-side network error after a successful
  // probe skips locally, but FAILS when CI is set, so it cannot become a silent
  // skip there. A routing regression still fails here: a routed request
  // lands on the egress stand-in's 405 page, which is a page, not a network
  // error, so the title check below fails.
  const skip = (why: string) => {
    const description = `arrival at a private literal not provable: ${why}`;
    console.warn(`[egress.spec (2a)] skipped: ${description}`);
    test.info().annotations.push({ type: "skipped-step", description });
  };
  if (net.directPrivateHost) {
    const privateOrigin = `${net.directPrivateHost}:${net.directPrivatePort}`;
    // A page of its own: the refused navigation in (2) can commit its error page late,
    // and that would interrupt this one's goto.
    const arrival = await ext.context.newPage();
    net.clearEgressLog();
    net.directHosts.length = 0;
    let reached = true;
    // Chromium reports a failed navigation as an interruption by its error page,
    // so the network error's own name comes from the failed request.
    const failures: string[] = [];
    const onFailed = (r: { failure(): { errorText: string } | null }) => failures.push(r.failure()?.errorText ?? "");
    arrival.on("requestfailed", onFailed);
    try {
      await arrival.goto(`http://${privateOrigin}/`, { timeout: 5_000 });
    } catch (e) {
      const text = [String(e instanceof Error ? e.message : e), ...failures].join(" ");
      // A dead proxy, or a PAC that did not load (ERR_MANDATORY_PROXY_CONFIGURATION_FAILED),
      // is a routing fault, not a missing network: it must fail.
      if (!/net::ERR_/.test(text) || /ERR_(MANDATORY_)?PROXY|ERR_TUNNEL/.test(text)) {
        throw new Error(`${text.split("\n")[0]}; failed requests: ${failures.join(", ") || "none"}`);
      }
      // The probe from node reached this origin, so a browser that cannot is a
      // fault in CI, where a skip here would hide it.
      if (process.env.CI) {
        throw new Error(`the browser could not reach the private origin the probe reached: ${failures[0] ?? text.split("\n")[0]}`);
      }
      reached = false;
      skip(failures[0] ?? text.split("\n")[0] ?? text);
    } finally {
      arrival.off("requestfailed", onFailed);
    }
    if (reached) {
      await expect(arrival).toHaveTitle("direct-origin");
      expect(net.directHosts, "the private literal ARRIVED at its own origin: it went direct").toContain(privateOrigin);
      expect(net.egressAttempts.filter((a) => a.host === net.directPrivateHost)).toHaveLength(0);
      expect(net.requestsTo(net.directPrivateHost)).toHaveLength(0);
    }
    await arrival.close();
  } else {
    skip("no private, non-loopback interface address on this machine, or it was not reachable");
  }

  // (2b) An IPv6 ULA literal exercises the PAC's IPv6 direct ranges. The
  // capture records the host as "[fd00::1]" (brackets kept) on both paths that
  // matter: the egress logs a routed GET (or CONNECT) for it, and a request
  // that falls back to the capture proxy is logged there. Either one fails
  // this step; any request that reaches neither proxy passes it, so this step
  // does not prove a direct connection (direct-destinations.spec pins fd00::1
  // as DIRECT).
  net.clearLog();
  await page.goto("http://[fd00::1]/", { timeout: 2_000 }).catch(() => undefined);
  expect(net.egressAttempts.filter((a) => a.host === "[fd00::1]")).toHaveLength(0);
  expect(net.requestsTo("[fd00::1]")).toHaveLength(0);

  // (3) A public host (a fresh name, so no pooled tunnel from the test above
  // hides the CONNECT) still leaves through the egress endpoint.
  await page.goto("https://public-control-e2e.com/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
  await expect.poll(() => net.egressConnects("public-control-e2e.com"), { timeout: 10_000 }).toBeGreaterThan(0);
  await page.close();

  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Identity reserved", { timeout: 20_000 });
  await dash.close();
});

test("browser-as-endpoint: the identity is register-once and reused, never duplicated", async () => {
  await setKey(ext, MOCK_KEY);
  const before = net.endpoints.filter((e) => e.label.includes("This browser")).length;
  // CONTROL: this test builds on the registration the previous one made, and
  // "no second row" is trivially true when there is no first row. Pin it, so
  // running this in isolation says so instead of passing on two zeroes.
  expect(before, "the browser must already be registered from the previous test, or reuse is untested").toBe(1);

  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#btn-protect")).toHaveText("Turn routing on", { timeout: 10_000 });
  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Protected", { timeout: 25_000 });

  // No SECOND device row was minted: the stored identity was reused.
  const after = net.endpoints.filter((e) => e.label.includes("This browser")).length;
  expect(after).toBe(before);

  await dash.locator("#btn-protect").click();
  await expect(dash.locator("#route-line")).toContainText("Identity reserved", { timeout: 20_000 });
  await dash.close();
});
