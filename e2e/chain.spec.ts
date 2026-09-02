// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE CHAIN, the join path behind a name.
//
// Four things have to be true, and only one of them is "it renders".
//
//   1. It really is a JOIN. Every rung comes from a different read, and the
//      later ones need a value the earlier ones produced. A chain that
//      quietly stopped after the first round would still show a name, a
//      vendor and an address; it could not show a prefix, a network, an
//      operator and a building. So the assertions are on the far end.
//
//   2. A STEP THAT COULD NOT BE READ SAYS SO. This is the one that matters.
//      "The graph holds nothing here" and "we could not ask" are different
//      facts, and a surface that renders the second as the first turns an
//      outage into the appearance of safety. The mock fails exactly one
//      query while answering the rest, which is the shape a real partial
//      outage has, and the rung must come back marked unreadable while its
//      neighbours stay live.
//
//   3. IT IS NOT BUILT ON NAVIGATION. The public tier allows a hundred
//      graph calls an hour from one address, measured with
//      CALL whisper.quota(). The walk costs seven. Building it on every
//      page load would empty a reader's budget inside twenty minutes of
//      ordinary browsing and leave nothing for the assess call that is the
//      thing actually protecting them. So browsing must cost ONE call and
//      opening the panel is what spends the rest.
//
//   4. EXPANDING A RUNG IS LAZY, for the same reason.

import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openPopup,
  restartExtension,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const HOST = "chain-full-guard-e2e.com";
const LOST = "chain-partial-guard-e2e.com";
const BUDGET = "chain-budget-guard-e2e.com";

function seed(host: string): void {
  net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setEnrich(host, {
    ip: "198.51.100.40",
    city: "London, GB",
    country: "GB",
    asn: "AS64540",
    owner: "MediaCo plc",
    asnName: "MEDIACO - MediaCo plc",
    prefix: "198.51.100.0/24",
    threatNeighbors: 0,
    prevalence: 812,
    verdict: "NONE",
  });
  net.setIdentify(host, [
    {
      host,
      canonical_name: "MediaCo",
      category: "media",
      roles: ["DNS_OPERATOR", "ORIGIN_AS"],
      confidence: 0.85,
      host_class: "single_tenant",
      evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco"],
    },
  ]);
  net.setPresence("AS64540", {
    facilities: ["Example Carrier Hotel LON1", "Example Colo LON2"],
    exchanges: ["Example Exchange LON"],
    facilityCount: 14,
    exchangeCount: 4,
  });
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const h of [HOST, LOST, BUDGET]) seed(h);
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function openChain(host: string): Promise<{ popup: import("@playwright/test").Page; tabId: number; page: import("@playwright/test").Page }> {
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  const popup = await openPopup(ext, tabId);
  await popup.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 20_000 });
  return { popup, tabId, page };
}

function rung(popup: import("@playwright/test").Page, label: string) {
  return popup.locator("#chain-mount .ch-rung").filter({ hasText: label });
}

test("the whole path renders, and the far end proves it was a join", async () => {
  const { popup, page } = await openChain(HOST);

  // The near end: what the first round produced.
  await expect(rung(popup, "NAME")).toContainText(HOST);
  await expect(rung(popup, "RUNS ON")).toContainText("MediaCo");
  await expect(rung(popup, "ADDRESS")).toContainText("198.51.100.40");

  // THE FAR END. Each of these needs a value the round before it produced:
  // the prefix needs the address, the operator needs the network, the
  // building needs the operator. A walk that stopped early renders the
  // three above and none of these.
  await expect(rung(popup, "PREFIX")).toContainText("198.51.100.0/24");
  await expect(rung(popup, "NETWORK")).toContainText("AS64540");
  await expect(rung(popup, "OPERATOR")).toContainText("MediaCo plc");
  await expect(rung(popup, "PRESENT AT")).toContainText("Example Carrier Hotel");
  await expect(rung(popup, "PRESENT AT")).toContainText("14 facilities");

  // And the completeness readout agrees with what is on screen, rather than
  // being a number written next to it.
  await expect(popup.locator(".ch-count")).toHaveText("7 of 7 joined");
  await expect(popup.locator("#chain-mount .ch-rung.ch-live")).toHaveCount(7);

  await popup.close();
  await page.close();
});

test("a step that could NOT be read says so, while its neighbours stay live", async () => {
  // CONTROL FIRST: with nothing failing, the presence rung is live. Without
  // this, the assertion below passes on a build where that rung never
  // renders at all.
  {
    const { popup, page } = await openChain(LOST);
    await expect(rung(popup, "PRESENT AT")).toContainText("Example Carrier Hotel");
    await expect(rung(popup, "PRESENT AT")).not.toHaveClass(/ch-lost/);
    await popup.close();
    await page.close();
  }

  // Now break exactly one read: the physical-presence join. Everything else
  // still answers, which is what a real partial outage looks like.
  net.failQueries.add("AS_PRESENT_AT");
  // The walk is memoised for ten minutes, so a fresh name is needed for the
  // second reading rather than a re-open of the first.
  const BROKEN = "chain-broken-guard-e2e.com";
  seed(BROKEN);
  const { popup, page } = await openChain(BROKEN);

  const presence = rung(popup, "PRESENT AT");
  await expect(presence).toHaveClass(/ch-lost/);
  // The WORDS matter as much as the class: this is the sentence that stops
  // an outage reading as a clean result.
  await expect(presence).toContainText("could not be read");
  await expect(presence, "an unreadable step must not claim there is nothing there").not.toContainText(
    "no recorded presence",
  );

  // Its neighbours are untouched, so the reader can see this is one missing
  // step and not a dead panel.
  await expect(rung(popup, "OPERATOR")).toContainText("MediaCo plc");
  await expect(rung(popup, "NETWORK")).toContainText("AS64540");

  // And the panel says it out loud, in a sentence a person can act on.
  await expect(popup.locator("#chain-note")).toContainText("could not be read");
  await expect(popup.locator("#chain-note")).toContainText("unknown, not clear");
  await expect(popup.locator(".ch-count")).toContainText("1 unreadable");

  net.failQueries.clear();
  await popup.close();
  await page.close();
});

test("browsing costs ONE graph call; the walk is spent on the reader's ask", async () => {
  net.clearLog();
  const { page, tabId } = await visit(ext, `https://${BUDGET}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  // Settle: anything the nav pipeline was going to do has happened.
  await page.waitForTimeout(1500);

  const graphCalls = (): string[] =>
    net.log
      .filter((r) => r.host === GRAPH_READ_HOST && r.method === "POST")
      .map((r) => {
        const m = /CALL (whisper\.[a-zA-Z.]+)/.exec(r.body);
        return m?.[1] ?? (r.body.includes("ANNOUNCED_BY") ? "route" : r.body.includes("AS_PRESENT_AT") ? "presence" : "raw");
      });

  const duringNav = graphCalls();
  expect(
    duringNav,
    `navigation must cost exactly the verdict, not a walk; it spent ${JSON.stringify(duringNav)}`,
  ).toEqual(["whisper.assess"]);

  // NOW the reader asks. The walk happens here and nowhere else.
  const popup = await openPopup(ext, tabId);
  await popup.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 20_000 });
  await popup.waitForTimeout(800);

  const afterPanel = graphCalls();
  expect(afterPanel.length, "the panel spent nothing").toBeGreaterThan(duringNav.length);
  // The walk's own reads, each one a different join.
  for (const call of ["whisper.enrich", "whisper.resolve", "whisper.identify", "whisper.history"]) {
    expect(afterPanel, `the walk never ran ${call}`).toContain(call);
  }
  expect(afterPanel, "the address-to-prefix-to-network join never ran").toContain("route");
  expect(afterPanel, "the physical-presence join never ran").toContain("presence");

  await popup.close();
  await page.close();
});

test("expanding a rung is lazy: nothing is spent until the reader asks", async () => {
  const HOST2 = "chain-drill-guard-e2e.com";
  seed(HOST2);
  const { popup, page } = await openChain(HOST2);
  await popup.waitForTimeout(600);

  const densityCalls = (): number =>
    net.log.filter((r) => r.body.includes("asnThreatDensity")).length;

  expect(densityCalls(), "the density read ran before anyone asked for it").toBe(0);

  // The reader expands the network rung.
  await rung(popup, "NETWORK").click();
  await expect(popup.locator(".ch-detail")).toBeVisible();
  await expect
    .poll(() => densityCalls(), { timeout: 10_000 })
    .toBe(1);

  // Clicking again closes it and does not spend a second read.
  await rung(popup, "NETWORK").click();
  await expect(popup.locator(".ch-detail")).toHaveCount(0);
  expect(densityCalls(), "closing a rung spent another read").toBe(1);

  await popup.close();
  await page.close();
});

test("a rung with nothing behind it is not dressed up as a control", async () => {
  const HOST3 = "chain-bare-guard-e2e.com";
  // No identify row, so the vendor rung is empty: nothing to expand.
  net.setVerdict(HOST3, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setIdentify(HOST3, []);
  const { popup, page } = await openChain(HOST3);

  const vendor = rung(popup, "RUNS ON");
  await expect(vendor).toHaveClass(/ch-empty/);
  await expect(
    vendor,
    "an empty rung offers a button that would do nothing when pressed",
  ).not.toHaveClass(/ch-open/);

  await popup.close();
  await page.close();
});

test("an unreadable graph scale shows NO figure at all", async () => {
  // CONTROL FIRST: with the endpoint up, the masthead really does show a
  // figure. Without this, the assertion below passes on a build where the
  // readout never appears at all.
  const UP = "scale-up-guard-e2e.com";
  seed(UP);
  {
    const { popup, page } = await openChain(UP);
    await expect(popup.locator("#scale:not([hidden])")).toBeVisible({ timeout: 15_000 });
    await expect(popup.locator("#scale-nodes")).toHaveText(/^\d/);
    await popup.close();
    await page.close();
  }

  // Now the statistics endpoint is unreachable, AND the worker is restarted
  // so it holds no reading of its own.
  //
  // The restart is the point. A reading is legitimately reused inside the
  // endpoint's own 30-second freshness window, which is the publisher's
  // declared Cache-Control, so simply switching the endpoint off does not
  // and should not empty the masthead within a second - the first version
  // of this test asserted that it would, and caught the module's own header
  // promising something stricter than the code did. What must hold is that
  // a surface with nothing fresh shows NOTHING: the figure is about our own
  // coverage, so an invented one would be the most flattering possible lie.
  net.statsDown = true;
  ext = await restartExtension(ext, { proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setSettings(ext, { cloudCheck: true });

  const DOWN = "scale-down-guard-e2e.com";
  seed(DOWN);
  const { popup, page } = await openChain(DOWN);
  await popup.waitForTimeout(1500);
  await expect(
    popup.locator("#scale"),
    "the masthead showed a graph figure it had never read",
  ).toBeHidden();
  // And the rest of the panel is unaffected: an unreadable scale is not an
  // outage, and the verdict and the walk still stand.
  await expect(popup.locator("#chain-mount .ch-rung.ch-live")).toHaveCount(7);
  net.statsDown = false;
  await popup.close();
  await page.close();
});
