// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE DRAWN WORK, proven.
//
// A screenshot proves a shape was painted. It cannot prove the shape came
// from a measurement, that it does not lie when the measurement is missing,
// or that it moves only when something really happened. Those are the three
// claims the drawing makes, so those are the three this file asserts, each
// with a control that fails if the guard is removed.
//
//   npx playwright test e2e/drawn.spec.ts

import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openDashboard,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const EVIL = "drawn-evil-guard-e2e.com";
const GOOD = "drawn-good-guard-e2e.com";
const SECOND = "drawn-second-guard-e2e.com";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();

  net.setVerdict(EVIL, { band: "CRITICAL", coverage: "malicious-evidenced", label: "credential-phishing suspect" });
  net.setEnrich(EVIL, {
    ip: "192.0.2.66", city: "Example City, CA", country: "CA", asn: "AS64550",
    owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC",
    prefix: "192.0.2.0/24", threatNeighbors: 9, verdict: "CRITICAL",
  });
  net.setPresence("AS64550", { facilities: ["Example Colo MTL1"], exchanges: [], facilityCount: 1 });
  net.setIdentify(EVIL, []);
  net.setExplain(EVIL, [{
    indicator: EVIL, type: "domain", found: true, level: "CRITICAL", score: 17.2,
    explanation: `${EVIL} is listed in 2 threat feed(s).`,
    sources: [{ feedId: "openphish", firstSeen: "2026-07-02T00:00:00Z" }],
  }]);
  net.setHistory(EVIL, [{ createDate: "2026-08-19T00:00:00Z", updateDate: "2026-08-19T00:00:00Z" }]);
  net.setPage(EVIL, "<!doctype html><html><body><h1>sign in</h1></body></html>");

  for (const [host, ip, asn] of [
    [GOOD, "198.51.100.40", "AS64540"],
    [SECOND, "198.51.100.41", "AS64540"],
  ] as const) {
    net.setVerdict(host, { band: "NONE", coverage: "known-clean", label: "clean" });
    net.setEnrich(host, {
      ip, city: "Example Town, GB", country: "GB", asn,
      owner: "MediaCo plc", asnName: "MEDIACO - MediaCo plc",
      prefix: "198.51.100.0/24", threatNeighbors: 0, prevalence: 812, verdict: "NONE",
    });
    net.setIdentify(host, [{
      host, canonical_name: "MediaCo", category: "media",
      roles: ["DNS_OPERATOR"], confidence: 0.85, host_class: "single_tenant",
      evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco"],
    }]);
    net.setPage(host, "<!doctype html><html><body><h1>news</h1></body></html>");
  }
  net.setDensity("AS64540", { listedIps: 5, announcedIpv4: 9216, routedPrefixes: 24 });
  net.setPresence("AS64540", {
    facilities: ["Example Carrier Hotel LON1"], exchanges: ["Example Exchange LON"],
    facilityCount: 14, exchangeCount: 4,
  });

  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

/** Drive the browser so the on-device destination list has real rows. */
async function browse(hosts: string[]): Promise<void> {
  for (const h of hosts) {
    const v = await visit(ext, `https://${h}/`);
    await waitForIcon(ext, v.tabId, ["benign", "malicious", "unknown", "signedout", "suspicious"]);
    await v.page.close();
  }
}

// ===========================================================================
// The interstitial: the argument is drawn, and honest when it cannot be
// ===========================================================================

test("the warning page draws the join, and every mark comes from a measurement", async () => {
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/warning.html?host=${EVIL}`);

  // The spine: seven rungs, drawn.
  const spine = page.locator("#ev-spine svg");
  await expect(spine).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#ev-chain .ch-rung")).toHaveCount(7);
  await expect(page.locator("#ev-completeness")).toContainText("joins answered");

  // The neighbourhood: ONE MARK PER FLAGGED HOST, and the count of marks is
  // the measurement. A picture of nine squares that was drawn from a
  // hardcoded nine would pass a screenshot review and fail here.
  await expect(page.locator("#ev-neighbours")).toBeVisible();
  await expect(page.locator("#ev-neighbours svg rect")).toHaveCount(9);
  await expect(page.locator("#ev-neighbours")).toContainText("192.0.2.0/24");

  // The age bar's fill is the age against a year, to three decimals, read
  // off the element rather than off the caption beside it: the caption and
  // the geometry can disagree, and only one of them is the picture.
  const pct = await page.locator("#ev-age svg").getAttribute("data-pct");
  expect(Number(pct)).toBeGreaterThan(0);
  expect(Number(pct), "16 days of a 365 day scale").toBeLessThan(10);

  // The privacy-critical one: the page must not claim more citations than
  // the graph gave reasons for.
  await expect(page.locator("#ev-feeds")).toContainText("cited by the graph");
  await expect(
    page.locator("#ev-feeds"),
    "counting reason strings as independent sources is an overclaim",
  ).not.toContainText("independent citations");

  await page.close();
});

test("CONTROL: an unreadable walk is drawn as unreadable, never as an empty one", async () => {
  // The whole point of the drawn argument is that it must not be able to
  // turn an outage into a quieter-looking page.
  //
  // With the graph down the walk still returns: the NAME rung is known
  // without asking anybody, and the other six come back marked
  // "unavailable". That is the right design and it is stronger than
  // rendering nothing, because a blank evidence panel and a panel full of
  // "could not be read" are the two things a reader most needs told apart.
  // What must never happen is a rung with a value in it that nobody read.
  const UNREACHABLE = `unreachable-${EVIL}`;
  net.graphMode = "down";
  try {
    const page = await ext.context.newPage();
    await page.goto(`chrome-extension://${ext.id}/warning.html?host=${UNREACHABLE}`);
    await expect(page.locator("#ev-completeness")).toContainText("unreadable", { timeout: 20_000 });
    await expect(page.locator("#ev-completeness")).toHaveClass(/lost/);

    // Every rung is present, and the ones that could not be read say so.
    await expect(page.locator("#ev-chain .ch-rung")).toHaveCount(7);
    // SIX of the seven, and the count matters. Three of these used to render
    // as "empty" instead: "not in a routed prefix", "no announcing network",
    // "no recorded presence", all asserted while the graph was unreachable.
    await expect(page.locator("#ev-chain .ch-rung.ch-lost")).toHaveCount(6);
    await expect(page.locator("#ev-chain")).toContainText("could not be read");
    for (const claim of ["not in a routed prefix", "no announcing network", "no recorded presence"]) {
      await expect(
        page.locator("#ev-chain"),
        `"${claim}" is a statement about the world, and nothing was read`,
      ).not.toContainText(claim);
    }

    // The one rung that IS live is the one that needs no graph, and it
    // carries the real name rather than a placeholder.
    await expect(page.locator("#ev-chain .ch-rung").first()).toContainText(UNREACHABLE);

    // Nothing was invented: no address, no prefix, no operator.
    const text = (await page.locator("#ev-chain").textContent()) ?? "";
    expect(text, "an unread rung must not carry an address").not.toContain("192.0.2");
    expect(text, "an unread rung must not name an operator").not.toContain("Bad Hosting");

    // No neighbourhood mark either: nine squares drawn from a figure nobody
    // fetched is the exact failure this panel exists to avoid.
    await expect(page.locator("#ev-neighbours svg")).toHaveCount(0);

    // And the stop itself is untouched: a failed read must never soften the
    // interruption.
    await expect(page.locator("h1")).toContainText("stopped a dangerous page");
    await page.close();
  } finally {
    net.graphMode = "mock";
  }
});

// ===========================================================================
// The pre-click window, and the privacy invariant the join must not break
// ===========================================================================

test("check-link draws the join before the page has loaded", async () => {
  await setSettings(ext, { cloudCheck: true });
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/check-link.html?host=${EVIL}`);

  await expect(page.locator("#chain-mount .ch-rung")).toHaveCount(7, { timeout: 20_000 });
  await expect(page.locator("#cl-rail")).toHaveClass(/malicious/);
  await expect(page.locator("#cl-metrics")).toContainText("Flagged neighbours");
  await expect(page.locator("#cl-metrics svg").first()).toBeVisible();
  await page.close();
});

test("CONTROL: with the live check off, check-link walks nothing and sends nothing", async () => {
  // The window prints "nothing left your browser" in that state. Walking
  // the join would send the hostname the setting exists to keep in the
  // browser, and would make the surface's own privacy line false. This is
  // the assertion that stops the join being added to a surface it must not
  // run on.
  await setSettings(ext, { cloudCheck: false });
  net.clearLog();
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/check-link.html?host=${GOOD}`);
  await expect(page.locator("#privacy")).toContainText("nothing left your browser", { timeout: 15_000 });
  await page.waitForTimeout(2500);

  await expect(page.locator("#chain-mount .ch-rung")).toHaveCount(0);
  const sent = net.requestsTo(GRAPH_READ_HOST).map((r) => r.body).join("\n");
  expect(sent, "the join must not send a hostname the live check was told to keep local").not.toContain(GOOD);

  await page.close();
  await setSettings(ext, { cloudCheck: true });
});

// ===========================================================================
// The join flow: drawn from the data, and legible
// ===========================================================================

test("the dashboard join draws real columns and real ribbons", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  await browse([GOOD, SECOND, EVIL]);

  const dash = await openDashboard(ext, "browser");
  const join = dash.locator("#b-join svg");
  await expect(join).toBeVisible({ timeout: 20_000 });

  // Four columns, named.
  for (const head of ["DESTINATIONS", "NETWORKS", "OPERATORS", "COUNTRIES"]) {
    await expect(join.locator("text").filter({ hasText: new RegExp(`^${head}$`) })).toHaveCount(1);
  }

  // The narrowing is the finding, so it must actually be drawn: two
  // destinations share one network, so there are strictly fewer network
  // nodes than destination nodes. A flow that drew one network per
  // destination would look identical at a glance and mean nothing.
  const counts = await join.evaluate((svg: SVGSVGElement) => {
    const texts = [...svg.querySelectorAll("text")].map((t) => t.textContent ?? "");
    return {
      destinations: texts.filter((t) => t.includes("guard-e2e")).length,
      networks: texts.filter((t) => /^AS\d+$/.test(t)).length,
    };
  });
  expect(counts.destinations).toBe(3);
  expect(counts.networks, "two of the three destinations share AS64540").toBe(2);

  // Ribbons exist and carry the hop.
  expect(await join.locator("path").count()).toBeGreaterThanOrEqual(3);
  await dash.close();
});

test("the join's ribbons never cross its labels", async () => {
  // A geometric guard for a real defect: the ribbons were drawn across the
  // full column width and struck straight through the text they connect,
  // which made the one picture whose entire job is legibility the least
  // legible thing on the page. It is not visible in a passing screenshot
  // test, because the picture is still "there".
  await setKey(ext, null);
  await browse([GOOD, SECOND, EVIL]);
  const dash = await openDashboard(ext, "browser");
  const join = dash.locator("#b-join svg");
  await expect(join).toBeVisible({ timeout: 20_000 });

  const overlaps = await join.evaluate((svg: SVGSVGElement) => {
    const boxes = (sel: string): { x0: number; x1: number; y0: number; y1: number; t: string }[] =>
      [...svg.querySelectorAll(sel)].map((el) => {
        const b = (el as SVGGraphicsElement).getBBox();
        return { x0: b.x, x1: b.x + b.width, y0: b.y, y1: b.y + b.height, t: el.textContent ?? "" };
      });
    // Column heads sit above every ribbon, so they are excluded by their y.
    const labels = boxes("text").filter((l) => l.y0 > 12);
    const hit: string[] = [];
    for (const p of boxes("path")) {
      for (const l of labels) {
        const xOverlap = p.x0 < l.x1 && l.x0 < p.x1;
        const yOverlap = p.y0 < l.y1 && l.y0 < p.y1;
        if (xOverlap && yOverlap) hit.push(l.t);
      }
    }
    return { hit, labels: labels.length };
  });
  // Control first: if no labels were found the sweep proves nothing.
  expect(overlaps.labels, "the sweep must have found labels to check").toBeGreaterThan(3);
  expect(overlaps.hit, "a ribbon is drawn over these labels").toEqual([]);
  await dash.close();
});

// ===========================================================================
// The empty state: no furniture around nothing
// ===========================================================================

test("with nothing seen, the analytics are hidden rather than drawn as zeros", async () => {
  // A fresh profile: the destination list is genuinely empty.
  const fresh = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  try {
    const dash = await openDashboard(fresh, "browser");
    await expect(dash.locator("#b-nodata")).toBeVisible({ timeout: 15_000 });
    await expect(dash.locator("#b-nodata")).toContainText("not been seen visiting anywhere yet");
    await expect(dash.locator("#b-tiles")).toBeHidden();
    await expect(dash.locator("#b-join-card")).toBeHidden();
    await expect(dash.locator("#b-breakdowns")).toBeHidden();
    await dash.close();
  } finally {
    await fresh.close();
  }
});

test("CONTROL: once something IS seen, the analytics come back", async () => {
  // Without this the test above passes just as well against a dashboard
  // that hides its analytics permanently.
  await setKey(ext, null);
  await browse([GOOD]);
  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#b-tiles")).toBeVisible({ timeout: 20_000 });
  await expect(dash.locator("#b-join-card")).toBeVisible();
  await expect(dash.locator("#b-nodata")).toBeHidden();
  await dash.close();
});

// ===========================================================================
// Alive, and honest about it
// ===========================================================================

/** How many marks the live track is currently showing. */
async function pulseMarks(dash: Page): Promise<number> {
  return dash.locator("#live-pulse svg rect").count();
}

test("the live mark moves when something arrives, and ONLY then", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#live-pulse svg")).toBeVisible({ timeout: 15_000 });

  // THE CONTROL, AND IT COMES FIRST. Four seconds pass with no navigation
  // anywhere. A spinner, a marquee, or anything driven by a timer would
  // have moved by now. This surface must not, because motion here is a
  // claim that an event happened, and no event has.
  const atRest = await pulseMarks(dash);
  await dash.waitForTimeout(4000);
  expect(
    await pulseMarks(dash),
    "the live mark moved while nothing was arriving, which makes every future movement meaningless",
  ).toBe(atRest);

  // Now something really happens.
  const v = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, v.tabId, ["benign", "unknown", "signedout"]);
  await expect
    .poll(() => pulseMarks(dash), { timeout: 15_000 })
    .toBeGreaterThan(atRest);

  await v.page.close();
  await dash.close();
});

test("the live mark goes quiet rather than pretending", async () => {
  // The other half of the same claim: when arrivals stop, the track says
  // so in the mark itself. A product that is doing nothing should look
  // like a product that is doing nothing.
  await setKey(ext, null);
  const dash = await openDashboard(ext, "browser");
  const track = dash.locator("#live-pulse svg");
  await expect(track).toBeVisible({ timeout: 15_000 });
  await expect(track).toHaveClass(/w-pulse-idle/);

  const v = await visit(ext, `https://${SECOND}/`);
  await waitForIcon(ext, v.tabId, ["benign", "unknown", "signedout"]);
  // An arrival lifts the idle state, so the two states are provably
  // different rather than one class that is always on.
  await expect(track).not.toHaveClass(/w-pulse-idle/, { timeout: 15_000 });
  await v.page.close();
  await dash.close();
});

test("a repeat fleet poll does not tick the live mark", async () => {
  // The fleet is polled every fifteen seconds whether or not anything
  // happened. Pushing a mark on each completed poll would have been a
  // heartbeat wearing an event's clothes, and would have made the mark's
  // whole claim false on the one view that polls. So the mark moves on new
  // activity and not on the poll that re-reads the old activity.
  test.setTimeout(90_000);
  const fresh = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  try {
    await setKey(fresh, MOCK_KEY);
    net.clearEndpoints();
    const t0 = Date.now();
    net.addEndpoint({
      agent: "agent-drawn-poll", address: "2a04:2a01:d4:2::1", label: "Polled device",
      device: true, counters: { dns_queries: 12 },
      logs: [{ ts: t0 - 60_000, kind: "dns", qname: `${GOOD}.`, qtype: "A", decision: "allow", agent: "agent-drawn-poll" }],
    });

    const dash = await openDashboard(fresh, "fleet");
    await expect(dash.locator("#f-roster")).toContainText("Polled device", { timeout: 20_000 });
    await dash.waitForTimeout(2000);
    const after = await pulseMarks(dash);

    // Two full poll cycles with nothing new. The mark must not move.
    await dash.waitForTimeout(34_000);
    expect(
      await pulseMarks(dash),
      "a repeat poll ticked the live mark, which makes it a heartbeat rather than an event",
    ).toBe(after);

    // CONTROL: genuinely new activity DOES move it, so the assertion above
    // is not passing against a mark that can never move at all.
    net.clearEndpoints();
    net.addEndpoint({
      agent: "agent-drawn-poll", address: "2a04:2a01:d4:2::1", label: "Polled device",
      device: true, counters: { dns_queries: 13 },
      logs: [
        { ts: t0 - 60_000, kind: "dns", qname: `${GOOD}.`, qtype: "A", decision: "allow", agent: "agent-drawn-poll" },
        { ts: Date.now(), kind: "dns", qname: `${SECOND}.`, qtype: "A", decision: "allow", agent: "agent-drawn-poll" },
      ],
    });
    await expect.poll(() => pulseMarks(dash), { timeout: 30_000 }).toBeGreaterThan(after);
    await dash.close();
  } finally {
    await fresh.close();
    net.clearEndpoints();
  }
});

// ===========================================================================
// The primitives refuse rather than lie
// ===========================================================================

test("a mark is absent when the measurement is, never drawn empty", async () => {
  // The donut, the time strip and the concentration bar all refuse to
  // render without enough real data. The failure mode they exist to
  // prevent is a chart of nothing that looks like a chart of something,
  // which on a security surface reads as "we looked and it was fine".
  const fresh = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  try {
    await setKey(fresh, MOCK_KEY);
    net.clearEndpoints();
    net.addEndpoint({
      agent: "agent-drawn-quiet", address: "2a04:2a01:d4:1::1", label: "Quiet device",
      device: true, counters: { dns_queries: 0 }, logs: [],
    });
    const dash = await openDashboard(fresh, "fleet");
    await expect(dash.locator("#f-roster")).toContainText("Quiet device", { timeout: 20_000 });
    // An endpoint exists, so the page says THAT rather than "no endpoints",
    // and draws no donut, no strip and no join for the traffic it has not
    // seen.
    await expect(dash.locator("#f-nodata")).toContainText("none of them seen going anywhere");
    await expect(dash.locator("#f-donut svg")).toHaveCount(0);
    await expect(dash.locator("#f-when svg")).toHaveCount(0);
    await expect(dash.locator("#f-join svg")).toHaveCount(0);
    await dash.close();
  } finally {
    await fresh.close();
    net.clearEndpoints();
  }
});
