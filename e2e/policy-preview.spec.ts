// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE CONSEQUENCE OF A SETTING, proven.
//
// A protection preset that cannot show what it would change is a checkbox
// asking to be trusted. This suite asserts the four claims the new governor
// preview makes, each with a control that fails if the guard is removed:
//
//   1. the counts are a MEASUREMENT (the same page against different graph
//      facts produces different numbers, so nothing here can be hardcoded)
//   2. a destination the graph holds no record of is counted SEPARATELY and
//      never folded into the clean side
//   3. the one protection that cannot be previewed says so and names the
//      call it would need, instead of reporting a zero it never measured
//   4. a read that FAILED renders as "not checked", never as "nothing
//      matched" - the error that renders as an empty state, refused
//
//   npx playwright test e2e/policy-preview.spec.ts

import { test, expect } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, openDashboard, setKey, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.graphMode = "mock";
  net.failQueries.clear();
  net.clearEndpoints();
  net.clearLog();
  await setKey(ext, MOCK_KEY);
});

/**
 * Seed one destination end to end: enrichment (so the ledger and the country
 * pills have something to draw) and, optionally, its protection facts.
 *
 * Passing no facts is the point of the third state: the graph is asked about
 * the name and answers with NO ROW, exactly as it does for a name it has
 * never seen.
 */
function seedHost(
  host: string,
  country: string,
  facts?: Parameters<E2ENetwork["setPolicyFacts"]>[1],
  verdict?: Parameters<E2ENetwork["setVerdict"]>[1],
): void {
  net.setVerdict(host, verdict ?? { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setEnrich(host, {
    ip: "203.0.113.7",
    city: "Somewhere",
    country,
    asn: "AS64500",
    owner: "Seeded Operator",
    asnName: "SEEDED - Seeded Operator",
    verdict: "NONE",
    prefix: "203.0.113.0/24",
  });
  if (facts) net.setPolicyFacts(host, facts);
}

function logsFor(agent: string, hosts: string[]): Record<string, unknown>[] {
  return hosts.map((h, i) => ({
    ts: Date.now() - (i + 1) * 1000,
    kind: "dns",
    qname: `${h}.`,
    qtype: "A",
    decision: "allow",
    agent,
  }));
}

// ------------------------------------------- 1 + 2: a real measurement

test("a preset shows what it would block on this endpoint's own traffic, and never counts an unknown as clean", async () => {
  const AGENT = "agent-e2eprev1";
  const TOR = "prev1-tor-guard-e2e.com";
  const BAD_NET = "prev1-bpnet-guard-e2e.com";
  const CLEAN = "prev1-clean-guard-e2e.com";
  const UNSEEN = "prev1-unseen-guard-e2e.com";

  seedHost(TOR, "DE", { tor: true, countries: ["DE"] });
  // Bulletproof is decided by the ASSESS verdict, because that is what the
  // resolver asks. Putting the marker in sub_labels rather than the label
  // exercises the same three-field search enforcement performs.
  seedHost(BAD_NET, "DE", { countries: ["DE"] }, {
    band: "HIGH", coverage: "partial", label: "suspicious", subLabels: ["bulletproof-hosting"],
  });
  seedHost(CLEAN, "US", { countries: ["US"] });
  // UNSEEN gets enrichment but NO protection facts: the graph answers the
  // batch cleanly and simply has no row for it.
  net.setEnrich(UNSEEN, { ip: "203.0.113.9", country: "US", asn: "AS64500", owner: "Seeded Operator", verdict: "UNKNOWN" });

  net.addEndpoint({
    agent: AGENT,
    address: "2a04:2a01:e2e:9::1",
    label: "Preview phone",
    device: true,
    counters: { dns_queries: 1200, dns_blocked: 40, dns_nxdomain: 12, connections_total: 8, bytes_up: 2048, bytes_down: 8192, last_seen: Date.now() },
    logs: logsFor(AGENT, [TOR, BAD_NET, CLEAN, UNSEEN]),
  });

  const dash = await openDashboard(ext, "endpoint");
  await expect(dash.locator("#g-body")).toBeVisible({ timeout: 15_000 });

  // The headline: four destinations, three of them in the graph, one not.
  const cons = dash.locator("#g-consequence");
  await expect(cons).toContainText("3 destinations checked", { timeout: 15_000 });
  await expect(cons).toContainText("1 of them are not in the graph at all");
  await expect(cons).toContainText("not counted as clear");
  // And it is DRAWN: the three-way split is a bar, not a sentence.
  await expect(dash.locator("#g-cons-mark svg")).toHaveCount(1);

  // Strict turns on every protection, so it matches the Tor destination and
  // the badly-hosted one. It says "at least" because one of its protections
  // (brand-new domains) could not be previewed at all.
  const strict = dash.locator(".preset-card", { hasText: "Strict" });
  await expect(strict).toHaveCount(1);
  await expect(strict).toContainText("blocks at least 2 of the 3 checked");
  await expect(strict).toContainText("1 not in the graph");

  // Standard is threat lists + bulletproof only: one match, and no floor
  // marker, because both of its protections WERE previewed.
  const standard = dash.locator(".preset-card", { hasText: "Standard" });
  await expect(standard).toContainText("blocks 1 of the 3 checked");
  await expect(standard).not.toContainText("at least");

  // Open turns everything off, so it is the control on the arithmetic: the
  // same destinations, the same page, and a count that must be zero.
  await expect(dash.locator(".preset-card", { hasText: "Open" })).toContainText("blocks none of the 3 checked");

  // Per-protection: the Tor row names the ONE destination it matched, and
  // names it correctly. A count with no receipts is just a smaller promise.
  const torRow = dash.locator(".bundle-row", { hasText: "Tor exit relays" });
  await expect(torRow).toContainText("1 of 3 checked, 1 not in the graph");
  await torRow.locator("details summary").click();
  await expect(torRow.locator(".b-hit-host")).toHaveText(TOR);
  await expect(torRow.locator(".b-hit-why")).toContainText("Tor exit relay");

  const bpRow = dash.locator(".bundle-row", { hasText: "Bulletproof hosting" });
  await expect(bpRow).toContainText("1 of 3 checked");
  await bpRow.locator("details summary").click();
  await expect(bpRow.locator(".b-hit-host")).toHaveText(BAD_NET);
  await expect(bpRow.locator(".b-hit-why")).toContainText("bulletproof-hosting");

  // The clean destination is on nobody's list, and the UNSEEN one is on
  // nobody's list either - which is the whole point: it is in neither the
  // matched set nor the clear count.
  await expect(dash.locator(".b-hit-host", { hasText: UNSEEN })).toHaveCount(0);
  await expect(dash.locator(".b-hit-host", { hasText: CLEAN })).toHaveCount(0);

  await dash.close();
});

// ------------------------------ 1 (control): different facts, different numbers

test("with nothing on the graph's lists, the same surface draws zero rather than a remembered count", async () => {
  const AGENT = "agent-e2eprev2";
  const A = "prev2-a-guard-e2e.com";
  const B = "prev2-b-guard-e2e.com";
  // Fresh names: the background caches protection facts per host, so reusing
  // the first test's hostnames would measure its answers, not these.
  seedHost(A, "SE", { countries: ["SE"] });
  seedHost(B, "SE", { countries: ["SE"] });

  net.addEndpoint({
    agent: AGENT,
    address: "2a04:2a01:e2e:9::2",
    label: "Quiet laptop",
    device: true,
    logs: logsFor(AGENT, [A, B]),
  });

  const dash = await openDashboard(ext, "endpoint");
  await expect(dash.locator("#g-body")).toBeVisible({ timeout: 15_000 });
  const cons = dash.locator("#g-consequence");
  await expect(cons).toContainText("Nothing currently on blocks any of the 2 destinations checked", { timeout: 15_000 });
  // Two destinations, both answered for, so the prose carries no unknown
  // clause. (The drawn bar always names its third segment in its own title,
  // which is what makes the mark readable to a screen reader; the assertion
  // is therefore against the sentence, not against the whole row.)
  await expect(dash.locator("#g-cons-note")).not.toContainText("not in the graph");
  // "None" is only claimed over the protections that could be previewed:
  // Strict includes one that cannot, so its zero carries that caveat.
  await expect(dash.locator(".preset-card", { hasText: "Strict" })).toContainText(
    "blocks none of the 2 checked (one protection not previewed)",
  );
  await expect(dash.locator(".bundle-row", { hasText: "Tor exit relays" })).toContainText("0 of 2 checked");
  await expect(dash.locator(".b-hits")).toHaveCount(0);
  await dash.close();
});

// ---------------------------------- 3: the protection that cannot be previewed

test("the protection that cannot be previewed says so and names the call it would need", async () => {
  const AGENT = "agent-e2eprev3";
  const A = "prev3-a-guard-e2e.com";
  seedHost(A, "NL", { countries: ["NL"] });
  net.addEndpoint({
    agent: AGENT, address: "2a04:2a01:e2e:9::3", label: "Preview desk", device: true,
    logs: logsFor(AGENT, [A]),
  });

  const dash = await openDashboard(ext, "endpoint");
  const row = dash.locator(".bundle-row", { hasText: "Brand-new domains" });
  await expect(row).toContainText("not previewed", { timeout: 15_000 });
  await expect(row).toContainText("whisper.history");
  await expect(row).toContainText("one graph call per destination");
  // It reports itself as unpreviewed rather than as a zero: no "of N checked"
  // count anywhere on that row.
  await expect(row).not.toContainText("of 1 checked");

  // And the label under the checkbox states the window the ENGINE actually
  // uses. It said 24 hours while the resolver tested 30 days, which is a
  // switch quietly doing thirty times more than its own description.
  await expect(row).toContainText("last 30 days");
  await expect(row).not.toContainText("24 hours");
  await dash.close();
});

// ------------------------------- 4: a failed read is a failed read

test("when the check itself fails, the surface says not checked and never says nothing matched", async () => {
  const AGENT = "agent-e2eprev4";
  const A = "prev4-a-guard-e2e.com";
  const B = "prev4-b-guard-e2e.com";
  seedHost(A, "FR", { tor: true, countries: ["FR"] });
  seedHost(B, "FR", { countries: ["FR"] });
  // A PARTIAL outage: this one query 500s while enrichment and the control
  // plane answer normally. That is the state that produces a plausible-
  // looking empty page in a product that treats an error as an answer.
  net.failQueries.add("rpkiStatus");

  net.addEndpoint({
    agent: AGENT, address: "2a04:2a01:e2e:9::4", label: "Offline-graph phone", device: true,
    logs: logsFor(AGENT, [A, B]),
  });

  const dash = await openDashboard(ext, "endpoint");
  await expect(dash.locator("#g-body")).toBeVisible({ timeout: 15_000 });
  const cons = dash.locator("#g-consequence");
  await expect(cons).toContainText("could not be checked against your traffic", { timeout: 15_000 });
  await expect(cons).toContainText("it is claiming that we could not find out");
  // The two sentences that would be lies here, refused explicitly.
  await expect(cons).not.toContainText("Nothing currently on blocks");
  await expect(cons).not.toContainText("are not in the graph at all");

  const torRow = dash.locator(".bundle-row", { hasText: "Tor exit relays" });
  await expect(torRow).toContainText("not checked:");
  await expect(torRow).not.toContainText("0 of");
  await expect(torRow).not.toContainText("are in the graph");

  // CONTROL: the same fixture with the outage lifted DOES find the Tor
  // destination, so the assertions above are measuring the failure path and
  // not a surface that never works.
  net.failQueries.clear();
  const AGENT2 = "agent-e2eprev4b";
  const C = "prev4-c-guard-e2e.com";
  seedHost(C, "FR", { tor: true, countries: ["FR"] });
  net.addEndpoint({
    agent: AGENT2, address: "2a04:2a01:e2e:9::5", label: "Recovered phone", device: true,
    logs: logsFor(AGENT2, [C]),
  });
  const dash2 = await openDashboard(ext, "endpoint");
  await dash2.locator("#e-picker").selectOption(AGENT2);
  await expect(dash2.locator(".bundle-row", { hasText: "Tor exit relays" })).toContainText("1 of 1 checked", {
    timeout: 15_000,
  });
  await dash2.close();
  await dash.close();
});

// -------------------------- the country blocker, over real destinations

test("the country blocker offers the countries this endpoint actually reaches, with the price of each", async () => {
  const AGENT = "agent-e2eprev5";
  const D1 = "prev5-de1-guard-e2e.com";
  const D2 = "prev5-de2-guard-e2e.com";
  const U1 = "prev5-us1-guard-e2e.com";
  seedHost(D1, "DE", { countries: ["DE"] });
  seedHost(D2, "DE", { countries: ["DE"] });
  // THE EVASION. This destination lands in the United States AND Germany at
  // once, which is the ordinary case for anything behind a CDN. A preview
  // that reads one country per name calls it American, reports that blocking
  // Germany costs two destinations, and is wrong by one: enforcement fires on
  // ANY resolved country, so blocking Germany stops this one too.
  seedHost(U1, "US", { countries: ["US", "DE"] });

  net.addEndpoint({
    agent: AGENT, address: "2a04:2a01:e2e:9::6", label: "Travelling laptop", device: true,
    logs: logsFor(AGENT, [D1, D2, U1]),
  });

  const dash = await openDashboard(ext, "endpoint");
  await expect(dash.locator("#g-body")).toBeVisible({ timeout: 15_000 });
  const suggest = dash.locator("#g-geo-suggest");
  await expect(suggest).toBeVisible({ timeout: 15_000 });
  await expect(suggest).toContainText("3 of 3 destinations placed");

  // THREE, not two: the dual-country destination is counted under Germany as
  // well as the United States, because blocking either one stops it.
  const de = suggest.locator(".geo-pill", { hasText: "Germany" });
  await expect(de).toHaveCount(1);
  await expect(de.locator(".gp-count")).toHaveText("3");
  await expect(suggest.locator(".geo-pill", { hasText: "United States" }).locator(".gp-count")).toHaveText("1");

  // One click blocks it, and the write is a real op:policy carrying geo:deny.
  await de.click();
  await expect(dash.locator("#g-geo-chips")).toContainText("DE", { timeout: 15_000 });
  expect(net.endpoints.find((e) => e.agent === AGENT)?.policy?.bundles).toContain("geo:deny:DE");
  // All THREE stop resolving, and the one a reader thinks of as American is
  // told exactly why it is on the list.
  await expect(dash.locator("#g-geo-cost")).toContainText("3 of 3 checked");
  await dash.locator("#g-geo-cost details summary").click();
  await expect(dash.locator("#g-geo-cost .b-hit", { hasText: U1 })).toContainText("resolves in DE (also US)");
  await dash.close();
});

// ----------------------------------------- the counters carry their whole

test("endpoint counters are drawn against the total they came out of", async () => {
  const AGENT = "agent-e2eprev6";
  net.addEndpoint({
    agent: AGENT, address: "2a04:2a01:e2e:9::7", label: "Counted phone", device: true,
    counters: { dns_queries: 1200, dns_blocked: 40, dns_nxdomain: 12, connections_total: 8, bytes_up: 2048, bytes_down: 8192, last_seen: Date.now() },
    logs: [],
  });
  const dash = await openDashboard(ext, "endpoint");
  await expect(dash.locator("#e-tiles")).toContainText("40 of 1200 lookups", { timeout: 15_000 });
  await expect(dash.locator("#e-tiles")).toContainText("12 of 1200 lookups");
  await expect(dash.locator("#e-tiles")).toContainText("of 10.0 KB moved");
  // Drawn, not only written: each proportion carries its own mark.
  expect(await dash.locator("#e-tiles .tile-mark svg").count()).toBeGreaterThanOrEqual(4);
  await dash.close();
});
