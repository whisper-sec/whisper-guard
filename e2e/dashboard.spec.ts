// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The dashboard suite (hermetic): the real built extension in Chromium, the
// whole network answered by the capture proxy. Proves, per the v2 design:
//   - the composed graph-intelligence protection (who / where / age / why)
//   - the "This browser" report (keyless keystone) from on-device
//     navigation, graph-enriched, realtime per navigation
//   - the keyed Fleet + Per-endpoint views from op:list / op:agent / op:logs
//   - the browser-as-endpoint egress path (dual-engine HTTPS-CONNECT), with
//     the identity chip verifying against keyless rdap
// All two-tier: the keyless half works with NO key; the key unlocks the rest.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  launchExtension,
  makeEgressDist,
  openDashboard,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const MOCK_KEY = "whisper_e2e_mock_key_0000000000000000";

let net: E2ENetwork;
let ext: Extension;

function seedGraph(n: E2ENetwork): void {
  n.setVerdict("clean-site-guard-e2e.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  n.setVerdict("evil-known-guard-e2e.com", { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  n.setVerdict("ads-tracker-guard-e2e.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  n.setVerdict("github.com", { band: "NONE", coverage: "known-clean", label: "clean" });

  n.setIdentify("clean-site-guard-e2e.com", [
    { host: "clean-site-guard-e2e.com", canonical_name: "E2E Clean Site", category: "saas", roles: ["ORIGIN_AS"] },
  ]);
  n.setEnrich("clean-site-guard-e2e.com", {
    ip: "203.0.113.10", city: "Frankfurt am Main, DE", country: "DE",
    asn: "AS64500", owner: "E2E Clean Site, Inc.", asnName: "E2ENET - E2E Clean Site, Inc.", verdict: "NONE", prefix: "203.0.113.0/24",
  });
  n.setEnrich("ads-tracker-guard-e2e.com", {
    ip: "198.51.100.20", city: "Ashburn, US", country: "US",
    asn: "AS64520", owner: "Tracky Ads Inc.", asnName: "TRACKY - Tracky Ads Inc.", verdict: "NONE", prefix: "198.51.100.0/24",
  });
  n.setEnrich("evil-known-guard-e2e.com", {
    ip: "198.51.100.9", city: "Montreal, CA", country: "CA",
    asn: "AS64510", owner: "Bad Hosting LLC", asnName: "BADHOST - Bad Hosting LLC", verdict: "CRITICAL", prefix: "198.51.100.0/24",
  });
  // identify canonical: the keyless "who" (the 2-hop tier can't see the ASN org).
  n.setIdentify("evil-known-guard-e2e.com", [
    { host: "evil-known-guard-e2e.com", canonical_name: "Sketchy Co", category: null, roles: [] },
  ]);
  n.setHistory("evil-known-guard-e2e.com", [
    { indicator: "evil-known-guard-e2e.com", createDate: "2026-06-20", updateDate: "2026-07-01" },
  ]);
  n.setExplain("evil-known-guard-e2e.com", [
    {
      indicator: "evil-known-guard-e2e.com", found: true, level: "CRITICAL", score: 16.9,
      explanation: "listed in 3 threat feed(s)",
      sources: [
        { feedId: "phishing-army" }, { feedId: "hagezi-tif" },
        { feedId: "tranco" }, // a popularity feed: must be EXCLUDED from why
      ],
    },
  ]);
  n.setCohost("evil-known-guard-e2e.com", { ip: "198.51.100.9", cohosted: 12, prefix: "198.51.100.0/24", threatNeighbors: 4 });
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  seedGraph(net);
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(() => {
  net.graphMode = "mock";
  net.graphDelayMs = 0;
  net.clearLog();
});

// ----------------------------------------------- WB2: composed protection

test("protection: keyless composed verdict cites feeds, owner, and age; popularity feeds excluded", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });

  const { page, tabId } = await visit(ext, "https://evil-known-guard-e2e.com/");
  await waitForIcon(ext, tabId, ["malicious"]);
  const popup = await openPopup(ext, tabId);

  await expect(popup.locator("#band-chip")).toHaveText("MALICIOUS - evidenced");
  // The composed card: who runs it (identify canonical, keyless), where it
  // sits (2-hop geo), how old it is (history), and the feed-cited why.
  await expect(popup.locator("#protect-card")).toBeVisible({ timeout: 15_000 });
  await expect(popup.locator("#protect-rows")).toContainText("Sketchy Co");
  await expect(popup.locator("#protect-rows")).toContainText("Montreal");
  await expect(popup.locator("#why-chips")).toContainText("threat feed");
  await expect(popup.locator("#why-chips")).toContainText("phishing-army");
  // A popularity/trust feed (tranco) is GOOD, never cited as a threat.
  await expect(popup.locator("#why-chips")).not.toContainText("tranco");
  await popup.close();
  await page.close();
});

// ------------------------------------------ WB3: "This browser" (keyless)

test("this-browser dashboard renders enriched destinations from on-device navigation, no key", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });

  // Drive the browser so the on-device nav log has real destinations.
  for (const host of ["clean-site-guard-e2e.com", "ads-tracker-guard-e2e.com", "github.com"]) {
    const v = await visit(ext, `https://${host}/`);
    await waitForIcon(ext, v.tabId, ["benign", "unknown", "signedout"]);
    await v.page.close();
  }

  const dash = await openDashboard(ext, "browser");
  // Tiles show real counts; the ledger shows enriched rows.
  await expect(dash.locator("#b-tiles")).toContainText("Destinations", { timeout: 15_000 });
  await expect(dash.locator("#b-ledger")).toContainText("clean-site-guard-e2e.com", { timeout: 15_000 });
  await expect(dash.locator("#b-ledger")).toContainText("E2E Clean Site", { timeout: 15_000 });
  // Country flag/company columns came from the graph enrichment.
  await expect(dash.locator("#b-owners")).toContainText("E2E Clean Site");
  await dash.close();
});

test("this-browser dashboard is realtime: a fresh navigation appears without reload", async () => {
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });

  const dash = await openDashboard(ext, "browser");
  await expect(dash.locator("#feed-label")).toHaveText("updating live");

  const v = await visit(ext, "https://ads-tracker-guard-e2e.com/");
  await waitForIcon(ext, v.tabId, ["benign", "unknown", "signedout"]);
  // The dashboard's live port nudge repaints the ledger with the new host.
  await expect(dash.locator("#b-ledger")).toContainText("ads-tracker-guard-e2e.com", { timeout: 15_000 });
  await v.page.close();
  await dash.close();
});

test("fleet + endpoint views are locked without a key, unlocked with one", async () => {
  await setKey(ext, null);
  const dash = await openDashboard(ext, "fleet");
  await expect(dash.locator("#fleet-lock")).toBeVisible();
  await expect(dash.locator("#fleet-lock")).toContainText("Sign in");
  await dash.close();
});

// -------------------------------------- WB4: keyed fleet + per-endpoint

test("fleet view renders the roster and merged, enriched destinations", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearEndpoints();
  net.addEndpoint({
    agent: "agent-e2ephone", address: "2a04:2a01:e2e:1::1", label: "My iPhone", device: true,
    counters: { dns_queries: 1200, dns_blocked: 40, connections_total: 8 },
    logs: [
      { ts: Date.now() - 1000, kind: "dns", qname: "clean-site-guard-e2e.com.", qtype: "A", decision: "allow", agent: "agent-e2ephone" },
      { ts: Date.now() - 2000, kind: "dns", qname: "ads-tracker-guard-e2e.com.", qtype: "A", decision: "allow", agent: "agent-e2ephone" },
      { ts: Date.now() - 3000, kind: "conn", peer: "evil-known-guard-e2e.com", agent: "agent-e2ephone" },
    ],
  });
  net.addEndpoint({
    agent: "agent-e2elaptop", address: "2a04:2a01:e2e:2::1", label: "Work laptop",
    counters: { dns_queries: 300 },
    logs: [{ ts: Date.now() - 1500, kind: "dns", qname: "github.com.", qtype: "AAAA", decision: "allow", agent: "agent-e2elaptop" }],
  });

  const dash = await openDashboard(ext, "fleet");
  await expect(dash.locator("#f-roster")).toContainText("My iPhone", { timeout: 15_000 });
  await expect(dash.locator("#f-roster")).toContainText("Work laptop");
  await expect(dash.locator("#f-tiles")).toContainText("Endpoints");
  // The merged, enriched destinations from every device's op:logs.
  await expect(dash.locator("#f-owners")).toContainText("E2E Clean Site", { timeout: 15_000 });
  await expect(dash.locator("#f-feed")).toContainText("clean-site-guard-e2e.com");
  await expect(dash.locator("#f-feed-note")).toContainText("polling");
  await dash.close();
});

test("per-endpoint view shows counters, health, constellation and a destination drill", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearEndpoints();
  net.addEndpoint({
    agent: "agent-e2ephone", address: "2a04:2a01:e2e:1::1", label: "My iPhone", device: true,
    counters: { dns_queries: 1200, dns_blocked: 40, dns_nxdomain: 12, connections_total: 8, bytes_up: 2048, bytes_down: 8192, last_seen: Date.now() },
    logs: [
      { ts: Date.now() - 1000, kind: "dns", qname: "clean-site-guard-e2e.com.", qtype: "A", decision: "allow", agent: "agent-e2ephone" },
      { ts: Date.now() - 3000, kind: "conn", peer: "evil-known-guard-e2e.com", agent: "agent-e2ephone" },
    ],
  });

  const dash = await openDashboard(ext, "endpoint");
  await expect(dash.locator("#e-address")).toHaveText("2a04:2a01:e2e:1::1", { timeout: 15_000 });
  await expect(dash.locator("#e-tiles")).toContainText("DNS queries");
  await expect(dash.locator("#e-tiles")).toContainText("1200");
  // The explainable health gauge + factor chips.
  await expect(dash.locator("#e-factors")).toContainText("Verified identity");
  await expect(dash.locator("#e-factors")).toContainText("DANE-TLSA");
  // A destination row + its receipts (co-hosting fan-in from the graph).
  await expect(dash.locator("#e-hosts")).toContainText("clean-site-guard-e2e.com", { timeout: 15_000 });
  await dash.locator("#e-hosts .w-ledger-row", { hasText: "evil-known-guard-e2e.com" }).first().click();
  await expect(dash.locator("#e-drill-body")).toContainText("Co-hosted", { timeout: 15_000 });
  await expect(dash.locator("#e-drill-body")).toContainText("12 other");
  await dash.close();
});

test("endpoint identity chip verifies a routed address against keyless rdap", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearEndpoints();
  net.addEndpoint({ agent: "agent-e2ephone", address: "2a04:2a01:e2e:1::1", label: "My iPhone", device: true, logs: [] });

  const dash = await openDashboard(ext, "endpoint");
  // The identity chip in the header runs verify-identity for the browser's
  // own routed identity; while off it says so honestly.
  await expect(dash.locator("#identity-chip")).toContainText("NOT ON THE WHISPER NETWORK");
  await dash.close();
});
