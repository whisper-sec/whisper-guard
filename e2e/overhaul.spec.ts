// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The overhaul gallery: every surface of the rebuilt Guard, captured from
// the REAL built extension in a REAL browser against the hermetic mock
// network. No real host is contacted and no key appears in any pixel.
//
//   npx playwright test e2e/overhaul.spec.ts
//
// Output: screenshots/overhaul/*.png.
//
// THE DUPLICATE GUARD. Every capture is hashed and the run FAILS if two
// files filed as different states are byte-identical. This exists because
// two captures shipped as "two states" once turned out to be the same
// file, and nothing in the suite noticed: a screenshot test that only
// checks a file was written passes just as happily when the page never
// changed. The guard is itself mutation-tested below, because a guard that
// cannot fail is worse than no guard - it is a guard everybody trusts.

import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import {
  launchExtension,
  makeShieldDist,
  openDashboard,
  openPopup,
  setKey,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(HERE, "../screenshots/overhaul");

const EVIL = "paypa1-secure-login.com";
const GOOD = "news.mediaco-vendor.com";
const NEW = "news-blog-example.com";
/** A name touched by exactly one test, so walking it genuinely SPENDS from
 *  the keyless budget. A name any earlier test has already walked is
 *  memoised and costs nothing, which is the product being right and the
 *  test being naive about it. */
const SPEND = "first-visit-example.com";

let net: E2ENetwork;
let ext: Extension;

// ---------------------------------------------------------- the duplicate guard

/** file name -> sha256 of the bytes actually written. */
const digests = new Map<string, string>();

function recordDigest(file: string): void {
  digests.set(file, createHash("sha256").update(readFileSync(join(SHOTS, file))).digest("hex"));
}

/** Names sharing one digest, i.e. states that are secretly the same picture. */
export function collisions(d: Map<string, string>): string[][] {
  const byHash = new Map<string, string[]>();
  for (const [name, hash] of d) {
    const list = byHash.get(hash) ?? [];
    list.push(name);
    byHash.set(hash, list);
  }
  return [...byHash.values()].filter((names) => names.length > 1);
}

// ------------------------------------------------------------------ fixture

test.beforeAll(async () => {
  mkdirSync(SHOTS, { recursive: true });
  net = new E2ENetwork();
  await net.start();

  // The flagged site, with a full chain behind it: the address, the routed
  // prefix it shares with nine other listed hosts, the network, the operator
  // and the one building that operator is present in.
  //
  // EVERY VALUE ON EVERY RUNG IS INVENTED, and the physical rung is the one
  // that catches people out. Hostnames were already reserved, addresses are
  // RFC 5737 documentation space and the ASNs are private-use - but the
  // first version of this fixture named REAL colocation facilities and REAL
  // internet exchanges, which put a named operator directly under a red
  // CRITICAL badge in a picture bound for two extension stores. A published
  // capture from a security product must not make a factual claim about a
  // real business, and that is the worst one available. The operator is not
  // named here either: restating the claim in searchable prose, in a public
  // repository, is the same claim in a form that indexes. Facilities and
  // exchanges are named the way the reserved domains are: unmistakably
  // examples, and e2e/claims.spec.ts fails the build if one is not.
  net.setVerdict(EVIL, { band: "CRITICAL", coverage: "partial", label: "credential-phishing suspect" });
  net.setEnrich(EVIL, {
    ip: "192.0.2.66",
    city: "Montreal, CA",
    country: "CA",
    asn: "AS64550",
    owner: "Bad Hosting LLC",
    asnName: "BADHOST - Bad Hosting LLC",
    prefix: "192.0.2.0/24",
    threatNeighbors: 9,
    verdict: "CRITICAL",
  });
  net.setPresence("AS64550", { facilities: ["Example Colo MTL1"], exchanges: [], facilityCount: 1 });
  net.setIdentify(EVIL, []);
  net.setExplain(EVIL, [
    {
      indicator: EVIL,
      type: "domain",
      found: true,
      level: "CRITICAL",
      score: 17.2,
      explanation: `${EVIL} is listed in 2 threat feed(s).`,
      sources: [
        { feedId: "openphish", firstSeen: "2026-07-02T00:00:00Z" },
        { feedId: "phishtank", firstSeen: "2026-07-01T00:00:00Z" },
      ],
    },
  ]);
  net.setHistory(EVIL, [{ createDate: "2026-08-19T00:00:00Z", updateDate: "2026-08-19T00:00:00Z" }]);

  // The unremarkable site, which is the case that has to justify the panel:
  // nothing is wrong, and the chain is still worth reading.
  net.setVerdict(GOOD, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setEnrich(GOOD, {
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
  net.setIdentify(GOOD, [
    {
      host: GOOD,
      canonical_name: "MediaCo",
      category: "media",
      roles: ["DNS_OPERATOR", "ORIGIN_AS"],
      confidence: 0.85,
      host_class: "single_tenant",
      evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco", "band=DERIVED"],
    },
  ]);
  net.setDensity("AS64540", { listedIps: 5, announcedIpv4: 9216, routedPrefixes: 24 });
  net.setPresence("AS64540", {
    facilities: ["Example Carrier Hotel LON1", "Example Colo LON2", "Example Halls LON3"],
    exchanges: ["Example Exchange LON", "Example Peering Point"],
    facilityCount: 14,
    exchangeCount: 4,
  });
  net.setExplain(GOOD, [
    {
      indicator: GOOD,
      type: "domain",
      found: true,
      level: "NONE",
      score: 0,
      explanation: "Not listed in any threat intelligence feed",
      sources: [{ feedId: "tranco", firstSeen: "2026-01-01T00:00:00Z" }],
    },
  ]);

  // The name the graph has never seen: the honest common state, and the one
  // that must never read as green.
  net.setVerdict(NEW, { band: "UNKNOWN", coverage: "no-data", label: null });
  net.setVerdict(SPEND, { band: "UNKNOWN", coverage: "no-data", label: null });

  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

// -------------------------------------------------------------------- helpers

async function popupShot(
  tabId: number,
  file: string,
  scheme: "dark" | "light",
  prep?: (p: import("@playwright/test").Page) => Promise<void>,
): Promise<void> {
  const popup = await openPopup(ext, tabId);
  // reducedMotion, and applied BEFORE the page's scripts run.
  //
  // The chain arrives rung by rung and the graph scale counts up, so a still
  // capture of a moving surface freezes a random animation phase. Emulating
  // after navigation is too late: the count-up had already started under
  // full motion, and a capture taken 600ms later published "7.46B nodes"
  // for a fixture that holds 7.48B - a figure that was never true, in a
  // picture of a security product, about its own coverage. Reloading with
  // the media state already set makes the page take its own reduced-motion
  // path, which writes every final value immediately.
  await popup.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
  await popup.setViewportSize({ width: 400, height: 720 });
  await popup.reload();
  // The chain is two rounds of graph calls deep; wait for the spine to stop
  // being a placeholder rather than for a fixed number of milliseconds.
  await popup.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 15_000 }).catch(() => undefined);
  await popup.waitForTimeout(500);
  // The scale is the one number on the panel that animates, so it is the
  // one that can be captured half-written. Pin it: whatever it says must be
  // a settled value, not a frame of a transition.
  const settled = await popup
    .locator("#scale-nodes")
    .textContent()
    .catch(() => null);
  if (settled !== null) {
    await popup.waitForTimeout(400);
    const again = await popup.locator("#scale-nodes").textContent();
    expect(again, `the graph scale was still animating when ${file} was captured`).toBe(settled);
  }
  if (prep) await prep(popup);
  await assertScheme(popup, scheme, file);
  await popup.screenshot({ path: join(SHOTS, file), fullPage: true });
  await popup.close();
  recordDigest(file);
}

async function assertScheme(
  page: import("@playwright/test").Page,
  scheme: "dark" | "light",
  file: string,
): Promise<void> {
  const luminance = await page.evaluate(() => {
    const c = getComputedStyle(document.body).backgroundColor;
    const m = c.match(/-?[\d.]+/g) ?? ["255", "255", "255"];
    const scale = c.startsWith("color(") ? 255 : 1;
    const [r, g, b] = m.slice(0, 3).map((v) => Number(v) * scale);
    const f = (v: number): number => {
      const x = v / 255;
      return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * f(r!) + 0.7152 * f(g!) + 0.0722 * f(b!);
  });
  if (scheme === "dark") {
    expect(luminance, `${file} is filed as dark but its ground is light`).toBeLessThan(0.15);
  } else {
    expect(luminance, `${file} is filed as light but its ground is dark`).toBeGreaterThan(0.3);
  }
}

// --------------------------------------------------------------------- captures

test("the panel on a flagged site, both schemes", async () => {
  const { page, tabId } = await visit(ext, `https://${EVIL}/signin`);
  await waitForIcon(ext, tabId, ["malicious"]);
  await popupShot(tabId, "panel-flagged-dark.png", "dark");
  await popupShot(tabId, "panel-flagged-light.png", "light");
  await page.close();
});

test("the panel on an ordinary site: the chain is the reason to open it", async () => {
  const { page, tabId } = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await popupShot(tabId, "panel-ordinary-dark.png", "dark");
  await popupShot(tabId, "panel-ordinary-light.png", "light");
  await page.close();
});

test("a rung expanded: the graph's own measurement behind the network", async () => {
  const { page, tabId } = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await popupShot(tabId, "chain-expanded-dark.png", "dark", async (pop) => {
    await pop.locator("#chain-mount .ch-rung").filter({ hasText: "NETWORK" }).click();
    await pop.locator(".ch-detail .ch-ratio").waitFor({ timeout: 15_000 });
    await pop.waitForTimeout(700);
  });
  await page.close();
});

test("the panel on a name the graph has never seen", async () => {
  const { page, tabId } = await visit(ext, `https://${NEW}/`);
  await waitForIcon(ext, tabId, ["unknown"]);
  await popupShot(tabId, "panel-unknown-dark.png", "dark");
  await page.close();
});

test("the keyless tier meter is a measurement, not a pitch", async () => {
  // Nearly spent: the meter has to be able to say so, and to look different
  // when it does. Both captures are of the same page in the same scheme, so
  // if the meter did not move they collide and the duplicate guard fires.
  const { page, tabId } = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  await popupShot(tabId, "tier-healthy-dark.png", "dark", async (pop) => {
    // Assert the figure, not just the pixels: a capture proves a meter was
    // drawn, never that it was drawn from a measurement.
    await expect(pop.locator("#tier-count")).toHaveText(/94 of 100/);
  });

  net.quota["hourlyRemaining"] = 4;
  net.quota["dailyRemaining"] = 41;
  // SPEND from the budget, the way a reader does: a name the panel has not
  // walked before costs a real chain walk. The quota memo is invalidated by
  // spending rather than by the clock (a remembered "94 left" is wrong by
  // seven the moment a walk runs), so without this the second capture would
  // honestly show the first figure - and the duplicate guard would say so.
  const { page: spender, tabId: spendTab } = await visit(ext, `https://${SPEND}/`);
  await waitForIcon(ext, spendTab, ["unknown"]);
  const warm = await openPopup(ext, spendTab);
  await warm.locator("#chain-mount .ch-rung").first().waitFor({ timeout: 15_000 });
  await warm.waitForTimeout(600);
  await warm.close();
  await spender.close();

  await popupShot(tabId, "tier-nearly-spent-dark.png", "dark", async (pop) => {
    await expect(pop.locator("#tier-count")).toHaveText(/4 of 100/);
    await expect(pop.locator("#tier-fill")).toHaveClass(/out|low/);
  });
  net.quota["hourlyRemaining"] = 94;
  await page.close();
});

test("the panel signed in but not yet enrolled: the state a new account lands in", async () => {
  const now = Date.now();
  net.addEndpoint({
    agent: "agent-shotlaptop",
    address: "2a04:2a01:5ec5:2::b2",
    label: "This browser",
    device: true,
    created: now - 6 * 86_400_000,
    counters: { dns_queries: 2210, dns_blocked: 18, connections_total: 30, last_seen: now - 4 * 60_000 },
    logs: [],
  });
  await setKey(ext, MOCK_KEY);
  const { page, tabId } = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, tabId, ["benign"]);
    // Named for what it IS. A roster entry is not an enrolment: the control
  // reads this browser's own local identity record, which a signed-in
  // reader does not have until they press the button. The ENROLLED state,
  // with the /128, its reverse-DNS name and the RDAP proof link, is
  // captured by e2e/protect.spec.ts, which walks the real enrol flow.
  await popupShot(tabId, "panel-signedin-not-enrolled-dark.png", "dark", async (pop) => {
    await expect(pop.locator("#identity-card")).toBeVisible();
  });
  await page.close();
  await setKey(ext, null);
});

test("the dashboard, both schemes", async () => {
  const { page: site, tabId } = await visit(ext, `https://${GOOD}/`);
  await waitForIcon(ext, tabId, ["benign"]);
  const { page: evil, tabId: evilTab } = await visit(ext, `https://${EVIL}/`);
  await waitForIcon(ext, evilTab, ["malicious"]);

  for (const scheme of ["dark", "light"] as const) {
    const dash = await openDashboard(ext);
    await dash.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await dash.setViewportSize({ width: 1280, height: 900 });
    await dash.locator("#scale-band:not([hidden])").waitFor({ timeout: 15_000 });
    // Open the join path behind the flagged destination, so the capture
    // shows the thing the ledger is actually for rather than a closed list.
    await dash.locator(`.w-ledger-row.expandable:has-text("${EVIL}")`).first().click();
    await dash.locator(".ledger-chain .ch-rung.ch-live").first().waitFor({ timeout: 15_000 });
    await dash.waitForTimeout(900);

    // Whatever the tier meter says here, it has to be a MEASUREMENT. An
    // earlier test in this file drives the mock's budget down and restores
    // it; if a memo carried the low figure across, a published screenshot
    // of the product would show a reader a budget that was never theirs.
    await expect(
      dash.locator("#tier-count"),
      "the dashboard's tier meter is showing a remembered figure, not a measured one",
    ).toHaveText(/94 of 100/);

    // A sticky topbar and a full-page capture do not mix: Playwright scrolls
    // and stitches, so the header is painted wherever it happened to be and
    // lands across the middle of the picture, over the card it is covering.
    // Pinning it for the capture shows the page as a reader sees it at the
    // top, which is the only position the header is ever actually in.
    await dash.addStyleTag({ content: ".topbar { position: static !important; }" });
    await dash.evaluate(() => window.scrollTo(0, 0));
    await dash.waitForTimeout(150);

    const file = `dashboard-${scheme}.png`;
    await assertScheme(dash, scheme, file);
    await dash.screenshot({ path: join(SHOTS, file), fullPage: true });
    await dash.close();
    recordDigest(file);
  }
  await evil.close();
  await site.close();
});

// ------------------------------------------------------- the guard, and its control

test("no two captures are the same picture", () => {
  // CONTROL FIRST. A duplicate detector that cannot detect a duplicate
  // passes every run and proves nothing, so feed it a known collision and
  // require it to find exactly that one. If this line ever stops failing on
  // a planted duplicate, the assertion below is decoration.
  const planted = new Map([
    ["a.png", "same"],
    ["b.png", "same"],
    ["c.png", "different"],
  ]);
  expect(collisions(planted)).toEqual([["a.png", "b.png"]]);

  // The real check, over everything this file wrote.
  expect(digests.size, "no captures were recorded; the gallery run did not happen").toBeGreaterThan(6);
  const dupes = collisions(digests);
  expect(
    dupes,
    `these captures are filed as different states but are byte-identical: ${dupes
      .map((g) => g.join(" == "))
      .join(" ; ")}`,
  ).toEqual([]);

  // Write the manifest beside the pictures, so the checksums ship with them
  // and a later reviewer can re-run the same arithmetic.
  const lines = [...digests.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, hash]) => `${hash}  ${name}`);
  writeFileSync(join(SHOTS, "SHA256SUMS"), `${lines.join("\n")}\n`);
});
