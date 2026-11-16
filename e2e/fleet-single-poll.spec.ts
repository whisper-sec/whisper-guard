// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// With the Fleet view open and signed in, the control plane is read once per
// refresh period, not twice: the worker's poll is the single source and the
// page shows what it produced.

import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_CONTROL_HOST, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { launchExtension, openDashboard, setKey, setSettings, type Extension } from "./helpers/extension";

// The worker's poll period while a dashboard is open (POLL_OPEN_MS).
const REFRESH_MS = 12_000;
// Past the first 30 s alarm tick, so the alarm is shown not to add a read.
const WINDOW_MS = 36_000;
const ALARM_MS = 30_000;

let net: E2ENetwork;
let ext: Extension;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort });
  await setKey(ext, MOCK_KEY);
  await setSettings(ext, { cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

// A test that failed while holding a read must not hold the next test's.
test.afterEach(() => {
  net.releaseHolds();
});

test("the Fleet view reads the control plane once per refresh period and still updates", async () => {
  net.clearEndpoints();
  const logs: Record<string, unknown>[] = [
    { ts: Date.now() - 1000, kind: "dns", qname: "first-single-poll-guard-e2e.com.", qtype: "A", decision: "allow", agent: "agent-e2esingle" },
  ];
  net.addEndpoint({ agent: "agent-e2esingle", address: "2a04:2a01:e2e:9::1", label: "Single poll box", device: true, logs });
  net.addEndpoint({ agent: "agent-e2esecond", address: "2a04:2a01:e2e:a::1", label: "Second box", logs: [] });

  const since = Date.now();
  const dash = await openDashboard(ext, "fleet");
  await expect(dash.locator("#f-feed")).toContainText("first-single-poll-guard-e2e.com", { timeout: 15_000 });

  await test.step("new activity shows up without a reload", async () => {
    logs.unshift({ ts: Date.now(), kind: "dns", qname: "second-single-poll-guard-e2e.com.", qtype: "A", decision: "allow", agent: "agent-e2esingle" });
    await expect(dash.locator("#f-feed")).toContainText("second-single-poll-guard-e2e.com", { timeout: REFRESH_MS + 8_000 });
  });

  await test.step("one set of list and log calls per refresh period", async () => {
    await expect.poll(() => Date.now() - since, { timeout: WINDOW_MS + 5_000, intervals: [500] }).toBeGreaterThanOrEqual(WINDOW_MS);
    const end = since + WINDOW_MS;
    const lists = net
      .requestsTo(GRAPH_CONTROL_HOST)
      .filter((r) => r.at >= since && r.at < end && r.body.includes("op:'list'")).length;
    const logCalls = net
      .requestsTo(GRAPH_CONTROL_HOST)
      .filter((r) => r.at >= since && r.at < end && r.body.includes("op:'logs'")).length;
    // Reads at 0, 12 and 24 s (the one at 36 s falls just outside). The alarm
    // tick at 30 s lands inside the window and must add nothing: a second
    // source would make it 4.
    expect(WINDOW_MS).toBeGreaterThan(ALARM_MS);
    const sets = Math.floor(WINDOW_MS / REFRESH_MS);
    expect(lists).toBeGreaterThanOrEqual(3);
    expect(lists).toBeLessThanOrEqual(sets);
    // Two endpoints, one log pull each, per list.
    expect(logCalls).toBe(lists * 2);
  });

  await dash.close();
});

const rosterText = (dash: import("@playwright/test").Page) => dash.locator("#f-roster").innerText();
const ask = (dash: import("@playwright/test").Page, cached: boolean) =>
  dash.evaluate(
    (c) => chrome.runtime.sendMessage({ kind: "getFleetReport", cached: c }) as Promise<{
      ok: boolean;
      nokey?: boolean;
      fleet?: { endpoints: { agent: string }[] };
    }>,
    cached,
  );

test("a read in flight while an endpoint is revoked never brings it back", async () => {
  net.clearEndpoints();
  net.addEndpoint({ agent: "agent-e2ekeep", address: "2a04:2a01:e2e:b::1", label: "Keep box", logs: [] });
  net.addEndpoint({ agent: "agent-e2egone", address: "2a04:2a01:e2e:c::1", label: "Gone box", logs: [] });
  // The opening read is the one held in flight.
  const hold = net.holdNextList();
  const dash = await openDashboard(ext, "fleet");
  await hold.held;
  const revoked = await dash.evaluate(
    () => chrome.runtime.sendMessage({ kind: "revokeEndpoint", agent: "agent-e2egone" }) as Promise<{ ok: boolean }>,
  );
  expect(revoked.ok).toBe(true);
  hold.release();

  // Asked after the held read landed: neither a fresh nor a cached ask may carry it.
  for (const cached of [false, true]) {
    const r = await ask(dash, cached);
    expect(r.ok).toBe(true);
    expect(r.fleet?.endpoints.map((e) => e.agent)).toEqual(["agent-e2ekeep"]);
  }
  await expect(dash.locator("#f-roster")).toContainText("Keep box");
  expect(await rosterText(dash)).not.toContain("Gone box");
  await dash.close();
});

test("signing out while a read is in flight ends on the signed-out view", async () => {
  net.clearEndpoints();
  net.addEndpoint({ agent: "agent-e2eprior", address: "2a04:2a01:e2e:d::1", label: "Prior account box", logs: [] });
  await setKey(ext, MOCK_KEY);
  const hold = net.holdNextList();
  const dash = await openDashboard(ext, "fleet");
  await hold.held;
  await dash.evaluate(() => chrome.runtime.sendMessage({ kind: "signOut" }));
  hold.release();

  await expect(dash.locator("#fleet-lock")).toBeVisible({ timeout: REFRESH_MS + 8_000 });
  await expect(dash.locator("#fleet-body")).toBeHidden();
  for (const cached of [false, true]) {
    const r = await ask(dash, cached);
    expect(r.ok).toBe(false);
    expect(r.nokey).toBe(true);
  }
  await setKey(ext, MOCK_KEY);
  await dash.close();
});

test("a failing control plane shows the Fleet view offline without a reload", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearEndpoints();
  net.addEndpoint({ agent: "agent-e2eoffline", address: "2a04:2a01:e2e:e::1", label: "Offline box", logs: [] });
  const dash = await openDashboard(ext, "fleet");
  await expect(dash.locator("#f-roster")).toContainText("Offline box", { timeout: 15_000 });
  await expect(dash.locator("#feed-label")).toContainText("polling");

  net.failQueries.add("whisper.agents");
  try {
    await expect(dash.locator("#feed-label")).toHaveText("offline", { timeout: REFRESH_MS + 8_000 });
  } finally {
    net.failQueries.clear();
  }
  await expect(dash.locator("#f-roster")).toContainText("Offline box");
  await dash.close();
});
