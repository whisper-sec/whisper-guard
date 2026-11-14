// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The fleet-poll alarm lives only while a dashboard holds its port open
// (#52): otherwise it re-wakes the MV3 worker every 30 s forever, and for a
// signed-in reader every tick calls the control plane.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  launchExtension,
  openDashboard,
  rebindWorker,
  setKey,
  setSettings,
  stopWorker,
  visit,
  waitForIcon,
  workerIsFresh,
  type Extension,
} from "./helpers/extension";

const ALARM = "whisper-guard-fleet-poll";

let net: E2ENetwork;
let ext: Extension;

const alarm = () =>
  ext.sw.evaluate((name) => chrome.alarms.get(name), ALARM).then((a) => a ?? null);

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort });
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("keeps the fleet-poll alarm while a dashboard is open", async () => {
  const dash = await openDashboard(ext, "browser");
  await expect.poll(async () => (await alarm())?.periodInMinutes).toBe(0.5);
  await dash.close();
  await expect.poll(alarm).toBeNull();
});

test("clears the fleet-poll alarm only when the last dashboard closes", async () => {
  const a = await openDashboard(ext, "browser");
  const b = await openDashboard(ext, "browser");
  await expect.poll(alarm).not.toBeNull();
  await a.close();
  // Give a wrongly-eager clear time to land before asserting it did not.
  await new Promise((r) => setTimeout(r, 1000));
  expect(await alarm()).not.toBeNull();
  await b.close();
  await expect.poll(alarm).toBeNull();
});

test("clears a leftover fleet-poll alarm when the worker starts with no dashboard", async () => {
  await ext.sw.evaluate((name) => chrome.alarms.create(name, { periodInMinutes: 0.5 }), ALARM);
  expect(await alarm()).not.toBeNull();
  await stopWorker(ext);
  await rebindWorker(ext);
  expect(await workerIsFresh(ext)).toBe(true);
  await expect.poll(alarm).toBeNull();
});

test("a dashboard open across a worker restart keeps its alarm and its live port", async () => {
  const dash = await openDashboard(ext, "browser");
  await expect.poll(alarm).not.toBeNull();
  await stopWorker(ext);
  await rebindWorker(ext);
  expect(await workerIsFresh(ext)).toBe(true);
  // The page reconnects its port; onConnect recreates the alarm after the
  // startup reconcile.
  await expect.poll(alarm, { timeout: 10_000 }).not.toBeNull();

  const v = await visit(ext, "https://reconnect-guard-e2e.com/");
  await waitForIcon(ext, v.tabId, ["benign", "unknown", "signedout"]);
  await expect(dash.locator("#b-ledger")).toContainText("reconnect-guard-e2e.com", { timeout: 15_000 });
  await v.page.close();
  await dash.close();
});
