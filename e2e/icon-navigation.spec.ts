// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Regression (#50): the browser resets a tab's action icon and title when its
// main frame commits a navigation. The painter's own memory of the last paint
// must not make it skip the repaint, or a second page of the same site loses
// its mark (a blank mark on a flagged site is a missing verdict).

import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST, type Verdict } from "./helpers/servers";
import {
  launchExtension,
  navigateInTab,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
  type IconState,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const CASES: (Verdict & { host: string; state: IconState; title: string })[] = [
  { host: "two-page-evil-guard-e2e.com", band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious", state: "malicious", title: "Whisper Guard: STOP, this site is a known threat" },
  { host: "two-page-shady-guard-e2e.com", band: "MEDIUM", coverage: "partial", label: "suspicious", state: "suspicious", title: "Whisper Guard: be careful on this site" },
  { host: "two-page-clean-guard-e2e.com", band: "NONE", coverage: "known-clean", label: "clean", state: "benign", title: "Whisper Guard: no known threat on this site" },
];

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict("github.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  for (const c of CASES) {
    net.setVerdict(c.host, { band: c.band, coverage: c.coverage, label: c.label });
  }
  ext = await launchExtension({ proxyPort: net.proxyPort });
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

for (const c of CASES) {
  test(`keeps the ${c.state} mark when a second page of the same site commits in the same tab`, async () => {
    const title = (tabId: number) =>
      ext.sw.evaluate(async (id: number) => chrome.action.getTitle({ tabId: id }), tabId);

    const { page, tabId } = await visit(ext, `https://${c.host}/`);
    await waitForIcon(ext, tabId, [c.state]);
    net.clearLog();

    await navigateInTab(page, `https://${c.host}/second`);
    await waitForIcon(ext, tabId, [c.state]);
    expect(await title(tabId)).toBe(c.title);
    expect(await title(tabId)).not.toBe("Whisper Guard");

    // The second page was answered from the cache: no "checking" paint
    // could have masked the bug.
    const assessed = net
      .requestsTo(GRAPH_READ_HOST)
      .filter((r) => r.body.includes("whisper.assess") && r.body.includes(c.host));
    expect(assessed).toHaveLength(0);

    // Past the navigation debounce the mark is still there.
    await page.waitForTimeout(400);
    expect(await title(tabId)).toBe(c.title);
    await page.close();
  });
}
