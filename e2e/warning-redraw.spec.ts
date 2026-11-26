// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The full-page stop, as board 4d draws it.
//
// Two kinds of test live here. Those that need Guard's own behaviour (which
// path reached the page, what the graph's label was) run against the real
// extension and the mock graph. Those that need exact figures run the built
// page from a file with a stand-in for the extension's answers, so every
// figure, label and failure is deterministic and nothing depends on timing.
//
//   npx playwright test e2e/warning-redraw.spec.ts

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, MOCK_API_KEY as MOCK_KEY } from "./helpers/servers";
import { DIST_CHROMIUM, launchExtension, makeShieldDist, markHostBlocked, setKey, setSettings, type Extension } from "./helpers/extension";
import { expectScheme, type Scheme } from "./helpers/theme";
import { settledLayout } from "./helpers/popup-fit";

let net: E2ENetwork;
let ext: Extension;

const MALICIOUS = { band: "CRITICAL", coverage: "malicious-evidenced", label: "credential-phishing suspect" } as const;
const HOST = "redraw-stop-guard-e2e.com";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setKey(ext, MOCK_KEY);
  await setSettings(ext, { shield: true, amberBanner: true, fieldGuard: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const warningUrl = (query: string): string => `chrome-extension://${ext.id}/warning.html?${query}`;

/** Text of an element, as one line. */
async function textOf(page: Page, selector: string): Promise<string> {
  return ((await page.locator(selector).textContent()) ?? "").replace(/\s+/g, " ").trim();
}

// ----------------------------------------------------------- the stand-in

interface Rung {
  kind: string;
  label: string;
  value: string | null;
  fact: string | null;
  state: "live" | "empty" | "unavailable";
  tone: "neutral" | "warn" | "hot";
}

const rung = (
  kind: string,
  label: string,
  value: string | null,
  fact: string | null,
  state: Rung["state"],
  tone: Rung["tone"] = "neutral",
): Rung & { detail: string[]; drillable: boolean } => ({ kind, label, value, fact, state, tone, detail: [], drillable: false });

function chainOf(rungs: ReturnType<typeof rung>[], over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    host: HOST,
    rungs,
    live: rungs.filter((r) => r.state === "live").length,
    unavailable: rungs.filter((r) => r.state === "unavailable").length,
    evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:badhosting"],
    facilities: [],
    exchanges: [],
    owner: "Bad Hosting LLC",
    country: "CA",
    city: "Example City",
    asn: "AS64550",
    asnOk: true,
    ip: "192.0.2.66",
    vendor: null,
    vendorCategory: null,
    identifyCategory: null,
    roles: [],
    ageDays: 16,
    prefix: "192.0.2.0/24",
    threatNeighbors: 9,
    at: 0,
    ...over,
  };
}

/** Every join read, one of them answered with nothing. */
const FULL_RUNGS = [
  rung("name", "NAME", HOST, "registered 16 days ago", "live", "warn"),
  rung("vendor", "RUNS ON", null, null, "empty"),
  rung("address", "ADDRESS", "192.0.2.66", "Example City", "live"),
  rung("prefix", "PREFIX", "192.0.2.0/24", "9 flagged neighbours", "live", "hot"),
  rung("network", "NETWORK", "AS64550", null, "live"),
  rung("operator", "OPERATOR", "Bad Hosting LLC", "CA", "live"),
  rung("presence", "PRESENT AT", "Example Colo MTL1", "1 facility", "live"),
];

/** The first, third and sixth joins could not be read; the second answered with nothing. */
const PARTLY_UNREAD_RUNGS = [
  rung("name", "NAME", HOST, null, "live"),
  rung("vendor", "RUNS ON", null, null, "empty"),
  rung("address", "ADDRESS", "could not be read", null, "unavailable"),
  rung("prefix", "PREFIX", "could not be read", null, "unavailable"),
  rung("network", "NETWORK", "AS64550", null, "live"),
  rung("operator", "OPERATOR", "Bad Hosting LLC", "CA", "live"),
  rung("presence", "PRESENT AT", "could not be read", null, "unavailable"),
];

function protectionOf(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    host: HOST,
    band: "CRITICAL",
    blocking: true,
    label: "credential-phishing suspect",
    coverage: "malicious-evidenced",
    who: "Bad Hosting LLC",
    category: null,
    where: null,
    ageDays: 16,
    why: ["Listed in 1 threat feed: openphish", "listed in 2 threat feed(s)"],
    score: 17.2,
    whyFactors: [],
    variants: [],
    partial: false,
    ...over,
  };
}

type Reply = { value: unknown } | { reject: true } | { hold: unknown };

interface Replies {
  getBlock?: Reply;
  getChain?: Reply;
  getProtection?: Reply;
}

const STOPPED_BLOCK = { value: { ok: true, block: { blocked: true, brand: null, brandDomain: null } } };

function scriptFor(replies: Replies): string {
  return `
    const R = ${JSON.stringify(replies)};
    window.__release = {};
    window.chrome = {
      runtime: {
        id: "shim",
        getURL: (p) => p,
        sendMessage: (msg) => {
          const r = R[msg.kind];
          if (r && r.reject) return Promise.reject(new Error("no answer"));
          if (r && "hold" in r) return new Promise((res) => { window.__release[msg.kind] = () => res(r.hold); });
          return Promise.resolve(r ? r.value : { ok: true });
        },
      },
      tabs: { query: () => Promise.resolve([{ id: 1 }]), update: () => Promise.resolve() },
      storage: { local: { get: () => Promise.resolve({}), set: () => Promise.resolve() } },
    };
  `;
}

interface OpenOptions {
  width?: number;
  height?: number;
  scheme?: Scheme;
  query?: string;
}

/** The built page, from a file, answered by `replies` instead of the extension. */
async function openStand(replies: Replies, opts: OpenOptions = {}): Promise<Page> {
  const page = await ext.context.newPage();
  await page.setViewportSize({ width: opts.width ?? 1100, height: opts.height ?? 900 });
  await page.emulateMedia({ colorScheme: opts.scheme ?? "dark", reducedMotion: "reduce" });
  await page.addInitScript(scriptFor(replies));
  await page.goto(`file://${DIST_CHROMIUM}/warning.html?host=${HOST}${opts.query ?? ""}`);
  await expectScheme(page, opts.scheme ?? "dark");
  return page;
}

const FULL: Replies = {
  getBlock: STOPPED_BLOCK,
  getChain: { value: { ok: true, chain: chainOf(FULL_RUNGS) } },
  getProtection: { value: { ok: true, protection: protectionOf() } },
};

async function stopped(page: Page): Promise<void> {
  await expect(page.locator("main")).toHaveAttribute("data-state", "stopped");
  await expect(page.locator("#evidence")).toBeVisible();
  await expect(page.locator("#ev-completeness")).not.toBeEmpty();
}

// ------------------------------------------------------- which path, which claim

/** The value the block rule's redirect put in a tab's address, or "" when it put none. */
const ruleValueOf = (url: string): string => new URL(url).searchParams.get("rule") ?? "";

test("should say nothing on the page loaded only when the block rule sent the tab, and not after the move that follows a verdict", async () => {
  const host = "redraw-path-guard-e2e.com";
  net.setVerdict(host, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });

  // First visit: the page commits, the verdict lands, the tab is moved.
  const novel = await ext.context.newPage();
  try {
    await novel.goto(`https://${host}/`, { waitUntil: "commit" });
    await novel.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
    await expect(novel.locator("main")).toHaveAttribute("data-state", "stopped");
    expect(ruleValueOf(novel.url()), "the move after a verdict carries no rule value").toBe("");
    await expect(novel.locator("#detail")).toContainText("It was blocked before any credentials could be entered.");
    await expect(novel.locator("#detail")).not.toContainText("Nothing on it has loaded.");
  } finally {
    await novel.close();
  }

  // Later visit: the block rule redirects before a request leaves.
  const ruled = await ext.context.newPage();
  try {
    await ruled.goto(`https://${host}/`, { waitUntil: "commit" });
    await ruled.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
    expect(ruleValueOf(ruled.url()), "the block rule puts 128 bits, in hex, in its redirect").toMatch(/^[0-9a-f]{32}$/);
    await expect(ruled.locator("main")).toHaveAttribute("data-state", "stopped");
    await expect(ruled.locator("#detail")).toContainText("Nothing on it has loaded.");
    await expect(ruled.locator("#detail")).not.toContainText("It was blocked before any credentials");
  } finally {
    await ruled.close();
  }
});

test("should give the stronger sentence only for the value the background holds for that host, never for an address someone wrote", async () => {
  const ruledHost = "redraw-rule-guard-e2e.com";
  const blocked = "redraw-marker-blocked-guard-e2e.com";
  const notBlocked = "redraw-marker-open-guard-e2e.com";
  net.setVerdict(ruledHost, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  await markHostBlocked(ext, blocked);

  // Get a real value: visit twice, the second visit is redirected by the rule.
  const first = await ext.context.newPage();
  await first.goto(`https://${ruledHost}/`, { waitUntil: "commit" });
  await first.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
  await first.close();
  const ruled = await ext.context.newPage();
  let real = "";
  try {
    await ruled.goto(`https://${ruledHost}/`, { waitUntil: "commit" });
    await ruled.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
    real = ruleValueOf(ruled.url());
  } finally {
    await ruled.close();
  }
  expect(real).toMatch(/^[0-9a-f]{32}$/);

  const sentenceFor = async (query: string): Promise<{ state: string | null; detail: string }> => {
    const page = await ext.context.newPage();
    try {
      await page.goto(warningUrl(query));
      await expect(page.locator("main")).not.toHaveAttribute("data-state", "pending");
      return {
        state: await page.locator("main").getAttribute("data-state"),
        detail: ((await page.locator("#detail").textContent()) ?? "").trim(),
      };
    } finally {
      await page.close();
    }
  };

  // The real value, for the host it belongs to, read by hand: confirmed by the background.
  const mine = await sentenceFor(`host=${ruledHost}&rule=${real}`);
  expect(mine.state).toBe("stopped");
  expect(mine.detail).toContain("Nothing on it has loaded.");

  // A made-up value, the old plain marker, an empty value and another host's real value for a blocked host.
  for (const q of [
    `host=${blocked}&rule=${"0".repeat(32)}`,
    `host=${blocked}&via=rule`,
    `host=${blocked}&rule=`,
    `host=${blocked}&rule=${real}`,
  ]) {
    const got = await sentenceFor(q);
    expect(got.state, q).toBe("stopped");
    expect(got.detail, q).toContain("It was blocked before any credentials could be entered.");
    expect(got.detail, q).not.toContain("Nothing on it has loaded.");
  }

  // For a host Guard does not block, a value changes nothing: still no block.
  const open = await ext.context.newPage();
  try {
    await open.goto(warningUrl(`host=${notBlocked}&rule=${real}`));
    await expect(open.locator("main")).toHaveAttribute("data-state", "no-block");
    await expect(open.locator("#detail")).toHaveText(
      `Whisper Guard is not blocking ${notBlocked}, so there is nothing here to continue past. This says nothing about whether the address is safe.`,
    );
    await expect(open.locator("#btn-continue")).toBeDisabled();
    await expect(open.locator("#evidence")).toBeHidden();
  } finally {
    await open.close();
  }

  // Once the block is cleared the value is no longer held.
  const cleared = await ext.context.newPage();
  try {
    await cleared.goto(warningUrl(`host=${ruledHost}&rule=${real}`));
    await expect(cleared.locator("main")).toHaveAttribute("data-state", "stopped");
    await cleared.locator("#btn-continue").click();
    await cleared.waitForURL(`https://${ruledHost}/`, { timeout: 15_000 });
  } finally {
    await cleared.close();
  }
  const held = await ext.sw.evaluate(async (h: string) => {
    const all = ((await chrome.storage.session.get("ruleNonces"))["ruleNonces"] ?? {}) as Record<string, string>;
    return h in all;
  }, ruledHost);
  expect(held, "the value is forgotten when the block is cleared").toBe(false);
});

test("should declare no-referrer, so leaving the page never sends its address or the block rule's value to the next site", async () => {
  const page = await ext.context.newPage();
  try {
    await page.goto(warningUrl("host=redraw-referrer-guard-e2e.com"));
    const policy = await page.evaluate(
      () => document.querySelector<HTMLMetaElement>('meta[name="referrer"]')?.content ?? null,
    );
    expect(policy).toBe("no-referrer");
  } finally {
    await page.close();
  }
});

test("should say listed for credential phishing, and the band line, from the label the graph gave the real extension", async () => {
  const host = "redraw-phish-guard-e2e.com";
  net.setVerdict(host, MALICIOUS);
  const page = await ext.context.newPage();
  try {
    await page.goto(`https://${host}/`, { waitUntil: "commit" });
    await page.waitForURL((u) => u.href.includes("warning.html"), { timeout: 15_000 });
    await expect(page.locator("main")).toHaveAttribute("data-state", "stopped");
    await expect(page.locator("#detail")).toContainText(`${host} is listed for credential phishing in the Whisper security graph.`);
    await expect(page.locator("#band")).toHaveText("CREDENTIAL-PHISHING SUSPECT · CRITICAL");
  } finally {
    await page.close();
  }
});

// ---------------------------------------------------------------- the claim

test("should say flagged as a known threat until the graph's label is read, then listed for credential phishing when it names phishing", async () => {
  const page = await openStand({
    getBlock: STOPPED_BLOCK,
    getChain: { value: { ok: true, chain: chainOf(FULL_RUNGS) } },
    getProtection: { hold: { ok: true, protection: protectionOf({ label: "Credential-Phishing suspect" }) } },
  });
  try {
    await expect(page.locator("main")).toHaveAttribute("data-state", "stopped");
    await expect(page.locator("#detail")).toContainText(`${HOST} is flagged as a known threat in the Whisper security graph.`);
    await expect(page.locator("#detail")).not.toContainText("listed for credential phishing");
    await expect(page.locator("#band")).toBeHidden();

    await page.evaluate(() => (window as unknown as { __release: Record<string, () => void> }).__release["getProtection"]!());
    await expect(page.locator("#detail")).toContainText(`${HOST} is listed for credential phishing in the Whisper security graph.`);
    await expect(page.locator("#band")).toHaveText("CREDENTIAL-PHISHING SUSPECT · CRITICAL");
  } finally {
    await page.close();
  }
});

test("should keep flagged as a known threat for a label that does not name phishing, and read the band from the graph", async () => {
  const page = await openStand({
    ...FULL,
    getProtection: { value: { ok: true, protection: protectionOf({ label: "malware distribution", band: "HIGH", category: "phishing" }) } },
  });
  try {
    await stopped(page);
    await expect(page.locator("#detail")).toContainText(`${HOST} is flagged as a known threat in the Whisper security graph.`);
    await expect(page.locator("#detail")).not.toContainText("phishing");
    await expect(page.locator("#band")).toHaveText("MALWARE DISTRIBUTION · HIGH");
  } finally {
    await page.close();
  }
});

test("should show only the band when the graph gave no label, and no band line when the protection read failed or said nothing", async () => {
  const noLabel = await openStand({ ...FULL, getProtection: { value: { ok: true, protection: protectionOf({ label: null, band: "HIGH" }) } } });
  try {
    await stopped(noLabel);
    await expect(noLabel.locator("#band")).toHaveText("HIGH");
  } finally {
    await noLabel.close();
  }

  const failed = await openStand({ ...FULL, getProtection: { reject: true } });
  try {
    await stopped(failed);
    await expect(failed.locator("#ev-note")).toBeVisible();
    await expect(failed.locator("#band")).toBeHidden();
  } finally {
    await failed.close();
  }

  const unknown = await openStand({
    ...FULL,
    getProtection: { value: { ok: true, protection: protectionOf({ label: null, band: "UNKNOWN", partial: true }) } },
  });
  try {
    await stopped(unknown);
    await expect(unknown.locator("#band")).toBeHidden();
  } finally {
    await unknown.close();
  }
});

test("should show the label alone when the graph gave a label but no rating", async () => {
  for (const band of ["UNKNOWN", "NONE"]) {
    const page = await openStand({
      ...FULL,
      getProtection: { value: { ok: true, protection: protectionOf({ label: "malicious", band }) } },
    });
    try {
      await stopped(page);
      await expect(page.locator("#band"), band).toHaveText("MALICIOUS");
    } finally {
      await page.close();
    }
  }
});

test("should keep the impersonation sentence when the background names a brand, even with a phishing label", async () => {
  const page = await openStand({
    ...FULL,
    getBlock: { value: { ok: true, block: { blocked: true, brand: "PayPal", brandDomain: "paypal.com" } } },
  });
  try {
    await stopped(page);
    await expect(page.locator("#detail")).toContainText(`${HOST} is flagged as a known threat impersonating PayPal.`);
    await expect(page.locator("#btn-real")).toHaveText("Go to the real paypal.com");
    await expect(page.locator("#btn-real")).toHaveAttribute("href", "https://paypal.com/");
    await expect(page.locator("#band")).toHaveText("CREDENTIAL-PHISHING SUSPECT · CRITICAL");
  } finally {
    await page.close();
  }
});

// ------------------------------------------------------------------ figures

test("should show three figures with the captions the graph's own words allow, and never the words feeds or / 256", async () => {
  const page = await openStand(FULL);
  try {
    await stopped(page);
    const age = page.locator("#ev-age");
    await expect(age.locator(".ev-figure")).toHaveText("16 days");
    await expect(age.locator(".ev-caption")).toHaveText("since the name was registered");
    const near = page.locator("#ev-neighbours");
    await expect(near.locator(".ev-figure")).toHaveText("9");
    await expect(near.locator(".ev-caption")).toHaveText("other flagged hosts in 192.0.2.0/24");
    const why = page.locator("#ev-feeds");
    await expect(why.locator(".ev-figure")).toHaveText("2 reasons");
    await expect(why.locator(".ev-caption")).toHaveText("cited by the graph");
    await expect(why.locator("li")).toHaveText(["Listed in 1 threat feed: openphish", "listed in 2 threat feed(s)"]);

    const words = await page.locator(".ev-figure, .ev-caption").allTextContents();
    expect(words.join(" | ")).not.toMatch(/feeds|\/ 256/i);
    // The old drawn marks give way to the figures.
    await expect(page.locator("#ev-age svg, #ev-neighbours svg, #ev-feeds svg")).toHaveCount(0);
    // A young name is drawn in the hot ink; the figure is the size and face the board gives.
    const style = await age.locator(".ev-figure").evaluate((el) => {
      const cs = getComputedStyle(el);
      const probe = document.createElement("span");
      probe.style.color = "var(--w-v-high)";
      document.body.append(probe);
      const hot = getComputedStyle(probe).color;
      probe.remove();
      return { color: cs.color, hot, size: cs.fontSize, weight: cs.fontWeight, family: cs.fontFamily };
    });
    expect(style.color).toBe(style.hot);
    expect(style.size).toBe("28px");
    expect(style.weight).toBe("700");
    expect(style.family).toContain("JetBrains Mono");
  } finally {
    await page.close();
  }
});

test("should use the singular for one day, one other host and one reason, and plain ink for a name past the new-name threshold", async () => {
  const page = await openStand({
    getBlock: STOPPED_BLOCK,
    getChain: { value: { ok: true, chain: chainOf(FULL_RUNGS, { threatNeighbors: 1 }) } },
    getProtection: { value: { ok: true, protection: protectionOf({ ageDays: 1, why: ["one reason"] }) } },
  });
  try {
    await stopped(page);
    await expect(page.locator("#ev-age .ev-figure")).toHaveText("1 day");
    await expect(page.locator("#ev-neighbours .ev-caption")).toHaveText("other flagged host in 192.0.2.0/24");
    await expect(page.locator("#ev-feeds .ev-figure")).toHaveText("1 reason");
  } finally {
    await page.close();
  }

  const old = await openStand({ ...FULL, getProtection: { value: { ok: true, protection: protectionOf({ ageDays: 200 }) } } });
  try {
    await stopped(old);
    await expect(old.locator("#ev-age .ev-figure")).toHaveText("200 days");
    const same = await old.locator("#ev-age .ev-figure").evaluate((el) => {
      const probe = document.createElement("span");
      probe.style.color = "var(--w-text)";
      document.body.append(probe);
      const ink = getComputedStyle(probe).color;
      probe.remove();
      return getComputedStyle(el).color === ink;
    });
    expect(same, "a name older than the threshold is drawn in the plain text colour").toBe(true);
  } finally {
    await old.close();
  }
});

test("should show a figure only when it was read: no age, no flagged neighbours and no reasons leave no figure", async () => {
  const page = await openStand({
    getBlock: STOPPED_BLOCK,
    getChain: { value: { ok: true, chain: chainOf(FULL_RUNGS, { threatNeighbors: 0 }) } },
    getProtection: { value: { ok: true, protection: protectionOf({ ageDays: null, why: [] }) } },
  });
  try {
    await stopped(page);
    await expect(page.locator("#ev-age")).toBeHidden();
    await expect(page.locator("#ev-neighbours")).toBeHidden();
    await expect(page.locator("#ev-feeds")).toBeHidden();
    await expect(page.locator(".ev-figure")).toHaveCount(0);
    // What was read is still counted.
    await expect(page.locator("#ev-completeness")).toHaveText("7 of 7 joins read");
  } finally {
    await page.close();
  }
});

test("should show no age or reason figure and say so when the protection read failed, and keep the neighbour count the chain read", async () => {
  const page = await openStand({ ...FULL, getProtection: { reject: true } });
  try {
    await stopped(page);
    await expect(page.locator("#ev-note")).toContainText("The citations behind this block could not be loaded.");
    await expect(page.locator("#ev-age")).toBeHidden();
    await expect(page.locator("#ev-feeds")).toBeHidden();
    // The neighbour count comes from the chain, which was read.
    await expect(page.locator("#ev-neighbours .ev-figure")).toHaveText("9");
    await expect(page.locator("#ev-completeness")).toHaveText("7 of 7 joins read");
  } finally {
    await page.close();
  }
});

test("should keep the honest line without a figure when the chain held no neighbourhood figure", async () => {
  const page = await openStand({
    ...FULL,
    getChain: { value: { ok: true, chain: chainOf(FULL_RUNGS, { threatNeighbors: null }) } },
  });
  try {
    await stopped(page);
    await expect(page.locator("#ev-neighbours")).toBeVisible();
    await expect(page.locator("#ev-neighbours .ev-caption")).toHaveText("the graph holds no neighbourhood figure for this prefix");
    await expect(page.locator("#ev-neighbours .ev-figure")).toHaveCount(0);
  } finally {
    await page.close();
  }
});

test("should keep the no-neighbourhood line when the protection read failed, because it depends on the chain alone", async () => {
  const page = await openStand({
    ...FULL,
    getChain: { value: { ok: true, chain: chainOf(FULL_RUNGS, { threatNeighbors: null }) } },
    getProtection: { reject: true },
  });
  try {
    await stopped(page);
    await expect(page.locator("#ev-note")).toContainText("could not be loaded");
    await expect(page.locator("#ev-neighbours .ev-caption")).toHaveText("the graph holds no neighbourhood figure for this prefix");
  } finally {
    await page.close();
  }
});

test("should give the chain rows the card's whole width when no figure is shown, and share it when one is", async () => {
  const widths = async (replies: Replies): Promise<{ chain: number; card: number }> => {
    const page = await openStand(replies);
    try {
      await stopped(page);
      await expect(page.locator("#ev-chain .ch-rung")).toHaveCount(7);
      return await page.evaluate(() => ({
        chain: (document.querySelector("#ev-chain") as HTMLElement).getBoundingClientRect().width,
        card: (document.querySelector("#evidence") as HTMLElement).getBoundingClientRect().width,
      }));
    } finally {
      await page.close();
    }
  };
  // Card padding is 24 px a side and its border 1 px.
  const alone = await widths({
    getBlock: STOPPED_BLOCK,
    getChain: { value: { ok: true, chain: chainOf(FULL_RUNGS, { threatNeighbors: 0 }) } },
    getProtection: { value: { ok: true, protection: protectionOf({ ageDays: null, why: [] }) } },
  });
  expect(alone.chain, "no figure: the rows fill the card").toBeGreaterThanOrEqual(alone.card - 2 * 24 - 2 - 1);
  const shared = await widths(FULL);
  expect(shared.chain, "with figures the rows share the card").toBeLessThan(shared.card * 0.7);
});

test("should name the partial-read note when the protection said some detail could not be fetched", async () => {
  const page = await openStand({ ...FULL, getProtection: { value: { ok: true, protection: protectionOf({ partial: true }) } } });
  try {
    await stopped(page);
    await expect(page.locator("#ev-note")).toContainText("Some of the supporting detail could not be fetched.");
    // What was read is still shown beside the note.
    await expect(page.locator("#ev-age .ev-figure")).toHaveText("16 days");
  } finally {
    await page.close();
  }
});

// ------------------------------------------------------- the joins and spine

test("should count the joins read, and label a join that was not read and one that holds nothing differently", async () => {
  const page = await openStand({
    getBlock: STOPPED_BLOCK,
    getChain: { value: { ok: true, chain: chainOf(PARTLY_UNREAD_RUNGS, { threatNeighbors: null }) } },
    getProtection: { value: { ok: true, protection: protectionOf() } },
  });
  try {
    await stopped(page);
    await expect(page.locator("#ev-completeness")).toHaveText("4 of 7 joins read, 3 unreadable");
    await expect(page.locator("#ev-completeness")).toHaveClass(/lost/);

    const rows = page.locator("#ev-chain .ch-rung");
    await expect(rows).toHaveCount(7);
    // Answered with nothing, in the board's words; not read, in its own.
    await expect(rows.nth(1).locator(".ch-value")).toHaveText("the graph holds nothing here");
    for (const i of [2, 3, 6]) {
      await expect(rows.nth(i).locator(".ch-value")).toHaveText("could not be read");
      await expect(rows.nth(i)).toHaveClass(/ch-lost/);
    }
    await expect(rows.nth(1)).not.toHaveClass(/ch-lost/);

    // The spine: one bar per join, and a join that was not read is drawn apart from one that holds nothing.
    const bars = page.locator("#ev-spine .ev-bar");
    await expect(bars).toHaveCount(7);
    const states = await bars.evaluateAll((els) => els.map((e) => e.getAttribute("data-state")));
    expect(states).toEqual(["live", "empty", "unavailable", "unavailable", "live", "live", "unavailable"]);
    const look = await bars.evaluateAll((els) =>
      els.map((e) => {
        const cs = getComputedStyle(e);
        return { style: cs.borderTopStyle, fill: cs.backgroundColor, edge: cs.borderTopColor };
      }),
    );
    const amber = await page.evaluate(() => {
      const p = document.createElement("span");
      p.style.color = "var(--w-v-low)";
      document.body.append(p);
      const c = getComputedStyle(p).color;
      p.remove();
      return c;
    });
    expect(look[2]!.style, "a join not read is hollow and dashed").toBe("dashed");
    expect(look[2]!.fill).toBe("rgba(0, 0, 0, 0)");
    expect(look[2]!.edge, "a join not read is amber").toBe(amber);
    expect(look[1]!.style, "a join that holds nothing is a plain bar").not.toBe("dashed");
    expect(look[1]!.fill).not.toBe("rgba(0, 0, 0, 0)");
    await expect(page.locator("#ev-spine .ev-bar-label")).toHaveText(["NAME", "RUNS ON", "ADDRESS", "PREFIX", "NETWORK", "OPERATOR", "PRESENT AT"]);
    await expect(page.locator("#ev-spine")).toHaveAttribute("aria-hidden", "true");
  } finally {
    await page.close();
  }
});

test("should count an answered-with-nothing join as read, and draw four different marks: finding, read with no finding, nothing held, not read", async () => {
  const rungs = [
    rung("name", "NAME", HOST, null, "live", "warn"),
    rung("vendor", "RUNS ON", null, null, "empty"),
    rung("address", "ADDRESS", "192.0.2.66", null, "live"),
    rung("prefix", "PREFIX", "192.0.2.0/24", null, "live", "hot"),
    rung("network", "NETWORK", "could not be read", null, "unavailable"),
    rung("operator", "OPERATOR", "Bad Hosting LLC", null, "live"),
    rung("presence", "PRESENT AT", "Example Colo MTL1", null, "live"),
  ];
  const page = await openStand({ ...FULL, getChain: { value: { ok: true, chain: chainOf(rungs) } } });
  try {
    await stopped(page);
    await expect(page.locator("#ev-completeness")).toHaveText("6 of 7 joins read, 1 unreadable");
    const marks = await page.locator("#ev-spine .ev-bar").evaluateAll((els) =>
      els.map((e) => {
        const cs = getComputedStyle(e);
        return { fill: cs.backgroundColor, edge: cs.borderTopColor, style: cs.borderTopStyle };
      }),
    );
    const tokens = await page.evaluate(() => {
      const of = (v: string): string => {
        const p = document.createElement("span");
        p.style.backgroundColor = `var(${v})`;
        document.body.append(p);
        const c = getComputedStyle(p).backgroundColor;
        p.remove();
        return c;
      };
      return { hot: of("--w-v-high-fill"), warn: of("--w-v-low-fill"), accent: of("--w-accent-line"), muted: of("--w-muted"), amber: of("--w-v-low") };
    });
    expect(marks[0]!.fill, "a finding keeps its tone: warn").toBe(tokens.warn);
    expect(marks[3]!.fill, "a finding keeps its tone: hot").toBe(tokens.hot);
    expect(marks[2]!.fill, "read with no finding is the accent").toBe(tokens.accent);
    expect(marks[5]!.fill).toBe(tokens.accent);
    expect(marks[1]!.fill, "answered with nothing is muted grey").toBe(tokens.muted);
    expect(marks[4]!.style, "not read is dashed").toBe("dashed");
    expect(marks[4]!.edge, "not read is amber").toBe(tokens.amber);
    expect(marks[4]!.fill, "not read is hollow").toBe("rgba(0, 0, 0, 0)");
    // No two of the four kinds look alike.
    const kinds = new Set([tokens.warn, tokens.hot, tokens.accent, tokens.muted, tokens.amber]);
    expect(kinds.size).toBe(5);
  } finally {
    await page.close();
  }
});

test("should say the join path is unreadable and show no chain figure when the chain could not be read", async () => {
  const page = await openStand({ ...FULL, getChain: { reject: true } });
  try {
    await stopped(page);
    await expect(page.locator("#ev-completeness")).toHaveText("join path unreadable");
    await expect(page.locator("#ev-completeness")).toHaveClass(/lost/);
    await expect(page.locator("#ev-chain")).toContainText("could not be read just now");
    await expect(page.locator("#ev-spine .ev-bar")).toHaveCount(0);
    await expect(page.locator("#ev-neighbours")).toBeHidden();
    // The protection read is separate: its figures still show.
    await expect(page.locator("#ev-age .ev-figure")).toHaveText("16 days");
    await expect(page.locator("#ev-feeds .ev-figure")).toHaveText("2 reasons");
  } finally {
    await page.close();
  }
});

// ------------------------------------------------------- the actions

test("should focus Back to safety when the stop appears, and take Enter and Escape as going back", async () => {
  for (const key of ["Enter", "Escape"] as const) {
    const page = await ext.context.newPage();
    try {
      await page.addInitScript(scriptFor(FULL));
      await page.goto("about:blank");
      await page.goto(`file://${DIST_CHROMIUM}/warning.html?host=${HOST}`);
      await expect(page.locator("main")).toHaveAttribute("data-state", "stopped");
      await expect(page.locator("#btn-back")).toBeFocused();
      await expect(page.locator("#btn-back")).toHaveText("← Back to safety");
      await page.keyboard.press(key);
      await page.waitForURL("about:blank");
    } finally {
      await page.close();
    }
  }
});

test("should not move focus to Back and keep every way past disabled in a state that is not a stop", async () => {
  const page = await openStand({ getBlock: { value: { ok: true, block: { blocked: false, brand: null, brandDomain: null } } } });
  try {
    await expect(page.locator("main")).toHaveAttribute("data-state", "no-block");
    await expect(page.locator("#btn-back")).toHaveText("← Go back");
    await expect(page.locator("#btn-back")).not.toBeFocused();
    await expect(page.locator("#btn-continue")).toBeDisabled();
    await expect(page.locator("#evidence")).toBeHidden();
    await expect(page.locator("#band")).toBeHidden();
    await expect(page.getByRole("img", { name: "Stop" })).toHaveCount(0);
    // The neutral glyph sits in the same header block as the stop does.
    await expect(page.locator(".hero #glyph")).toBeVisible();
  } finally {
    await page.close();
  }
});

test("should draw the stop as an image named Stop only in the stopped state", async () => {
  const page = await openStand(FULL);
  try {
    await stopped(page);
    const stop = page.getByRole("img", { name: "Stop" });
    await expect(stop).toHaveCount(1);
    await expect(stop).toBeVisible();
    const box = await stop.boundingBox();
    expect(box?.width).toBe(96);
    expect(box?.height).toBe(96);
  } finally {
    await page.close();
  }
});

test("should hide the Back button until a state is confirmed, and ship the stopped wording as its markup text", async () => {
  const page = await openStand({ getBlock: { hold: STOPPED_BLOCK.value } });
  try {
    await expect(page.locator("main")).toHaveAttribute("data-state", "pending");
    await expect(page.locator("#btn-back")).toBeHidden();
    await expect(page.locator("#btn-back")).toHaveText("← Back to safety");
  } finally {
    await page.close();
  }
});

test("should keep Continue as it was: enabled only in the stopped state, and ending in the neutral state on a refusal", async () => {
  const enabled = await openStand({
    ...FULL,
    getBlock: STOPPED_BLOCK,
  });
  try {
    await stopped(enabled);
    await expect(enabled.locator("#btn-continue")).toBeEnabled();
    await expect(enabled.locator("#btn-continue")).toHaveText("I understand the risk, continue anyway");
    const look = await enabled.locator("#btn-continue").evaluate((el) => {
      const cs = getComputedStyle(el);
      return { size: cs.fontSize, line: cs.textDecorationLine, bg: cs.backgroundColor };
    });
    expect(look).toEqual({ size: "13px", line: "underline", bg: "rgba(0, 0, 0, 0)" });
    // The stand-in answers allowHost with a plain ok, so only the label, the look and the
    // enabled state are checked here; the real navigation is covered where the real extension answers.
  } finally {
    await enabled.close();
  }
  const answer = await openStand({ ...FULL, getBlock: STOPPED_BLOCK });
  try {
    await answer.evaluate(() => {
      const w = window as unknown as { chrome: { runtime: { sendMessage: (m: { kind: string }) => Promise<unknown> } } };
      const was = w.chrome.runtime.sendMessage;
      w.chrome.runtime.sendMessage = (m) => (m.kind === "allowHost" ? Promise.resolve({ ok: false, error: "no" }) : was(m));
    });
    await stopped(answer);
    await answer.locator("#btn-continue").click();
    await expect(answer.locator("main")).toHaveAttribute("data-state", "no-block");
    await expect(answer.locator("#btn-continue")).toBeDisabled();
    await expect(answer.locator("#evidence")).toBeHidden();
  } finally {
    await answer.close();
  }
});

test("should word the privacy line with curly quotes around the host, and place Continue and the line on one row", async () => {
  const page = await openStand(FULL);
  try {
    await stopped(page);
    await expect(page.locator("#privacy")).toHaveText(`Privacy: only “${HOST}” was checked.`);
    const [c, p] = await Promise.all([page.locator("#btn-continue").boundingBox(), page.locator("#privacy").boundingBox()]);
    expect(c && p).toBeTruthy();
    // Continue on the left, the line on the right, sharing a row.
    expect(c!.x).toBeLessThan(p!.x);
    expect(Math.abs(c!.y + c!.height / 2 - (p!.y + p!.height / 2))).toBeLessThan(12);
  } finally {
    await page.close();
  }
});

// ------------------------------------------------------- board values, contrast

test("should draw the dark stop with the board's ground, glow, card, band pill, button, heading and figures", async () => {
  const page = await openStand(FULL);
  try {
    await stopped(page);
    await expect(page.locator("#band")).toBeVisible();
    await page.evaluate(() => document.fonts.ready.then(() => undefined));
    const got = await page.evaluate(() => {
      const q = (s: string): HTMLElement => document.querySelector(s) as HTMLElement;
      const cs = (s: string): CSSStyleDeclaration => getComputedStyle(q(s));
      const loaded = [...document.fonts].filter((f) => f.status === "loaded").map((f) => `${f.family.replace(/"/g, "")} ${f.weight}`);
      return {
        bg: cs("body").backgroundColor,
        bgImage: cs("body").backgroundImage,
        card: cs("#evidence").backgroundColor,
        cardRadius: cs("#evidence").borderTopLeftRadius,
        band: { bg: cs("#band").backgroundColor, ink: cs("#band").color, size: cs("#band").fontSize, weight: cs("#band").fontWeight, radius: cs("#band").borderTopLeftRadius },
        back: { bg: cs("#btn-back").backgroundColor, ink: cs("#btn-back").color, size: cs("#btn-back").fontSize, weight: cs("#btn-back").fontWeight, minHeight: cs("#btn-back").minHeight, radius: cs("#btn-back").borderTopLeftRadius },
        h1: { size: cs("h1").fontSize, weight: cs("h1").fontWeight, family: cs("h1").fontFamily, line: cs("h1").lineHeight },
        detail: { size: cs("#detail").fontSize },
        well: cs("#ev-age").backgroundColor,
        main: q("main").getBoundingClientRect().width,
        loaded,
      };
    });
    expect(got.bg).toBe("rgb(1, 1, 3)");
    expect(got.bgImage).toContain("radial-gradient");
    expect(got.card).toBe("rgb(13, 13, 26)");
    expect(got.cardRadius).toBe("16px");
    expect(got.band).toEqual({ bg: "rgb(184, 32, 42)", ink: "rgb(255, 255, 255)", size: "11px", weight: "700", radius: "999px" });
    expect(got.back).toEqual({ bg: "rgb(125, 92, 224)", ink: "rgb(255, 255, 255)", size: "16px", weight: "700", minHeight: "50px", radius: "6px" });
    expect(got.h1.size).toBe("36px");
    expect(got.h1.weight).toBe("900");
    expect(got.h1.family).toMatch(/^Lato/);
    expect(got.h1.line).toBe("43.2px");
    expect(got.detail.size).toBe("17px");
    expect(got.well).toBe("rgb(6, 6, 12)");
    expect(got.main, "one column, 880 px at most").toBeLessThanOrEqual(880);
    expect(got.loaded, "the bundled faces are the ones drawn").toEqual(expect.arrayContaining(["Lato 900", "JetBrains Mono 700"]));
  } finally {
    await page.close();
  }
});

/**
 * Every text and control on the page, measured as drawn. A page ground that is a
 * gradient reports only its base colour, so text sitting straight on the ground
 * is measured against the base with the glow's full strength over it (the glow
 * is strongest at the top centre, so that is the worst case anywhere on the page).
 */
async function contrastSamples(page: Page): Promise<{ what: string; ratio: number; floor: number }[]> {
  return page.evaluate(() => {
    const px = (c: string): number[] => {
      const raw = (c.match(/-?[\d.]+/g) ?? []).map(Number);
      const scale = c.startsWith("color(") ? 255 : 1;
      return [raw[0]! * scale, raw[1]! * scale, raw[2]! * scale, raw[3] ?? 1];
    };
    const over = (fg: number[], bg: number[]): number[] => {
      const a = fg[3]!;
      return [0, 1, 2].map((i) => fg[i]! * a + bg[i]! * (1 - a)).concat(1);
    };
    const lum = (c: number[]): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * f(c[0]!) + 0.7152 * f(c[1]!) + 0.0722 * f(c[2]!);
    };
    const token = (name: string): number[] => {
      const p = document.createElement("span");
      p.style.backgroundColor = `var(${name})`;
      document.body.append(p);
      const c = px(getComputedStyle(p).backgroundColor);
      p.remove();
      return c;
    };
    const base = px(getComputedStyle(document.body).backgroundColor);
    const worstGround = over(token("--w-stop-glow"), base);
    const groundOf = (el: Element): number[] => {
      const stack: number[][] = [];
      let reachedBody = false;
      for (let n: Element | null = el; n; n = n.parentElement) {
        if (n === document.body) {
          reachedBody = true;
          stack.push(worstGround);
          break;
        }
        const c = px(getComputedStyle(n).backgroundColor);
        if (c[3]! > 0) stack.push(c);
        if (c[3] === 1) break;
      }
      let out = reachedBody ? [0, 0, 0, 1] : [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i]!, out);
      return out;
    };
    const out: { what: string; ratio: number; floor: number }[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("body *"))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? "")
        .join("")
        .trim();
      if (own === "") continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;
      if ((el as HTMLButtonElement).disabled) continue;
      const ink = over(px(cs.color), groundOf(el));
      const [hi, lo] = [lum(ink), lum(groundOf(el))].sort((a, b) => b - a);
      const size = parseFloat(cs.fontSize);
      const weight = Number(cs.fontWeight) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      out.push({
        what: `<${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${typeof el.className === "string" && el.className ? `.${el.className.trim().split(/\s+/).join(".")}` : ""}> "${own.slice(0, 40)}"`,
        ratio: (hi! + 0.05) / (lo! + 0.05),
        floor: large ? 3 : 4.5,
      });
    }
    return out;
  });
}

for (const scheme of ["dark", "light"] as const) {
  test(`should keep every text and control on the stop at 4.5:1 or better in the ${scheme} scheme, and show a focus ring on each`, async () => {
    const page = await openStand(
      {
        ...FULL,
        getBlock: { value: { ok: true, block: { blocked: true, brand: "PayPal", brandDomain: "paypal.com" } } },
      },
      { scheme },
    );
    try {
      await stopped(page);
      await expect(page.locator("#band")).toBeVisible();
      await expect(page.locator("#ev-chain .ch-evidence")).toBeVisible();
      await settledLayout(page);
      const samples = await contrastSamples(page);
      expect(samples.length, "a page that painted nothing has no failing sample either").toBeGreaterThan(25);
      const whats = samples.map((s) => s.what).join("\n");
      for (const must of ["#btn-back", "#btn-continue", "#privacy", "#detail", "#band", "#ev-completeness", ".ev-figure", ".ev-caption", ".ch-label", ".ch-value", ".ev-bar-label", ".ch-ev-lead"]) {
        expect(whats, `nothing measured for ${must}`).toContain(must.replace(/^[#.]/, ""));
      }
      const bad = samples.filter((s) => s.ratio < s.floor).map((s) => `${s.ratio.toFixed(2)}:1 (needs ${s.floor}) ${s.what}`);
      expect(bad, `text under the floor:\n${bad.join("\n")}`).toEqual([]);

      // A visible ring on every control reached by keyboard, measured at 3:1 against the page ground
      // (the base colour with the glow at full strength over it, the worst case anywhere on the page).
      const rings: string[] = [];
      for (let i = 0; i < 6; i++) {
        await page.keyboard.press("Tab");
        const ring = await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          if (!el || el === document.body) return null;
          const cs = getComputedStyle(el);
          const px = (c: string): number[] => {
            const raw = (c.match(/-?[\d.]+/g) ?? []).map(Number);
            const scale = c.startsWith("color(") ? 255 : 1;
            return [raw[0]! * scale, raw[1]! * scale, raw[2]! * scale, raw[3] ?? 1];
          };
          const lum = (c: number[]): number => {
            const f = (v: number): number => {
              const x = v / 255;
              return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
            };
            return 0.2126 * f(c[0]!) + 0.7152 * f(c[1]!) + 0.0722 * f(c[2]!);
          };
          const probe = document.createElement("span");
          probe.style.backgroundColor = "var(--w-stop-glow)";
          document.body.append(probe);
          const glow = px(getComputedStyle(probe).backgroundColor);
          probe.remove();
          const base = px(getComputedStyle(document.body).backgroundColor);
          const ground = [0, 1, 2].map((i) => glow[i]! * glow[3]! + base[i]! * (1 - glow[3]!));
          const ring = px(cs.outlineColor);
          const [hi, lo] = [lum(ring), lum(ground)].sort((x, y) => y - x);
          return { id: el.id, style: cs.outlineStyle, width: parseFloat(cs.outlineWidth), ratio: (hi! + 0.05) / (lo! + 0.05) };
        });
        if (ring && ring.id) {
          expect(ring.style, `${ring.id} has no focus ring`).not.toBe("none");
          expect(ring.width, `${ring.id} ring is too thin`).toBeGreaterThanOrEqual(2);
          expect(ring.ratio, `${ring.id} ring against the ground`).toBeGreaterThanOrEqual(3);
          rings.push(ring.id);
        }
      }
      expect(new Set(rings)).toEqual(new Set(["btn-back", "btn-real", "btn-continue"]));
    } finally {
      await page.close();
    }
  });
}

// ------------------------------------------------------------ narrow window

test("should fit a 375 px window with no sideways overflow, the columns stacked and every control and the privacy line in view", async () => {
  const page = await openStand(
    {
      ...FULL,
      getBlock: { value: { ok: true, block: { blocked: true, brand: "PayPal", brandDomain: "paypal.com" } } },
      getProtection: { value: { ok: true, protection: protectionOf({ label: "credentialphishingsuspect".repeat(5) }) } },
    },
    { width: 375, height: 800 },
  );
  try {
    await stopped(page);
    await settledLayout(page);
    const m = await page.evaluate(() => {
      const r = (s: string): { left: number; right: number; top: number } => {
        const b = (document.querySelector(s) as HTMLElement).getBoundingClientRect();
        return { left: b.left, right: b.right, top: b.top };
      };
      const wide = [...document.querySelectorAll<HTMLElement>("main *")]
        .filter((e) => e.getBoundingClientRect().right > document.documentElement.clientWidth + 0.5 && getComputedStyle(e).display !== "none")
        .map((e) => `${e.tagName.toLowerCase()}${e.id ? `#${e.id}` : ""}`);
      return {
        scroll: document.documentElement.scrollWidth,
        client: document.documentElement.clientWidth,
        wide,
        back: r("#btn-back"),
        band: r("#band"),
        real: r("#btn-real"),
        cont: r("#btn-continue"),
        privacy: r("#privacy"),
        chain: r("#ev-chain"),
        side: r("#ev-age"),
        main: r("main"),
      };
    });
    expect(m.scroll, "no sideways scroll").toBeLessThanOrEqual(m.client);
    expect(m.wide, "elements past the right edge").toEqual([]);
    for (const k of ["back", "band", "real", "cont", "privacy"] as const) {
      expect(m[k].left, `${k} left edge`).toBeGreaterThanOrEqual(0);
      expect(m[k].right, `${k} right edge`).toBeLessThanOrEqual(375);
    }
    expect(m.main.left).toBeGreaterThanOrEqual(0);
    expect(m.back.left, "a 16 px gutter at the window's edge").toBe(16);
    // The two columns stack: the figures sit below the rows, not beside them.
    expect(m.side.top, "the figures sit under the chain rows").toBeGreaterThan(m.chain.top + 50);
    expect(Math.abs(m.side.left - m.chain.left)).toBeLessThan(2);
  } finally {
    await page.close();
  }
});

test("should name the host in the claim and carry none of the board's sample values", async () => {
  const text = await (async () => {
    const page = await openStand(FULL);
    try {
      await stopped(page);
      return await textOf(page, "main");
    } finally {
      await page.close();
    }
  })();
  expect(text).toMatch(new RegExp(`${escapeRe(HOST)} is listed for credential phishing`));
  for (const sample of ["secure-wallet-restore.app", "198.51.100.23", "87 / 256", "312 other names"]) {
    expect(text, `the board's sample "${sample}" is never in the page`).not.toContain(sample);
  }
});
