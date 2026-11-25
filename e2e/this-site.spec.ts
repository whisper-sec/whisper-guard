// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: THE THIS SITE PART. The verdict, the facts behind the name and the way
// to the graph path, at the top of the popup's one scroll.
//
// It shows a verdict card, a row of plain chips, a "who is behind it" card
// with a count of the facts read, a link to the graph path and one closed row
// holding the four drawers. Each claim is measured on the built extension:
//
//   - on a clean site the verdict card, its chips and all seven facts are on
//     the first screen, clear of the fade, in both schemes;
//   - a site name that fits the card keeps one line, with the pill under it
//     when both do not fit side by side; a longer name breaks, never cut;
//   - the counter counts rows ANSWERED, and an unread row says so in words;
//   - a chip shows only when the data behind it exists;
//   - the graph path link opens the check-link page for the hostname, by
//     keyboard and by mouse, and sends nothing the page does not send itself;
//   - the privacy line names the exact hostname that was sent;
//   - "Why this verdict" shows only for a threat factor or a non-zero score;
//   - the drawers stay lazy inside their one row;
//   - the neighbours note shows only where it is true;
//   - the reason line adds the age only after the history read came back.
//
// Every case uses its own host: the chain walk is memoised per name.

import { test, expect, type Page } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST, MOCK_API_KEY } from "./helpers/servers";
import {
  launchExtension,
  openPopup,
  setKey,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";
import { WIDER_EM, expectFirstScreen, withWiderGlyphs } from "./helpers/popup-fit";

let net: E2ENetwork;
let ext: Extension;

const CLEAN = "site-clean-guard-e2e.com";
const LOW_LABELLED = "site-lowlabel-guard-e2e-ok.com";
const DAY = 86_400_000;
const AGE_DAYS = 800;

interface SeedOptions {
  band?: string;
  label?: string;
  coverage?: string;
  hostClass?: string;
  threatNeighbors?: number;
  /** Rows for whisper.explain; omitted means the graph has none. */
  explain?: Record<string, unknown>[];
  /** Days since registration; omitted means no history row. */
  ageDays?: number;
}

// The mock answers the route read by address, so each host gets its own.
let nextAddress = 40;

function seed(host: string, o: SeedOptions = {}): void {
  net.setVerdict(host, { band: o.band ?? "NONE", coverage: o.coverage ?? "known-clean", label: o.label ?? "clean" });
  net.setEnrich(host, {
    ip: `198.51.100.${nextAddress++}`,
    city: "London, GB",
    country: "GB",
    asn: "AS64540",
    owner: "MediaCo plc",
    asnName: "MEDIACO - MediaCo plc",
    prefix: "198.51.100.0/24",
    threatNeighbors: o.threatNeighbors ?? 0,
    prevalence: 812,
    verdict: o.band ?? "NONE",
  });
  net.setIdentify(host, [
    {
      host,
      canonical_name: "MediaCo",
      category: "media",
      roles: ["DNS_OPERATOR", "ORIGIN_AS"],
      confidence: 0.85,
      host_class: o.hostClass ?? "single_tenant",
      evidence: ["RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco"],
    },
  ]);
  net.setPresence("AS64540", {
    facilities: ["Example Carrier Hotel LON1", "Example Colo LON2"],
    exchanges: ["Example Exchange LON"],
    facilityCount: 14,
    exchangeCount: 4,
  });
  if (o.explain) net.setExplain(host, o.explain);
  if (o.ageDays !== undefined) {
    const created = new Date(Date.now() - o.ageDays * DAY).toISOString();
    net.setHistory(host, [{ createDate: created, updateDate: created }]);
  }
}

const POPULARITY = [{ score: 0, sources: [{ feedId: "tranco" }] }];

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  seed(CLEAN, { explain: POPULARITY, ageDays: AGE_DAYS });
  seed(LOW_LABELLED, { band: "LOW", label: "shared hosting provider", explain: POPULARITY, ageDays: AGE_DAYS });
  ext = await launchExtension({ proxyPort: net.proxyPort });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(async () => {
  net.graphMode = "mock";
  net.failQueries.clear();
  net.clearLog();
  await setKey(ext, null);
  await setSettings(ext, { cloudCheck: true, allowlist: [] });
});

// -------------------------------------------------------------- the helpers

/** The popup for a site, once the facts card has drawn. */
async function openSite(
  url: string,
  opts: { colorScheme?: "dark" | "light"; icon?: Parameters<typeof waitForIcon>[2] } = {},
): Promise<{ popup: Page; page: Page; tabId: number }> {
  const { page, tabId } = await visit(ext, url);
  await waitForIcon(ext, tabId, opts.icon ?? ["benign", "unknown"]);
  const popup = await openPopup(ext, tabId);
  if (opts.colorScheme) await popup.emulateMedia({ colorScheme: opts.colorScheme });
  await popup.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 20_000 });
  return { popup, page, tabId };
}

/** One more round trip to the worker for the same protection answer: by the time it
 *  returns, the popup's own read of it has been drawn, so a "stays hidden" check is
 *  not passing only because the answer had not landed yet. */
async function protectionDrawn(popup: Page, host: string): Promise<void> {
  await popup.evaluate((h) => chrome.runtime.sendMessage({ kind: "getProtection", host: h }), host);
}

/** The kind of every graph read since the log was cleared. */
function graphKinds(): string[] {
  return net.requestsTo(GRAPH_READ_HOST)
    .filter((r) => r.method === "POST")
    .map((r) => /CALL (whisper\.[a-zA-Z.]+)/.exec(r.body)?.[1] ?? "raw")
    .sort();
}

// -------------------------------------------------------------------- 1

// Signed in, the footer holds its two buttons as well as the sent-line, which is
// the least room the first screen ever has. The second case has a 30-character
// name, a LOW verdict and a label in the reason: the longest reason line.
const FIRST_SCREEN_CASES = [
  { name: "a clean site", host: CLEAN, note: "Nothing in the graph lists this site." },
  { name: "a LOW verdict with a label on a 30-character name", host: LOW_LABELLED, note: "(shared hosting provider)" },
];

for (const c of FIRST_SCREEN_CASES) {
  test(`${c.name}: the verdict card, its chips and all seven facts are on the first screen, clear of the fade, in the dark and the light scheme`, async () => {
    await setKey(ext, MOCK_API_KEY);
    for (const scheme of ["dark", "light"] as const) {
      const { popup, page } = await openSite(`https://${c.host}/`, { colorScheme: scheme });

      // The measurement is not vacuous: everything the part holds is drawn.
      await expect(popup.locator("#score-chip")).toBeVisible();
      await expect(popup.locator("#band-age")).toBeVisible();
      await expect(popup.locator("#band-note")).toContainText(c.note);
      await expect(popup.locator("#btn-console")).toBeVisible();
      await expect(popup.locator("#btn-dossier")).toBeVisible();
      await expect(popup.locator("#chain-mount .ch-rung")).toHaveCount(7);
      await expect(popup.locator("#expanders")).toBeVisible();
      await expect(popup.locator("#expanders")).not.toHaveAttribute("open", "");
      await expect(popup.locator("#protect-card")).toBeHidden();
      await protectionDrawn(popup, c.host);

      await expectFirstScreen(popup, `first-screen-${scheme}`);

      await popup.close();
      await page.close();
    }
  });
}

// ------------------------------------------------------------------ 1b

// The verdict card's name: it shares the row with the pill when both fit, keeps
// one line with the pill under it when only the name fits the card, and breaks
// (never cut, never wider than the card) when it is wider than the card.
const NAMES = {
  short: "ex-site.io",
  alone: "intranet-tools-vendor.com",
  long: "a-name-far-too-long-to-fit-the-card-on-one-line-guard-e2e.com",
} as const;

async function nameBoxes(popup: Page): Promise<{
  text: string;
  line: number;
  nameHeight: number;
  nameTop: number;
  nameBottom: number;
  pillTop: number;
  pillBottom: number;
  nameOverflow: boolean;
  cardOverflow: boolean;
  regionOverflow: boolean;
  nameWidth: number;
  textColumn: number;
  pillWidth: number;
}> {
  return popup.evaluate(() => {
    const name = document.getElementById("hostname") as HTMLElement;
    const pill = document.getElementById("band-chip") as HTMLElement;
    const card = document.getElementById("host-row") as HTMLElement;
    const region = document.getElementById("popup-scroll") as HTMLElement;
    const n = name.getBoundingClientRect();
    const p = pill.getBoundingClientRect();
    return {
      text: name.textContent ?? "",
      line: parseFloat(getComputedStyle(name).lineHeight),
      nameHeight: n.height,
      nameTop: n.top,
      nameBottom: n.bottom,
      pillTop: p.top,
      pillBottom: p.bottom,
      nameWidth: n.width,
      textColumn: (card.querySelector(".pp-verdict-text") as HTMLElement).getBoundingClientRect().width,
      pillWidth: p.width,
      nameOverflow: name.scrollWidth > name.clientWidth,
      cardOverflow: card.scrollWidth > card.clientWidth,
      regionOverflow: region.scrollWidth > region.clientWidth,
    };
  });
}

for (const scheme of ["dark", "light"] as const) {
  test(`the site name keeps one line where it fits the card, with the pill under it when both do not fit, and breaks without a cut when it is wider (${scheme})`, async () => {
    for (const host of Object.values(NAMES)) seed(host, { explain: POPULARITY, ageDays: AGE_DAYS });
    const seen: Record<string, string> = {};
    const say = (m: Awaited<ReturnType<typeof nameBoxes>>): string =>
      `name ${m.nameWidth.toFixed(1)} px, pill ${m.pillWidth.toFixed(1)} px, column ${m.textColumn.toFixed(1)} px`;
    for (const [kind, host] of Object.entries(NAMES) as [keyof typeof NAMES, string][]) {
      const { popup, page } = await openSite(`https://${host}/`, { colorScheme: scheme });
      await expect(popup.locator("#hostname")).toHaveText(host);
      await popup.evaluate(() => document.fonts.ready.then(() => undefined));
      const plain = await nameBoxes(popup);
      const wider = await withWiderGlyphs(popup, WIDER_EM, () => nameBoxes(popup));
      for (const [how, m] of [["as drawn", plain], [`${WIDER_EM}em wider`, wider]] as const) {
        const at = `${kind} name, ${scheme}, ${how}`;
        expect(m.text, `${at}: the name is cut`).toBe(host);
        expect(m.nameOverflow, `${at}: the name is wider than its own box`).toBe(false);
        expect(m.cardOverflow, `${at}: the card is wider than itself`).toBe(false);
        expect(m.regionOverflow, `${at}: the popup scrolls sideways`).toBe(false);
        const lines = m.nameHeight / m.line;
        if (kind === "short") {
          expect(lines, `${at}: the name is on one line`).toBeCloseTo(1, 1);
          // The pill is on the name's row: their boxes overlap in height.
          expect(m.pillTop, `${at}: the pill is not beside the name`).toBeLessThan(m.nameBottom);
          expect(m.pillBottom, `${at}: the pill is not beside the name`).toBeGreaterThan(m.nameTop);
        } else if (kind === "alone") {
          expect(lines, `${at}: the name is broken over lines`).toBeCloseTo(1, 1);
          expect(m.pillTop, `${at}: the pill is not under the name`).toBeGreaterThanOrEqual(m.nameBottom);
        } else {
          expect(lines, `${at}: the name was not broken`).toBeGreaterThan(1.5);
          expect(m.pillTop, `${at}: the pill is not under the name`).toBeGreaterThanOrEqual(m.nameBottom);
        }
      }
      seen[kind] = `${host.length} characters; as drawn ${say(plain)}; ${WIDER_EM}em wider ${say(wider)}`;
      await popup.close();
      await page.close();
    }
    for (const [kind, what] of Object.entries(seen)) test.info().annotations.push({ type: `name-${kind}-${scheme}`, description: what });
  });
}

// -------------------------------------------------------------------- 2

test("the counter counts the rows read, and an unread row says so", async () => {
  // Control: every row answered.
  {
    const { popup, page } = await openSite(`https://${CLEAN}/`);
    await expect(popup.locator("#facts-count")).toHaveText("7/7 facts read");
    await expect(popup.locator("#chain-mount .ch-rung.ch-lost")).toHaveCount(0);
    await popup.close();
    await page.close();
  }

  // One read fails while the rest answer.
  net.failQueries.add("AS_PRESENT_AT");
  const BROKEN = "site-unread-guard-e2e.com";
  seed(BROKEN);
  {
    const { popup, page } = await openSite(`https://${BROKEN}/`);
    await expect(popup.locator("#facts-count")).toHaveText("6/7 facts read");
    const lost = popup.locator("#chain-mount .ch-rung.ch-lost");
    await expect(lost).toHaveCount(1);
    await expect(lost).toContainText("Present at");
    await expect(lost).toContainText("could not be read");
    for (const v of await popup.locator("#chain-mount .ch-value").allTextContents()) {
      expect(v.trim(), "a row was left blank").not.toBe("");
    }
    await popup.close();
    await page.close();
  }
  net.failQueries.clear();

  // A row the graph answered with nothing counts as read.
  const EMPTY = "site-empty-vendor-guard-e2e.com";
  seed(EMPTY);
  net.setIdentify(EMPTY, []);
  {
    const { popup, page } = await openSite(`https://${EMPTY}/`);
    await expect(popup.locator("#facts-count")).toHaveText("7/7 facts read");
    expect(await popup.locator("#chain-mount .ch-rung.ch-live").count()).toBeLessThan(7);
    await popup.close();
    await page.close();
  }
});

// -------------------------------------------------------------------- 3

test("the coverage, graph score and Allowlisted chips show only when their data exists", async () => {
  // Data present.
  {
    const { popup, page } = await openSite(`https://${CLEAN}/`);
    await expect(popup.locator("#coverage-chip")).toContainText("Coverage: known-clean");
    await expect(popup.locator("#coverage-chip")).toContainText("not a safety score");
    await expect(popup.locator("#score-chip")).toHaveText("Graph score 0");
    await expect(popup.locator("#allow-chip")).toBeHidden();
    await popup.close();
    await page.close();
  }

  // The graph knows nothing about the name: no chip, and no empty row.
  {
    const UNSEEN = "site-unseen-guard-e2e.com";
    const { popup, page } = await openSite(`https://${UNSEEN}/`);
    await protectionDrawn(popup, UNSEEN);
    await expect(popup.locator("#band-chip")).toHaveText("UNKNOWN");
    await expect(popup.locator("#coverage-chip")).toBeHidden();
    await expect(popup.locator("#score-chip")).toBeHidden();
    await expect(popup.locator("#site-chips")).toBeHidden();
    await popup.close();
    await page.close();
  }

  // The reader's own Trusted sites list, matched by the detector's rule.
  const TRUSTED = "site-trusted-guard-e2e.com";
  const TWIN = "site-twin-guard-e2e.com";
  for (const h of [TRUSTED, TWIN]) seed(`www.${h}`, { explain: POPULARITY, ageDays: AGE_DAYS });
  const kindsOfOpen = async (host: string): Promise<string[]> => {
    const { page, tabId } = await visit(ext, `https://www.${host}/`);
    await waitForIcon(ext, tabId, ["benign", "unknown"]);
    net.clearLog();
    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#band-age")).toBeVisible({ timeout: 20_000 });
    await expect(popup.locator("#score-chip")).toBeVisible();
    await protectionDrawn(popup, `www.${host}`);
    const shown = await popup.locator("#allow-chip").isVisible();
    const kinds = graphKinds();
    if (shown) await expect(popup.locator("#allow-chip")).toHaveText("Allowlisted");
    await popup.close();
    await page.close();
    return [shown ? "chip" : "no chip", ...kinds];
  };
  const twin = await kindsOfOpen(TWIN);
  await setSettings(ext, { allowlist: [TRUSTED] });
  const trusted = await kindsOfOpen(TRUSTED);
  await setSettings(ext, { allowlist: [] });
  expect(twin[0]).toBe("no chip");
  expect(trusted[0]).toBe("chip");
  expect(trusted.slice(1), "the chip sent something the twin did not").toEqual(twin.slice(1));
});

// -------------------------------------------------------------------- 4

test.describe("Show the graph path", () => {
  const PATHY = "site-graph-path-guard-e2e.com";

  const hostnamesIn = (body: string): string[] => {
    let parsed: { parameters?: Record<string, unknown> };
    try {
      parsed = JSON.parse(body) as typeof parsed;
    } catch {
      return [];
    }
    const out: string[] = [];
    for (const v of Object.values(parsed.parameters ?? {})) {
      for (const s of Array.isArray(v) ? v : [v]) {
        if (typeof s !== "string") continue;
        // Names only: an address, a prefix or an AS number is not a hostname.
        if (/^[0-9a-f:.\/]+$/i.test(s) || /^AS\d+$/i.test(s)) continue;
        if (/[a-z]/i.test(s) && s.includes(".")) out.push(s.toLowerCase());
      }
    }
    return out;
  };

  async function openedBy(how: () => Promise<void>): Promise<Page> {
    const opened = ext.context.waitForEvent("page", { timeout: 20_000 });
    await how();
    const tab = await opened;
    await expect.poll(() => tab.url(), { timeout: 20_000 }).not.toBe("about:blank");
    return tab;
  }

  for (const how of ["keyboard", "mouse"] as const) {
    test(`opens the check-link page for this hostname by ${how}, and sends nothing new`, async () => {
      const host = `${how}-${PATHY}`;
      seed(host, { explain: POPULARITY, ageDays: AGE_DAYS });
      const { page, tabId } = await visit(ext, `https://${host}/private-path-marker?q=secret`);
      await waitForIcon(ext, tabId, ["benign", "unknown"]);
      const popup = await openPopup(ext, tabId);
      await popup.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 20_000 });
      await expect(popup.locator("#graph-path")).toBeVisible();
      await expect(popup.locator("#graph-path")).toHaveText("Show the graph path →");
      net.clearLog();

      const tab = await openedBy(async () => {
        if (how === "mouse") {
          await popup.locator("#graph-path").click();
          return;
        }
        // From the first control in the popup: the header's Re-check button.
        await popup.locator("#btn-refresh").focus();
        let presses = 0;
        while ((await popup.evaluate(() => document.activeElement?.id)) !== "graph-path") {
          if (++presses > 40) throw new Error("Tab never reached #graph-path in 40 presses");
          await popup.keyboard.press("Tab");
        }
        await popup.keyboard.press("Enter");
      });
      expect(tab.url()).toBe(`chrome-extension://${ext.id}/check-link.html?host=${encodeURIComponent(host)}`);
      await expect(tab.locator("#host")).toHaveText(host);
      await expect(tab.locator("#chain-card")).toContainText("THE JOIN PATH");
      await tab.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 20_000 });

      for (const r of net.requestsTo(GRAPH_READ_HOST)) {
        for (const name of hostnamesIn(r.body)) expect(name, "a graph request named another host").toBe(host);
        expect(r.body).not.toContain("private-path-marker");
        expect(r.body).not.toContain("secret");
      }
      await tab.close().catch(() => undefined);
      await popup.close();
      await page.close();
    });
  }
});

// -------------------------------------------------------------------- 5

test("the privacy line names the exact hostname that was sent, where it went, and that the path was not", async () => {
  const host = "site-privacy-guard-e2e.com";
  seed(`www.${host}`, { explain: POPULARITY, ageDays: AGE_DAYS });
  const { page, tabId } = await visit(ext, `https://www.${host}/some/path?x=1`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  const popup = await openPopup(ext, tabId);
  await popup.locator("#chain-mount .ch-rung.ch-live").first().waitFor({ timeout: 20_000 });

  const sentHosts = net
    .requestsTo(GRAPH_READ_HOST)
    .filter((r) => r.body.includes("whisper.assess"))
    .flatMap((r) => {
      const hs = (JSON.parse(r.body) as { parameters?: { hs?: string[] } }).parameters?.hs;
      return hs ?? [];
    });
  expect(sentHosts).toEqual([`www.${host}`]);
  const sent = sentHosts[0]!;
  await expect(popup.locator("#privacy-line")).toHaveText(
    `Privacy: Only “${sent}” was sent, to ${GRAPH_READ_HOST}. Never the page, the path or your history.`,
  );
  await popup.close();
  await page.close();
});

// -------------------------------------------------------------------- 6

test("Why this verdict shows only for a threat factor or a non-zero score, above the facts", async () => {
  {
    const { popup, page } = await openSite(`https://${CLEAN}/`);
    await protectionDrawn(popup, CLEAN);
    await expect(popup.locator("#protect-card")).toBeHidden();
    await popup.close();
    await page.close();
  }

  const FLAGGED = "site-flagged-guard-e2e.com";
  seed(FLAGGED, { band: "MEDIUM", coverage: "malicious-evidenced", explain: [{ score: 16.9, sources: [{ feedId: "e2e-feed" }] }] });
  {
    const { popup, page } = await openSite(`https://${FLAGGED}/`, { icon: ["suspicious"] });
    await expect(popup.locator("#protect-card")).toBeVisible();
    const why = await popup.locator("#protect-card").boundingBox();
    const facts = await popup.locator("#chain-card").boundingBox();
    expect(why!.y, "Why this verdict does not sit above the facts").toBeLessThan(facts!.y);
    await popup.close();
    await page.close();
  }
});

// -------------------------------------------------------------------- 7

test("the four drawers sit in one closed row at the end of the facts card, and still load only when opened", async () => {
  const { popup, page } = await openSite(`https://${CLEAN}/`);
  const card = popup.locator("#chain-card");
  await expect(card.locator("#expanders")).toHaveCount(1);
  expect(await card.evaluate((c) => c.lastElementChild?.id)).toBe("expanders");
  await expect(popup.locator("#expanders")).not.toHaveAttribute("open", "");
  await expect(popup.locator("#exp-why")).toBeHidden();

  net.clearLog();
  await popup.locator("#expanders > summary").click();
  await expect(popup.locator("#exp-why")).toBeVisible();
  expect(
    net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.explain")),
    "opening the row asked the graph",
  ).toHaveLength(0);
  await popup.locator("#exp-why summary").click();
  await expect(popup.locator("#why-body")).not.toHaveText(/^(Loading\.\.\.|Asking the graph\.\.\.)$/);
  await popup.close();
  await page.close();
});

// -------------------------------------------------------------------- 8

test("the neighbours note shows only on a clean CDN host with flagged neighbours", async () => {
  const NOTE = "Neighbours flagged on a shared CDN range are common and do not change this verdict.";
  const cases: { host: string; opts: SeedOptions; icon: Parameters<typeof waitForIcon>[2]; shown: boolean }[] = [
    { host: "site-cdn-guard-e2e.com", opts: { threatNeighbors: 3, hostClass: "cdn" }, icon: ["benign", "unknown"], shown: true },
    { host: "site-single-guard-e2e.com", opts: { threatNeighbors: 3, hostClass: "single_tenant" }, icon: ["benign", "unknown"], shown: false },
    { host: "site-medium-cdn-guard-e2e.com", opts: { threatNeighbors: 3, hostClass: "cdn", band: "MEDIUM" }, icon: ["suspicious"], shown: false },
  ];
  for (const c of cases) {
    seed(c.host, c.opts);
    const { popup, page } = await openSite(`https://${c.host}/`, { icon: c.icon });
    await expect(popup.locator("#facts-count")).toBeVisible();
    if (c.shown) {
      await expect(popup.locator("#neighbours-note")).toBeVisible();
      await expect(popup.locator("#neighbours-note")).toHaveText(NOTE);
    } else {
      await expect(popup.locator("#neighbours-note")).toBeHidden();
    }
    await popup.close();
    await page.close();
  }
});

// -------------------------------------------------------------------- 9

test("the reason line adds the age only after the history read came back", async () => {
  // The age as the chain words it: whole days since the seeded date, then whole years.
  const years = Math.floor(AGE_DAYS / 365.25);
  {
    const { popup, page } = await openSite(`https://${CLEAN}/`);
    await expect(popup.locator("#band-age")).toHaveText(`Registered ${years} years ago.`);
    await expect(popup.locator("#band-note")).toHaveText("Nothing in the graph lists this site.");
    await popup.close();
    await page.close();
  }

  net.failQueries.add("whisper.history");
  const NOHIST = "site-nohistory-guard-e2e.com";
  seed(NOHIST, { ageDays: AGE_DAYS });
  {
    const { popup, page } = await openSite(`https://${NOHIST}/`);
    await expect(popup.locator("#band-age")).toBeHidden();
    await expect(popup.locator("#band-note")).toHaveText("Nothing in the graph lists this site.");
    await popup.close();
    await page.close();
  }
  net.failQueries.clear();
});

// ------------------------------------------------------------------- 10

test("a failed facts read says so, keeps the heading, and leaves the link and the drawers", async () => {
  const host = "site-factsdown-guard-e2e.com";
  seed(host, { explain: POPULARITY, ageDays: AGE_DAYS, threatNeighbors: 3, hostClass: "cdn" });
  const { page, tabId } = await visit(ext, `https://${host}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  // The worker cannot be asked for the walk: the popup is given the failure the
  // transport would give, for that one request.
  const popup = await ext.context.newPage();
  await popup.addInitScript(() => {
    const ask = chrome.runtime.sendMessage.bind(chrome.runtime) as (m: { kind?: string }) => Promise<unknown>;
    (chrome.runtime as unknown as { sendMessage: unknown }).sendMessage = (m: { kind?: string }) =>
      m?.kind === "getChain" ? Promise.resolve({ ok: false, error: "unreachable" }) : ask(m);
  });
  await popup.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);

  await expect(popup.locator("#chain-mount")).toContainText(
    "The facts behind this name could not be read just now. Unknown, not clear.",
  );
  await expect(popup.locator("#chain-mount .ch-head")).toContainText("WHO IS BEHIND IT");
  await expect(popup.locator("#chain-mount .ch-rung")).toHaveCount(0);
  await expect(popup.locator("#facts-count")).toHaveCount(0);
  await expect(popup.locator("#chain-mount .ch-count")).toHaveCount(0);
  await expect(popup.locator("#band-age")).toBeHidden();
  await expect(popup.locator("#neighbours-note")).toBeHidden();
  await expect(popup.locator("#graph-path")).toBeVisible();
  await expect(popup.locator("#expanders")).toBeVisible();
  await popup.close();
  await page.close();
});
