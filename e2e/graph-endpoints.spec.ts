// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The graph endpoint, pinned against the real built extension.
//
// The defect this exists to prevent: Guard's whole public tier (the
// signed-out popup verdict, the link sweep, keyless enrichment, and the
// pre-emptive click check, which is keyless BY DESIGN) pointed at a
// host that could not answer it. Nothing failed loudly. assessHostKeyless
// throws, preemptCheck catches and fails open, and the flagship interruption
// simply never appears. An endpoint defect in this client is invisible by
// construction, which is why it needs pinning from the outside.
//
// Guard addresses ONE graph host, which answers both the keyless read arm
// and the keyed control arm. The invariants below are properties of the
// REQUEST rather than of the hostname, which is why they are worth pinning
// separately even though both constants name the same host today:
//
//   1. a read is keyless-capable and carries a bare hostname and nothing else
//   2. a control call is always keyed and carries no browsing datum
//   3. neither verb ever appears on the other's call path
//   4. a browsing hostname reaches exactly ONE Whisper host, ever
//   5. when the graph sheds a keyless read, the verdict degrades to unknown
//      and never to a false clean
//
// Plus a spanning guard (the last test) that no source file or spec may name
// a graph host in a literal. That is not tidiness. `requestsTo("a host
// nobody contacts")` returns an empty array, so every `toHaveLength(0)`
// written against a stale literal passes for the wrong reason, and a whole
// privacy assertion quietly stops asserting anything.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_CONTROL_HOST, GRAPH_READ_HOST } from "./helpers/servers";
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

let net: E2ENetwork;
let ext: Extension;

const START = "start-endpoints-guard-e2e.com";
const CTRL = "control-endpoints-guard-e2e.com";
const SHED = "shed-endpoints-guard-e2e.com";
const EVIL = "evil-endpoints-guard-e2e.com";
// Deliberately not in the shape of a real credential. The client treats the
// key as opaque and never parses it, so nothing is lost by keeping the
// production prefix out of a public repository.
const MOCK_KEY = "e2e-endpoint-mock-key-not-a-credential";

function startHtml(): string {
  return `<!doctype html>
<html><head><title>${START}</title></head>
<body><h1>${START}</h1>
<a id="lnk-evil" href="https://${EVIL}/lure?token=hunter2#frag">win a prize</a>
</body></html>`;
}

const OVERLAY = "div[style*='2147483647']";

async function waitArmed(tabId: number): Promise<void> {
  await expect
    .poll(
      async () =>
        ext.sw.evaluate(async (id: number) => {
          try {
            const r = (await chrome.tabs.sendMessage(id, { kind: "whisper-preempt-ping" })) as
              | { armed?: boolean }
              | undefined;
            return r?.armed === true;
          } catch {
            return false;
          }
        }, tabId),
      { timeout: 15_000 },
    )
    .toBe(true);
}

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  net.setVerdict(START, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage(START, startHtml());
  net.setVerdict(EVIL, { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  // Both of the shed test's hosts are CLEAN in the mock, so "benign" is what a
  // client that ignored the shed would show. The failure mode being excluded
  // is a false clean, so the fixture has to be able to produce one.
  net.setVerdict(CTRL, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict(SHED, { band: "NONE", coverage: "known-clean", label: "clean" });
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setSettings(ext, { shield: true, cloudCheck: true });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test.beforeEach(() => {
  net.graphMode = "mock";
  net.clearLog();
});

test("a signed-out read is keyless, carries a bare hostname, and reaches one host", async () => {
  await setKey(ext, null); // signed out: every call below is keyless
  net.clearLog();

  const { page, tabId } = await visit(ext, `https://${START}/`);
  await waitForIcon(ext, tabId, ["benign"]);

  // The read went out keyless, carrying the hostname and nothing else. Not
  // the path, not the query, not the fragment - the URL visited has none of
  // those, so the sharper assertion is the exact parameter shape.
  //
  // Asserted over EVERY read rather than over reads[0]. The first-run page
  // live-samples a host of its own on install, so which read lands first is
  // a race, and pinning the first one made this test fail for a reason that
  // had nothing to do with what it is guarding. Asserting the invariant over
  // all of them is both order-independent and strictly stronger: no keyless
  // read may carry anything but bare hostnames, whoever sent it.
  const reads = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https");
  expect(reads.length).toBeGreaterThan(0);
  for (const r of reads) {
    const params = JSON.parse(r.body).parameters;
    expect(Object.keys(params)).toEqual(["hs"]);
    for (const h of params.hs) expect(h).not.toMatch(/[/?#]/);
    expect(r.key).toBeNull();
  }

  // And the read for the page actually visited carried exactly its hostname.
  const startRead = reads.find((r) => JSON.parse(r.body).parameters.hs.includes(START));
  expect(startRead, `no keyless read carried ${START}`).toBeDefined();
  expect(JSON.parse(startRead!.body).parameters).toEqual({ hs: [START] });

  // Signed out there is nothing for the control plane to answer, so it is
  // never called: no whisper.agents on the wire at all.
  for (const r of net.log) expect(r.body).not.toContain("whisper.agents");

  // And a browsing hostname reached exactly one Whisper host. The visited
  // site itself is the only other destination.
  const whisperHosts = net
    .contactedHosts()
    .filter((h) => h.endsWith(".whisper.online") || h.endsWith(".whisper.security"));
  expect(whisperHosts).toEqual([GRAPH_READ_HOST]);
  await page.close();
});

test("a shed keyless read degrades to unknown, never to a false clean", async () => {
  await setKey(ext, null);

  // Two hosts neither of which has been resolved before, because the verdict
  // cache answers a second visit to the same name and would make this test
  // measure the cache instead of the graph.
  //
  // CONTROL first, so a pass below cannot be a dead harness: with the graph
  // healthy, a clean host reads benign and the read is on the wire.
  net.graphMode = "mock";
  net.clearLog();
  const healthy = await visit(ext, `https://${CTRL}/`);
  await waitForIcon(ext, healthy.tabId, ["benign"]);
  const ok = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https");
  expect(ok.length).toBeGreaterThan(0);
  expect(JSON.parse(ok[0].body).parameters).toEqual({ hs: [CTRL] });
  await healthy.page.close();

  // Now the fixture sheds every KEYLESS read while still answering keyed
  // ones. The read is genuinely attempted and genuinely refused, so the
  // verdict must say it does not know. The mock calls this host CLEAN, so a
  // client that let an error stand in for an answer would show benign here,
  // which is the one thing it must never do.
  net.graphMode = "keylessShed";
  net.clearLog();
  const { page, tabId } = await visit(ext, `https://${SHED}/`);
  await waitForIcon(ext, tabId, ["unknown"]);
  const shed = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https");
  expect(shed.length).toBeGreaterThan(0); // it was asked, not skipped
  expect(shed[0].key).toBeNull();
  await page.close();
});

test("the pre-emptive interstitial fires on the keyless read path", async () => {
  await setKey(ext, null);
  net.graphMode = "mock";
  net.clearLog();

  const { page, tabId } = await visit(ext, `https://${START}/`);
  await waitArmed(tabId);
  net.clearLog();

  // THE headline. The target check is keyless BY DESIGN. Point it at a host
  // that cannot serve keyless and assessHostKeyless throws, preemptCheck
  // fails open, and the click sails through to the flagged destination with
  // no interstitial and no trace: the flagship interruption, silently dead.
  await page.click("#lnk-evil");
  await expect
    .poll(async () => page.locator(OVERLAY).count(), { timeout: 10_000 })
    .toBeGreaterThan(0);
  expect(page.url()).toBe(`https://${START}/`);
  expect(net.requestsTo(EVIL).filter((r) => r.scheme === "https")).toHaveLength(0);

  const reads = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.scheme === "https");
  expect(reads).toHaveLength(1);
  expect(JSON.parse(reads[0].body).parameters).toEqual({ hs: [EVIL] });
  expect(reads[0].key).toBeNull();
  await page.close();
});

test("the control plane is always keyed and never carries a browsing hostname", async () => {
  await setKey(ext, MOCK_KEY);
  net.clearEndpoints();
  net.addEndpoint({
    agent: "agent-e2e-endpoints",
    address: "2a04:2a01:e2e:9::1",
    label: "Endpoint split probe",
    device: true,
    counters: { dns_queries: 12 },
    logs: [],
  });
  net.clearLog();

  const dash = await openDashboard(ext, "fleet");
  await expect(dash.locator("#f-roster")).toContainText("Endpoint split probe", { timeout: 15_000 });

  const control = net
    .requestsTo(GRAPH_CONTROL_HOST)
    .filter((r) => r.scheme === "https" && r.body.includes("whisper.agents"));
  expect(control.length).toBeGreaterThan(0);
  for (const r of control) {
    // The roster is account data, not browsing data.
    expect(r.key).toBe(MOCK_KEY);
    expect(r.body).not.toContain("whisper.assess");
    expect(r.body).not.toContain(START);
    expect(r.body).not.toContain(EVIL);
  }
  // And no read ever carries the control verb, which would simply 400.
  const reads = net.requestsTo(GRAPH_READ_HOST).filter((r) => r.body.includes("whisper.assess"));
  for (const r of reads) expect(r.body).not.toContain("whisper.agents");
  await dash.close();
  await setKey(ext, null);
});

test("no file names a graph host in a literal, or a credential prefix at all", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = resolve(here, "..");

  // Generated trees and the git database, by name. This used to skip every
  // dot-entry, which took .git and node_modules out (right) and .github out
  // with them (wrong): the two workflow YAMLs are as public as any other file
  // and a key pasted into one is as leaked.
  const SKIP_DIRS = new Set([
    ".git",
    "node_modules",
    "dist",
    "e2e-report",
    "e2e-artifacts",
    "test-results",
    "web-ext-artifacts",
  ]);
  const walk = (dir: string, match: RegExp, out: string[] = []): string[] => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (SKIP_DIRS.has(e.name)) continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) walk(full, match, out);
      else if (match.test(e.name)) out.push(full);
    }
    return out;
  };

  // Four files may write a graph host down, each because a stale literal
  // there FAILS rather than passes quietly, which is the whole hazard:
  //
  //   src/shared/config.ts          defines the endpoint and the rules that
  //                                 separate a read from a control call
  //   e2e/helpers/servers.ts        defines the mock host constants that every
  //                                 other file must go through
  //   e2e/escalation-decision.spec.ts  pins host_permissions with toEqual
  //                                 against the real manifest, so a drift is
  //                                 a red test, not a silent one
  //   e2e/live.spec.ts              talks to the real production endpoint,
  //                                 which is the subject of that suite
  const allowed = new Set(
    [
      "src/shared/config.ts",
      "e2e/helpers/servers.ts",
      "e2e/escalation-decision.spec.ts",
      "e2e/live.spec.ts",
    ].map((r) => resolve(root, r)),
  );

  // The HOST rule reads code only: its detector strips comments, and comment
  // syntax is a property of code. The CREDENTIAL rule reads code AND the text
  // formats a key actually gets pasted into. Its comment said "anywhere in a
  // public repository" while its walk said .ts/.tsx/.mjs/.js, so every store
  // listing, the README, SECURITY.md, both manifests, both workflow YAMLs and
  // every HTML page went unscanned. A key lands in a README far more often
  // than in a spec, and a rule whose stated scope and actual scope disagree is
  // the same defect class the rule exists to catch.
  const files = walk(root, /\.(ts|tsx|mjs|js)$/);
  // Everything else that is text, by exclusion rather than by list. An
  // allow-list of extensions is the same defect one level down: the previous
  // version named md/yml/json/html and so walked past .css, .svg and every
  // extensionless file (LICENSE, NOTICE, .gitignore). A credential does not
  // care what suffix it lands under, so the walk stops guessing and takes
  // everything that is not a known binary.
  const textFiles = walk(root, /^(?!.*\.(png|jpg|jpeg|gif|webp|ico|woff2?|ttf|zip|pdf)$).*$/i).filter(
    (f) => !/\.(ts|tsx|mjs|js)$/.test(f),
  );
  const credFiles = [...files, ...textFiles];

  // CONTROL: the walk must actually reach the tree it is auditing, or an
  // empty result would read as a clean one.
  expect(files.length).toBeGreaterThan(30);
  expect(files).toContain(resolve(root, "src/shared/config.ts"));

  // CONTROL for the by-exclusion walk: name one file per format that the
  // previous allow-list walked past, so a future narrowing fails here.
  for (const rel of ["src/shared/theme.css", "assets/icons/base.svg", "LICENSE", "NOTICE"]) {
    expect(credFiles, `${rel} must be inside the credential walk`).toContain(resolve(root, rel));
  }

  // CONTROL for the widened half, and it is NOT a count: a count drifts and
  // then gets lowered. These are the specific files that once went unscanned,
  // named one by one, so dropping any format from the walk fails here rather
  // than quietly shrinking the guard.
  for (const rel of [
    "README.md",
    "SECURITY.md",
    "store/chrome-web-store.md",
    "store/firefox-amo.md",
    "store/cws-submission-fields.md",
    "manifests/manifest.chromium.json",
    "manifests/manifest.firefox.json",
    "package.json",
    ".github/workflows/ci.yml",
    ".github/workflows/dep-audit.yml",
    "src/popup/popup.html",
    "src/pages/dashboard.html",
  ]) {
    expect(textFiles, `the credential walk must reach ${rel}`).toContain(resolve(root, rel));
  }

  // A comment may discuss a hostname; a literal must not be one. Stripping
  // the comment is therefore the whole detector, and it has to strip ONLY a
  // comment: a naive /\/\/.*$/ also eats the "//" of "https://", so the most
  // dangerous literal of all, a full URL passed to fetch, was invisible to
  // this guard. Requiring the "//" not to follow a ":" keeps a URL scheme out
  // of the strip.
  const codeOf = (line: string): string =>
    line.replace(/(^|[^:])\/\/.*$/, "$1").replace(/^\s*\*.*$/, "");
  const namesAHost = (line: string): boolean =>
    /graph\.whisper\.(online|security)/.test(codeOf(line));

  // CONTROL: the detector must flag a real offender, or an empty offender
  // list below means the detector is broken rather than the tree being clean.
  // Both forms, because the URL form is the one it used to miss.
  //
  // The samples are BUILT from the constants rather than written out, because
  // this file is not in the allowlist and a hand-written sample would be a
  // literal like any other. The guard holding its own control to its own rule
  // is the point, not an inconvenience.
  const sibling = GRAPH_READ_HOST.replace(".online", ".security");
  expect(namesAHost(`const u = "https://${GRAPH_READ_HOST}/api/query";`)).toBe(true);
  expect(namesAHost(`net.requestsTo("${sibling}")`)).toBe(true);
  // And it must NOT flag prose, or the guard would be unusable and get deleted.
  expect(namesAHost(`// ${GRAPH_READ_HOST} is the host Guard reads from`)).toBe(false);
  expect(namesAHost(` * ${sibling} is not contacted`)).toBe(false);

  // The same walk carries a second rule, for the same reason. A PRODUCTION
  // CREDENTIAL PREFIX must not appear anywhere in a public repository, not in
  // a value and not in prose describing one. Prose is the half that gets
  // missed: a mock can be renamed while the comment six lines above it still
  // spells the real prefix out, and a comment is not something anyone greps.
  // Unlike the host rule this one deliberately does NOT strip comments.
  //
  // The prefixes are ASSEMBLED from fragments rather than written out, for
  // exactly the reason the host samples are built from constants: this file is
  // held to its own rule, and a rule that has to spell out the thing it forbids
  // would be its own first offender.
  const CRED_PREFIXES = ["whisper" + "_live_", "whisper" + "_key_", "e" + "t_"];
  const namesACredPrefix = (line: string): boolean =>
    CRED_PREFIXES.some((p) => new RegExp(`\\b${p}`).test(line));

  // CONTROL, both directions, so an empty list cannot mean a broken detector.
  expect(namesACredPrefix(`const k = "${CRED_PREFIXES[0]}abc123";`)).toBe(true);
  expect(namesACredPrefix(`// Proxy-Authorization (Basic w:${CRED_PREFIXES[2]}...)`)).toBe(true);
  expect(namesACredPrefix('const k = "e2e-mock-key-not-a-credential";')).toBe(false);
  expect(namesACredPrefix("// the egressToken below")).toBe(false);

  const offenders: string[] = [];
  const credOffenders: string[] = [];
  for (const f of credFiles) {
    const text = readFileSync(f, "utf8");
    const isCode = files.includes(f);
    text.split("\n").forEach((line, i) => {
      const where = `${f.slice(root.length + 1)}:${i + 1}: ${line.trim()}`;
      if (isCode && !allowed.has(f) && namesAHost(line)) offenders.push(where);
      if (namesACredPrefix(line)) credOffenders.push(where);
    });
  }
  expect(offenders, `use GRAPH_QUERY_URL / GRAPH_READ_HOST instead:\n${offenders.join("\n")}`).toEqual([]);
  expect(
    credOffenders,
    `a production credential prefix must not appear in a public repo, in a value OR in prose:\n${credOffenders.join("\n")}`,
  ).toEqual([]);
});
