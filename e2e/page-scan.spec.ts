// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The on-demand page scan, hermetic proof of EXACTLY what leaves.
//
// This is the one feature in Guard that reads a page's visible TEXT, so it is
// the one feature whose privacy claim cannot be argued from the code alone. The
// listings tick "Website content" from 2.6.0 because of it, and this test is
// what makes that tick honest: the capture proxy holds a complete record of
// every request the browser made, and the assertions below are made against
// that whole log rather than a sample.
//
// The fixture deliberately carries things a real analyst page carries and
// which must be treated DIFFERENTLY:
//
//   a hostname           the only indicator kind that SHOULD leave
//   a hash, a CVE id,    never assessed by the scan: they must NEVER leave and
//   a public IPv4        the popup reads them as "Not assessed"
//   a secret-bearing     the reason the scan reads textContent and not innerHTML,
//   path                 and it must never appear in any request
//
// A test that only asserted "the hash arrived" would pass just as well against a
// scanner that shipped the entire page, which is the failure this is written to
// catch.
import { test, expect } from "@playwright/test";
import { E2ENetwork, GRAPH_READ_HOST } from "./helpers/servers";
import { launchExtension, makeShieldDist, openPopup, visit, waitForIcon, type Extension } from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

// sha256 of the empty string: a real, well-formed hash with no meaning of its
// own, so a maintainer reading this is not tempted to look it up.
const HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const CVE = "CVE-2026-31337";
const IPV4 = "203.0.113.7"; // RFC 5737 documentation range, never routed
const SECRET_PATH = "/download?token=sk_live_do_not_exfiltrate_me";

const FIXTURE_HTML = `<!doctype html>
<html><head><title>incident notes</title></head>
<body>
  <h1>Incident notes</h1>
  <p>Dropper observed with sha256 ${HASH} on three hosts.</p>
  <p>Exploited via ${CVE}, patched upstream last week.</p>
  <p>Beaconed to <span>evil-scan.com</span> shortly after, and to ${IPV4}.</p>
  <p>Also seen: quiet-scan.com.</p>
  <a href="https://fixture-scan.com${SECRET_PATH}">the staging download</a>
  <!-- a comment carrying ${SECRET_PATH} too, which textContent never sees -->
</body></html>`;

/** The control page: no hash, no domain, no CVE, nothing assessable. */
const PLAIN_HTML = `<!doctype html>
<html><head><title>release notes</title></head>
<body><h1>Release notes</h1><p>Tidied the changelog and bumped the year.</p></body></html>`;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  // THE FIXTURE HAS TO BE REGISTERED. `start()` takes no arguments, so the
  // page map passed to it here was silently discarded and every navigation
  // in this file died on ERR_NAME_NOT_RESOLVED. The suite has therefore
  // never once proven the claim it exists to prove, while the store
  // listings tick "Website content" on the strength of it. It is now
  // registered through the API that exists, and the whole e2e tree is
  // typechecked (npm run typecheck) so a call to a signature that does not
  // exist cannot reach main again.
  net.setPage("fixture-scan.com", FIXTURE_HTML);
  net.setPagePath("fixture-scan.com", "/plain", PLAIN_HTML);
  net.setVerdict("fixture-scan.com", { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setVerdict("evil-scan.com", { band: "CRITICAL", coverage: "malicious-evidenced", label: "malicious" });
  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

test("the scan sends the indicators and nothing else of the page", async () => {
  const { page, tabId } = await visit(ext, "https://fixture-scan.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);

  // Reachability is part of this feature's contract: the scanner was merged and had no
  // sender, so the listing's old answer was true only because nobody could run
  // it. If this card is absent the feature has silently gone unreachable again.
  await expect(popup.locator("#iocscan-card")).toBeVisible({ timeout: 10_000 });
  await popup.locator("#btn-iocscan").click();
  await expect(popup.locator("#iocscan-summary")).toContainText("found", { timeout: 20_000 });

  const bodies = net
    .requestsTo(GRAPH_READ_HOST)
    .map((r) => r.body)
    .join("\n");

  // WHAT MUST LEAVE. Without this the rest of the test would pass against a
  // scanner that sent nothing at all, which is private and useless.
  expect(bodies).toContain("evil-scan.com");

  // Hashes, CVE ids and IP literals are never assessed, so none may leave.
  expect(bodies).not.toContain(HASH);
  expect(bodies).not.toContain(CVE);
  expect(bodies).not.toContain(IPV4);

  // WHAT MUST NOT. Each of these is a different way to leak.
  expect(bodies).not.toContain("sk_live_do_not_exfiltrate_me"); // the secret itself
  expect(bodies).not.toContain("token=");                  // the query that carried it
  expect(bodies).not.toContain("Dropper observed");        // the page's prose
  expect(bodies).not.toContain("Incident notes");          // its title and heading

  // The note the reader is shown must match what the capture proves, or the UI
  // is making a promise the wire does not keep. Both halves are asserted: what
  // it promises never leaves, and the full list of what does. Naming the list
  // is what stops the note drifting back to a shorter, friendlier, false one.
  await expect(popup.locator("#iocscan-note")).toContainText("never leaves your browser");
  await expect(popup.locator("#iocscan-note")).toContainText("are not sent");
  await expect(
    popup.locator("#iocscan-note"),
    "the note must not claim hashes and CVE ids are checked",
  ).not.toContainText("file hashes and CVE ids are checked");

  await popup.close();
  await page.close();
});

test("should draw unassessed indicators as Not assessed, never the ok chip", async () => {
  const { page, tabId } = await visit(ext, "https://fixture-scan.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  await popup.locator("#btn-iocscan").click();
  await expect(popup.locator("#iocscan-summary")).toContainText("found", { timeout: 20_000 });

  for (const v of [HASH, CVE, IPV4]) {
    const chip = popup.locator("#iocscan-list .link-row", { hasText: v }).locator(".w-chip");
    await expect(chip).toHaveText("Not assessed");
    await expect(chip).toHaveClass(/unassessed/);
    await expect(chip).not.toHaveClass(/\bok\b/);
  }
  await expect(popup.locator("#iocscan-list .link-row", { hasText: "evil-scan.com" }).locator(".w-chip")).toHaveText("MALICIOUS");
  await expect(popup.locator("#iocscan-list .link-row", { hasText: "quiet-scan.com" }).locator(".w-chip")).toHaveText("UNKNOWN");
  await expect(popup.locator("#iocscan-list .w-chip.ok")).toHaveCount(0);

  // UNKNOWN is not flagged: only evil-scan.com is.
  const summary = popup.locator("#iocscan-summary");
  await expect(summary).toContainText("1 flagged");
  await expect(summary).toContainText("3 not assessed");

  await popup.close();
  await page.close();
});

test("should make no explain call when scanning or when a row is clicked", async () => {
  const { page, tabId } = await visit(ext, "https://fixture-scan.com/");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  const before = net.requestsTo(GRAPH_READ_HOST).length;

  await popup.locator("#btn-iocscan").click();
  await expect(popup.locator("#iocscan-summary")).toContainText("found", { timeout: 20_000 });
  await popup.locator("#iocscan-list .link-row", { hasText: "Not assessed" }).first().click();
  await popup.locator("#btn-iocscan").click();
  await expect(popup.locator("#btn-iocscan")).toHaveText("Scanning…");
  await expect(popup.locator("#btn-iocscan")).toHaveText("Re-scan", { timeout: 20_000 });

  const added = net.requestsTo(GRAPH_READ_HOST).slice(before).map((r) => r.body).join("\n");
  expect(added).not.toContain("whisper.explain");

  await popup.close();
  await page.close();
});

test("CONTROL: a page with no indicators sends nothing at all", async () => {
  // The counterpart to the test above. If the scan reached the graph on a page
  // holding nothing worth asking about, then something other than the extracted
  // indicators is driving the request, and every claim above would be accidental.
  const { page, tabId } = await visit(ext, "https://fixture-scan.com/plain");
  await waitForIcon(ext, tabId, ["benign"]);
  const popup = await openPopup(ext, tabId);
  const before = net.requestsTo(GRAPH_READ_HOST).length;

  await popup.locator("#btn-iocscan").click();
  await expect(popup.locator("#iocscan-summary")).toContainText("found", { timeout: 20_000 });

  const added = net.requestsTo(GRAPH_READ_HOST).slice(before);
  const addedBodies = added.map((r) => r.body).join("\n");
  expect(addedBodies).not.toContain("fixture-scan.com/plain");
  expect(addedBodies).not.toContain(SECRET_PATH);

  await popup.close();
  await page.close();
});
