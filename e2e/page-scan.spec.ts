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
// The fixture deliberately carries three things a real analyst page carries and
// which must be treated DIFFERENTLY:
//
//   a file hash          assessable, so it SHOULD leave (whisper.assess verdicts
//                        hashes as well as names, coverage "known-hash")
//   a CVE id             has no assessable subject, so it must NEVER leave
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
const SECRET_PATH = "/download?token=sk_live_do_not_exfiltrate_me";

const FIXTURE_HTML = `<!doctype html>
<html><head><title>incident notes</title></head>
<body>
  <h1>Incident notes</h1>
  <p>Dropper observed with sha256 ${HASH} on three hosts.</p>
  <p>Exploited via ${CVE}, patched upstream last week.</p>
  <p>Beaconed to <span>evil-scan.com</span> shortly after.</p>
  <a href="https://fixture-scan.com${SECRET_PATH}">the staging download</a>
  <!-- a comment carrying ${SECRET_PATH} too, which textContent never sees -->
</body></html>`;

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start({ "fixture-scan.com": FIXTURE_HTML });
  ext = await launchExtension(await makeShieldDist(), net);
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
  expect(bodies).toContain(HASH);
  expect(bodies).toContain("evil-scan.com");

  // WHAT MUST NOT. Each of these is a different way to leak.
  expect(bodies).not.toContain(CVE);                       // no assessable subject
  expect(bodies).not.toContain("sk_live_do_not_exfiltrate_me"); // the secret itself
  expect(bodies).not.toContain("token=");                  // the query that carried it
  expect(bodies).not.toContain("Dropper observed");        // the page's prose
  expect(bodies).not.toContain("Incident notes");          // its title and heading

  // The note the reader is shown must match what the capture proves, or the UI
  // is making a promise the wire does not keep.
  await expect(popup.locator("#iocscan-note")).toContainText("never leaves your browser");
  await expect(popup.locator("#iocscan-note")).toContainText("CVE ids are never sent");

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
