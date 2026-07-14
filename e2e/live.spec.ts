// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The live suite: the same built extension against the REAL Whisper graph
// with a REAL key. Two-tier, per the shipping bar: keyless on-device value
// first, then the keyed live signal on real production verdicts.
//
// The key comes from the environment (WHISPER_GUARD_E2E_KEY) and is never
// committed or written to any artifact; evidence files redact it.
//
// Safety: the evidenced-malicious hostname is chosen live from the graph
// (assessed CRITICAL against real threat feeds), but its DNS is pinned to a
// local harmless page via --host-resolver-rules, so the browser renders no
// real malware while the hostname, the assess call, the verdict, and the
// icon are all genuinely end to end.

import { test, expect } from "@playwright/test";
import * as http from "node:http";
import * as net from "node:net";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  launchExtension,
  openPopup,
  setKey,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIVE_KEY = process.env["WHISPER_GUARD_E2E_KEY"] ?? "";
const GRAPH = "https://graph.whisper.security/api/query";
const EVIDENCE = resolve(HERE, "../e2e-artifacts/live-evidence.md");

// A fresh URLhaus pull happens first; these recently-listed hosts are the
// fallback when the feed is unreachable from CI.
const FALLBACK_BAD_HOSTS = [
  "airyvineic.help",
  "1717.1000uc.com",
  "abdulahad.net",
  "alineeleuterio.com.br",
  "aftelecom.com.br",
  "123.ywxww.net",
];

const LOOKALIKE = "paypa1-login-verify.com";

let ext: Extension;
let badHost = "";
let badVerdict: Record<string, unknown> = {};
let localServer: http.Server;
let localPort = 0;

function evidence(line: string): void {
  mkdirSync(dirname(EVIDENCE), { recursive: true });
  appendFileSync(EVIDENCE, line + "\n");
}

async function assess(hosts: string[]): Promise<Record<string, unknown>[]> {
  const res = await fetch(GRAPH, {
    method: "POST",
    headers: { "content-type": "application/json", "X-API-Key": LIVE_KEY },
    body: JSON.stringify({
      query: "CALL whisper.assess($hs) YIELD host,label,band,coverage RETURN host,label,band,coverage",
      parameters: { hs: hosts },
    }),
  });
  if (!res.ok) throw new Error(`graph returned ${res.status}`);
  const parsed = (await res.json()) as { rows?: Record<string, unknown>[] };
  return parsed.rows ?? [];
}

async function pickCriticalHost(): Promise<{ host: string; row: Record<string, unknown> }> {
  let candidates = [...FALLBACK_BAD_HOSTS];
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 15_000);
    const feed = await fetch("https://urlhaus.abuse.ch/downloads/text_online/", { signal: ctl.signal });
    clearTimeout(t);
    if (feed.ok) {
      const text = await feed.text();
      const fresh = [
        ...new Set(
          text
            .split("\n")
            .filter((l) => /^https?:\/\//.test(l))
            .map((l) => l.replace(/^[a-z]+:\/\//, "").replace(/[/:].*$/, ""))
            .filter((h) => h && !/^[0-9.]+$/.test(h)),
        ),
      ].slice(0, 30);
      candidates = [...fresh, ...candidates];
    }
  } catch {
    // fallback list stands
  }
  const rows = await assess(candidates);
  const critical = rows.find((r) => r["band"] === "CRITICAL");
  if (!critical) throw new Error("no CRITICAL host available from the live graph right now");
  return { host: String(critical["host"]), row: critical };
}

test.describe("live graph, real key", () => {
  test.skip(LIVE_KEY === "", "set WHISPER_GUARD_E2E_KEY to run the live suite");

  test.beforeAll(async () => {
    test.setTimeout(180_000);

    const picked = await pickCriticalHost();
    badHost = picked.host;
    badVerdict = picked.row;

    // Harmless local page standing in for the malicious host's content.
    localServer = http.createServer((_req, res) => {
      res
        .writeHead(200, { "content-type": "text/html" })
        .end("<!doctype html><title>stand-in</title><h1>harmless local stand-in page</h1>");
    });
    await new Promise<void>((r) => localServer.listen(0, "127.0.0.1", r));
    localPort = (localServer.address() as net.AddressInfo).port;

    ext = await launchExtension({
      hostResolverRules: `MAP ${badHost} 127.0.0.1, MAP ${LOOKALIKE} 127.0.0.1`,
    });

    evidence(`# Whisper Guard live e2e evidence`);
    evidence(``);
    evidence(`- run: ${new Date().toISOString()}`);
    evidence(`- key: whisper-****************************************************(redacted)`);
    evidence(`- graph endpoint: graph.whisper.security (production)`);
    evidence(`- evidenced-malicious host under test: ${badHost} (DNS pinned to a local harmless page; verdict is the real graph's)`);
    evidence(`- baseline assess row: ${JSON.stringify(badVerdict)}`);
  });

  test.afterAll(async () => {
    await ext?.close();
    await new Promise((r) => localServer?.close(r));
  });

  test("keyless: on-device look-alike protection works against the real network", async () => {
    await setKey(ext, null);
    const { page, tabId } = await visit(ext, `http://${LOOKALIKE}:${localPort}/`);
    expect(await waitForIcon(ext, tabId, ["suspicious"])).toBe("suspicious");

    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#lookalike-text")).toContainText("paypal.com");
    await expect(popup.locator("#lookalike-text")).toContainText("nothing left your browser");
    await popup.close();
    await page.close();
    evidence(`- keyless on-device hit: ${LOOKALIKE} flagged as look-alike of paypal.com, icon=suspicious, zero egress (hermetic suite proves the zero-egress invariant with a full capture)`);
  });

  test("keyed: a real known-clean host paints benign with the graph's own coverage", async () => {
    await setKey(ext, LIVE_KEY);
    const { page, tabId } = await visit(ext, "https://example.com/");
    expect(await waitForIcon(ext, tabId, ["benign"], 15_000)).toBe("benign");

    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#band-chip")).toHaveText("NO KNOWN THREAT");
    await expect(popup.locator("#coverage-chip")).toContainText("known-clean");
    await expect(popup.locator("#privacy-line")).toContainText('only "example.com" was sent');
    await popup.close();
    await page.close();
    evidence(`- keyed clean: example.com -> band NONE, coverage known-clean, icon=benign`);
  });

  test("keyed: a real evidenced-malicious host paints the red plate with real explain sources", async () => {
    await setKey(ext, LIVE_KEY);
    const { page, tabId } = await visit(ext, `http://${badHost}:${localPort}/`);
    expect(await waitForIcon(ext, tabId, ["malicious"], 20_000)).toBe("malicious");

    const popup = await openPopup(ext, tabId);
    await expect(popup.locator("#band-chip")).toHaveText("MALICIOUS - evidenced");
    await expect(popup.locator("#coverage-chip")).toContainText("not a safety score");

    // The "why": whisper.explain against production, real feed listings.
    await popup.locator("#exp-why summary").click();
    await expect(popup.locator("#why-body")).toContainText("CRITICAL", { timeout: 20_000 });
    const why = await popup.locator("#why-body").textContent();
    evidence(`- keyed evidenced-malicious: ${badHost} -> band CRITICAL, icon=malicious (red plate)`);
    evidence(`- real explain excerpt: ${(why ?? "").slice(0, 300).replace(/\s+/g, " ")}`);

    await popup.close();
    await page.close();
  });

  test("keyed: whisper.identify renders a real operator", async () => {
    await setKey(ext, LIVE_KEY);
    const { page, tabId } = await visit(ext, "https://github.com/");
    await waitForIcon(ext, tabId, ["benign", "unknown"], 15_000);
    const popup = await openPopup(ext, tabId);
    await popup.locator("#exp-who summary").click();
    await expect(popup.locator("#who-body")).toContainText("ithub", { timeout: 20_000 });
    await popup.close();
    await page.close();
    evidence(`- keyed identify: github.com -> canonical operator rendered from whisper.identify`);
  });

  test("keyed: the enterprise paste-a-key path signs in against the real graph", async () => {
    await setKey(ext, null);
    const options = await ext.context.newPage();
    await options.goto(`chrome-extension://${ext.id}/options.html`);
    await options.locator(".fallback summary").click();
    await options.locator("#key-input").fill(LIVE_KEY);
    await options.locator("#btn-savekey").click();
    await expect(options.locator("#account-signedin")).toBeVisible({ timeout: 10_000 });
    await options.close();
    evidence(`- enterprise paste-a-key path: signed in against production; key never shown in evidence`);
  });

  test("live look-alike confirmation: candidates assessed against the production graph", async () => {
    await setKey(ext, LIVE_KEY);
    const { page, tabId } = await visit(ext, `http://${LOOKALIKE}:${localPort}/`);
    await waitForIcon(ext, tabId, ["suspicious", "unknown"], 15_000);
    const popup = await openPopup(ext, tabId);
    await popup.locator("#exp-neighborhood summary").click();
    // Real answer either way: confirmed look-alikes or the honest "none
    // currently flagged". Both are legitimate production outcomes.
    await expect(popup.locator("#neighborhood-note")).toContainText(/flagged in the graph|no registered look-alike/i, {
      timeout: 30_000,
    });
    const note = await popup.locator("#neighborhood-note").textContent();
    evidence(`- live assess-on-candidates: ${note?.trim()}`);
    await popup.close();
    await page.close();
  });
});
