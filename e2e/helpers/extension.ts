// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Launch the REAL built extension in Chromium and give tests first-class
// access to its service worker: storage, tab lookup, and the per-tab icon
// state. The icon state is read through chrome.action.getTitle, which the
// icon painter sets atomically with every setIcon call, so title text is a
// faithful 1:1 readout of the painted icon without reaching into internals.

import { chromium, type BrowserContext, type Page, type Worker } from "@playwright/test";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const DIST_CHROMIUM = resolve(HERE, "../../dist/chromium");

export type IconState =
  | "benign"
  | "suspicious"
  | "malicious"
  | "unknown"
  | "checking"
  | "signedout"
  | "neutral";

// Exact copies of the titles the icon painter sets (src/background/icon-state.ts).
const TITLE_TO_STATE: Record<string, IconState> = {
  "Whisper Guard: no known threat on this site": "benign",
  "Whisper Guard: be careful on this site": "suspicious",
  "Whisper Guard: STOP, this site is a known threat": "malicious",
  "Whisper Guard: new or low-coverage site, not confirmed either way": "unknown",
  "Whisper Guard: checking this site": "checking",
  "Whisper Guard: on-device protection active; sign in for the live signal": "signedout",
  "Whisper Guard": "neutral",
};

export interface Extension {
  context: BrowserContext;
  sw: Worker;
  id: string;
  close(): Promise<void>;
}

export interface LaunchOptions {
  proxyPort?: number;
  dist?: string;
  hostResolverRules?: string;
}

/**
 * Launch a persistent Chromium context with the built extension loaded.
 * headless via the full chromium build (headless shell has no extensions).
 */
export async function launchExtension(opts: LaunchOptions = {}): Promise<Extension> {
  const dist = opts.dist ?? DIST_CHROMIUM;
  const userDataDir = mkdtempSync(join(tmpdir(), "whisper-guard-profile-"));
  const args = [
    `--disable-extensions-except=${dist}`,
    `--load-extension=${dist}`,
    "--ignore-certificate-errors",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
    // Quiet the browser's own background services so the capture proxy log
    // is dominated by what the EXTENSION does, not Chromium chatter.
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-sync",
    "--no-default-browser-check",
    "--no-first-run",
  ];
  if (opts.proxyPort) {
    args.push(`--proxy-server=http://127.0.0.1:${opts.proxyPort}`);
  }
  if (opts.hostResolverRules) {
    args.push(`--host-resolver-rules=${opts.hostResolverRules}`);
  }
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args,
    viewport: { width: 1280, height: 800 },
  });

  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  return {
    context,
    sw,
    id,
    close: async () => {
      await context.close();
    },
  };
}

/**
 * A shield-enabled build: same dist, but <all_urls> is granted at install
 * time (required host permission) because the browser's native permission
 * consent dialog cannot be automated. shieldGranted() checks
 * permissions.contains, which is true either way, so every downstream code
 * path under test (DNR rules, tabs.update, injection) is the real one.
 */
export function makeShieldDist(): string {
  const dir = mkdtempSync(join(tmpdir(), "whisper-guard-shield-dist-"));
  cpSync(DIST_CHROMIUM, dir, { recursive: true });
  const mpath = join(dir, "manifest.json");
  const manifest = JSON.parse(readFileSync(mpath, "utf8"));
  manifest.host_permissions = [...manifest.host_permissions, "<all_urls>"];
  writeFileSync(mpath, JSON.stringify(manifest, null, 2));
  return dir;
}

/**
 * An egress-enabled build: the optional proxy permissions and <all_urls>
 * are promoted to REQUIRED at install time, because the browser's own
 * consent dialog for optional permissions cannot be automated. Every code
 * path under test (register/connect, chrome.proxy.set, onAuthRequired, the
 * WebRTC policy) is the real one; only the consent click is pre-satisfied.
 */
export function makeEgressDist(): string {
  const dir = mkdtempSync(join(tmpdir(), "whisper-guard-egress-dist-"));
  cpSync(DIST_CHROMIUM, dir, { recursive: true });
  const mpath = join(dir, "manifest.json");
  const manifest = JSON.parse(readFileSync(mpath, "utf8"));
  manifest.permissions = [
    ...manifest.permissions,
    "proxy",
    "webRequest",
    "webRequestAuthProvider",
    "privacy",
  ];
  manifest.host_permissions = [...manifest.host_permissions, "<all_urls>"];
  delete manifest.optional_permissions;
  writeFileSync(mpath, JSON.stringify(manifest, null, 2));
  return dir;
}

/** Open the full-tab dashboard and return its page (pinned by URL hash). */
export async function openDashboard(ext: Extension, view = ""): Promise<Page> {
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/dashboard.html${view ? `#${view}` : ""}`);
  return page;
}

/**
 * List current tab ids from inside the extension. Note the product
 * deliberately has NO "tabs" permission, so tab.url is invisible here;
 * tests identify tabs by id-diff around creation instead.
 */
export async function tabIds(ext: Extension): Promise<number[]> {
  return ext.sw.evaluate(async () => {
    const tabs = await chrome.tabs.query({});
    return tabs.map((t) => t.id).filter((id): id is number => id !== undefined);
  });
}

/** Read the painted per-tab icon state (via its 1:1 action title). */
export async function iconState(ext: Extension, tabId: number): Promise<IconState | "unset"> {
  const title = await ext.sw.evaluate(
    async (id: number) => chrome.action.getTitle({ tabId: id }),
    tabId,
  );
  return TITLE_TO_STATE[title] ?? "unset";
}

/** Poll until the icon settles on one of the given states. */
export async function waitForIcon(
  ext: Extension,
  tabId: number,
  states: IconState[],
  timeoutMs = 8000,
): Promise<IconState> {
  const deadline = Date.now() + timeoutMs;
  let last: IconState | "unset" = "unset";
  while (Date.now() < deadline) {
    last = await iconState(ext, tabId);
    if (states.includes(last as IconState)) return last as IconState;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`icon never reached ${states.join("/")}; last was ${last}`);
}

/** Put/remove the API key exactly where the product stores it. */
export async function setKey(ext: Extension, key: string | null): Promise<void> {
  await ext.sw.evaluate(async (k: string | null) => {
    if (k === null) await chrome.storage.local.remove("apiKey");
    else await chrome.storage.local.set({ apiKey: k });
  }, key);
}

export async function getStoredKey(ext: Extension): Promise<string | null> {
  return ext.sw.evaluate(async () => {
    const s = await chrome.storage.local.get("apiKey");
    return typeof s["apiKey"] === "string" ? (s["apiKey"] as string) : null;
  });
}

/** Patch settings directly in storage (the options UI path is tested separately). */
export async function setSettings(ext: Extension, patch: Record<string, unknown>): Promise<void> {
  await ext.sw.evaluate(async (p: Record<string, unknown>) => {
    const cur = (await chrome.storage.local.get("settings"))["settings"] ?? {};
    await chrome.storage.local.set({ settings: { ...(cur as object), ...p } });
    // Let the background's storage.onChanged listener invalidate its settings
    // cache before we return, so the next navigation reads the new value.
    await new Promise((r) => setTimeout(r, 80));
  }, patch);
}

/** Open the popup pinned to a tab (the ?tab= debugging/testing affordance). */
export async function openPopup(ext: Extension, tabId: number): Promise<Page> {
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
  return page;
}

/** Navigate a fresh page and identify its tab id by creation diff. */
export async function visit(ext: Extension, url: string): Promise<{ page: Page; tabId: number }> {
  const before = new Set(await tabIds(ext));
  const page = await ext.context.newPage();
  const after = await tabIds(ext);
  const created = after.filter((id) => !before.has(id));
  if (created.length !== 1) {
    await page.close();
    throw new Error(`expected exactly one new tab, saw ${created.length}`);
  }
  await page.goto(url, { waitUntil: "domcontentloaded" });
  return { page, tabId: created[0] };
}
