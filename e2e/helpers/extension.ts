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
  /** The profile directory, for a same-profile relaunch (restart tests). */
  userDataDir: string;
  close(): Promise<void>;
}

export interface LaunchOptions {
  proxyPort?: number;
  dist?: string;
  hostResolverRules?: string;
  /** Additional unpacked extensions to load NEXT TO Whisper Guard (they
   *  install after it, so e.g. a proxy holder wins the proxy setting). */
  extraExtensions?: string[];
  /** Reuse an existing profile (after close()): chrome.storage.local
   *  persists, in-memory worker state does not: the deterministic way to
   *  exercise a service-worker restart end to end. */
  userDataDir?: string;
}

/**
 * Launch a persistent Chromium context with the built extension loaded.
 * headless via the full chromium build (headless shell has no extensions).
 */
export async function launchExtension(opts: LaunchOptions = {}): Promise<Extension> {
  const dist = opts.dist ?? DIST_CHROMIUM;
  const userDataDir = opts.userDataDir ?? mkdtempSync(join(tmpdir(), "whisper-guard-profile-"));
  const allDists = [dist, ...(opts.extraExtensions ?? [])].join(",");
  const args = [
    `--disable-extensions-except=${allDists}`,
    `--load-extension=${allDists}`,
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

  // With extra extensions loaded there is more than one service worker:
  // Whisper Guard's is the one running background.js.
  const isGuardSw = (w: Worker): boolean => w.url().endsWith("/background.js");
  let sw = context.serviceWorkers().find(isGuardSw);
  while (!sw) {
    const next = await context.waitForEvent("serviceworker");
    if (isGuardSw(next)) sw = next;
  }
  const id = new URL(sw.url()).host;

  // Settle the first-run page's live sample before handing the extension
  // over. On install the background opens firstrun.html, which assesses one
  // real host (github.com) to show a working verdict. That request is
  // asynchronous and slow relative to test setup, so under load it lands
  // AFTER a test's net.clearLog() and inside a window the test believes is
  // its own. Every "exactly one graph request" and "reads[0] is mine"
  // assertion in the suite is then measuring someone else's traffic.
  //
  // visit() already knows about this tab for tab-identification; its network
  // is the same race one layer down. Waiting for the sample to finish is the
  // fix, rather than teaching each assertion to ignore one hostname.
  //
  // The signal is the sample's own chip, which starts at "CHECKING" and is
  // replaced on BOTH outcomes (a verdict or UNAVAILABLE), so this waits for
  // the request to be finished rather than for it to have succeeded.
  //
  // Bounded and non-fatal: if a future build drops the first-run sample there
  // is no such page and nothing to wait for, and a suite that then sees no
  // stray request is correct anyway. What must not happen is waiting forever.
  // The background opens that tab asynchronously, so look for it for a beat
  // before deciding it is not coming.
  let firstrun: Page | undefined;
  const appearBy = Date.now() + 5_000;
  while (Date.now() < appearBy) {
    firstrun = context.pages().find((p) => p.url().includes("firstrun.html"));
    if (firstrun) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  if (firstrun) {
    await firstrun
      .locator("#sample-chip")
      .filter({ hasNotText: "CHECKING" })
      .waitFor({ timeout: 15_000 })
      .catch(() => undefined);
  }

  return {
    context,
    sw,
    id,
    userDataDir,
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
 * A dist WITHOUT any broad grant but WITH a scoped host permission for
 * the given hosts only: the faithful stand-in for an activeTab
 * invocation, whose grant gesture (a real toolbar click) cannot be
 * automated: activeTab is, mechanically, a temporary scoped host grant
 * for the one invoked tab. <all_urls> is absent everywhere (the optional
 * route is deleted too), so every code path under test is the
 * no-broad-grant one: scripting succeeds ONLY on the named hosts, and
 * anything DNR does for other hosts provably needs no host permission.
 */
export function makeScopedDist(hosts: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "whisper-guard-scoped-dist-"));
  cpSync(DIST_CHROMIUM, dir, { recursive: true });
  const mpath = join(dir, "manifest.json");
  const manifest = JSON.parse(readFileSync(mpath, "utf8"));
  manifest.host_permissions = [
    ...manifest.host_permissions,
    ...hosts.map((h) => `https://${h}/*`),
  ];
  delete manifest.optional_host_permissions;
  writeFileSync(mpath, JSON.stringify(manifest, null, 2));
  return dir;
}

/**
 * A REAL background-service-worker restart, delivered the deterministic
 * way: close the browser and relaunch it on the SAME profile with the
 * SAME dist. chrome.storage.local persists on disk; every scrap of the
 * old worker's in-memory state is gone, a strict superset of the MV3
 * idle-eviction event. Returns the fresh Extension (new context, new
 * worker, same extension id since the id derives from the dist path).
 */
export async function restartExtension(ext: Extension, opts: LaunchOptions): Promise<Extension> {
  const profile = ext.userDataDir;
  await ext.close();
  return launchExtension({ ...opts, userDataDir: profile });
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
  // proxy is already REQUIRED on Chromium (it cannot be optional); the rest
  // are promoted here so the e2e never faces the un-scriptable consent dialog.
  manifest.permissions = [
    ...new Set([
      ...manifest.permissions,
      "proxy",
      "webRequest",
      "webRequestAuthProvider",
      "privacy",
    ]),
  ];
  manifest.host_permissions = [...manifest.host_permissions, "<all_urls>"];
  delete manifest.optional_permissions;
  writeFileSync(mpath, JSON.stringify(manifest, null, 2));
  return dir;
}

/**
 * A minimal SECOND extension that takes ownership of the browser's proxy
 * setting (pointed at the capture proxy, so the run stays hermetic). Loaded
 * after Whisper Guard it wins the setting, and Guard's proxy.settings.get
 * reports levelOfControl "controlled_by_other_extensions": the real-world
 * VPN/proxy-manager conflict, reproduced faithfully.
 */
export function makeProxyHolderExt(captureProxyPort: number): string {
  const dir = mkdtempSync(join(tmpdir(), "whisper-guard-proxy-holder-"));
  writeFileSync(
    join(dir, "manifest.json"),
    JSON.stringify(
      {
        manifest_version: 3,
        name: "e2e proxy holder",
        version: "1.0.0",
        permissions: ["proxy"],
        background: { service_worker: "holder.js" },
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(dir, "holder.js"),
    `chrome.proxy.settings.set({
  value: { mode: "fixed_servers", rules: { singleProxy: { scheme: "http", host: "127.0.0.1", port: ${captureProxyPort} } } },
  scope: "regular",
});
`,
  );
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
  let created = after.filter((id) => !before.has(id));
  if (created.length > 1) {
    // A fresh install can race its firstrun tab into the diff window. The
    // extension always sees its OWN pages' URLs (no "tabs" permission
    // needed for its origin), so extension-page tabs are dropped here.
    const own = await ext.sw.evaluate(async (ids: number[]) => {
      const tabs = await chrome.tabs.query({});
      return tabs
        .filter(
          (t) =>
            t.id !== undefined && ids.includes(t.id) && (t.url ?? t.pendingUrl ?? "").startsWith("chrome-extension://"),
        )
        .map((t) => t.id as number);
    }, created);
    created = created.filter((id) => !own.includes(id));
  }
  if (created.length !== 1) {
    await page.close();
    throw new Error(`expected exactly one new tab, saw ${created.length}`);
  }
  await page.goto(url, { waitUntil: "domcontentloaded" });
  return { page, tabId: created[0] };
}
