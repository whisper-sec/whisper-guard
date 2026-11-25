// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Launch the REAL built extension in Chromium and give tests first-class
// access to its service worker: storage, tab lookup, and the per-tab icon
// state. The icon state is read through chrome.action.getTitle, which the
// icon painter sets last in every paint, after the tile and the badge clear, so
// title text is a faithful 1:1 readout of the painted icon without reaching
// into internals.

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
  /**
   * The browser's locale, which sets Accept-Language and navigator.language.
   * It exists for the live consent probe: a German publisher serves a German
   * wall to a German browser and an English one to an English browser, so a
   * probe that always browses in English can never exercise anything but the
   * English decline vocabulary, however many languages the module speaks.
   */
  locale?: string;
  /**
   * Draw scrollbars. Playwright starts headless Chromium with
   * `--hide-scrollbars`, so by default no page ever has a gutter, which is not
   * what a reader on Windows or Linux, or with "always show scroll bars", sees.
   */
  showScrollbars?: boolean;
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
    ...(opts.showScrollbars ? { ignoreDefaultArgs: ["--hide-scrollbars"] } : {}),
    ...(opts.locale ? { locale: opts.locale } : {}),
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

/** The per-tab toolbar badge text ("" when the tab shows none). */
export async function badgeText(ext: Extension, tabId: number): Promise<string> {
  return ext.sw.evaluate(async (id: number) => chrome.action.getBadgeText({ tabId: id }), tabId);
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

/**
 * Put a host in the stopped state for a spec that renders the warning page
 * directly. It writes the same session block ledger entry a real stop records
 * (the warning page asks the background whether the host is in it), so the
 * page shows its blocked state without the spec having to stop a tab first.
 */
export async function markHostBlocked(ext: Extension, host: string): Promise<void> {
  await ext.sw.evaluate(async (h: string) => {
    const cur = (await chrome.storage.session.get("blocked"))["blocked"];
    const list = Array.isArray(cur) ? (cur as string[]) : [];
    if (!list.includes(h)) await chrome.storage.session.set({ blocked: [...list, h] });
  }, host);
}

export type PopupSection = "site" | "page" | "browser";

/**
 * Scroll the popup so one of its three parts (This site, This page, This
 * browser) starts at the top of the scrolling region, then wait until the
 * scroll has settled. The part must be shown: a part the popup hides (while a
 * check runs, for example) is an error here, never a silent no-op. It takes
 * only a Page, so it also works on the file:// page of the Firefox render spec.
 */
export async function scrollPopupTo(popup: Page, section: PopupSection): Promise<void> {
  await popup.locator(`#panel-${section}`).waitFor({ state: "visible" });
  await popup.evaluate(async (id) => {
    const region = document.getElementById("popup-scroll") as HTMLElement;
    const part = document.getElementById(id) as HTMLElement;
    region.scrollTop += part.getBoundingClientRect().top - region.getBoundingClientRect().top;
    // Two frames: the fade and anything watching the scroll have seen it.
    await new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())));
  }, `panel-${section}`);
}

/**
 * Open the one closed row that holds the four graph drawers on This site, so
 * a drawer's own summary can be clicked. Does nothing when it is already open.
 */
export async function openGraphDrawers(popup: Page): Promise<void> {
  const row = popup.locator("#expanders");
  await row.waitFor({ state: "visible" });
  if ((await row.getAttribute("open")) === null) await popup.locator("#expanders > summary").click();
}

/**
 * Open the popup pinned to a browser tab (the ?tab= debugging/testing
 * affordance). `section` is the part of the popup to scroll to once it has
 * loaded; the popup always opens at the top, on This site.
 */
export async function openPopup(ext: Extension, tabId: number, opts: { section?: PopupSection } = {}): Promise<Page> {
  const page = await ext.context.newPage();
  await page.goto(`chrome-extension://${ext.id}/popup.html?tab=${tabId}`);
  if (opts.section && opts.section !== "site") await scrollPopupTo(page, opts.section);
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
  return { page, tabId: created[0]! };
}

/**
 * Navigate an EXISTING page (same tab id) to another URL. visit() always
 * opens a new tab, so it cannot exercise what the browser does to a tab's
 * per-tab action state when its main frame commits a second document.
 */
export async function navigateInTab(page: Page, url: string): Promise<void> {
  await page.goto(url, { waitUntil: "domcontentloaded" });
}

/**
 * Settle a popup for a still capture: reduced motion applied BEFORE the
 * page's scripts run, then a wait until the one animated number has stopped
 * moving.
 *
 * Emulating media AFTER navigation is too late for anything that animates on
 * load. The graph-scale readout counts up over 650ms, so a capture taken
 * 250ms later published "6.95B nodes" for a fixture holding 7.48B: a figure
 * that was never true, in a published picture of a security product, about
 * its own coverage. Reloading with the media state already set makes the
 * page take its own prefers-reduced-motion path, which writes every final
 * value on the first frame.
 *
 * Returns the settled scale text (or null when the readout is absent), so a
 * caller can assert on it rather than trust this.
 */
export async function settlePopup(
  popup: Page,
  opts: { colorScheme?: "dark" | "light"; width?: number; height?: number; section?: PopupSection } = {},
): Promise<string | null> {
  await popup.emulateMedia({
    colorScheme: opts.colorScheme ?? "dark",
    reducedMotion: "reduce",
  });
  await popup.setViewportSize({ width: opts.width ?? 400, height: opts.height ?? 600 });
  await popup.reload();
  await popup
    .locator("#chain-mount .ch-rung")
    .first()
    .waitFor({ timeout: 15_000 })
    .catch(() => undefined);
  await popup.waitForTimeout(500);

  // The part is scrolled to after the rung wait and before the readout reads,
  // which would otherwise return early when the readout is absent.
  if (opts.section && opts.section !== "site") await scrollPopupTo(popup, opts.section);

  const first = await popup.locator("#scale-nodes").textContent().catch(() => null);
  if (first === null) return null;
  await popup.waitForTimeout(350);
  const second = await popup.locator("#scale-nodes").textContent().catch(() => null);
  if (first !== second) {
    throw new Error(
      `the graph scale was still animating at capture time ("${first}" then "${second}"): ` +
        "a published figure must be a settled value, not a frame of a transition",
    );
  }
  return second;
}

// ------------------------------------------------------ service-worker stop

const helperPages = new WeakMap<Extension, Page>();

const isGuardWorker = (w: Worker): boolean => w.url().endsWith("/background.js");

/**
 * A long-lived page of the extension's own, kept open for the whole run. It
 * is the place to reach storage and the worker's message handler FROM WHILE
 * THE WORKER IS STOPPED, and it must outlive stopWorker: closing a tab
 * activates its neighbour, and that activation wakes the worker we just
 * stopped.
 */
export async function extensionPage(ext: Extension): Promise<Page> {
  let page = helperPages.get(ext);
  if (!page || page.isClosed()) {
    page = await ext.context.newPage();
    await page.goto(`chrome-extension://${ext.id}/options.html`);
    helperPages.set(ext, page);
  }
  return page;
}

/**
 * Stop Guard's service worker the way the browser does after about 30 s
 * idle, and resolve only once the worker has really stopped.
 *
 * Playwright's DevTools attachment keeps a worker from idling out by itself,
 * so the stop is forced through the ServiceWorker CDP domain and resolves when
 * the browser reports the worker stopped. A marker is set
 * on the old worker's global first: a worker that did NOT stop still carries
 * it, which is how workerIsFresh() tells a real restart from a stop that
 * silently failed.
 */
export async function stopWorker(ext: Extension): Promise<void> {
  const via = await extensionPage(ext);
  await ext.sw.evaluate(() => {
    (globalThis as unknown as { __e2eMarker?: boolean }).__e2eMarker = true;
  });
  const cdp = await ext.context.newCDPSession(via);
  try {
    // Playwright does not emit "close" for an extension worker the browser
    // stops, so the stop is observed where it is reported: the worker version's
    // own running status.
    const stopped = new Promise<void>((resolveStopped, reject) => {
      const timer = setTimeout(
        () => reject(new Error("the service worker did not stop after stopAllWorkers")),
        10_000,
      );
      cdp.on("ServiceWorker.workerVersionUpdated", (e) => {
        if (e.versions.some((v) => v.scriptURL.endsWith("/background.js") && v.runningStatus === "stopped")) {
          clearTimeout(timer);
          resolveStopped();
        }
      });
    });
    await cdp.send("ServiceWorker.enable");
    await cdp.send("ServiceWorker.stopAllWorkers");
    await stopped;
  } finally {
    await cdp.detach().catch(() => undefined);
  }
}

/**
 * Make ext.sw usable again after stopWorker. Wakes the worker with one harmless
 * message from the helper page, then waits until it answers. Playwright keeps
 * the same Worker handle across a browser-initiated restart (it reconnects to
 * the new execution context), so the handle is kept unless the context
 * reports a different Guard worker.
 */
export async function rebindWorker(ext: Extension): Promise<void> {
  const via = await extensionPage(ext);
  await via.evaluate(() => chrome.runtime.sendMessage({ kind: "getSession" })).catch(() => undefined);
  const until = Date.now() + 10_000;
  for (;;) {
    const other = ext.context.serviceWorkers().find((w) => isGuardWorker(w) && w !== ext.sw);
    if (other) ext.sw = other;
    try {
      await ext.sw.evaluate(() => true);
      return;
    } catch {
      if (Date.now() > until) throw new Error("the service worker did not come back");
      await new Promise((r) => setTimeout(r, 100));
    }
  }
}

/** True when the worker holds none of the old worker's in-memory state. */
export async function workerIsFresh(ext: Extension): Promise<boolean> {
  return ext.sw.evaluate(
    () => (globalThis as unknown as { __e2eMarker?: boolean }).__e2eMarker === undefined,
  );
}

/**
 * Allow Guard in private windows and return the relaunched extension.
 *
 * Without that browser setting Guard never sees a private tab, so a test of
 * "nothing is written for a private tab" would pass against a build that
 * writes everything. The setting has no launch flag, and flipping it on the
 * extensions page leaves a command-line extension unloaded until the browser
 * starts again, so the toggle is persisted in the profile and the browser is
 * relaunched on that same profile. Throws if the browser still says no.
 */
export async function allowInIncognito(ext: Extension, opts: LaunchOptions): Promise<Extension> {
  const page = await ext.context.newPage();
  await page.goto(`chrome://extensions/?id=${ext.id}`);
  await page.locator("#allow-incognito").click();
  await page.waitForTimeout(1500);
  const next = await restartExtension(ext, opts);
  const allowed = await next.sw.evaluate(() => chrome.extension.isAllowedIncognitoAccess());
  if (!allowed) {
    await next.close();
    throw new Error("could not allow the extension in private windows; the private-window test would prove nothing");
  }
  return next;
}
