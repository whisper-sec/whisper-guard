# Whisper Guard

The Whisper security graph, native in your browser. On-device look-alike
detection starts the instant you install it, and a live graph verdict answers
"is THIS site safe?" on every site you visit, with no account needed. A
dashboard shows where this browser (and, signed in, every device on your
account) actually goes: who answers, in which country, on which network, and
whether anything is flagged. Sign in free to unlock your whole fleet and, if
you want, put this browser itself on the Whisper network with its own routable
identity.

Only a site's name is ever checked. Never the page, never the path, never your
history.

## Two tiers, both a full product

**No account (fully keyless, works the instant it installs):**

- **Live graph verdict on every site.** The toolbar mark answers "is THIS site
  safe?" from the Whisper security graph: green for no known threat, amber for
  suspicious, a filled red octagon plate reserved for evidenced-malicious, and
  an honest dashed-slate UNKNOWN for the internet's long tail. Never a fake
  green. Popularity feeds (Tranco and friends) are treated as good, never as a
  threat.
- **The composed picture, WHY included.** Click the mark for who runs the site
  and where it lives, how old the domain is, and the WHY behind the verdict
  shown by default: the graph's score and its named, weighted factors (each
  threat-feed listing with its weight; popularity listings shown as good
  standing), plus a look-alike neighborhood confirmed against the graph.
- **Page-link pre-verdicts.** One click reads every link on the current page
  and verdicts each destination BEFORE you visit any of them: malicious,
  suspicious, unknown, or clean, riskiest first. The links are reduced to bare
  hostnames inside the page itself; only those names are checked, never the
  page, its text, or your history. No new permissions.
- **On-device look-alike detection.** Homoglyph tricks (`paypa1.com`, Cyrillic
  `pаypal.com`), TLD swaps (`paypal.tk`), hyphenation squats (`face-book.com`),
  brand-subdomain abuse (`paypal.com.evil.example`) and combosquats
  (`paypal-secure-login.com`), across a bundled corpus of 800+ heavily phished
  brands. One tap goes to the real site. This runs entirely on-device and is the
  zero-network fallback if you switch the live check off.
- **The "This browser" dashboard.** A full-tab, console-style view of where this
  browser goes, built from your on-device navigation log and enriched through
  the graph: destination / company / country / network tiles, a category donut,
  company and country breakdowns, a concentration callout, and an activity
  ledger that updates live per navigation. Zero extra permissions.
- **Pre-click check.** Right-click any link and pick "Check this link with
  Whisper" to vet the destination before anything loads.

**Signed in (free, one tap, no API key to handle):**

- **Your whole fleet, one view.** Every device and agent on your Whisper account,
  their last-24h destinations merged and graph-enriched into the same panels.
- **Per-endpoint drill-down.** Live counters, an explainable identity-health
  score (each factor shown met / unmet / unknown, never a black box), a
  connection constellation from the endpoint to where it went, and destination
  receipts with co-hosting fan-in and announcing-prefix threat neighbours. Every
  identity is anchored by an RDAP provenance link.
- **Enroll this browser.** One click reserves this browser's own routable
  Whisper identity: a real IPv6 address with reverse-DNS, verifiable by anyone
  via public RDAP. Enrollment is pure control plane: it needs no browser
  permission and works the moment you are signed in.
- **Route this browser (opt-in, off by default).** A separate toggle then
  routes the browser's traffic out through that identity, so it joins your
  fleet as a device whose activity you can audit. WebRTC is hardened to
  proxied-only so nothing leaks around the route. The proxy permissions are
  optional and requested on that click; if another extension (a VPN, a proxy
  manager) holds the browser's proxy setting, Guard says so plainly and keeps
  the identity and verdicts working; routing is never a dead end.
- Sign-in is the RFC 8628 device flow: you approve in the Whisper console and
  the extension receives its credential. You never see or paste a key.

**Active Shield (optional, off by default):**

- A single toggle that asks the browser for on-page permission, used only to
  draw warnings: a full-page stop before known credential-phishing pages (with
  the feed-cited receipts), a slim amber banner on look-alikes, and a caution
  when a password field gains focus on a flagged site. Decline it and everything
  else still works.

## Honest scope

The graph verdict reports UNKNOWN for most of the web, because that is the
truth: absence of evidence is shown as absence of evidence. Coverage is shown as
a category (known-clean, partial, no-data), never dressed up as a percentage or
a safety score. The on-device tier catches look-alikes of major brands you
navigate to; it does not catch compromised legitimate sites or brand-new
domains on its own. The fleet, per-endpoint and browser-egress features need an
account; the verdict, the composed picture, the this-browser dashboard and
public identity verification all work with no key.

## Privacy model

- The only browsing datum that can ever leave the browser is a **hostname**,
  sent to exactly one endpoint, `graph.whisper.security`, whether or not you are
  signed in. Extraction happens at parse time; path, query, fragment, page
  content, and form data are discarded before any network code runs. Your
  on-device navigation list and session allow-list never leave the device.
- `console.whisper.security` is contacted only during sign-in (no browsing
  data). `get.whisper.online` is contacted only for signed brand-corpus
  updates (no browsing data). `rdap.whisper.online` is contacted only to verify
  the identity of your own endpoints, and only receives IP literals of those
  endpoints, never a browsing hostname.
- Verdicts are cached locally and navigations debounced, so revisits paint
  from cache with zero network.
- Hostnames are used to answer the live safety check, not retained to build a
  browsing profile.
- No telemetry, no analytics, no sync. The credential lives in local extension
  storage only. Internal pages (`chrome://`), localhost, private addresses,
  IP literals, and `.local`/`.internal` names are never checked at all.
- Every popup view states exactly what was sent for the current site.

Docs: [whisper.online/docs/whisper-guard](https://whisper.online/docs/whisper-guard) ·
Screenshots: [`shots/`](shots/index.html)

## Install

Chrome Web Store and Firefox AMO listings are in submission. Until they land,
load the built extension directly:

```bash
npm ci
npm run build
```

Then in Chrome / Edge / Brave / Opera / Vivaldi:

1. Open `chrome://extensions`
2. Enable "Developer mode"
3. "Load unpacked" and pick `dist/chromium`

In Firefox: open `about:debugging#/runtime/this-firefox`, choose "Load
Temporary Add-on", and pick `dist/firefox/manifest.json`.

## Build and development

```bash
npm run typecheck        # strict TypeScript, no emit
npm run build            # typecheck + build dist/chromium and dist/firefox
npm run build:chromium   # one target
npm run package          # zip both targets for store upload
npm run icons            # regenerate icon PNGs from the brand mark in assets/logo.png (ImageMagick)
npm run psl              # refresh the vendored Public Suffix List snapshot
```

The build is esbuild + a manifest transform per target, and it self-checks:
a dist missing any file the manifest references fails the build.

## End-to-end tests

The e2e suite loads the real built extension into Chromium with Playwright.
The hermetic suites point the whole browser at a local capture proxy, so the
request log is a complete record of everything that left the browser; the
hostname-only privacy invariant is asserted against that full capture, not a
sample.

```bash
npm run e2e              # hermetic: protection, dashboard, egress, Active Shield
npm run e2e:firefox      # web-ext lint (zero findings) + headless load gate
WHISPER_GUARD_E2E_KEY=... npm run e2e:live   # against the real production graph
npx playwright test e2e/screenshots.spec.ts  # regenerate shots/
```

The browser-as-endpoint feature has its own hard dual-engine e2e
(`e2e/egress.spec.ts`): it flips the toggle, then proves the browser is actually
routed through the Whisper egress endpoint (its own registered identity), that
the identity appears in the account roster, and that keyless RDAP
verify-identity of the routed address returns `is_whisper_agent: true`. It is
never a structural pass. `e2e/enroll.spec.ts` proves the split: enrollment
succeeds with zero proxy permissions granted (and no traffic routed), and a
REAL second proxy-holding extension cannot dead-end the flow: the browser
still enrolls, and the conflict renders as an explanation with a way forward.
`e2e/links.spec.ts` proves the page-link sweep against the full capture: only
registrable hostnames reach the graph; the links' paths, queries and the
page's text never leave the browser.

The live suite picks a currently-listed malicious hostname, pins its DNS to
a local harmless page, and verifies the real verdict end to end; the key is
read from the environment and never appears in any artifact. Fail-open
(graph unreachable means UNKNOWN, never a block) is a tested path.

## Store packaging

`npm run package` produces `dist/whisper-guard-chromium-<v>.zip` and
`dist/whisper-guard-firefox-<v>.zip`. Listing copy, permission
justifications, and reviewer notes live in [`store/`](store/).

## Architecture

```
src/
  shared/      config, types, messages, the offline Public Suffix List,
               and the hostname chokepoint (the one place URLs are parsed)
  detector/    the on-device engine: punycode decode, confusable skeleton,
               the bundled brand corpus, candidate generation
  background/  MV3 service worker: navigation pipeline, verdict cache,
               per-tab icon state, graph client (assess/explain/identify/
               submit), RFC 8628 device flow, context menu, corpus updater,
               Active Shield (DNR rules + injection)
  content/     the on-page guard, injected only on flagged hosts after the
               Active Shield opt-in
  popup/       the click panel
  options/     settings, sign-in, privacy panel
  pages/       full-page warning + pre-click check result
manifests/     manifest.chromium.json, manifest.firefox.json
icons/         pre-rendered PNG state sets (built from the brand mark in assets/logo.png)
```

Default permissions are deliberately minimal: `activeTab`, `webNavigation`,
`storage`, `scripting`, `contextMenus`, `declarativeNetRequest`, `alarms`, and
host access to the three Whisper endpoints above. There is no `<all_urls>`
grant and no standing content script; broad host access exists only as the
optional, revocable Active Shield permission, requested at runtime.

## Browser support

- **Chromium** (Chrome, Edge, Brave, Opera, Vivaldi): the primary target,
  MV3, `dist/chromium`.
- **Firefox** (142+): built from the same code via a manifest transform,
  `dist/firefox`; verified with web-ext (AMO lint, zero findings) and a
  headless temporary-install load test.
- **Safari**: planned; requires the Safari Web Extension converter and Xcode.

## Fail-open by design

If the graph is slow or unreachable, the icon shows UNKNOWN (never a false
green, never a false red), the on-device protection keeps running, and
browsing is never blocked. An expired sign-in says so plainly and offers to
sign in again.

## License

MIT (c) 2026 viaGraph B.V. (Whisper Security). See `LICENSE`.

The bundled Public Suffix List snapshot is maintained by Mozilla and the PSL
community under the Mozilla Public License 2.0; see `NOTICE`.
