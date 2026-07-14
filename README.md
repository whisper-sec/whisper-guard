# Whisper Guard

Proactive phishing and brand protection in your browser. On-device look-alike
detection starts working the instant you install it, no account needed. Sign in
free and the Whisper security graph lights up a live threat signal on every
site you visit.

Only a site's name is ever checked. Never the page, never the path, never your
history.

## What you get

**The instant it installs (no sign-in, fully on-device):**

- Warns you before you type a password into a look-alike of a major brand's
  login page: homoglyph tricks (`paypa1.com`, Cyrillic `pаypal.com`), TLD swaps
  (`paypal.tk`), hyphenation squats (`face-book.com`), brand-subdomain abuse
  (`paypal.com.evil.example`) and combosquats (`paypal-secure-login.com`),
  across a bundled corpus of 800+ heavily phished brands.
- One tap takes you to the real site: "Go to the real paypal.com".
- Right-click any link and pick "Check this link with Whisper" to vet the
  destination before you navigate. The safest path for links that arrive in
  email, SMS, or chat: nothing has loaded yet when the verdict appears.
- All of it runs in your browser. Nothing leaves the device.

**Signed in (free, one tap, no API key to handle):**

- The toolbar mark answers "is THIS site safe?" on every navigation, from the
  3.67B-node Whisper security graph: green ring for no known threat, amber for
  suspicious, a filled red octagon plate reserved for evidenced-malicious, and
  an honest dashed slate UNKNOWN for the internet's long tail. Never a fake
  green.
- Click the mark for the "why" (the graph's explanation and label), who runs
  the site, a look-alike neighborhood confirmed against the graph (generated
  candidates, each assessed for real), a session log of risky hosts, one-click
  reporting, and a copyable dossier.
- Sign-in is the RFC 8628 device flow: you approve in the Whisper console and
  the extension receives its credential. You never see or paste a key.

**Active Shield (optional, off by default):**

- A single toggle that asks the browser for on-page permission, used only to
  draw warnings: a full-page stop before known credential-phishing pages, a
  slim amber banner on look-alikes, and a caution when a password field gains
  focus on a flagged site. Decline it and everything else still works.

## Honest scope

The keyless tier catches look-alikes of major brands that you navigate to. It
does not catch compromised legitimate sites, brand-new domains on shared
hosting, or threats on links you never open. The signed-in graph signal covers
far more, and still reports UNKNOWN for most of the web, because that is the
truth: absence of evidence is shown as absence of evidence. Coverage is shown
as a category (known-clean, partial, no-data), never dressed up as a score.

## Privacy model

- The only thing that can ever leave the browser is a **hostname**, sent to
  exactly one endpoint, `graph.whisper.security`, and only when you are signed
  in. Extraction happens at parse time; path, query, fragment, page content,
  and form data are discarded before any network code runs.
- `console.whisper.security` is contacted only during sign-in (no browsing
  data). `get.whisper.online` is contacted only for signed brand-corpus
  updates (no browsing data).
- Verdicts are cached locally and navigations debounced, so revisits paint
  from cache with zero network.
- Hostnames are used to answer the live safety check, not retained to build a
  browsing profile.
- No telemetry, no analytics, no sync. The credential lives in local extension
  storage only. Internal pages (`chrome://`), localhost, private addresses,
  IP literals, and `.local`/`.internal` names are never checked at all.
- Every popup view states exactly what was sent for the current site.

## Install

Store listings (Chrome Web Store, Edge Add-ons, Firefox AMO) are on the way.
Until then, load the built extension directly:

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
npm run icons            # regenerate icon PNGs from the SVG sources (ImageMagick)
npm run psl              # refresh the vendored Public Suffix List snapshot
```

The build is esbuild + a manifest transform per target, and it self-checks:
a dist missing any file the manifest references fails the build.

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
icons/         pre-rendered PNG state sets (built from assets/icons)
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
